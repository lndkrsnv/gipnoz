package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"gipnoz/internal/crypto"
	pb "gipnoz/internal/proto"
)

const decoyTarget = "127.0.0.1:1"

var (
	sidOne = []byte("aaaaaaaaaaaaaaaa")
	sidTwo = []byte("bbbbbbbbbbbbbbbb")
)

type fixture struct {
	tunnel    pb.TunnelClient
	clientID  ed25519.PrivateKey
	serverPub ed25519.PublicKey
	secBuf    *bytes.Buffer
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	_, clientID, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	serverPub, serverID, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	secBuf := &bytes.Buffer{}
	secLog := slog.New(slog.NewTextHandler(secBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	clientPub := clientID.Public().(ed25519.PublicKey)
	tunnelSrv := NewTunnelServer(TunnelServerConfig{
		HostKey: serverID,
		Clients: map[string]ClientIdentity{
			string(clientPub): {Name: "test-client", Pub: clientPub},
		},
		PadMin:       16,
		PadMax:       256,
		Replay:       crypto.NewReplayGuard(crypto.TimestampToleranceSeconds),
		RateLimiter:  NewRateLimiter(64),
		SecLog:       secLog,
		SessionGrace: 100 * time.Millisecond,
		DialTimeout:  2 * time.Second,
		IdleTimeout:  30 * time.Second,
	})

	lis := bufconn.Listen(1024 * 1024)
	grpcSrv := grpc.NewServer()
	pb.RegisterTunnelServer(grpcSrv, tunnelSrv)
	go func() { _ = grpcSrv.Serve(lis) }()
	t.Cleanup(grpcSrv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("bufconn dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	return &fixture{
		tunnel:    pb.NewTunnelClient(conn),
		clientID:  clientID,
		serverPub: serverPub,
		secBuf:    secBuf,
	}
}

func (f *fixture) attemptHello(t *testing.T, payload []byte) (codes.Code, error) {
	t.Helper()
	return f.attemptHelloFrom(t, payload, "")
}

func (f *fixture) attemptHelloFrom(t *testing.T, payload []byte, xff string) (codes.Code, error) {
	t.Helper()

	ctx := context.Background()
	if xff != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "x-forwarded-for", xff)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	stream, err := f.tunnel.Connect(ctx)
	if err != nil {
		return status.Code(err), err
	}
	if err := stream.Send(&pb.Chunk{Payload: payload}); err != nil {
		return status.Code(err), err
	}
	_, err = stream.Recv()
	return status.Code(err), err
}

func TestHandlerAuthSuccess(t *testing.T) {
	f := newFixture(t)

	payload, _, err := crypto.BuildClientHello(f.clientID, decoyTarget, sidOne)
	if err != nil {
		t.Fatalf("BuildClientHello: %v", err)
	}
	code, err := f.attemptHello(t, payload)
	if code != codes.Unavailable {
		t.Fatalf("want Unavailable (auth passed, decoy unreachable), got %s: %v", code, err)
	}
}

func TestHandlerUnknownKey(t *testing.T) {
	f := newFixture(t)

	_, rogue, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate rogue key: %v", err)
	}
	payload, _, err := crypto.BuildClientHello(rogue, decoyTarget, sidOne)
	if err != nil {
		t.Fatalf("BuildClientHello: %v", err)
	}
	code, _ := f.attemptHello(t, payload)
	if code != codes.Unauthenticated {
		t.Fatalf("want Unauthenticated, got %s", code)
	}
}

func TestHandlerExpiredTimestamp(t *testing.T) {
	f := newFixture(t)

	payload, _, err := crypto.BuildClientHelloAt(f.clientID, time.Now().Add(-60*time.Second), decoyTarget, sidOne)
	if err != nil {
		t.Fatalf("BuildClientHelloAt: %v", err)
	}
	code, _ := f.attemptHello(t, payload)
	if code != codes.Unauthenticated {
		t.Fatalf("want Unauthenticated, got %s", code)
	}
}

func TestHandlerReplay(t *testing.T) {
	f := newFixture(t)

	payload, _, err := crypto.BuildClientHello(f.clientID, decoyTarget, sidOne)
	if err != nil {
		t.Fatalf("BuildClientHello: %v", err)
	}

	code, _ := f.attemptHello(t, payload)
	if code != codes.Unavailable {
		t.Fatalf("first attempt: want Unavailable (auth passed), got %s", code)
	}
	code, _ = f.attemptHello(t, payload)
	if code != codes.Unauthenticated {
		t.Fatalf("second attempt (replay): want Unauthenticated, got %s", code)
	}
}

func TestPeerIP(t *testing.T) {
	ctxWithPeer := func(addr string) context.Context {
		return peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP(addr), Port: 1234}})
	}
	withXFF := func(ctx context.Context, xff string) context.Context {
		return metadata.NewIncomingContext(ctx, metadata.Pairs("x-forwarded-for", xff))
	}

	tests := []struct {
		name string
		ctx  context.Context
		want string
	}{
		{
			name: "public direct peer, no xff",
			ctx:  ctxWithPeer("203.0.113.10"),
			want: "203.0.113.10",
		},
		{
			name: "private direct peer (docker proxy), xff wins",
			ctx:  withXFF(ctxWithPeer("172.18.0.3"), "198.51.100.7, 172.18.0.1"),
			want: "198.51.100.7",
		},
		{
			name: "loopback direct peer, xff wins",
			ctx:  withXFF(ctxWithPeer("127.0.0.1"), "198.51.100.7"),
			want: "198.51.100.7",
		},
		{
			name: "public direct peer, xff ignored (spoofing)",
			ctx:  withXFF(ctxWithPeer("203.0.113.10"), "198.51.100.7"),
			want: "203.0.113.10",
		},
		{
			name: "private direct peer, empty xff",
			ctx:  ctxWithPeer("172.18.0.3"),
			want: "172.18.0.3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := peerIP(tt.ctx); got != tt.want {
				t.Fatalf("peerIP: want %s, got %s", tt.want, got)
			}
		})
	}
}

func echoTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(c, c)
				c.Close()
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func (f *fixture) openStream(t *testing.T, target string, sessionID []byte, xff string) pb.Tunnel_ConnectClient {
	t.Helper()

	ctx := context.Background()
	if xff != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "x-forwarded-for", xff)
	}
	stream, err := f.tunnel.Connect(ctx)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	payload, _, err := crypto.BuildClientHello(f.clientID, target, sessionID)
	if err != nil {
		t.Fatalf("BuildClientHello: %v", err)
	}
	if err := stream.Send(&pb.Chunk{Payload: payload}); err != nil {
		t.Fatalf("send hello: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	return stream
}

func TestHandlerSessionBusy(t *testing.T) {
	f := newFixture(t)
	echo := echoTarget(t)

	stream1 := f.openStream(t, echo, sidOne, "203.0.113.1")
	defer stream1.CloseSend()

	payload, _, err := crypto.BuildClientHello(f.clientID, decoyTarget, sidTwo)
	if err != nil {
		t.Fatalf("BuildClientHello: %v", err)
	}
	if code, _ := f.attemptHelloFrom(t, payload, "203.0.113.2"); code != codes.ResourceExhausted {
		t.Fatalf("other session while busy: want ResourceExhausted, got %s", code)
	}

	if got := f.secBuf.String(); !strings.Contains(got, "possible key sharing") ||
		!strings.Contains(got, "session busy") {
		t.Fatalf("security log missing busy entry, got: %q", got)
	}

	payload, _, err = crypto.BuildClientHello(f.clientID, decoyTarget, sidTwo)
	if err != nil {
		t.Fatalf("BuildClientHello: %v", err)
	}
	if code, _ := f.attemptHelloFrom(t, payload, "203.0.113.2"); code != codes.ResourceExhausted {
		t.Fatalf("retry while busy: want ResourceExhausted, got %s", code)
	}
	if n := strings.Count(f.secBuf.String(), "session busy"); n != 1 {
		t.Fatalf("busy log must be throttled to one entry, got %d", n)
	}
}

func TestHandlerSameSessionJoins(t *testing.T) {
	f := newFixture(t)
	echo := echoTarget(t)

	stream1 := f.openStream(t, echo, sidOne, "")
	defer stream1.CloseSend()

	payload, _, err := crypto.BuildClientHello(f.clientID, decoyTarget, sidOne)
	if err != nil {
		t.Fatalf("BuildClientHello: %v", err)
	}
	if code, _ := f.attemptHello(t, payload); code != codes.Unavailable {
		t.Fatalf("same session: want Unavailable (joined), got %s", code)
	}
}

func TestHandlerSessionExpires(t *testing.T) {
	f := newFixture(t)
	echo := echoTarget(t)

	stream1 := f.openStream(t, echo, sidOne, "")

	payload, _, err := crypto.BuildClientHello(f.clientID, decoyTarget, sidTwo)
	if err != nil {
		t.Fatalf("BuildClientHello: %v", err)
	}
	if code, _ := f.attemptHello(t, payload); code != codes.ResourceExhausted {
		t.Fatalf("while busy: want ResourceExhausted, got %s", code)
	}

	stream1.CloseSend()
	time.Sleep(300 * time.Millisecond)

	payload, _, err = crypto.BuildClientHello(f.clientID, decoyTarget, sidTwo)
	if err != nil {
		t.Fatalf("BuildClientHello: %v", err)
	}
	if code, _ := f.attemptHello(t, payload); code != codes.Unavailable {
		t.Fatalf("after lease expiry: want Unavailable (admitted), got %s", code)
	}
}
