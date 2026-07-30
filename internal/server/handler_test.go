package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"gipnoz/internal/crypto"
	pb "gipnoz/internal/proto"
)

const decoyTarget = "127.0.0.1:1"

type fixture struct {
	tunnel    pb.TunnelClient
	clientID  ed25519.PrivateKey
	serverPub ed25519.PublicKey
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

	clientPub := clientID.Public().(ed25519.PublicKey)
	tunnelSrv := NewTunnelServer(TunnelServerConfig{
		HostKey: serverID,
		Clients: map[string]ClientIdentity{
			string(clientPub): {Name: "test-client", Pub: clientPub},
		},
		PadMin:      16,
		PadMax:      256,
		Replay:      crypto.NewReplayGuard(crypto.TimestampToleranceSeconds),
		RateLimiter: NewRateLimiter(64),
		DialTimeout: 2 * time.Second,
		IdleTimeout: 30 * time.Second,
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
	}
}

func (f *fixture) attemptHello(t *testing.T, payload []byte) (codes.Code, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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

	payload, _, err := crypto.BuildClientHello(f.clientID, decoyTarget)
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
	payload, _, err := crypto.BuildClientHello(rogue, decoyTarget)
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

	payload, _, err := crypto.BuildClientHelloAt(f.clientID, time.Now().Add(-60*time.Second), decoyTarget)
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

	payload, _, err := crypto.BuildClientHello(f.clientID, decoyTarget)
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
