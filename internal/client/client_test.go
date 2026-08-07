package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"gipnoz/internal/crypto"
	pb "gipnoz/internal/proto"
	"gipnoz/internal/routing"
	"gipnoz/internal/server"
)

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

func bufconnTunnel(t *testing.T, tunnelSrv pb.TunnelServer) pb.TunnelClient {
	t.Helper()

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
	return pb.NewTunnelClient(conn)
}

func newTestPair(t *testing.T) (clientID, serverID ed25519.PrivateKey) {
	t.Helper()
	var err error
	_, clientID, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	_, serverID, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	return clientID, serverID
}

var testSessionID = []byte("0123456789abcdef")

func newTunnelServer(t *testing.T, clientID, serverID ed25519.PrivateKey) *server.TunnelServer {
	t.Helper()
	clientPub := clientID.Public().(ed25519.PublicKey)
	return server.NewTunnelServer(server.TunnelServerConfig{
		HostKey: serverID,
		Clients: map[string]server.ClientIdentity{
			string(clientPub): {Name: "test-client", Pub: clientPub},
		},
		PadMin:      16,
		PadMax:      256,
		Replay:      crypto.NewReplayGuard(crypto.TimestampToleranceSeconds),
		RateLimiter: server.NewRateLimiter(64),
		DialTimeout: 2 * time.Second,
		IdleTimeout: 30 * time.Second,
	})
}

func newClient(t *testing.T, tunnel pb.TunnelClient, priv ed25519.PrivateKey, serverPub ed25519.PublicKey, router *routing.Router) *Client {
	t.Helper()

	dial := func() (pb.TunnelClient, *grpc.ClientConn, error) {
		return tunnel, nil, nil
	}
	c, err := New(dial, priv, serverPub, testSessionID, 16, 256, router, 2*time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestHandleConnEndToEnd(t *testing.T) {
	echo := echoTarget(t)
	clientID, serverID := newTestPair(t)
	tunnel := bufconnTunnel(t, newTunnelServer(t, clientID, serverID))

	serverPub := serverID.Public().(ed25519.PublicKey)
	c := newClient(t, tunnel, clientID, serverPub, nil)

	p1, p2 := net.Pipe()
	defer p1.Close()
	defer p2.Close()
	go c.HandleConn(p1, echo)

	if err := p2.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	msg := []byte("hello through the tunnel")
	go func() { _, _ = p2.Write(msg) }()

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(p2, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("echo mismatch: got %q, want %q", buf, msg)
	}
}

func TestHandleConnWrongServerPin(t *testing.T) {
	echo := echoTarget(t)
	clientID, serverID := newTestPair(t)
	tunnel := bufconnTunnel(t, newTunnelServer(t, clientID, serverID))

	_, rogueID, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate rogue key: %v", err)
	}
	c := newClient(t, tunnel, clientID, rogueID.Public().(ed25519.PublicKey), nil)

	p1, p2 := net.Pipe()
	defer p1.Close()
	defer p2.Close()
	go c.HandleConn(p1, echo)

	if err := p2.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := p2.Write([]byte("x")); err == nil {
		if _, err := io.ReadFull(p2, make([]byte, 1)); err == nil {
			t.Fatal("connection must be dropped when the server fails host-key verification")
		}
	}
}

func TestHandleConnDirectRouting(t *testing.T) {
	echo := echoTarget(t)
	clientID, serverID := newTestPair(t)
	tunnel := bufconnTunnel(t, newTunnelServer(t, clientID, serverID))

	serverPub := serverID.Public().(ed25519.PublicKey)
	router := routing.New(routing.Config{Mode: routing.ModeDirectExceptProxy})
	c := newClient(t, tunnel, clientID, serverPub, router)

	p1, p2 := net.Pipe()
	defer p1.Close()
	defer p2.Close()
	go c.HandleConn(p1, echo)

	if err := p2.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	msg := []byte("hello direct path")
	go func() { _, _ = p2.Write(msg) }()

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(p2, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("echo mismatch: got %q, want %q", buf, msg)
	}
}

type stallTunnel struct{ pb.UnimplementedTunnelServer }

func (stallTunnel) Connect(stream pb.Tunnel_ConnectServer) error {
	<-stream.Context().Done()
	return stream.Context().Err()
}

func TestHandleConnRedialAfterTimeout(t *testing.T) {
	echo := echoTarget(t)
	clientID, serverID := newTestPair(t)
	serverPub := serverID.Public().(ed25519.PublicKey)

	stall := bufconnTunnel(t, stallTunnel{})
	working := bufconnTunnel(t, newTunnelServer(t, clientID, serverID))

	dials := 0
	dial := func() (pb.TunnelClient, *grpc.ClientConn, error) {
		dials++
		if dials == 1 {
			return stall, nil, nil
		}
		return working, nil, nil
	}
	c, err := New(dial, clientID, serverPub, testSessionID, 16, 256, nil, 300*time.Millisecond)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(c.Close)

	p1, p2 := net.Pipe()
	defer p1.Close()
	defer p2.Close()
	go c.HandleConn(p1, echo)

	if err := p2.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	msg := []byte("hello after redial")
	go func() { _, _ = p2.Write(msg) }()

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(p2, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("echo mismatch: got %q, want %q", buf, msg)
	}
	if dials != 2 {
		t.Fatalf("want 2 dials (initial + redial), got %d", dials)
	}
}

func TestCloseStopsHandleConn(t *testing.T) {
	echo := echoTarget(t)
	clientID, serverID := newTestPair(t)
	serverPub := serverID.Public().(ed25519.PublicKey)

	lis := bufconn.Listen(1024 * 1024)
	grpcSrv := grpc.NewServer()
	pb.RegisterTunnelServer(grpcSrv, newTunnelServer(t, clientID, serverID))
	go func() { _ = grpcSrv.Serve(lis) }()
	t.Cleanup(grpcSrv.Stop)

	dials := 0
	dial := func() (pb.TunnelClient, *grpc.ClientConn, error) {
		dials++
		conn, err := grpc.NewClient("passthrough:///bufnet",
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				return lis.DialContext(ctx)
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err != nil {
			return nil, nil, err
		}
		return pb.NewTunnelClient(conn), conn, nil
	}
	c, err := New(dial, clientID, serverPub, testSessionID, 16, 256, nil, 2*time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	p1, p2 := net.Pipe()
	defer p2.Close()
	if err := p2.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	done := make(chan struct{})
	go func() {
		c.HandleConn(p1, echo)
		close(done)
	}()

	msg := []byte("ping before close")
	go func() { _, _ = p2.Write(msg) }()
	if _, err := io.ReadFull(p2, make([]byte, len(msg))); err != nil {
		t.Fatalf("read echo: %v", err)
	}

	c.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("HandleConn did not finish after Close")
	}

	if err := c.redial(c.generation); !errors.Is(err, errClientClosed) {
		t.Fatalf("redial after Close: want errClientClosed, got %v", err)
	}
	if dials != 1 {
		t.Fatalf("want 1 dial, got %d", dials)
	}
}

func TestProtectorAppliedToDirectDial(t *testing.T) {
	echo := echoTarget(t)
	clientID, serverID := newTestPair(t)
	tunnel := bufconnTunnel(t, newTunnelServer(t, clientID, serverID))

	serverPub := serverID.Public().(ed25519.PublicKey)
	router := routing.New(routing.Config{Mode: routing.ModeDirectExceptProxy})
	c := newClient(t, tunnel, clientID, serverPub, router)

	var calls atomic.Int32
	SetProtector(func(fd uintptr) bool {
		calls.Add(1)
		return true
	})
	t.Cleanup(func() { SetProtector(nil) })

	p1, p2 := net.Pipe()
	defer p1.Close()
	defer p2.Close()
	go c.HandleConn(p1, echo)

	if err := p2.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	msg := []byte("hello protected direct")
	go func() { _, _ = p2.Write(msg) }()

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(p2, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("echo mismatch: got %q, want %q", buf, msg)
	}
	if calls.Load() == 0 {
		t.Fatal("protector was not called for direct dial")
	}
}
