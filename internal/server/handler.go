package server

import (
	"context"
	"crypto/ed25519"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"gipnoz/internal/crypto"
	pb "gipnoz/internal/proto"
)

type TunnelServer struct {
	pb.UnimplementedTunnelServer
	hostKey     ed25519.PrivateKey
	clients     map[string]ClientIdentity
	clientPubs  map[string]ed25519.PublicKey
	padMin      int
	padMax      int
	replay      *crypto.ReplayGuard
	rateLimiter *RateLimiter
	sessions    *sessionRegistry
	secLog      *slog.Logger
	dialTimeout time.Duration
	idleTimeout time.Duration
}

type TunnelServerConfig struct {
	HostKey      ed25519.PrivateKey
	Clients      map[string]ClientIdentity
	PadMin       int
	PadMax       int
	Replay       *crypto.ReplayGuard
	RateLimiter  *RateLimiter
	SecLog       *slog.Logger
	SessionGrace time.Duration
	DialTimeout  time.Duration
	IdleTimeout  time.Duration
}

func NewTunnelServer(cfg TunnelServerConfig) *TunnelServer {
	pubs := make(map[string]ed25519.PublicKey, len(cfg.Clients))
	for key, id := range cfg.Clients {
		pubs[key] = id.Pub
	}
	return &TunnelServer{
		hostKey:     cfg.HostKey,
		clients:     cfg.Clients,
		clientPubs:  pubs,
		padMin:      cfg.PadMin,
		padMax:      cfg.PadMax,
		replay:      cfg.Replay,
		rateLimiter: cfg.RateLimiter,
		sessions:    newSessionRegistry(cfg.SessionGrace),
		secLog:      cfg.SecLog,
		dialTimeout: cfg.DialTimeout,
		idleTimeout: cfg.IdleTimeout,
	}
}

func (s *TunnelServer) Connect(stream pb.Tunnel_ConnectServer) error {
	clientIP := peerIP(stream.Context())
	if clientIP != "" && !s.rateLimiter.Acquire(clientIP) {
		slog.Warn("rate limit exceeded", "ip", clientIP)
		return status.Error(codes.ResourceExhausted, "too many connections")
	}
	if clientIP != "" {
		defer s.rateLimiter.Release(clientIP)
	}

	chunk, err := stream.Recv()
	if err != nil {
		return status.Error(codes.Internal, "failed to receive initial chunk")
	}

	hello, err := crypto.ParseClientHello(chunk.Payload, s.clientPubs)
	if err != nil {
		slog.Warn("auth failed", "ip", clientIP, "err", err)
		return status.Error(codes.Unauthenticated, "invalid request")
	}
	clientName := s.clients[string(hello.IDPub)].Name

	if !s.replay.Check(hello.Sig) {
		slog.Warn("replay detected", "ip", clientIP, "client", clientName)
		return status.Error(codes.Unauthenticated, "invalid request")
	}

	keyStr := string(hello.IDPub)
	sessionID := string(hello.SessionID)
	admit := s.sessions.admit(keyStr, sessionID, clientIP, time.Now())
	if admit.busy {
		slog.Warn("session busy", "ip", clientIP, "client", clientName, "holder_ip", admit.holderIP)
		if s.secLog != nil && clientIP != admit.holderIP && !s.sessions.busyLoggedRecently(keyStr, time.Now()) {
			s.secLog.Warn("possible key sharing",
				"client", clientName, "ip", clientIP, "reason", "session busy",
				"holder_ip", admit.holderIP,
			)
		}
		return status.Error(codes.ResourceExhausted, "key in use by another device")
	}
	if admit.takeover {
		slog.Info("new session", "client", clientName, "ip", clientIP)
		if admit.flaps == flapThreshold && s.secLog != nil {
			s.secLog.Warn("possible key sharing",
				"client", clientName, "ip", clientIP, "reason", "session flapping",
				"flaps", admit.flaps,
			)
		}
	}

	release := sync.OnceFunc(func() {
		s.sessions.release(keyStr, sessionID, time.Now())
	})
	defer release()

	slog.Info("connecting to target", "addr", hello.Target, "ip", clientIP, "client", clientName)

	conn, err := net.DialTimeout("tcp", hello.Target, s.dialTimeout)
	if err != nil {
		slog.Warn("dial target failed", "addr", hello.Target, "err", err)
		return status.Error(codes.Unavailable, "target unreachable")
	}
	defer conn.Close()

	serverHello, eph, err := crypto.BuildServerHello(s.hostKey, hello.Payload)
	if err != nil {
		slog.Warn("build server hello failed", "err", err)
		return status.Error(codes.Internal, "internal error")
	}

	c2s, s2c, err := crypto.DeriveSessionKeys(eph, hello.EphPub, hello.Payload, serverHello)
	if err != nil {
		slog.Warn("derive session keys failed", "err", err)
		return status.Error(codes.Internal, "internal error")
	}
	decCipher, err := crypto.NewCipher(c2s)
	if err != nil {
		return status.Error(codes.Internal, "internal error")
	}
	encCipher, err := crypto.NewCipher(s2c)
	if err != nil {
		return status.Error(codes.Internal, "internal error")
	}

	padding, err := crypto.GeneratePadding(s.padMin, s.padMax)
	if err != nil {
		return status.Error(codes.Internal, "internal error")
	}
	if err := stream.Send(&pb.Chunk{Payload: serverHello, Padding: padding}); err != nil {
		return status.Error(codes.Internal, "failed to send handshake reply")
	}

	relay(stream, conn, decCipher, encCipher, s.padMin, s.padMax, s.idleTimeout, release)
	return nil
}

func (s *TunnelServer) Health(_ context.Context, _ *pb.HealthRequest) (*pb.HealthResponse, error) {
	return &pb.HealthResponse{Status: "SERVING"}, nil
}

func peerIP(ctx context.Context) string {
	direct := directPeerIP(ctx)
	if direct != "" && !isTrustedProxy(direct) {
		return direct
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		if xff := md.Get("x-forwarded-for"); len(xff) > 0 {
			if first := strings.TrimSpace(strings.SplitN(xff[0], ",", 2)[0]); first != "" {
				return first
			}
		}
	}
	return direct
}

func directPeerIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return ""
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		return ""
	}
	return host
}

func isTrustedProxy(ip string) bool {
	parsed, err := netip.ParseAddr(ip)
	return err == nil && (parsed.IsLoopback() || parsed.IsPrivate())
}
