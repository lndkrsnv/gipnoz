package client

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"gipnoz/internal/config"
	"gipnoz/internal/crypto"
	pb "gipnoz/internal/proto"
	"gipnoz/internal/routing"
)

type Client struct {
	tunnel      pb.TunnelClient
	id          ed25519.PrivateKey
	serverPub   ed25519.PublicKey
	sessionID   []byte
	padMin      int
	padMax      int
	router      *routing.Router
	dialTimeout time.Duration
}

func New(tunnel pb.TunnelClient, id ed25519.PrivateKey, serverPub ed25519.PublicKey, sessionID []byte, padMin, padMax int, router *routing.Router, dialTimeout time.Duration) *Client {
	return &Client{
		tunnel:      tunnel,
		id:          id,
		serverPub:   serverPub,
		sessionID:   sessionID,
		padMin:      padMin,
		padMax:      padMax,
		router:      router,
		dialTimeout: dialTimeout,
	}
}

func (c *Client) HandleConn(conn net.Conn, targetAddr string) {
	if c.router != nil && c.router.Decide(targetAddr) == routing.Direct {
		c.handleDirect(conn, targetAddr)
		return
	}
	c.handleTunnel(conn, targetAddr)
}

func (c *Client) handleTunnel(conn net.Conn, targetAddr string) {
	defer conn.Close()
	start := time.Now()

	stream, err := c.tunnel.Connect(context.Background())
	if err != nil {
		slog.Warn("failed to open stream", "err", err)
		return
	}

	encCipher, decCipher, err := c.handshake(stream, targetAddr)
	if err != nil {
		slog.Warn("handshake failed", "err", err)
		return
	}
	slog.Info("tunnel opened", "target", targetAddr)

	var (
		wg        sync.WaitGroup
		bytesSent int64
		bytesRecv int64
	)
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer stream.CloseSend()
		bytesSent = c.upload(conn, stream, encCipher)
	}()

	go func() {
		defer wg.Done()
		defer conn.Close()
		bytesRecv = c.download(conn, stream, decCipher)
	}()

	wg.Wait()
	slog.Info("tunnel closed",
		"target", targetAddr,
		"duration", time.Since(start).Round(time.Millisecond),
		"sent", bytesSent,
		"recv", bytesRecv,
	)
}

func (c *Client) handshake(stream pb.Tunnel_ConnectClient, targetAddr string) (enc, dec *crypto.Cipher, err error) {
	helloPayload, eph, err := crypto.BuildClientHello(c.id, targetAddr, c.sessionID)
	if err != nil {
		return nil, nil, fmt.Errorf("build client hello: %w", err)
	}
	padding, err := crypto.GeneratePadding(c.padMin, c.padMax)
	if err != nil {
		return nil, nil, fmt.Errorf("generate padding: %w", err)
	}
	if err := stream.Send(&pb.Chunk{Payload: helloPayload, Padding: padding}); err != nil {
		return nil, nil, fmt.Errorf("send client hello: %w", err)
	}

	reply, err := stream.Recv()
	if err != nil {
		return nil, nil, err
	}
	serverEphPub, err := crypto.ParseServerHello(reply.Payload, helloPayload, c.serverPub)
	if err != nil {
		return nil, nil, fmt.Errorf("verify server hello: %w", err)
	}

	c2s, s2c, err := crypto.DeriveSessionKeys(eph, serverEphPub, helloPayload, reply.Payload)
	if err != nil {
		return nil, nil, fmt.Errorf("derive session keys: %w", err)
	}
	enc, err = crypto.NewCipher(c2s)
	if err != nil {
		return nil, nil, err
	}
	dec, err = crypto.NewCipher(s2c)
	if err != nil {
		return nil, nil, err
	}
	return enc, dec, nil
}

func (c *Client) upload(conn net.Conn, stream pb.Tunnel_ConnectClient, cipher *crypto.Cipher) int64 {
	var sent int64
	buf := make([]byte, 32*1024)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			sent += int64(n)
			if sendErr := sendChunk(stream, cipher, buf[:n], c.padMin, c.padMax); sendErr != nil {
				slog.Warn("stream send error", "err", sendErr)
				return sent
			}
		}
		if err != nil {
			if err != io.EOF {
				slog.Debug("conn read error", "err", err)
			}
			return sent
		}
	}
}

func (c *Client) download(conn net.Conn, stream pb.Tunnel_ConnectClient, cipher *crypto.Cipher) int64 {
	var received int64
	for {
		chunk, err := stream.Recv()
		if err != nil {
			if err != io.EOF {
				slog.Warn("stream recv error", "err", err)
			}
			return received
		}
		plaintext, err := cipher.Decrypt(chunk.Payload)
		if err != nil {
			slog.Warn("decrypt error", "err", err)
			return received
		}
		received += int64(len(plaintext))
		if _, err := conn.Write(plaintext); err != nil {
			slog.Debug("conn write error", "err", err)
			return received
		}
	}
}

func sendChunk(stream pb.Tunnel_ConnectClient, cipher *crypto.Cipher, data []byte, padMin, padMax int) error {
	encrypted, err := cipher.Encrypt(data)
	if err != nil {
		return err
	}
	padding, err := crypto.GeneratePadding(padMin, padMax)
	if err != nil {
		return err
	}
	return stream.Send(&pb.Chunk{Payload: encrypted, Padding: padding})
}

func (c *Client) handleDirect(conn net.Conn, targetAddr string) {
	defer conn.Close()
	start := time.Now()

	target, err := net.DialTimeout("tcp", targetAddr, c.dialTimeout)
	if err != nil {
		slog.Warn("direct dial failed", "addr", targetAddr, "err", err)
		return
	}
	defer target.Close()
	slog.Info("direct connection", "target", targetAddr)

	var (
		wg        sync.WaitGroup
		bytesSent int64
		bytesRecv int64
	)
	wg.Add(2)

	go func() {
		defer wg.Done()
		bytesSent = copyConn(target, conn)
	}()
	go func() {
		defer wg.Done()
		bytesRecv = copyConn(conn, target)
	}()

	wg.Wait()
	slog.Info("direct closed",
		"target", targetAddr,
		"duration", time.Since(start).Round(time.Millisecond),
		"sent", bytesSent,
		"recv", bytesRecv,
	)
}

func copyConn(dst, src net.Conn) int64 {
	defer closeWrite(dst)
	n, _ := io.Copy(dst, src)
	return n
}

func closeWrite(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
}

type RunConfig struct {
	ServerAddr      string
	SNI             string
	PrivateKey      string
	ServerPublicKey string
	ListenAddr      string
	Fingerprint     string
	Insecure        bool
	DoHURL          string
	PadMin          int
	PadMax          int
	ConnectSeconds  int
	Routing         config.RoutingConfig
}

func Run(cfg RunConfig) error {
	serverAddr := cfg.ServerAddr

	sessionID, err := crypto.GenerateSessionID()
	if err != nil {
		return err
	}

	if cfg.DoHURL != "" {
		doh := NewDoHResolver(cfg.DoHURL)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		resolved, err := doh.ResolveAddress(ctx, serverAddr)
		cancel()
		if err != nil {
			return fmt.Errorf("doh resolve server address: %w", err)
		}
		slog.Info("server address resolved via DoH", "addr", cfg.ServerAddr, "resolved", resolved)
		serverAddr = resolved
	}

	tunnel, grpcConn, err := DialServer(serverAddr, cfg.SNI, cfg.Fingerprint, cfg.Insecure)
	if err != nil {
		return fmt.Errorf("dial server: %w", err)
	}
	defer grpcConn.Close()

	id, err := crypto.ParsePrivateKey(cfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("auth.private_key: %w", err)
	}
	serverPub, err := crypto.ParsePublicKey(cfg.ServerPublicKey)
	if err != nil {
		return fmt.Errorf("auth.server_public_key: %w", err)
	}

	router, err := buildRouter(cfg.Routing, cfg.DoHURL)
	if err != nil {
		return err
	}

	dialTimeout := time.Duration(cfg.ConnectSeconds) * time.Second
	c := New(tunnel, id, serverPub, sessionID, cfg.PadMin, cfg.PadMax, router, dialTimeout)
	return ListenSOCKS5(cfg.ListenAddr, c.HandleConn)
}

func buildRouter(cfg config.RoutingConfig, dohURL string) (*routing.Router, error) {
	mode, ok := routing.ParseMode(cfg.Mode)
	if !ok {
		return nil, fmt.Errorf("routing.mode: unknown mode %q", cfg.Mode)
	}

	proxyDomains, err := loadDomains(cfg.Proxy)
	if err != nil {
		return nil, fmt.Errorf("routing.proxy: %w", err)
	}
	directDomains, err := loadDomains(cfg.Direct)
	if err != nil {
		return nil, fmt.Errorf("routing.direct: %w", err)
	}
	proxyCIDRs, err := loadCIDRs(cfg.Proxy)
	if err != nil {
		return nil, fmt.Errorf("routing.proxy: %w", err)
	}
	directCIDRs, err := loadCIDRs(cfg.Direct)
	if err != nil {
		return nil, fmt.Errorf("routing.direct: %w", err)
	}

	slog.Info("routing loaded",
		"mode", cfg.Mode,
		"proxy_cidrs", proxyCIDRs.Len(),
		"direct_cidrs", directCIDRs.Len(),
	)

	return routing.New(routing.Config{
		Mode:          mode,
		ProxyDomains:  proxyDomains,
		DirectDomains: directDomains,
		ProxyCIDRs:    proxyCIDRs,
		DirectCIDRs:   directCIDRs,
		Resolve:       buildResolver(dohURL),
	}), nil
}

func loadDomains(rules config.RoutingRules) (*routing.DomainMatcher, error) {
	m := routing.NewDomainMatcher()
	for _, d := range rules.Domains {
		m.Add(d)
	}
	for _, path := range rules.DomainLists {
		if err := routing.LoadDomainList(m, path); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func loadCIDRs(rules config.RoutingRules) (*routing.CIDRMatcher, error) {
	m := routing.NewCIDRMatcher()
	for _, path := range rules.GeoIPLists {
		if err := routing.LoadCIDRList(m, path); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func buildResolver(dohURL string) routing.Resolver {
	if dohURL != "" {
		doh := NewDoHResolver(dohURL)
		return func(host string) ([]netip.Addr, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			addrs, err := doh.LookupHost(ctx, host)
			if err != nil {
				return nil, err
			}
			return parseAddrs(addrs)
		}
	}

	var warned atomic.Bool
	return func(host string) ([]netip.Addr, error) {
		if warned.CompareAndSwap(false, true) {
			slog.Warn("routing resolves domains via the system resolver; configure dns.doh to avoid DNS leaks")
		}
		addrs, err := net.DefaultResolver.LookupHost(context.Background(), host)
		if err != nil {
			return nil, err
		}
		return parseAddrs(addrs)
	}
}

func parseAddrs(addrs []string) ([]netip.Addr, error) {
	ips := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		ip, err := netip.ParseAddr(a)
		if err != nil {
			return nil, fmt.Errorf("parse resolved address %q: %w", a, err)
		}
		ips = append(ips, ip)
	}
	return ips, nil
}
