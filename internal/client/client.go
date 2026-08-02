package client

import (
	"context"
	"crypto/ed25519"
	"errors"
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

	"google.golang.org/grpc"
)

const (
	StatusConnecting   = "connecting"
	StatusConnected    = "connected"
	StatusReconnecting = "reconnecting"
	StatusError        = "error"
)

type Client struct {
	mu         sync.Mutex
	dial       func() (pb.TunnelClient, *grpc.ClientConn, error)
	tunnel     pb.TunnelClient
	conn       *grpc.ClientConn
	generation uint64
	stopped    bool
	onStatus   func(status, detail string)
	wg         sync.WaitGroup

	txBytes atomic.Int64
	rxBytes atomic.Int64

	id          ed25519.PrivateKey
	serverPub   ed25519.PublicKey
	sessionID   []byte
	padMin      int
	padMax      int
	router      *routing.Router
	dialTimeout time.Duration
}

func New(dial func() (pb.TunnelClient, *grpc.ClientConn, error), id ed25519.PrivateKey, serverPub ed25519.PublicKey, sessionID []byte, padMin, padMax int, router *routing.Router, dialTimeout time.Duration) (*Client, error) {
	c := &Client{
		dial:        dial,
		id:          id,
		serverPub:   serverPub,
		sessionID:   sessionID,
		padMin:      padMin,
		padMax:      padMax,
		router:      router,
		dialTimeout: dialTimeout,
	}
	if err := c.redial(0); err != nil {
		return nil, err
	}
	return c, nil
}

var errClientClosed = fmt.Errorf("client closed")

func (c *Client) redial(generation uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.stopped {
		return errClientClosed
	}
	if c.generation != generation {
		return nil
	}
	if c.conn != nil {
		c.conn.Close()
	}
	tunnel, conn, err := c.dial()
	if err != nil {
		return err
	}
	c.tunnel = tunnel
	c.conn = conn
	c.generation++
	return nil
}

const closeDrainTimeout = 5 * time.Second

func (c *Client) Close() {
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return
	}
	c.stopped = true
	conn := c.conn
	c.mu.Unlock()

	if conn != nil {
		conn.Close()
	}

	drained := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(closeDrainTimeout):
		slog.Warn("client close: timed out waiting for active connections")
	}
}

func (c *Client) SetStatusHandler(fn func(status, detail string)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onStatus = fn
}

func (c *Client) emitStatus(status, detail string) {
	c.mu.Lock()
	fn := c.onStatus
	c.mu.Unlock()
	if fn != nil {
		fn(status, detail)
	}
}

func (c *Client) TxBytes() int64 {
	return c.txBytes.Load()
}

func (c *Client) RxBytes() int64 {
	return c.rxBytes.Load()
}

func (c *Client) Ping(ctx context.Context) error {
	c.mu.Lock()
	tunnel := c.tunnel
	c.mu.Unlock()
	if tunnel == nil {
		return errClientClosed
	}
	_, err := tunnel.Health(ctx, &pb.HealthRequest{})
	return err
}

func (c *Client) HandleConn(conn net.Conn, targetAddr string) {
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		conn.Close()
		return
	}
	c.wg.Add(1)
	c.mu.Unlock()
	defer c.wg.Done()

	if c.router != nil && c.router.Decide(targetAddr) == routing.Direct {
		c.handleDirect(conn, targetAddr)
		return
	}
	c.handleTunnel(conn, targetAddr)
}

func (c *Client) handleTunnel(conn net.Conn, targetAddr string) {
	defer conn.Close()
	start := time.Now()

	stream, encCipher, decCipher, stopStream, err := c.openStream(targetAddr)
	if err != nil {
		if errors.Is(err, errClientClosed) {
			return
		}
		slog.Warn("failed to open tunnel", "err", err)
		c.emitStatus(StatusError, err.Error())
		return
	}
	defer stopStream()
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

var errHandshakeTimeout = fmt.Errorf("handshake timeout")

func (c *Client) openStream(targetAddr string) (pb.Tunnel_ConnectClient, *crypto.Cipher, *crypto.Cipher, context.CancelFunc, error) {
	stream, enc, dec, generation, stop, err := c.tryOpen(targetAddr)
	if err == nil {
		return stream, enc, dec, stop, nil
	}
	if !errors.Is(err, errHandshakeTimeout) {
		return nil, nil, nil, nil, err
	}
	slog.Info("handshake timed out, redialing")
	c.emitStatus(StatusReconnecting, "")
	if redialErr := c.redial(generation); redialErr != nil {
		return nil, nil, nil, nil, redialErr
	}
	stream, enc, dec, _, stop, err = c.tryOpen(targetAddr)
	if err == nil {
		c.emitStatus(StatusConnected, "")
	}
	return stream, enc, dec, stop, err
}

func (c *Client) tryOpen(targetAddr string) (pb.Tunnel_ConnectClient, *crypto.Cipher, *crypto.Cipher, uint64, context.CancelFunc, error) {
	c.mu.Lock()
	tunnel, generation := c.tunnel, c.generation
	c.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	stream, err := tunnel.Connect(ctx)
	if err != nil {
		cancel()
		return nil, nil, nil, generation, nil, err
	}

	type handshakeResult struct {
		enc *crypto.Cipher
		dec *crypto.Cipher
		err error
	}
	result := make(chan handshakeResult, 1)
	go func() {
		enc, dec, err := c.handshake(stream, targetAddr)
		result <- handshakeResult{enc, dec, err}
	}()

	timer := time.NewTimer(c.dialTimeout)
	defer timer.Stop()
	select {
	case res := <-result:
		if res.err != nil {
			cancel()
			return nil, nil, nil, generation, nil, res.err
		}
		return stream, res.enc, res.dec, generation, cancel, nil
	case <-timer.C:
		cancel()
		return nil, nil, nil, generation, nil, errHandshakeTimeout
	}
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
			c.txBytes.Add(int64(n))
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
		c.rxBytes.Add(int64(len(plaintext)))
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

	target, err := (&net.Dialer{Timeout: c.dialTimeout, Control: protectControl}).Dial("tcp", targetAddr)
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
	OnStatus        func(status, detail string)
}

func Start(cfg RunConfig) (*Client, net.Listener, error) {
	serverAddr := cfg.ServerAddr

	sessionID, err := crypto.GenerateSessionID()
	if err != nil {
		return nil, nil, err
	}

	if cfg.DoHURL != "" {
		doh := NewDoHResolver(cfg.DoHURL)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		resolved, err := doh.ResolveAddress(ctx, serverAddr)
		cancel()
		if err != nil {
			return nil, nil, fmt.Errorf("doh resolve server address: %w", err)
		}
		slog.Info("server address resolved via DoH", "addr", cfg.ServerAddr, "resolved", resolved)
		serverAddr = resolved
	}

	dial := func() (pb.TunnelClient, *grpc.ClientConn, error) {
		return DialServer(serverAddr, cfg.SNI, cfg.Fingerprint, cfg.Insecure)
	}

	id, err := crypto.ParsePrivateKey(cfg.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("auth.private_key: %w", err)
	}
	serverPub, err := crypto.ParsePublicKey(cfg.ServerPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("auth.server_public_key: %w", err)
	}

	router, err := buildRouter(cfg.Routing, cfg.DoHURL)
	if err != nil {
		return nil, nil, err
	}

	emitStatus := cfg.OnStatus
	if emitStatus == nil {
		emitStatus = func(_, _ string) {}
	}

	dialTimeout := time.Duration(cfg.ConnectSeconds) * time.Second
	emitStatus(StatusConnecting, "")
	c, err := New(dial, id, serverPub, sessionID, cfg.PadMin, cfg.PadMax, router, dialTimeout)
	if err != nil {
		return nil, nil, fmt.Errorf("dial server: %w", err)
	}
	c.SetStatusHandler(cfg.OnStatus)

	var lis net.Listener
	if cfg.ListenAddr != "" {
		lis, err = net.Listen("tcp", cfg.ListenAddr)
		if err != nil {
			c.Close()
			return nil, nil, fmt.Errorf("socks5 listen: %w", err)
		}
		slog.Info("socks5 listening", "addr", cfg.ListenAddr)
	}
	return c, lis, nil
}

func Run(cfg RunConfig) error {
	c, lis, err := Start(cfg)
	if err != nil {
		return err
	}
	defer c.Close()
	return ServeSOCKS5(lis, c.HandleConn)
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
