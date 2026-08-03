package mobile

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"

	"gipnoz/internal/client"
	"gipnoz/internal/config"
	"gipnoz/internal/crypto"
	pb "gipnoz/internal/proto"
)

func guardedCall(name string, fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("panic in "+name, "panic", r, "stack", string(debug.Stack()))
			err = fmt.Errorf("%s panicked: %v", name, r)
		}
	}()
	return fn()
}

func guardedProtect(p Protector, fd uintptr) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("panic in protector", "panic", r, "stack", string(debug.Stack()))
			ok = false
		}
	}()
	return p.Protect(int32(fd))
}

func guardedRun(name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("panic in "+name, "panic", r, "stack", string(debug.Stack()))
		}
	}()
	fn()
}

type KeyPair struct {
	Seed string
	Pub  string
}

func Keygen() (*KeyPair, error) {
	seed, pub, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	return &KeyPair{Seed: seed, Pub: pub}, nil
}

func Check(address, sni, fingerprint string) error {
	tunnel, grpcConn, err := client.DialServer(address, sni, fingerprint, false)
	if err != nil {
		return err
	}
	defer grpcConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := tunnel.Health(ctx, &pb.HealthRequest{}); err != nil {
		return fmt.Errorf("health check: %w", err)
	}
	return nil
}

type Protector interface {
	Protect(fd int32) bool
}

type StatusHandler interface {
	OnStatus(status string, detail string)
}

var state = struct {
	sync.Mutex
	client *client.Client
	tun    *tunDevice
	dohURL string
}{}

func Start(configYAML string, protector Protector, handler StatusHandler) error {
	return guardedCall("Start", func() error { return start(configYAML, protector, handler) })
}

func start(configYAML string, protector Protector, handler StatusHandler) error {
	cfg, err := config.ParseClient([]byte(configYAML))
	if err != nil {
		return err
	}

	state.Lock()
	defer state.Unlock()
	if state.client != nil {
		return fmt.Errorf("client already started")
	}

	if protector != nil {
		client.SetProtector(func(fd uintptr) bool {
			return guardedProtect(protector, fd)
		})
	}

	var onStatus func(status, detail string)
	if handler != nil {
		onStatus = handler.OnStatus
	}

	c, _, err := client.Start(client.RunConfig{
		ServerAddr:      cfg.Server.Address,
		SNI:             cfg.Server.SNI,
		PrivateKey:      cfg.Auth.PrivateKey,
		ServerPublicKey: cfg.Auth.ServerPublicKey,
		Fingerprint:     cfg.TLS.Fingerprint,
		Insecure:        cfg.TLS.Insecure,
		DoHURL:          cfg.DNS.DOH,
		PadMin:          cfg.Padding.Min,
		PadMax:          cfg.Padding.Max,
		ConnectSeconds:  cfg.Timeouts.ConnectSeconds,
		Routing:         cfg.Routing,
		OnStatus:        onStatus,
	})
	if err != nil {
		client.SetProtector(nil)
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Timeouts.ConnectSeconds)*time.Second)
	pingErr := c.Ping(ctx)
	cancel()
	if pingErr != nil {
		c.Close()
		client.SetProtector(nil)
		return fmt.Errorf("server check: %w", pingErr)
	}
	if onStatus != nil {
		onStatus(client.StatusConnected, "")
	}

	state.client = c
	state.dohURL = cfg.DNS.DOH
	return nil
}

func StartTun(fd int32) error {
	return guardedCall("StartTun", func() error { return startTun(fd) })
}

func startTun(fd int32) error {
	state.Lock()
	defer state.Unlock()
	if state.client == nil {
		return fmt.Errorf("client not started")
	}
	if state.tun != nil {
		return fmt.Errorf("tun already started")
	}
	tun, err := newTunDevice(int(fd), state.client.HandleConn, state.dohURL)
	if err != nil {
		return err
	}
	state.tun = tun
	return nil
}

func Stop() error {
	state.Lock()
	defer state.Unlock()
	if state.tun != nil {
		state.tun.close()
		state.tun = nil
	}
	if state.client != nil {
		state.client.Close()
		state.client = nil
	}
	client.SetProtector(nil)
	return nil
}

func TxBytes() int64 {
	state.Lock()
	defer state.Unlock()
	if state.client == nil {
		return 0
	}
	return state.client.TxBytes()
}

func RxBytes() int64 {
	state.Lock()
	defer state.Unlock()
	if state.client == nil {
		return 0
	}
	return state.client.RxBytes()
}
