package server

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"

	"gipnoz/internal/config"
	"gipnoz/internal/crypto"
	pb "gipnoz/internal/proto"
)

func Run(cfg *config.ServerConfig) error {
	hostKey, err := crypto.ParsePrivateKey(cfg.Auth.PrivateKey)
	if err != nil {
		return fmt.Errorf("auth.private_key: %w", err)
	}
	clients, err := parseClients(cfg.Auth.Clients)
	if err != nil {
		return err
	}

	secLog, secLogClose, err := openSecurityLog(cfg.SecurityLog)
	if err != nil {
		return err
	}
	defer secLogClose()

	lis, err := net.Listen("tcp", cfg.Listen.Address)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	srv := grpc.NewServer()
	tunnelSrv := NewTunnelServer(TunnelServerConfig{
		HostKey:      hostKey,
		Clients:      clients,
		PadMin:       cfg.Padding.Min,
		PadMax:       cfg.Padding.Max,
		Replay:       crypto.NewReplayGuard(crypto.TimestampToleranceSeconds),
		RateLimiter:  NewRateLimiter(cfg.RateLimit.MaxStreamsPerIP),
		SecLog:       secLog,
		SessionGrace: time.Minute,
		DialTimeout:  time.Duration(cfg.Timeouts.ConnectSeconds) * time.Second,
		IdleTimeout:  time.Duration(cfg.Timeouts.IdleSeconds) * time.Second,
	})
	pb.RegisterTunnelServer(srv, tunnelSrv)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		slog.Info("received signal, shutting down", "signal", sig)
		srv.Stop()
	}()

	slog.Info("gipnoz server starting", "addr", cfg.Listen.Address)
	return srv.Serve(lis)
}

func openSecurityLog(path string) (*slog.Logger, func(), error) {
	if path == "" {
		return nil, func() {}, nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, nil, fmt.Errorf("security_log: %w", err)
	}
	logger := slog.New(slog.NewTextHandler(f, &slog.HandlerOptions{Level: slog.LevelWarn}))
	return logger, func() {
		if err := f.Close(); err != nil {
			slog.Warn("security log close error", "err", err)
		}
	}, nil
}
