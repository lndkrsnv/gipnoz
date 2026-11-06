package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gipnoz/internal/client"
	"gipnoz/internal/config"
	"gipnoz/internal/crypto"
	pb "gipnoz/internal/proto"
)

func main() {
	configPath := flag.String("config", "client.yaml", "path to client config file")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	if flag.NArg() > 0 && flag.Arg(0) == "keygen" {
		runKeygen()
		return
	}

	cfg, err := config.LoadClient(*configPath)
	if err != nil {
		slog.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	if flag.NArg() > 0 && flag.Arg(0) == "test" {
		runTest(cfg)
		return
	}

	c, lis, err := client.Start(client.RunConfig{
		ServerAddr:      cfg.Server.Address,
		SNI:             cfg.Server.SNI,
		PrivateKey:      cfg.Auth.PrivateKey,
		ServerPublicKey: cfg.Auth.ServerPublicKey,
		ListenAddr:      cfg.Listen.SOCKS5,
		Fingerprint:     cfg.TLS.Fingerprint,
		Insecure:        cfg.TLS.Insecure,
		DoHURL:          cfg.DNS.DOH,
		PadMin:          cfg.Padding.Min,
		PadMax:          cfg.Padding.Max,
		ConnectSeconds:  cfg.Timeouts.ConnectSeconds,
		Routing:         cfg.Routing,
	})
	if err != nil {
		slog.Error("client error", "err", err)
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sig
		slog.Info("shutting down", "signal", s)
		lis.Close()
	}()

	if err := client.ServeSOCKS5(lis, c.HandleConn); err != nil {
		c.Close()
		slog.Error("client error", "err", err)
		os.Exit(1)
	}
	c.Close()
}

func runKeygen() {
	seed, pub, err := crypto.GenerateKeyPair()
	if err != nil {
		slog.Error("keygen failed", "err", err)
		os.Exit(1)
	}
	fmt.Println("new Ed25519 client identity:")
	fmt.Println("  private key (auth.private_key in client.yaml — keep secret):")
	fmt.Printf("    %s\n", seed)
	fmt.Println("  public key (add to auth.clients in server.yaml):")
	fmt.Printf("    %s\n", pub)
}

func runTest(cfg *config.ClientConfig) {
	fmt.Println("gipnoz connection test")
	fmt.Printf("  server:      %s\n", cfg.Server.Address)
	fmt.Printf("  sni:         %s\n", cfg.Server.SNI)
	fmt.Printf("  fingerprint: %s\n", cfg.TLS.Fingerprint)
	fmt.Printf("  insecure:    %v\n", cfg.TLS.Insecure)
	fmt.Println()

	fmt.Print("connecting... ")
	start := time.Now()

	tunnel, grpcConn, err := client.DialServer(cfg.Server.Address, cfg.Server.SNI, cfg.TLS.Fingerprint, cfg.TLS.Insecure)
	if err != nil {
		fmt.Printf("FAIL\n  error: %v\n", err)
		os.Exit(1)
	}
	defer grpcConn.Close()

	latency := time.Since(start)
	fmt.Printf("OK (%s)\n", latency.Round(time.Millisecond))

	fmt.Print("health check... ")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := tunnel.Health(ctx, &pb.HealthRequest{})
	if err != nil {
		fmt.Printf("FAIL\n  error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("OK (status: %s)\n", resp.Status)

	fmt.Println()
	fmt.Println("all checks passed")
}
