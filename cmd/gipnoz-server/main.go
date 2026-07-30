package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"gipnoz/internal/config"
	"gipnoz/internal/crypto"
	"gipnoz/internal/server"
)

func main() {
	configPath := flag.String("config", "server.yaml", "path to server config file")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	if flag.NArg() > 0 && flag.Arg(0) == "keygen" {
		runKeygen()
		return
	}

	cfg, err := config.LoadServer(*configPath)
	if err != nil {
		slog.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	if err := server.Run(cfg); err != nil {
		slog.Error("server error", "err", err)
		os.Exit(1)
	}
}

func runKeygen() {
	seed, pub, err := crypto.GenerateKeyPair()
	if err != nil {
		slog.Error("keygen failed", "err", err)
		os.Exit(1)
	}
	fmt.Println("new Ed25519 server host key:")
	fmt.Println("  private key (auth.private_key in server.yaml — keep secret):")
	fmt.Printf("    %s\n", seed)
	fmt.Println("  public key (auth.server_public_key in every client.yaml):")
	fmt.Printf("    %s\n", pub)
}
