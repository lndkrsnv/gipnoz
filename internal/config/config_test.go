package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

func TestLoadClientDefaults(t *testing.T) {
	path := writeTemp(t, `
server:
  address: "example.com:443"
  sni: "example.com"
auth:
  private_key: "c2VlZA=="
  server_public_key: "cHVi"
`)
	cfg, err := LoadClient(path)
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if cfg.Server.Address != "example.com:443" {
		t.Fatalf("server.address mismatch: %q", cfg.Server.Address)
	}
	if cfg.Auth.PrivateKey != "c2VlZA==" || cfg.Auth.ServerPublicKey != "cHVi" {
		t.Fatalf("auth fields mismatch: %+v", cfg.Auth)
	}
	if cfg.Listen.SOCKS5 != "127.0.0.1:1080" {
		t.Fatalf("default socks5 mismatch: %q", cfg.Listen.SOCKS5)
	}
	if cfg.TLS.Fingerprint != "chrome" {
		t.Fatalf("default fingerprint mismatch: %q", cfg.TLS.Fingerprint)
	}
	if cfg.Padding.Min != 16 || cfg.Padding.Max != 256 {
		t.Fatalf("default padding mismatch: %+v", cfg.Padding)
	}
	if cfg.Timeouts.ConnectSeconds != 10 || cfg.Timeouts.IdleSeconds != 300 {
		t.Fatalf("default timeouts mismatch: %+v", cfg.Timeouts)
	}
}

func TestLoadServerNamedClients(t *testing.T) {
	path := writeTemp(t, `
auth:
  private_key: "c2VlZA=="
  clients:
    - name: "leo"
      key: "cHViMQ=="
    - name: "masha"
      key: "cHViMg=="
`)
	cfg, err := LoadServer(path)
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if len(cfg.Auth.Clients) != 2 {
		t.Fatalf("want 2 clients, got %d", len(cfg.Auth.Clients))
	}
	if cfg.Auth.Clients[0].Name != "leo" || cfg.Auth.Clients[0].Key != "cHViMQ==" {
		t.Fatalf("client[0] mismatch: %+v", cfg.Auth.Clients[0])
	}
	if cfg.Auth.Clients[1].Name != "masha" || cfg.Auth.Clients[1].Key != "cHViMg==" {
		t.Fatalf("client[1] mismatch: %+v", cfg.Auth.Clients[1])
	}
	if cfg.Listen.Address != "127.0.0.1:8443" {
		t.Fatalf("default listen mismatch: %q", cfg.Listen.Address)
	}
	if cfg.RateLimit.MaxStreamsPerIP != 64 {
		t.Fatalf("default rate limit mismatch: %d", cfg.RateLimit.MaxStreamsPerIP)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := LoadClient("/nonexistent/client.yaml"); err == nil {
		t.Fatal("expected error for missing config file")
	}
}
