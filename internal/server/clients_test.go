package server

import (
	"testing"

	"gipnoz/internal/config"
	"gipnoz/internal/crypto"
)

func keyPair(t *testing.T) (seed, pub string) {
	t.Helper()
	seed, pub, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return seed, pub
}

func TestParseClients(t *testing.T) {
	_, pub1 := keyPair(t)
	_, pub2 := keyPair(t)

	clients, err := parseClients([]config.ClientEntry{
		{Name: "leo", Key: pub1},
		{Name: "masha", Key: pub2},
	})
	if err != nil {
		t.Fatalf("parseClients: %v", err)
	}
	if len(clients) != 2 {
		t.Fatalf("want 2 clients, got %d", len(clients))
	}

	p, err := crypto.ParsePublicKey(pub1)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	id, ok := clients[string(p)]
	if !ok {
		t.Fatal("client pub1 not found")
	}
	if id.Name != "leo" {
		t.Fatalf("want name leo, got %q", id.Name)
	}
}

func TestParseClientsEmptyNameFallsBackToKeyPrefix(t *testing.T) {
	_, pub := keyPair(t)

	clients, err := parseClients([]config.ClientEntry{{Key: pub}})
	if err != nil {
		t.Fatalf("parseClients: %v", err)
	}
	p, _ := crypto.ParsePublicKey(pub)
	id := clients[string(p)]
	if id.Name != pub[:8] {
		t.Fatalf("want fallback name %q, got %q", pub[:8], id.Name)
	}
}

func TestParseClientsErrors(t *testing.T) {
	_, pub := keyPair(t)

	if _, err := parseClients(nil); err == nil {
		t.Fatal("expected error for empty client list")
	}
	if _, err := parseClients([]config.ClientEntry{{Name: "bad", Key: "not-base64"}}); err == nil {
		t.Fatal("expected error for invalid key")
	}
	if _, err := parseClients([]config.ClientEntry{
		{Name: "a", Key: pub},
		{Name: "b", Key: pub},
	}); err == nil {
		t.Fatal("expected error for duplicate key")
	}
}
