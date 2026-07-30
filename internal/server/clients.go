package server

import (
	"crypto/ed25519"
	"fmt"

	"gipnoz/internal/config"
	"gipnoz/internal/crypto"
)

type ClientIdentity struct {
	Name string
	Pub  ed25519.PublicKey
}

func parseClients(entries []config.ClientEntry) (map[string]ClientIdentity, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("no clients configured (auth.clients)")
	}
	clients := make(map[string]ClientIdentity, len(entries))
	for i, entry := range entries {
		pub, err := crypto.ParsePublicKey(entry.Key)
		if err != nil {
			return nil, fmt.Errorf("auth.clients[%d] (%s): %w", i, entry.Name, err)
		}
		name := entry.Name
		if name == "" {
			name = shortKeyName(entry.Key)
		}
		if _, exists := clients[string(pub)]; exists {
			return nil, fmt.Errorf("auth.clients[%d] (%s): duplicate public key", i, name)
		}
		clients[string(pub)] = ClientIdentity{Name: name, Pub: pub}
	}
	return clients, nil
}

func shortKeyName(key string) string {
	if len(key) > 8 {
		return key[:8]
	}
	return key
}
