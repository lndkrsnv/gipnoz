package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func GenerateKeyPair() (seedB64, pubB64 string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate ed25519 key: %w", err)
	}
	seed := base64.StdEncoding.EncodeToString(priv.Seed())
	public := base64.StdEncoding.EncodeToString(pub)
	return seed, public, nil
}

func ParsePrivateKey(seedB64 string) (ed25519.PrivateKey, error) {
	seed, err := base64.StdEncoding.DecodeString(seedB64)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("private key seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func ParsePublicKey(pubB64 string) (ed25519.PublicKey, error) {
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	return ed25519.PublicKey(pub), nil
}

func GenerateSessionID() ([]byte, error) {
	id := make([]byte, SessionIDLen)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("generate session id: %w", err)
	}
	return id, nil
}
