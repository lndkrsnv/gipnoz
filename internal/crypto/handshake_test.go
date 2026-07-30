package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func newIdentity(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return priv
}

func clientsWith(id ed25519.PrivateKey) map[string]ed25519.PublicKey {
	pub := id.Public().(ed25519.PublicKey)
	return map[string]ed25519.PublicKey{string(pub): pub}
}

func TestHandshakeRoundtrip(t *testing.T) {
	clientID := newIdentity(t)
	serverID := newIdentity(t)
	serverPub := serverID.Public().(ed25519.PublicKey)

	clientPayload, clientEph, err := BuildClientHello(clientID, "example.com:443")
	if err != nil {
		t.Fatalf("BuildClientHello: %v", err)
	}

	hello, err := ParseClientHello(clientPayload, clientsWith(clientID))
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if hello.Target != "example.com:443" {
		t.Fatalf("target mismatch: %q", hello.Target)
	}

	serverPayload, serverEph, err := BuildServerHello(serverID, clientPayload)
	if err != nil {
		t.Fatalf("BuildServerHello: %v", err)
	}

	serverEphPub, err := ParseServerHello(serverPayload, clientPayload, serverPub)
	if err != nil {
		t.Fatalf("ParseServerHello: %v", err)
	}

	c2sClient, s2cClient, err := DeriveSessionKeys(clientEph, serverEphPub, clientPayload, serverPayload)
	if err != nil {
		t.Fatalf("DeriveSessionKeys (client): %v", err)
	}
	c2sServer, s2cServer, err := DeriveSessionKeys(serverEph, hello.EphPub, clientPayload, serverPayload)
	if err != nil {
		t.Fatalf("DeriveSessionKeys (server): %v", err)
	}
	if !bytes.Equal(c2sClient, c2sServer) {
		t.Fatal("c2s keys differ")
	}
	if !bytes.Equal(s2cClient, s2cServer) {
		t.Fatal("s2c keys differ")
	}
	if bytes.Equal(c2sClient, s2cClient) {
		t.Fatal("directional keys must differ")
	}

	enc, err := NewCipher(c2sClient)
	if err != nil {
		t.Fatalf("NewCipher enc: %v", err)
	}
	dec, err := NewCipher(c2sServer)
	if err != nil {
		t.Fatalf("NewCipher dec: %v", err)
	}
	ct, err := enc.Encrypt([]byte("hello tunnel"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	pt, err := dec.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(pt) != "hello tunnel" {
		t.Fatalf("plaintext mismatch: %q", pt)
	}
}

func TestParseClientHelloUnknownKey(t *testing.T) {
	clientID := newIdentity(t)
	otherID := newIdentity(t)

	payload, _, err := BuildClientHello(clientID, "example.com:443")
	if err != nil {
		t.Fatalf("BuildClientHello: %v", err)
	}
	if _, err := ParseClientHello(payload, clientsWith(otherID)); err == nil {
		t.Fatal("expected error for unknown client key")
	}
}

func TestParseClientHelloExpired(t *testing.T) {
	clientID := newIdentity(t)

	payload, _, err := BuildClientHelloAt(clientID, time.Now().Add(-60*time.Second), "example.com:443")
	if err != nil {
		t.Fatalf("BuildClientHelloAt: %v", err)
	}
	if _, err := ParseClientHello(payload, clientsWith(clientID)); err == nil {
		t.Fatal("expected error for expired timestamp")
	}
}

func TestParseClientHelloTampered(t *testing.T) {
	clientID := newIdentity(t)

	payload, _, err := BuildClientHello(clientID, "example.com:443")
	if err != nil {
		t.Fatalf("BuildClientHello: %v", err)
	}
	payload[len(payload)-1] ^= 0xFF
	if _, err := ParseClientHello(payload, clientsWith(clientID)); err == nil {
		t.Fatal("expected error for tampered payload")
	}
}

func TestParseServerHelloWrongKey(t *testing.T) {
	clientID := newIdentity(t)
	serverID := newIdentity(t)
	otherID := newIdentity(t)

	clientPayload, _, err := BuildClientHello(clientID, "example.com:443")
	if err != nil {
		t.Fatalf("BuildClientHello: %v", err)
	}
	serverPayload, _, err := BuildServerHello(serverID, clientPayload)
	if err != nil {
		t.Fatalf("BuildServerHello: %v", err)
	}

	wrongPub := otherID.Public().(ed25519.PublicKey)
	if _, err := ParseServerHello(serverPayload, clientPayload, wrongPub); err == nil {
		t.Fatal("expected error for wrong server public key")
	}
}

func TestSessionKeysUniquePerSession(t *testing.T) {
	clientID := newIdentity(t)
	serverID := newIdentity(t)
	serverPub := serverID.Public().(ed25519.PublicKey)

	derive := func() []byte {
		clientPayload, clientEph, err := BuildClientHello(clientID, "example.com:443")
		if err != nil {
			t.Fatalf("BuildClientHello: %v", err)
		}
		serverPayload, _, err := BuildServerHello(serverID, clientPayload)
		if err != nil {
			t.Fatalf("BuildServerHello: %v", err)
		}
		serverEphPub, err := ParseServerHello(serverPayload, clientPayload, serverPub)
		if err != nil {
			t.Fatalf("ParseServerHello: %v", err)
		}
		c2s, _, err := DeriveSessionKeys(clientEph, serverEphPub, clientPayload, serverPayload)
		if err != nil {
			t.Fatalf("DeriveSessionKeys: %v", err)
		}
		return c2s
	}

	if bytes.Equal(derive(), derive()) {
		t.Fatal("session keys must be unique per handshake (ephemeral ECDH)")
	}
}
