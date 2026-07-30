package crypto

import (
	"bytes"
	"testing"
)

func TestCipherRoundtrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	c, err := NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	for _, msg := range [][]byte{[]byte("hello tunnel"), {}, bytes.Repeat([]byte{0xAB}, 64*1024)} {
		ct, err := c.Encrypt(msg)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		pt, err := c.Decrypt(ct)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if !bytes.Equal(pt, msg) {
			t.Fatalf("roundtrip mismatch: got %d bytes, want %d", len(pt), len(msg))
		}
	}
}

func TestCipherWrongKey(t *testing.T) {
	c1, _ := NewCipher(bytes.Repeat([]byte{0x01}, 32))
	c2, _ := NewCipher(bytes.Repeat([]byte{0x02}, 32))

	ct, err := c1.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := c2.Decrypt(ct); err == nil {
		t.Fatal("expected decrypt error with wrong key")
	}
}

func TestCipherTampered(t *testing.T) {
	c, _ := NewCipher(bytes.Repeat([]byte{0x01}, 32))

	ct, err := c.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ct[len(ct)-1] ^= 0xFF
	if _, err := c.Decrypt(ct); err == nil {
		t.Fatal("expected decrypt error for tampered ciphertext")
	}
}

func TestCipherTooShort(t *testing.T) {
	c, _ := NewCipher(bytes.Repeat([]byte{0x01}, 32))
	if _, err := c.Decrypt([]byte("short")); err == nil {
		t.Fatal("expected decrypt error for short ciphertext")
	}
}

func TestNewCipherBadKeyLen(t *testing.T) {
	if _, err := NewCipher([]byte("too short")); err == nil {
		t.Fatal("expected error for bad key length")
	}
}
