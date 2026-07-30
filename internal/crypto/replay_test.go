package crypto

import "testing"

func TestReplayGuard(t *testing.T) {
	rg := NewReplayGuard(30)

	token := []byte("unique-signature-bytes")
	if !rg.Check(token) {
		t.Fatal("first use of a token must be accepted")
	}
	if rg.Check(token) {
		t.Fatal("reused token must be rejected")
	}
	if !rg.Check([]byte("other-signature-bytes")) {
		t.Fatal("distinct token must be accepted")
	}
}
