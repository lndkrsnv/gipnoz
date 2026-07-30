package server

import "testing"

func TestRateLimiter(t *testing.T) {
	rl := NewRateLimiter(2)

	if !rl.Acquire("1.2.3.4") || !rl.Acquire("1.2.3.4") {
		t.Fatal("first two acquires must succeed")
	}
	if rl.Acquire("1.2.3.4") {
		t.Fatal("third acquire must be rejected")
	}
	if !rl.Acquire("5.6.7.8") {
		t.Fatal("other IP must not be affected")
	}

	rl.Release("1.2.3.4")
	if !rl.Acquire("1.2.3.4") {
		t.Fatal("acquire after release must succeed")
	}
}
