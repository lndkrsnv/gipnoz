package server

import (
	"testing"
	"time"
)

func TestSessionAdmitAndJoin(t *testing.T) {
	r := newSessionRegistry(time.Minute)
	now := time.Now()

	res := r.admit("key", "sess-a", "203.0.113.1", now)
	if !res.ok || res.busy || res.takeover {
		t.Fatalf("first admit: want plain ok, got %+v", res)
	}

	res = r.admit("key", "sess-a", "203.0.113.1", now)
	if !res.ok || res.busy || res.takeover {
		t.Fatalf("same session id: want join, got %+v", res)
	}
}

func TestSessionBusy(t *testing.T) {
	r := newSessionRegistry(time.Minute)
	now := time.Now()

	r.admit("key", "sess-a", "203.0.113.1", now)
	res := r.admit("key", "sess-b", "203.0.113.2", now)
	if res.ok || !res.busy || res.holderIP != "203.0.113.1" {
		t.Fatalf("other session id: want busy held by 203.0.113.1, got %+v", res)
	}
}

func TestSessionExpiry(t *testing.T) {
	r := newSessionRegistry(time.Minute)
	now := time.Now()

	r.admit("key", "sess-a", "203.0.113.1", now)
	r.release("key", "sess-a", now)

	res := r.admit("key", "sess-b", "203.0.113.2", now.Add(30*time.Second))
	if !res.busy {
		t.Fatalf("within grace: want busy, got %+v", res)
	}

	res = r.admit("key", "sess-b", "203.0.113.2", now.Add(61*time.Second))
	if !res.ok || !res.takeover {
		t.Fatalf("after grace: want takeover, got %+v", res)
	}
}

func TestSessionReleaseWrongID(t *testing.T) {
	r := newSessionRegistry(time.Minute)
	now := time.Now()

	r.admit("key", "sess-a", "203.0.113.1", now)
	r.release("key", "sess-b", now)

	res := r.admit("key", "sess-b", "203.0.113.2", now.Add(2*time.Minute))
	if !res.busy {
		t.Fatalf("release with wrong id must not free the session, got %+v", res)
	}
}

func TestSessionEnd(t *testing.T) {
	r := newSessionRegistry(time.Minute)
	now := time.Now()

	r.admit("key", "sess-a", "203.0.113.1", now)
	r.release("key", "sess-a", now)
	r.end("key", "sess-a")

	res := r.admit("key", "sess-b", "203.0.113.2", now.Add(30*time.Second))
	if !res.ok || res.busy {
		t.Fatalf("end with matching id must free the session within grace, got %+v", res)
	}
}

func TestSessionEndWrongID(t *testing.T) {
	r := newSessionRegistry(time.Minute)
	now := time.Now()

	r.admit("key", "sess-a", "203.0.113.1", now)
	r.release("key", "sess-a", now)
	r.end("key", "sess-b")

	res := r.admit("key", "sess-b", "203.0.113.2", now.Add(30*time.Second))
	if !res.busy {
		t.Fatalf("end with wrong id must keep the session busy within grace, got %+v", res)
	}
}

func TestSessionFlapping(t *testing.T) {
	r := newSessionRegistry(time.Minute)
	now := time.Now()

	r.admit("key", "sess-a", "203.0.113.1", now)
	r.release("key", "sess-a", now)

	res := r.admit("key", "sess-b", "203.0.113.2", now.Add(61*time.Second))
	if res.flaps != 1 {
		t.Fatalf("first ip change: want flaps 1, got %d", res.flaps)
	}
	r.release("key", "sess-b", now.Add(61*time.Second))

	res = r.admit("key", "sess-c", "203.0.113.1", now.Add(122*time.Second))
	if res.flaps != 2 {
		t.Fatalf("alternating ip: want flaps 2, got %d", res.flaps)
	}
	r.release("key", "sess-c", now.Add(122*time.Second))

	res = r.admit("key", "sess-d", "203.0.113.1", now.Add(183*time.Second))
	if res.flaps != 0 {
		t.Fatalf("same-ip registration: want flaps reset, got %d", res.flaps)
	}
	r.release("key", "sess-d", now.Add(183*time.Second))

	res = r.admit("key", "sess-e", "203.0.113.2", now.Add(183*time.Second+flapWindow+time.Minute))
	if res.flaps != 0 {
		t.Fatalf("slow registrations: want flaps reset, got %d", res.flaps)
	}
}

func TestSessionBusyLogThrottle(t *testing.T) {
	r := newSessionRegistry(time.Minute)
	now := time.Now()

	if r.busyLoggedRecently("key", now) {
		t.Fatal("first report must not be throttled")
	}
	if !r.busyLoggedRecently("key", now.Add(time.Minute)) {
		t.Fatal("report within window must be throttled")
	}
	if r.busyLoggedRecently("key", now.Add(busyLogWindow+time.Minute)) {
		t.Fatal("report after window must not be throttled")
	}
}
