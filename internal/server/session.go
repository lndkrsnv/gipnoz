package server

import (
	"sync"
	"time"
)

const (
	flapWindow    = 10 * time.Minute
	flapThreshold = 3
	busyLogWindow = 10 * time.Minute
)

type session struct {
	id       string
	ip       string
	streams  int
	lastSeen time.Time
}

type registration struct {
	ip    string
	at    time.Time
	flaps int
}

type admitResult struct {
	ok       bool
	busy     bool
	holderIP string
	takeover bool
	flaps    int
}

type sessionRegistry struct {
	mu           sync.Mutex
	grace        time.Duration
	sessions     map[string]*session
	registration map[string]registration
	busyLogged   map[string]time.Time
}

func newSessionRegistry(grace time.Duration) *sessionRegistry {
	return &sessionRegistry{
		grace:        grace,
		sessions:     make(map[string]*session),
		registration: make(map[string]registration),
		busyLogged:   make(map[string]time.Time),
	}
}

func (r *sessionRegistry) admit(key, id, ip string, now time.Time) admitResult {
	r.mu.Lock()
	defer r.mu.Unlock()

	s, ok := r.sessions[key]
	if ok && (s.streams > 0 || now.Sub(s.lastSeen) < r.grace) {
		if s.id == id {
			s.streams++
			s.lastSeen = now
			return admitResult{ok: true}
		}
		return admitResult{busy: true, holderIP: s.ip}
	}

	flaps := 0
	if prev, seen := r.registration[key]; seen && prev.ip != ip && now.Sub(prev.at) < flapWindow {
		flaps = prev.flaps + 1
	}
	r.registration[key] = registration{ip: ip, at: now, flaps: flaps}

	r.sessions[key] = &session{id: id, ip: ip, streams: 1, lastSeen: now}
	return admitResult{ok: true, takeover: ok, flaps: flaps}
}

func (r *sessionRegistry) release(key, id string, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()

	s, ok := r.sessions[key]
	if !ok || s.id != id {
		return
	}
	s.streams--
	s.lastSeen = now
}

func (r *sessionRegistry) end(key, id string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if s, ok := r.sessions[key]; ok && s.id == id {
		delete(r.sessions, key)
	}
}

func (r *sessionRegistry) busyLoggedRecently(key string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if t, ok := r.busyLogged[key]; ok && now.Sub(t) < busyLogWindow {
		return true
	}
	r.busyLogged[key] = now
	return false
}
