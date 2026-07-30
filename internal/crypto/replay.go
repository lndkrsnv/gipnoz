package crypto

import (
	"sync"
	"time"
)

type ReplayGuard struct {
	mu     sync.Mutex
	seen   map[string]int64
	window int64
}

func NewReplayGuard(windowSeconds int64) *ReplayGuard {
	rg := &ReplayGuard{
		seen:   make(map[string]int64),
		window: windowSeconds,
	}
	go rg.cleanup()
	return rg
}

func (rg *ReplayGuard) Check(token []byte) bool {
	rg.mu.Lock()
	defer rg.mu.Unlock()
	if _, exists := rg.seen[string(token)]; exists {
		return false
	}
	rg.seen[string(token)] = time.Now().Unix()
	return true
}

func (rg *ReplayGuard) cleanup() {
	ticker := time.NewTicker(time.Duration(rg.window) * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		rg.mu.Lock()
		cutoff := time.Now().Unix() - rg.window*2
		for token, ts := range rg.seen {
			if ts < cutoff {
				delete(rg.seen, token)
			}
		}
		rg.mu.Unlock()
	}
}
