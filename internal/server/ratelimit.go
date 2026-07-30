package server

import "sync"

type RateLimiter struct {
	mu       sync.Mutex
	counts   map[string]int
	maxPerIP int
}

func NewRateLimiter(maxPerIP int) *RateLimiter {
	return &RateLimiter{
		counts:   make(map[string]int),
		maxPerIP: maxPerIP,
	}
}

func (rl *RateLimiter) Acquire(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rl.counts[ip] >= rl.maxPerIP {
		return false
	}
	rl.counts[ip]++
	return true
}

func (rl *RateLimiter) Release(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.counts[ip]--
	if rl.counts[ip] <= 0 {
		delete(rl.counts, ip)
	}
}
