package handlers

import (
	"sync"
	"time"
)

type slidingWindow struct {
	times []time.Time
}

func newSlidingWindow(limit int) *slidingWindow {
	return &slidingWindow{
		times: make([]time.Time, 0, limit+1),
	}
}

func (sw *slidingWindow) allow(now time.Time, cutoff time.Time, limit int) bool {
	var valid []time.Time
	for _, t := range sw.times {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	sw.times = valid

	if len(sw.times) >= limit {
		return false
	}

	sw.times = append(sw.times, now)
	return true
}

type rateLimiter struct {
	mu       sync.Mutex
	requests map[string]*slidingWindow
	limit    int
	window   time.Duration
	done     chan struct{}
	once     sync.Once
	maxKeys  int
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		requests: make(map[string]*slidingWindow),
		limit:    limit,
		window:   window,
		done:     make(chan struct{}),
		maxKeys:  100_000,
	}
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	sw, exists := rl.requests[key]
	if !exists {
		if len(rl.requests) >= rl.maxKeys {
			return false
		}
		sw = newSlidingWindow(rl.limit)
		rl.requests[key] = sw
	}

	return sw.allow(now, cutoff, rl.limit)
}

func (rl *rateLimiter) Stop() {
	rl.once.Do(func() {
		close(rl.done)
	})
}

func (rl *rateLimiter) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-rl.done:
			return
		case <-ticker.C:
			rl.mu.Lock()
			cutoff := time.Now().Add(-rl.window)
			for key, sw := range rl.requests {
				sw.allow(cutoff.Add(1), cutoff, rl.limit)
				if len(sw.times) == 0 {
					delete(rl.requests, key)
				}
			}
			rl.mu.Unlock()
		}
	}
}
