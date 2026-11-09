package httpmw

import (
	"net/http"
	"sync"
	"time"

	"github.com/reireirei/yabanin/pkg/clientip"
)

// RateLimitConfig holds the parameters for per-IP rate limiting.
type RateLimitConfig struct {
	RequestsPerSecond float64       // max requests per second per IP (0 = disabled)
	BurstSize         int           // max burst size (default: 10 if RequestsPerSecond > 0)
	TrustedProxies    []string      // CIDR/IP list of trusted reverse proxies
	EvictionInterval  time.Duration // how often to sweep stale buckets (default: 5m)
	MaxBuckets        int           // max bucket count before LRU eviction starts (default: 100k)
}

// rateBucket tracks request timestamps for a single IP.
type rateBucket struct {
	tokens     int
	lastRefill time.Time
	rate       float64 // tokens per second
	burst      int
	mu         sync.Mutex
	lastAccess time.Time // track for eviction
}

// RateLimiter returns an http.Handler middleware that enforces per-IP rate
// limiting using a token bucket algorithm. Requests exceeding the limit
// receive HTTP 429 (Too Many Requests) with a Retry-After header.
//
// The client IP is extracted from X-Forwarded-For only when the remote address
// matches a trusted proxy (from cfg.TrustedProxies). Otherwise, RemoteAddr is
// used directly. This prevents XFF spoofing bypass.
func RateLimiter(cfg RateLimitConfig) func(http.Handler) http.Handler {
	if cfg.RequestsPerSecond <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}

	burst := cfg.BurstSize
	if burst <= 0 {
		burst = 10
	}

	interval := cfg.EvictionInterval
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	maxBuckets := cfg.MaxBuckets
	if maxBuckets <= 0 {
		maxBuckets = 100_000
	}

	store := &ipStore{
		buckets:          make(map[string]*rateBucket),
		trustedProxies:   cfg.TrustedProxies,
		evictionInterval: interval,
		maxBuckets:       maxBuckets,
	}

	// Start background eviction goroutine.
	go store.evictLoop()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientip.Extract(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-IP"), cfg.TrustedProxies)
			if !store.allow(ip, cfg.RequestsPerSecond, burst) {
				w.Header().Set("Retry-After", "1")
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ipStore is a thread-safe in-memory rate limit bucket store with TTL eviction
// and LRU-based cap enforcement to prevent unbounded memory growth.
type ipStore struct {
	mu               sync.RWMutex
	buckets          map[string]*rateBucket
	trustedProxies   []string
	evictionInterval time.Duration
	maxBuckets       int
}

func (s *ipStore) evictLoop() {
	ticker := time.NewTicker(s.evictionInterval)
	defer ticker.Stop()
	for range ticker.C {
		s.evictStale()
	}
}

// evictStale removes buckets that haven't been accessed in 10 minutes and
// enforces the max-bucket cap by removing the oldest (LRU).
func (s *ipStore) evictStale() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	threshold := now.Add(-10 * time.Minute)

	// Remove stale buckets.
	for ip, b := range s.buckets {
		b.mu.Lock()
		if b.lastAccess.Before(threshold) {
			delete(s.buckets, ip)
		}
		b.mu.Unlock()
	}

	// Enforce max cap via LRU if still over.
	for len(s.buckets) > s.maxBuckets {
		var oldestIP string
		var oldestTime time.Time
		for ip, b := range s.buckets {
			b.mu.Lock()
			if b.lastAccess.Before(oldestTime) || oldestTime.IsZero() {
				oldestIP = ip
				oldestTime = b.lastAccess
			}
			b.mu.Unlock()
		}
		if oldestIP != "" {
			delete(s.buckets, oldestIP)
		} else {
			break // safety: should not happen
		}
	}
}

func (s *ipStore) allow(ip string, rate float64, burst int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	bucket, ok := s.buckets[ip]
	if !ok {
		bucket = &rateBucket{
			tokens:     burst,
			lastRefill: time.Now(),
			rate:       rate,
			burst:      burst,
			lastAccess: time.Now(),
		}
		s.buckets[ip] = bucket
	}

	now := time.Now()
	bucket.lastAccess = now
	elapsed := now.Sub(bucket.lastRefill).Seconds()
	bucket.tokens += int(elapsed * bucket.rate)
	if bucket.tokens > bucket.burst {
		bucket.tokens = bucket.burst
	}
	bucket.lastRefill = now

	if bucket.tokens >= 1 {
		bucket.tokens--
		return true
	}
	return false
}
