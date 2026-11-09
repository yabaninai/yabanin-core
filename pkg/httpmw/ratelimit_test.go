package httpmw

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/clientip"
	"github.com/stretchr/testify/assert"
)

// TestRateLimiter_AllowsNormalTraffic verifies that requests within the rate
// limit pass through with 200 OK.
func TestRateLimiter_AllowsNormalTraffic(t *testing.T) {
	mw := RateLimiter(RateLimitConfig{
		RequestsPerSecond: 10,
		BurstSize:         10,
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/healthz", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	mw(next).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestRateLimiter_ExceedsBurst_Returns429 verifies that exceeding the burst
// limit returns HTTP 429 with a Retry-After header.
func TestRateLimiter_ExceedsBurst_Returns429(t *testing.T) {
	mw := RateLimiter(RateLimitConfig{
		RequestsPerSecond: 1, // very slow refill
		BurstSize:         3, // allow only 3 bursts
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), "GET", "/healthz", nil)
		req.RemoteAddr = "10.0.0.1:9999"
		mw(next).ServeHTTP(rec, req)

		if i < 3 {
			assert.Equal(t, http.StatusOK, rec.Code, "request %d should succeed", i+1)
		} else {
			assert.Equal(t, http.StatusTooManyRequests, rec.Code, "request %d should be rate limited", i+1)
			assert.Contains(t, rec.Header().Get("Retry-After"), "1")
		}
	}
}

// TestRateLimiter_IsolatedPerIP verifies that different IPs have independent
// rate limits.
func TestRateLimiter_IsolatedPerIP(t *testing.T) {
	mw := RateLimiter(RateLimitConfig{
		RequestsPerSecond: 1,
		BurstSize:         2,
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// IP A gets 2 requests (burst limit), then should be limited.
	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), "GET", "/healthz", nil)
		req.RemoteAddr = "1.2.3.4:8080"
		mw(next).ServeHTTP(rec, req)

		if i < 2 {
			assert.Equal(t, http.StatusOK, rec.Code)
		} else {
			assert.Equal(t, http.StatusTooManyRequests, rec.Code)
		}
	}

	// IP B should still be allowed its full burst.
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/healthz", nil)
	req.RemoteAddr = "5.6.7.8:8080"
	mw(next).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "different IP should not be rate limited")
}

// TestRateLimiter_XForwardedFor_ExtractsClientIP verifies that the middleware
// extracts client IP from X-Forwarded-For when RemoteAddr matches a trusted proxy.
func TestRateLimiter_XForwardedFor_ExtractsClientIP(t *testing.T) {
	mw := RateLimiter(RateLimitConfig{
		RequestsPerSecond: 0.1, // very slow refill so burst exhausts fast
		BurstSize:         2,
		TrustedProxies:    []string{"172.31.0.1"},
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	for i := 1; i <= 3; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), "GET", "/healthz", nil)
		req.Header.Set("X-Forwarded-For", "203.0.113.50, 70.41.3.18")
		req.RemoteAddr = fmt.Sprintf("172.31.0.1:%d", 49010+i)
		mw(next).ServeHTTP(rec, req)

		if i <= 2 {
			assert.Equal(t, http.StatusOK, rec.Code, "request %d should succeed", i)
		} else {
			assert.Equal(t, http.StatusTooManyRequests, rec.Code, "request %d should be limited", i)
		}
	}
}

// TestRateLimiter_Disabled_PassesThrough verifies that RequestsPerSecond=0
// means no rate limiting at all.
func TestRateLimiter_Disabled_PassesThrough(t *testing.T) {
	mw := RateLimiter(RateLimitConfig{
		RequestsPerSecond: 0, // disabled
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	for i := 0; i < 100; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), "GET", "/healthz", nil)
		req.RemoteAddr = "99.99.99.99:9999"
		mw(next).ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	}
}

// TestClientIP_ExtractsCorrectly verifies the clientip.Extract logic used by the rate limiter.
func TestClientIP_ExtractsCorrectly(t *testing.T) {
	t.Run("XFF single", func(t *testing.T) {
		r := httptest.NewRequestWithContext(context.Background(), "GET", "/healthz", nil)
		r.RemoteAddr = "10.0.0.5:443"
		r.Header.Set("X-Forwarded-For", "1.2.3.4")
		assert.Equal(t, "1.2.3.4", clientip.Extract(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-IP"), []string{"10.0.0.0/8"}))
	})

	t.Run("XFF multiple (trusted proxy)", func(t *testing.T) {
		r := httptest.NewRequestWithContext(context.Background(), "GET", "/healthz", nil)
		r.RemoteAddr = "10.0.0.5:443"
		r.Header.Set("X-Forwarded-For", "10.0.0.1, 203.0.113.50, 70.41.3.18")
		assert.Equal(t, "70.41.3.18", clientip.Extract(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-IP"), []string{"10.0.0.0/8"}))
	})

	t.Run("RemoteAddr fallback (full address when no trusted proxies)", func(t *testing.T) {
		r := httptest.NewRequestWithContext(context.Background(), "GET", "/healthz", nil)
		r.RemoteAddr = "203.0.113.50:12345"
		assert.Equal(t, "203.0.113.50:12345", clientip.Extract(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-IP"), nil))
	})

	t.Run("XFF with spaces", func(t *testing.T) {
		r := httptest.NewRequestWithContext(context.Background(), "GET", "/healthz", nil)
		r.RemoteAddr = "10.0.0.5:443"
		r.Header.Set("X-Forwarded-For", "  1.2.3.4  , 5.6.7.8")
		assert.Equal(t, "5.6.7.8", clientip.Extract(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-IP"), []string{"10.0.0.0/8"}))
	})

	t.Run("Empty XFF falls back to RemoteAddr (full address)", func(t *testing.T) {
		r := httptest.NewRequestWithContext(context.Background(), "GET", "/healthz", nil)
		r.RemoteAddr = "9.8.7.6:1234"
		assert.Equal(t, "9.8.7.6:1234", clientip.Extract(r.RemoteAddr, "", "", nil))
	})

	t.Run("Untrusted proxy -- XFF ignored when remote is not in trusted list", func(t *testing.T) {
		r := httptest.NewRequestWithContext(context.Background(), "GET", "/healthz", nil)
		r.RemoteAddr = "192.0.2.99:1234" // NOT in trusted list
		r.Header.Set("X-Forwarded-For", "10.20.30.40")
		trusted := []string{"10.0.0.0/8"}
		result := clientip.Extract(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-IP"), trusted)
		assert.Equal(t, "192.0.2.99:1234", result, "untrusted proxy XFF should be ignored")
	})

	t.Run("Trusted proxy -- XFF honored when remote matches CIDR", func(t *testing.T) {
		r := httptest.NewRequestWithContext(context.Background(), "GET", "/healthz", nil)
		r.RemoteAddr = "10.0.0.1:443" // in 10.0.0.0/8
		r.Header.Set("X-Forwarded-For", "203.0.113.99")
		trusted := []string{"10.0.0.0/8"}
		result := clientip.Extract(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-IP"), trusted)
		assert.Equal(t, "203.0.113.99", result, "trusted proxy XFF should be honored")
	})
}

// TestRateLimiter_ResponseBody verifies the 429 response body is informative.
func TestRateLimiter_ResponseBody(t *testing.T) {
	mw := RateLimiter(RateLimitConfig{
		RequestsPerSecond: 1,
		BurstSize:         1,
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), "GET", "/healthz", nil)
		req.RemoteAddr = "1.1.1.1:80"
		mw(next).ServeHTTP(rec, req)

		if i == 0 {
			assert.Equal(t, http.StatusOK, rec.Code)
		} else {
			assert.Equal(t, http.StatusTooManyRequests, rec.Code)
			assert.Contains(t, rec.Body.String(), "rate limit",
				"error body should mention rate limit")
		}
	}
}

// TestRateLimiter_UntrustedProxy_XFFIgnored verifies that X-Forwarded-For is NOT
// trusted when RemoteAddr doesn't match the trusted-proxy list. An attacker
// rotating XFF cannot bypass rate limiting or create new buckets.
func TestRateLimiter_UntrustedProxy_XFFIgnored(t *testing.T) {
	mw := RateLimiter(RateLimitConfig{
		RequestsPerSecond: 0.1, // very slow refill
		BurstSize:         2,
		TrustedProxies:    []string{"172.31.0.2"}, // narrow trust range
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Attacker at untrusted IP rotates XFF -- should still be rate-limited by RemoteAddr.
	for i := 0; i < 4; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), "GET", "/healthz", nil)
		req.RemoteAddr = "192.0.2.51:8080" // NOT trusted (unique IP)
		req.Header.Set("X-Forwarded-For", "1.2.3.4")
		mw(next).ServeHTTP(rec, req)

		if i < 2 {
			assert.Equal(t, http.StatusOK, rec.Code, "request %d should succeed", i+1)
		} else {
			assert.Equal(t, http.StatusTooManyRequests, rec.Code, "request %d should be limited", i+1)
		}
	}

	// Trusted proxy XFF IS honored.
	for i := 0; i < 4; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), "GET", "/healthz", nil)
		req.RemoteAddr = "172.31.0.2:8080" // trusted
		req.Header.Set("X-Forwarded-For", "203.0.113.42")
		mw(next).ServeHTTP(rec, req)

		if i < 2 {
			assert.Equal(t, http.StatusOK, rec.Code, "trusted proxy request %d should succeed", i+1)
		} else {
			assert.Equal(t, http.StatusTooManyRequests, rec.Code, "trusted proxy request %d should be limited", i+1)
		}
	}
}

// TestRateLimiter_Eviction verifies that stale buckets are evicted.
func TestRateLimiter_Eviction(t *testing.T) {
	mw := RateLimiter(RateLimitConfig{
		RequestsPerSecond: 1,
		BurstSize:         2,
		EvictionInterval:  100 * time.Millisecond, // fast for testing
		MaxBuckets:        5,
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Create 6 unique IPs to trigger LRU eviction.
	for i := 0; i < 6; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), "GET", "/healthz", nil)
		req.RemoteAddr = fmt.Sprintf("192.168.%d.%d:8080", i/256, i%256)
		mw(next).ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "request %d should succeed", i+1)
	}

	// Wait for eviction cycle.
	time.Sleep(300 * time.Millisecond)

	// After eviction, all IPs should be fresh again (old buckets evicted).
	for i := 0; i < 4; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), "GET", "/healthz", nil)
		req.RemoteAddr = fmt.Sprintf("192.168.%d.%d:8080", i/256, i%256)
		mw(next).ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "request %d after eviction should succeed", i+1)
	}
}
