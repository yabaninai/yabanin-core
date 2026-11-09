//go:build integration

package adminauth

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	testredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

func redisContainerAddr(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping testcontainers (Redis) test in -short mode")
	}
	ctx := context.Background()

	container, err := testredis.Run(ctx, "redis:7-alpine")
	require.NoError(t, err)
	t.Cleanup(func() { _ = container.Terminate(ctx) })

	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "6379")
	require.NoError(t, err)
	portStr := port.Port()
	if i := len(portStr) - 4; i > 0 && portStr[i:] == "/tcp" {
		portStr = portStr[:i]
	}
	return host + ":" + portStr
}

func redisProcess(t *testing.T, addr string) *redis.Client {
	t.Helper()
	rdb := redis.NewClient(&redis.Options{
		Addr:         addr,
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
		DialTimeout:  time.Second,
	})
	require.NoError(t, rdb.Ping(context.Background()).Err(), "test redis should be reachable")
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

func intTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(testWriter{}, nil))
}

type testWriter struct{}

func (testWriter) Write(p []byte) (int, error) { return len(p), nil }

// TestRedisRateLimiter_TwoInstancesShareLimit verifies the core
// invariant: two limiter instances (simulating two admin replicas) sharing
// one Redis admit exactly `limit` requests in total, while a single
// in-memory limiter per process would have admitted 2*limit.
func TestRedisRateLimiter_TwoInstancesShareLimit(t *testing.T) {
	addr := redisContainerAddr(t)
	const (
		limit = 5
		key   = "203.0.113.7"
	)

	// Two separate connections = two "processes".
	a := NewRedisRateLimiter(redisProcess(t, addr), "itwo", limit, time.Minute, intTestLogger())
	b := NewRedisRateLimiter(redisProcess(t, addr), "itwo", limit, time.Minute, intTestLogger())

	allowed := 0
	for i := 0; i < limit*3; i++ {
		l := a
		if i%2 == 1 {
			l = b
		}
		if l.Allow(key) {
			allowed++
		}
	}
	require.Equal(t, limit, allowed, "the limit must be shared across instances, exactly N admissions")
}

// TestRedisRateLimiter_SingleInstanceThresholdsUnchanged verifies that the
// Redis limiter preserves the previous in-memory single-instance behaviour:
// exactly `limit` admissions inside the window, the next one denied, other
// keys unaffected, and the window slides after expiry.
func TestRedisRateLimiter_SingleInstanceThresholdsUnchanged(t *testing.T) {
	addr := redisContainerAddr(t)
	rdb := redisProcess(t, addr)
	const (
		limit = 3
		ip    = "198.51.100.9"
	)
	rl := NewRedisRateLimiter(rdb, "ithr", limit, 300*time.Millisecond, intTestLogger())

	for i := 0; i < limit; i++ {
		require.True(t, rl.Allow(ip), "admission %d of %d must pass", i+1, limit)
	}
	assert.False(t, rl.Allow(ip), "limit+1 must be denied within the window")
	assert.True(t, rl.Allow("192.0.2.77"), "another key must have its own window")

	// Deadline-poll for the 300ms window to slide: denial changes no state,
	// so retrying Allow is side-effect free and the pass is observed the
	// moment the window expires — no fixed sleep guess.
	deadline := time.Now().Add(3 * time.Second)
	for !rl.Allow(ip) {
		if !time.Now().Before(deadline) {
			t.Fatalf("rate-limit window did not slide within 3s")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestRedisRateLimiter_FailOpenWhenRedisDown verifies the degradation
// contract: Redis unavailability never denies an admin request, and every
// fallback increments admin_ratelimit_fallback_total{scope}.
func TestRedisRateLimiter_FailOpenWhenRedisDown(t *testing.T) {
	addr := redisContainerAddr(t)
	rdb := redisProcess(t, addr)
	rl := NewRedisRateLimiter(rdb, "ifail", 2, time.Minute, intTestLogger())
	rl.warnEvery = time.Millisecond

	require.True(t, rl.Allow("10.1.1.1"), "healthy path admits")

	// Simulate an outage: kill this instance's connection so every call errors.
	require.NoError(t, rdb.Close())

	before := testutil.ToFloat64(AdminRateLimitFallbackTotal.WithLabelValues("ifail"))
	assert.True(t, rl.Allow("10.1.1.1"), "fail-open must admit when Redis is down")
	assert.True(t, rl.Allow("10.1.1.1"))
	after := testutil.ToFloat64(AdminRateLimitFallbackTotal.WithLabelValues("ifail"))
	assert.GreaterOrEqual(t, after-before, float64(2), "each fallback decision must count once")

	// The healthy limiter must recover once Redis is reachable again.
	recovered := NewRedisRateLimiter(redisProcess(t, addr), "ifail2", 1, time.Minute, intTestLogger())
	assert.True(t, recovered.Allow("10.2.2.2"), "a healthy limiter admits")
	assert.False(t, recovered.Allow("10.2.2.2"), "a healthy limiter still enforces the limit")
}
