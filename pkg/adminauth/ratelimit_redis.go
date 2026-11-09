package adminauth

import (
	"context"
	"log/slog"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/redis/go-redis/v9"
)

// AdminRateLimitFallbackTotal counts admin-plane rate-limit decisions taken
// without Redis, labelled by limiter scope ("login", "api").
var AdminRateLimitFallbackTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "admin_ratelimit_fallback_total",
		Help: "Admin-plane rate-limit decisions taken without Redis.",
	},
	[]string{"scope"},
)

// slidingWindowScript admits or denies one request atomically. The window
// state is a per-key ZSET of admission timestamps; time comes from the Redis
// server (TIME) so replicas with skewed clocks agree on the window.
//
//	KEYS[1] — ZSET key
//	ARGV[1] — window in milliseconds
//	ARGV[2] — limit
//	ARGV[3] — unique member for this request
//
// Returns 1 when the request is admitted, 0 when it is over the limit.
var slidingWindowScript = `
local t = redis.call('TIME')
local now = t[1] * 1000 + math.floor(t[2] / 1000)
local window = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - window)
local count = redis.call('ZCARD', KEYS[1])
if count >= limit then
	redis.call('PEXPIRE', KEYS[1], window)
	return 0
end
redis.call('ZADD', KEYS[1], now, ARGV[3])
redis.call('PEXPIRE', KEYS[1], window)
return 1
`

// Scripter is the subset of the Redis client the limiter needs. *redis.Client
// (and the cluster client) satisfy it; tests substitute a fake.
type Scripter interface {
	Eval(ctx context.Context, script string, keys []string, args ...interface{}) *redis.Cmd
}

// RedisRateLimiter is a Redis-backed sliding-window rate limiter for the
// admin plane: login per-IP and global per-IP. Window state lives in
// Redis, so every replica pointed at the same Redis enforces one shared
// limit instead of one limit per process (the in-memory limiter in
// services/admin/handlers). Thresholds are caller-supplied and must match the
// previous in-memory ones to keep single-instance behaviour unchanged.
//
// Redis failures follow the configured open/closed policy and are counted in
// AdminRateLimitFallbackTotal with a throttled WARN.
type RedisRateLimiter struct {
	rdb    Scripter
	scope  string
	limit  int
	window time.Duration
	prefix string
	logger *slog.Logger

	// callTimeout bounds each Redis round-trip so a slow (not only down)
	// Redis cannot stall login attempts.
	callTimeout time.Duration
	// warnEvery throttles outage warnings (no log spam).
	warnEvery time.Duration
	// lastWarn is the unix-nano timestamp of the last WARN emission.
	lastWarn atomic.Int64
	// memberSeq makes ZSET members unique per process; combined with the
	// nanosecond timestamp, cross-process collisions are negligible.
	memberSeq  atomic.Uint64
	failClosed bool
}

// NewRedisRateLimiter builds a shared limiter. scope namespaces the Redis
// keys ("login", "api"); key is typically the client IP. A nil logger falls
// back to slog.Default().
func NewRedisRateLimiter(rdb Scripter, scope string, limit int, window time.Duration, logger *slog.Logger) *RedisRateLimiter {
	// Login throttling is an authentication boundary: admitting attempts when
	// the shared counter is unavailable would disable brute-force protection.
	return newRedisRateLimiter(rdb, scope, limit, window, logger, scope == "login")
}

// NewRedisRateLimiterFailClosed rejects requests when Redis cannot provide a
// decision. Use this for authentication entry points.
func NewRedisRateLimiterFailClosed(rdb Scripter, scope string, limit int, window time.Duration, logger *slog.Logger) *RedisRateLimiter {
	return newRedisRateLimiter(rdb, scope, limit, window, logger, true)
}

func newRedisRateLimiter(rdb Scripter, scope string, limit int, window time.Duration, logger *slog.Logger, failClosed bool) *RedisRateLimiter {
	if logger == nil {
		logger = slog.Default()
	}
	return &RedisRateLimiter{
		rdb:         rdb,
		scope:       scope,
		limit:       limit,
		window:      window,
		prefix:      "admin:rl:" + scope + ":",
		logger:      logger,
		callTimeout: 500 * time.Millisecond,
		warnEvery:   30 * time.Second,
		failClosed:  failClosed,
	}
}

// Allow reports whether one more request for key is within the limit.
// Redis errors follow the configured failure policy and emit a throttled WARN.
func (rl *RedisRateLimiter) Allow(key string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), rl.callTimeout)
	defer cancel()

	member := strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + strconv.FormatUint(rl.memberSeq.Add(1), 10)
	res, err := rl.rdb.Eval(ctx, slidingWindowScript, []string{rl.prefix + key},
		rl.window.Milliseconds(), rl.limit, member).Int()
	if err != nil {
		rl.recordFailure(err)
		return !rl.failClosed
	}
	return res == 1
}

// Stop exists for parity with the in-memory limiter so both satisfy the same
// wiring interface. Redis window state expires via the key TTL; there is no
// background goroutine to stop.
func (rl *RedisRateLimiter) Stop() {}

// recordFailure counts one Redis failure and throttles the WARN.
func (rl *RedisRateLimiter) recordFailure(err error) {
	AdminRateLimitFallbackTotal.WithLabelValues(rl.scope).Inc()

	now := time.Now().UnixNano()
	last := rl.lastWarn.Load()
	if last != 0 && now-last < rl.warnEvery.Nanoseconds() {
		return
	}
	if rl.lastWarn.CompareAndSwap(last, now) {
		policy := "open"
		if rl.failClosed {
			policy = "closed"
		}
		rl.logger.Warn("admin rate limiter: redis unavailable",
			"scope", rl.scope, "failure_policy", policy, "limit", rl.limit, "window", rl.window, "error", err)
	}
}
