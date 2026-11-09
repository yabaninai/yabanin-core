package adminauth

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeScripter stands in for *redis.Client without a server.
type fakeScripter struct {
	mu      sync.Mutex
	evalErr error
	result  int64
	scripts []string
	keys    []string
	args    [][]interface{}
}

func (f *fakeScripter) Eval(ctx context.Context, script string, keys []string, args ...interface{}) *redis.Cmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scripts = append(f.scripts, script)
	f.keys = append(f.keys, keys[0])
	f.args = append(f.args, args)
	cmd := redis.NewCmd(ctx)
	if f.evalErr != nil {
		cmd.SetErr(f.evalErr)
		return cmd
	}
	cmd.SetVal(f.result)
	return cmd
}

func (f *fakeScripter) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.scripts)
}

type captureHandler struct {
	mu      sync.Mutex
	records []string
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Level.String()+" "+r.Message)
	return nil
}

func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *captureHandler) WithGroup(string) slog.Handler { return h }

func (h *captureHandler) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.records)
}

func (h *captureHandler) hasWarn(substr string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, rec := range h.records {
		if strings.Contains(rec, substr) {
			return true
		}
	}
	return false
}

func fallbackDelta(t *testing.T, scope string, fn func()) float64 {
	t.Helper()
	before := testutil.ToFloat64(AdminRateLimitFallbackTotal.WithLabelValues(scope))
	fn()
	after := testutil.ToFloat64(AdminRateLimitFallbackTotal.WithLabelValues(scope))
	return after - before
}

func TestRedisRateLimiter_FailOpenWhenRedisErrors(t *testing.T) {
	fake := &fakeScripter{evalErr: errors.New("redis down")}
	logs := &captureHandler{}
	rl := NewRedisRateLimiter(fake, "ulogin", 5, 15*time.Minute, slog.New(logs))

	delta := fallbackDelta(t, "ulogin", func() {
		for i := 0; i < 3; i++ {
			assert.True(t, rl.Allow("203.0.113.5"), "fail-open must admit the request")
		}
	})

	assert.InDelta(t, 3, delta, 0.0001, "every Redis failure counts one fallback")
	require.Equal(t, 3, fake.calls(), "every decision must attempt Redis first")
	assert.True(t, logs.hasWarn("redis unavailable"), "outage must be visible in logs")
}

func TestRedisRateLimiter_LoginFailsClosedWhenRedisErrors(t *testing.T) {
	fake := &fakeScripter{evalErr: errors.New("redis down")}
	logs := &captureHandler{}
	rl := NewRedisRateLimiter(fake, "login", 5, 15*time.Minute, slog.New(logs))

	if rl.Allow("203.0.113.5") {
		t.Fatal("login limiter admitted request during Redis outage")
	}
	assert.Equal(t, 1, fake.calls(), "outage decision must attempt Redis")
	assert.True(t, logs.hasWarn("redis unavailable"), "outage must be visible in logs")
}

func TestRedisRateLimiter_FailOpenWarnThrottled(t *testing.T) {
	fake := &fakeScripter{evalErr: errors.New("redis down")}
	logs := &captureHandler{}
	rl := NewRedisRateLimiter(fake, "ulogin", 5, 15*time.Minute, slog.New(logs))
	rl.warnEvery = time.Hour // suppress repeats within the test

	for i := 0; i < 10; i++ {
		assert.True(t, rl.Allow("203.0.113.5"))
	}

	assert.Equal(t, 1, logs.count(), "WARN must not spam: one per warnEvery window")
}

func TestRedisRateLimiter_WarnRepeatsAfterInterval(t *testing.T) {
	fake := &fakeScripter{evalErr: errors.New("redis down")}
	logs := &captureHandler{}
	rl := NewRedisRateLimiter(fake, "ulogin", 5, 15*time.Minute, slog.New(logs))
	rl.warnEvery = time.Millisecond

	assert.True(t, rl.Allow("203.0.113.5"))
	time.Sleep(2 * time.Millisecond)
	assert.True(t, rl.Allow("203.0.113.5"))

	assert.Equal(t, 2, logs.count(), "a sustained outage must re-warn after warnEvery")
}

func TestRedisRateLimiter_AllowDenyFollowsScriptVerdict(t *testing.T) {
	fake := &fakeScripter{result: 1}
	rl := NewRedisRateLimiter(fake, "uapi", 1000, time.Minute, nil)

	assert.True(t, rl.Allow("198.51.100.1"), "script verdict 1 admits")

	fake.mu.Lock()
	fake.result = 0
	fake.mu.Unlock()
	assert.False(t, rl.Allow("198.51.100.1"), "script verdict 0 denies")

	require.Equal(t, 2, fake.calls())
	script := fake.scripts[0]
	assert.Contains(t, script, "ZREMRANGEBYSCORE")
	assert.Contains(t, script, "ZCARD")
	assert.Contains(t, script, "ZADD")
	assert.Contains(t, script, "PEXPIRE")

	fake.mu.Lock()
	key, args := fake.keys[0], fake.args[0]
	fake.mu.Unlock()
	assert.Equal(t, "admin:rl:uapi:198.51.100.1", key, "keys are scoped per limiter and per client IP")
	require.Len(t, args, 3)
	assert.Equal(t, int64(60000), args[0], "window is passed in milliseconds")
	assert.Equal(t, 1000, args[1], "limit is passed verbatim")
}

func TestRedisRateLimiter_ScopesDoNotShareKeys(t *testing.T) {
	fake := &fakeScripter{result: 1}
	login := NewRedisRateLimiter(fake, "slogin", 5, time.Minute, nil)
	api := NewRedisRateLimiter(fake, "sapi", 1000, time.Minute, nil)

	login.Allow("192.0.2.1")
	api.Allow("192.0.2.1")

	fake.mu.Lock()
	loginKey, apiKey := fake.keys[0], fake.keys[1]
	fake.mu.Unlock()
	assert.Equal(t, "admin:rl:slogin:192.0.2.1", loginKey)
	assert.Equal(t, "admin:rl:sapi:192.0.2.1", apiKey)
}
