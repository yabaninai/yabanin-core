package run

// Characterization tests for the Loggerd entrypoint (services/run/loggerd.go):
// the startup fail-closed ordering (config → Postgres required → Redis →
// readiness gate → listener) and the shutdown contract Loggerd drives — it
// blocks on SIGINT/SIGTERM or parent-context cancellation, then drains the
// health/metrics listener (readiness=false → propagation window → close) and
// stops the consumer before returning nil. Run-lifecycle tests use the
// disposable Postgres/Redis stands and a real loopback listener; the parent
// context cancellation path exercises the same select as the signal path.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// logdBaseEnv pins the ambient env to a known shape for one Loggerd run:
// every knob that could flip a feature on from the outside is explicitly
// cleared, so only what the test sets matters.
func logdBaseEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"YABANIN_REGION",
		"YABANIN_OTEL_ENDPOINT",
		"YABANIN_OTEL_LOGS_ENDPOINT",
		"YABANIN_LOG_RETENTION_DAYS",
		"YABANIN_LOGGERD_LEADER_ELECTION",
		"YABANIN_LOGGERD_LEADER_TTL",
		"YABANIN_LOGGERD_REPLICATION_ENDPOINT",
		"YABANIN_READINESS_DRAIN_DELAY",
		"YABANIN_HTTP_MAX_HEADER_BYTES",
		"YABANIN_ROLLUP_BACKFILL",
	} {
		t.Setenv(k, "")
	}
	t.Setenv("YABANIN_LOGGERD_LOG_LEVEL", "warn")
	// An empty YAML config keeps env-provided defaults in charge.
	cfgPath := filepath.Join(t.TempDir(), "cfg.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("{}\n"), 0600))
	t.Setenv("YABANIN_CONFIG", cfgPath)
}

// logdFreeAddr reserves a loopback port and releases it for the listener
// Loggerd will bind.
func logdFreeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	return addr
}

// logdUniqueStream avoids consumer-group and leader-lock collisions on the
// shared per-binary Redis stand.
func logdUniqueStream() string {
	return fmt.Sprintf("loggerd-characterization:%d", time.Now().UnixNano())
}

// logdRunUntilCancelled runs Loggerd against live stands, waits for its
// health endpoint to answer ready, proves it stays blocked while the context
// is alive, cancels, and returns the result channel plus the cancel func.
func logdRunUntilCancelled(t *testing.T, extraEnv func()) (addr string, resCh <-chan error, cancel context.CancelFunc) {
	t.Helper()
	pool := testdb.Postgres(t)
	rdb := testdb.Redis(t)

	addr = logdFreeAddr(t)
	logdBaseEnv(t)
	t.Setenv("YABANIN_PG_URI", pool.Config().ConnString())
	t.Setenv("YABANIN_REDIS_ADDR", rdb.Options().Addr)
	t.Setenv("YABANIN_LOGGERD_LISTEN", addr)
	t.Setenv("YABANIN_LOGGERD_STREAM", logdUniqueStream())
	t.Setenv("YABANIN_READINESS_DRAIN_DELAY", "50ms")
	if extraEnv != nil {
		extraEnv()
	}

	ctx, ctxCancel := context.WithCancel(context.Background())
	ch := make(chan error, 1)
	go func() { ch <- Loggerd(ctx) }()

	healthURL := "http://" + addr + "/healthz"
	require.Eventually(t, func() bool {
		resp, err := http.Get(healthURL) //nolint:noctx // bounded by the test deadline
		if err != nil {
			return false
		}
		defer resp.Body.Close() //nolint:bodyclose // closed here; the status is the assertion
		return resp.StatusCode == http.StatusOK
	}, 20*time.Second, 100*time.Millisecond, "loggerd /healthz must answer 200 while running")

	// Negative control: nothing but a signal or parent cancellation releases
	// Loggerd — a live context must keep it blocked.
	select {
	case err := <-ch:
		t.Fatalf("Loggerd returned %v before the parent context was cancelled", err)
	default:
	}

	return addr, ch, ctxCancel
}

// logdAssertBoundedCleanShutdown waits for Loggerd to return nil after
// cancellation within the drain budget and proves the listener is closed.
func logdAssertBoundedCleanShutdown(t *testing.T, addr string, resCh <-chan error) {
	t.Helper()
	select {
	case err := <-resCh:
		require.NoError(t, err, "cancellation-driven shutdown is a clean exit")
	case <-time.After(20 * time.Second):
		t.Fatal("Loggerd did not return after parent cancellation")
	}
	_, err := http.Get("http://" + addr + "/healthz") //nolint:noctx,bodyclose // the connection error IS the assertion
	require.Error(t, err, "the health listener must be closed after Loggerd returns")
}

// An invalid leader_lock_ttl is a startup error from loggerd config
// validation, before any connection attempt.
func TestLoggerd_InvalidLeaderLockTTLRejected(t *testing.T) {
	logdBaseEnv(t)
	t.Setenv("YABANIN_PG_URI", "postgres://loggerd@127.0.0.1:1/loggerd")
	t.Setenv("YABANIN_LOGGERD_LEADER_TTL", "soon")

	err := Loggerd(context.Background())

	require.Error(t, err)
	assert.ErrorContains(t, err, "invalid duration")
	assert.NotContains(t, err.Error(), "read config file")
}

// A parseable but unreachable Postgres must fail startup (request logging is
// loggerd's whole job — no degraded start), not fall through to Redis.
func TestLoggerd_UnreachablePostgresFailsClosed(t *testing.T) {
	logdBaseEnv(t)
	t.Setenv("YABANIN_PG_URI", "postgres://loggerd@127.0.0.1:1/loggerd")

	err := Loggerd(context.Background())

	require.Error(t, err)
	assert.ErrorContains(t, err, "connection refused")
	assert.NotContains(t, err.Error(), "pg_uri is required",
		"the URI is configured; the failure must be the dial, not validation")
}

// With a live Postgres, an unreachable Redis must fail startup: loggerd is a
// stream consumer. The connection-refused error also pins the ordering —
// Postgres already passed when Redis is checked.
func TestLoggerd_RequiresRedisAfterLivePostgres(t *testing.T) {
	pool := testdb.Postgres(t)
	logdBaseEnv(t)
	t.Setenv("YABANIN_PG_URI", pool.Config().ConnString())
	t.Setenv("YABANIN_REDIS_ADDR", "127.0.0.1:1")

	err := Loggerd(context.Background())

	require.Error(t, err)
	assert.ErrorContains(t, err, "connection refused")
}

// An invalid readiness drain delay must fail startup before the listener
// opens (fail-closed knob convention shared with the gateway).
func TestLoggerd_InvalidDrainDelayFailsStartup(t *testing.T) {
	pool := testdb.Postgres(t)
	rdb := testdb.Redis(t)
	logdBaseEnv(t)
	t.Setenv("YABANIN_PG_URI", pool.Config().ConnString())
	t.Setenv("YABANIN_REDIS_ADDR", rdb.Options().Addr)
	t.Setenv("YABANIN_READINESS_DRAIN_DELAY", "soon")

	err := Loggerd(context.Background())

	require.Error(t, err)
	assert.ErrorContains(t, err, "YABANIN_READINESS_DRAIN_DELAY")
}

// An invalid header-cap override must fail server construction instead of
// silently riding the Go default.
func TestLoggerd_InvalidHeaderCapFailsStartup(t *testing.T) {
	pool := testdb.Postgres(t)
	rdb := testdb.Redis(t)
	logdBaseEnv(t)
	t.Setenv("YABANIN_PG_URI", pool.Config().ConnString())
	t.Setenv("YABANIN_REDIS_ADDR", rdb.Options().Addr)
	t.Setenv("YABANIN_HTTP_MAX_HEADER_BYTES", "not-a-number")

	err := Loggerd(context.Background())

	require.Error(t, err)
	assert.ErrorContains(t, err, "YABANIN_HTTP_MAX_HEADER_BYTES")
}

// The direct-run lifecycle (no leader election): /healthz serves 200 while
// running, Loggerd blocks until parent cancellation, then returns nil with
// the listener closed — readiness observed, drain bounded, clean exit.
func TestLoggerd_RunServesReadyHealthUntilParentCancel(t *testing.T) {
	addr, resCh, cancel := logdRunUntilCancelled(t, nil)

	cancel()

	logdAssertBoundedCleanShutdown(t, addr, resCh)
}

// The leader-elected lifecycle: with leader election on, the elected replica
// holds the Redis lock (observable in the stand) while serving health, and
// parent cancellation still produces the bounded clean shutdown.
func TestLoggerd_LeaderElectedRunHoldsLockUntilParentCancel(t *testing.T) {
	stream := logdUniqueStream()
	rdb := testdb.Redis(t)

	addr, resCh, cancel := logdRunUntilCancelled(t, func() {
		t.Setenv("YABANIN_LOGGERD_LEADER_ELECTION", "true")
		t.Setenv("YABANIN_LOGGERD_STREAM", stream)
	})

	lockKey := stream + ":loggerd-leader"
	require.Eventually(t, func() bool {
		n, err := rdb.Exists(t.Context(), lockKey).Result()
		return err == nil && n == 1
	}, 20*time.Second, 100*time.Millisecond, "the elected replica must hold the leader lock")

	cancel()

	logdAssertBoundedCleanShutdown(t, addr, resCh)
}
