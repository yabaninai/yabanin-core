package testdb

// FIX-12 (audit 2026-10-28, hypothesis H2): the per-binary sync.Once stand
// cache poisoned the whole test binary after one transient Docker VM kill —
// every later Postgres/PostgresRegion/PostgresApp caller kept getting
// `connection refused` with no re-check and no recovery.
//
// These tests simulate the dead DSN without Docker: a real *pgxpool.Pool
// pointed at 127.0.0.1:1 produces exactly the dial-refused error chain the
// audited suites saw, and package-local stand lifecycle seams (pgStandStart /
// pgStandProbe) let the tests drive the ensure/recreate control flow with
// fake container handles. The contract pinned here:
//
//   - a healthy stand is reused as-is (same pool, same DSN, no extra starts);
//   - a confirmed dead listener triggers EXACTLY ONE bounded recreate;
//   - the recreate error is diagnosable: dead container ID, mapped port,
//     elapsed lifetime, original liveness error, recreate cause and a
//     `docker events` hint;
//   - dependent pools (region/app-role caches) are invalidated and the old
//     container handle is terminated best-effort (never leaked);
//   - a failed recreate degrades to a sticky diagnosable error, not a storm
//     of start attempts.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
)

// fix12FakeHandle is a testcontainers.Container handle stand-in that records
// whether the best-effort terminate ran (the old handle must never leak).
type fix12FakeHandle struct {
	terminated bool
}

func (f *fix12FakeHandle) Terminate(_ context.Context, _ ...testcontainers.TerminateOption) error {
	f.terminated = true
	return nil
}

// fix12DeadPool returns a real pool bound to a DSN with no listener: pinging
// it reproduces the audited `dial tcp ... connect: connection refused` chain.
func fix12DeadPool(t *testing.T, port string) *pgxpool.Pool {
	t.Helper()
	uri := fmt.Sprintf("postgres://yabanin:yabanin@127.0.0.1:%s/yabanin?sslmode=disable&connect_timeout=1", port)
	pool, err := pgxpool.New(context.Background(), uri)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

// fix12Reset clears the package-level stand state and seams, and restores
// everything at test end so the Docker-backed tests in this package are
// unaffected.
func fix12Reset(t *testing.T) {
	t.Helper()
	prevOnce, prevPool, prevURI := pgOnce, pgPool, pgContainerURI
	prevContainer, prevID, prevPort, prevStarted := pgContainer, pgContainerID, pgContainerPort, pgStartedAt
	prevInitErr, prevRegion, prevApp := pgInitErr, pgRegionPools, pgAppRolePools
	prevStart, prevProbe := pgStandStart, pgStandProbe
	t.Cleanup(func() {
		pgOnce, pgPool, pgContainerURI = prevOnce, prevPool, prevURI
		pgContainer, pgContainerID, pgContainerPort, pgStartedAt = prevContainer, prevID, prevPort, prevStarted
		pgInitErr, pgRegionPools, pgAppRolePools = prevInitErr, prevRegion, prevApp
		pgStandStart, pgStandProbe = prevStart, prevProbe
	})
	pgOnce = new(sync.Once)
	pgPool, pgContainerURI, pgInitErr = nil, "", nil
	pgContainer, pgContainerID, pgContainerPort, pgStartedAt = nil, "", "", time.Time{}
	pgRegionPools = map[string]*pgxpool.Pool{}
	pgAppRolePools = map[string]*pgxpool.Pool{}
	pgStandStart, pgStandProbe = pgStandStartReal, pgLiveness
}

// TestFix12ListenerDownClassification pins which ping failures mean "the
// listener is gone" (worth a recreate) versus "a live server rejected the
// probe" (never a recreate reason).
func TestFix12ListenerDownClassification(t *testing.T) {
	dialRefused := fmt.Errorf("failed to connect to `host=127.0.0.1 port=50906 database=yabanin`: %w",
		fmt.Errorf("dial error (127.0.0.1:50906): %w",
			&net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}))
	hostUnreachable := fmt.Errorf("wrapped: %w",
		&net.OpError{Op: "dial", Net: "tcp", Err: syscall.EHOSTUNREACH})
	require.True(t, listenerDown(dialRefused))
	require.True(t, listenerDown(hostUnreachable))

	// A live server answering with a startup race or a closed pooled
	// connection is NOT a dead listener: recreation cannot fix it.
	require.False(t, listenerDown(errors.New("FATAL: the database system is starting up (SQLSTATE 57P03)")))
	require.False(t, listenerDown(fmt.Errorf("ping: %w",
		&net.OpError{Op: "read", Net: "tcp", Err: errors.New("use of closed network connection")})))
	require.False(t, listenerDown(nil))
}

// TestFix12LivenessProbeRealDeadDSN drives the real bounded probe against a
// real pool whose DSN has no listener: every probe attempt must fail with the
// dial-refused chain and the final error must be classified as listener-down.
func TestFix12LivenessProbeRealDeadDSN(t *testing.T) {
	fix12Reset(t)
	dead := fix12DeadPool(t, "1")

	err := pgLiveness(dead)
	require.Error(t, err, "a dead DSN must never pass the liveness probe")
	require.True(t, listenerDown(err), "refused dials must classify as listener-down, got: %v", err)
	require.Contains(t, err.Error(), "connection refused")

	require.Error(t, pgLiveness(nil), "a missing pool must not pass as live")
}

// TestFix12DeadListenerRecreatesOnce is the H2 contract: the binary boots a
// stand that has already died (the audited poisoning scenario); the first
// Postgres() caller must observe the dead listener, recreate exactly once,
// and every later caller must reuse the recovered stand.
func TestFix12DeadListenerRecreatesOnce(t *testing.T) {
	fix12Reset(t)

	dead := fix12DeadPool(t, "1")
	healthy := fix12DeadPool(t, "2") // never probed for real; identity only
	deadHandle := &fix12FakeHandle{}
	freshHandle := &fix12FakeHandle{}

	starts := 0
	pgStandStart = func(tb testing.TB) (*pgStand, error) {
		tb.Helper()
		starts++
		switch starts {
		case 1:
			return &pgStand{ //nolint:gosec // G101: composite literal carries a dead-stand fixture URI, throwaway test creds
				pool:        dead,
				uri:         "postgres://yabanin:yabanin@127.0.0.1:50906/yabanin?sslmode=disable",
				containerID: "ctr-fix12-dead",
				port:        "50906",
				started:     time.Now().Add(-2 * time.Minute),
				container:   deadHandle,
			}, nil
		case 2:
			return &pgStand{ //nolint:gosec // G101: composite literal carries a dead-stand fixture URI, throwaway test creds
				pool:        healthy,
				uri:         "postgres://yabanin:yabanin@127.0.0.1:50907/yabanin?sslmode=disable",
				containerID: "ctr-fix12-fresh",
				port:        "50907",
				started:     time.Now(),
				container:   freshHandle,
			}, nil
		default:
			return nil, fmt.Errorf("unexpected stand start #%d (recreate must be bounded to one)", starts)
		}
	}
	pgStandProbe = func(pool *pgxpool.Pool) error {
		if pool == dead {
			return pgLiveness(dead) // real bounded probe on the real dead DSN
		}
		return nil
	}
	// Stale epoch leftovers: the recreate must invalidate dependent pools.
	pgRegionPools["eu"] = healthy
	pgAppRolePools["us"] = healthy

	pool := Postgres(t)
	require.Same(t, healthy, pool, "the recovered stand must be handed out")
	require.Equal(t, 2, starts, "boot + exactly one bounded recreate")
	require.True(t, deadHandle.terminated, "the dead container handle must be terminated (no leak)")
	require.False(t, freshHandle.terminated, "the fresh container must stay alive")
	require.Equal(t, "ctr-fix12-fresh", pgContainerID)
	require.Equal(t, "50907", pgContainerPort)
	require.Equal(t, "postgres://yabanin:yabanin@127.0.0.1:50907/yabanin?sslmode=disable", pgContainerURI)
	require.Empty(t, pgRegionPools, "region pools bound to the dead DSN must be invalidated")
	require.Empty(t, pgAppRolePools, "app-role pools bound to the dead DSN must be invalidated")
	require.NoError(t, pgInitErr)

	// Reuse when healthy: repeated callers never trigger another recreate.
	require.Same(t, healthy, Postgres(t))
	require.Same(t, healthy, Postgres(t))
	require.Equal(t, 2, starts)

	// Dependent paths rebuild from the recovered DSN.
	regionPool := PostgresRegion(t, "eu")
	require.NotNil(t, regionPool)
	require.NotSame(t, healthy, regionPool)
	require.NotSame(t, dead, regionPool)
	require.Same(t, regionPool, PostgresRegion(t, "eu"), "region pool cache must work again")
	appPool := PostgresApp(t, "eu")
	require.NotNil(t, appPool)
	require.Equal(t, 2, starts)
}

// TestFix12RecreateFailureStickyDiagnosable proves the failure half of the
// bound: when the single recreate attempt also fails, the caller gets one
// diagnosable error (dead container ID, port, lifetime, liveness cause,
// recreate cause, docker events hint) and no further start attempts.
func TestFix12RecreateFailureStickyDiagnosable(t *testing.T) {
	fix12Reset(t)

	dead := fix12DeadPool(t, "1")
	deadHandle := &fix12FakeHandle{}

	// Simulate a stand that booted fine and then died (Once consumed).
	pgOnce.Do(func() {})
	pgPool = dead
	pgContainerURI = "postgres://yabanin:yabanin@127.0.0.1:50906/yabanin?sslmode=disable" //nolint:gosec // G101: dead-stand fixture URI, throwaway test creds
	pgContainer = deadHandle
	pgContainerID = "ctr-fix12-dead"
	pgContainerPort = "50906"
	pgStartedAt = time.Now().Add(-2 * time.Minute)
	pgRegionPools["eu"] = dead

	starts := 0
	pgStandStart = func(tb testing.TB) (*pgStand, error) {
		tb.Helper()
		starts++
		return nil, fmt.Errorf("start disposable postgres (is Docker running?): docker daemon exploded")
	}
	pgStandProbe = func(pool *pgxpool.Pool) error { return pgLiveness(dead) }

	pool, uri, err := ensurePostgres(t)
	require.Error(t, err)
	require.Nil(t, pool)
	require.Empty(t, uri)
	require.Equal(t, 1, starts, "the recreate must be attempted exactly once")
	require.True(t, deadHandle.terminated, "the dead handle must still be retired (no leak)")
	require.Empty(t, pgRegionPools)

	for _, want := range []string{
		"ctr-fix12-dead",         // dead container ID
		"50906",                  // dead mapped port
		"connection refused",     // original liveness error (real dead DSN)
		"docker daemon exploded", // recreate cause
		"docker events",          // diagnosability hint
	} {
		require.Contains(t, err.Error(), want, "recreate error must be diagnosable")
	}

	// Sticky degradation: further callers fail fast with the same diagnosis
	// instead of hammering Docker with start attempts.
	_, _, errAgain := ensurePostgres(t)
	require.Error(t, errAgain)
	require.Equal(t, 1, starts)
}

// TestFix12ConcurrentEnsureRecreatesOnce is the race-safety contract: many
// parallel Postgres() callers hitting a freshly dead stand must produce
// exactly one recreate, one terminated dead handle, and one shared healthy
// pool — under -race.
func TestFix12ConcurrentEnsureRecreatesOnce(t *testing.T) {
	fix12Reset(t)

	dead := fix12DeadPool(t, "1")
	healthy := fix12DeadPool(t, "2")
	deadHandle := &fix12FakeHandle{}

	starts := 0
	pgStandStart = func(tb testing.TB) (*pgStand, error) {
		tb.Helper()
		starts++
		if starts == 1 {
			return &pgStand{pool: dead, uri: "postgres://127.0.0.1:50906/yabanin", container: deadHandle}, nil
		}
		return &pgStand{pool: healthy, uri: "postgres://127.0.0.1:50907/yabanin"}, nil
	}
	pgStandProbe = func(pool *pgxpool.Pool) error {
		if pool == dead {
			return pgLiveness(dead)
		}
		return nil
	}

	// Goroutine-safe caller path: the fatal require lives in Postgres, so the
	// spawned callers use ensurePostgres directly and surface errors to the
	// test goroutine (require/assert must not run on spawned goroutines).
	// requireDocker is hoisted so its Skip can only fire on the test goroutine.
	requireDocker(t)
	const callers = 8
	results := make([]*pgxpool.Pool, callers)
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pool, _, err := ensurePostgres(t)
			results[i], errs[i] = pool, err
		}(i)
	}
	wg.Wait()

	for i, pool := range results {
		require.NoError(t, errs[i], "caller %d ensure failed", i)
		require.Same(t, healthy, pool, "caller %d must see the recovered stand", i)
	}
	require.Equal(t, 2, starts, "boot + exactly one recreate under concurrency")
	require.True(t, deadHandle.terminated)
}
