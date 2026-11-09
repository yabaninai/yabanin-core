// Package testdb provides disposable Docker-backed test stands (QG2-B3,
// owner decision 2026-09-13: Docker is REQUIRED for the tests gate).
//
// Postgres starts a real container per test binary, applies the production
// migration set from migrations/*.up.sql in filename order, and returns a
// connected pool. Redis starts a real redis container. Containers are
// managed by the testcontainers reaper and terminate when the test binary
// exits; a per-binary singleton keeps startup cost at one container per
// package. FIX-12: both stands' liveness is re-checked on every helper use —
// a stand killed mid-binary (e.g. a Docker VM restart under parallel churn)
// is recreated once with diagnosable errors instead of poisoning the rest of
// the binary with connection refused.
//
// Tests skip only under -short (the fast loop stays Dockerless); outside
// -short a missing Docker is a hard failure — a red gate must mean broken
// code, not a missing stand.
package testdb

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/regionrouter"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	testpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	testredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

func requireDocker(tb testing.TB) {
	tb.Helper()
	if testing.Short() {
		tb.Skip("disposable stands are skipped in -short mode (fast loop stays Dockerless)")
	}
}

// repoRoot walks up from the working directory to the directory holding go.mod.
func repoRoot(tb testing.TB) string {
	tb.Helper()
	dir, err := os.Getwd()
	require.NoError(tb, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			tb.Fatal("go.mod not found while walking up from the working directory")
		}
		dir = parent
	}
}

// applyMigrations executes every migrations/*.up.sql in filename order on
// the pool — the same set a real deployment applies (single simple-query
// round trip per file, no parameters). Afterwards it replays the
// deploy-layer app-role bootstrap: the consolidated pg_dump-based baseline
// cannot carry cluster roles (pg_dump never emits them), so the yabanin_app
// role the RLS pools assume is provisioned here exactly as the deployment
// layer does (NOLOGIN least-privilege + application-surface grants; LOGIN
// and the password stay a deploy-layer concern the stands never need).
func applyMigrations(tb testing.TB, pool *pgxpool.Pool) {
	tb.Helper()
	root := repoRoot(tb)
	paths, err := filepath.Glob(filepath.Join(root, "migrations", "*.up.sql"))
	require.NoError(tb, err)
	require.NotEmpty(tb, paths, "no up-migrations discovered")
	sort.Strings(paths)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for _, p := range paths {
		sqlBytes, err := os.ReadFile(p) //nolint:gosec // G304: repo-relative migration fixture
		require.NoError(tb, err, "read %s", p)
		_, err = pool.Exec(ctx, string(sqlBytes))
		require.NoError(tb, err, "apply %s", p)
	}
	const bootstrap = `DO $$ BEGIN
		IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'yabanin_app') THEN
			CREATE ROLE yabanin_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
		END IF;
	END $$;
	GRANT USAGE ON SCHEMA public TO yabanin_app;
	GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO yabanin_app;
	GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO yabanin_app;
	ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO yabanin_app;
	ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO yabanin_app;`
	_, err = pool.Exec(ctx, bootstrap)
	require.NoError(tb, err, "bootstrap yabanin_app role")
}

// waitStablePostmaster blocks until the server's postmaster start time reads
// the same on two polls 2s apart (or the deadline passes): the pgvector image
// entrypoint restarts the cluster once after first-boot setup, and anything
// applied before that restart is wiped by the re-initialization.
func waitStablePostmaster(ctx context.Context, pool *pgxpool.Pool) error {
	return waitStablePostmasterQ(ctx, pool, 2*time.Second, time.Now().Add(90*time.Second))
}

// postmasterQuerier is the read surface of a pgx pool (satisfied by
// *pgxpool.Pool); an interface so the restart-wait logic is unit-testable.
type postmasterQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// postmasterStable decides whether two consecutive start-time polls agree: a
// non-zero start time that repeats across the settle window means the server
// survived without a first-boot re-initialization restart.
func postmasterStable(last time.Time, haveLast bool, cur time.Time) bool {
	return haveLast && cur.Equal(last)
}

// waitStablePostmasterQ blocks until the server's postmaster start time reads
// the same on two polls `settle` apart (or the deadline passes): the pgvector
// image entrypoint restarts the cluster once after first-boot setup, and
// anything applied before that restart is wiped by the re-initialization.
func waitStablePostmasterQ(ctx context.Context, q postmasterQuerier, settle time.Duration, deadline time.Time) error {
	var last time.Time
	haveLast := false
	for {
		var cur time.Time
		err := q.QueryRow(ctx, "SELECT pg_postmaster_start_time()").Scan(&cur)
		switch {
		case err != nil:
			// Server restarting — keep waiting for it to come back.
		case postmasterStable(last, haveLast, cur):
			return nil
		default:
			last, haveLast = cur, true
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("disposable postgres start time never stabilized: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(settle):
		}
	}
}

// coreTablesPresent reports whether the migration pass visibly landed: a
// first-boot restart racing the migrations wipes the data directory, so at
// least one product table must exist before the pool is handed to tests.
func coreTablesPresent(ctx context.Context, pool *pgxpool.Pool) bool {
	return coreTablesPresentQ(ctx, pool)
}

// coreTablesPresentQ is the testable read of coreTablesPresent.
func coreTablesPresentQ(ctx context.Context, q postmasterQuerier) bool {
	var n int
	err := q.QueryRow(ctx,
		"SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name IN ('organizations','request_logs')",
	).Scan(&n)
	return err == nil && n == 2
}

// Shared per-binary Postgres stand state. pgInitErr is sticky only for a
// failed boot or a failed bounded recreate (FIX-12); a stand that dies after
// a successful boot is detected per use and recreated once instead of
// poisoning every later caller through the sync.Once cache.
var (
	pgOnce         = new(sync.Once) // pointer: the Fix12 unit tests swap/restore it without copying a lock
	pgPool         *pgxpool.Pool
	pgContainerURI string
	pgInitErr      error

	pgContainer     pgContainerHandle
	pgContainerID   string
	pgContainerPort string
	pgStartedAt     time.Time

	pgMu           sync.Mutex
	pgRegionPools  = map[string]*pgxpool.Pool{}
	pgAppRolePools = map[string]*pgxpool.Pool{}
)

// pgContainerHandle is the subset of testcontainers.Container the stand
// retains for best-effort cleanup (satisfied by the real PostgresContainer).
type pgContainerHandle interface {
	Terminate(ctx context.Context, opts ...testcontainers.TerminateOption) error
}

// pgStand bundles the live handles of one disposable Postgres stand.
type pgStand struct {
	pool        *pgxpool.Pool
	uri         string
	containerID string
	port        string
	started     time.Time
	container   pgContainerHandle
}

// Stand lifecycle seams: package variables so fix12_liveness_test.go can
// inject a dead-then-recovered stand without Docker. Production behavior is
// the default implementation assigned here.
var (
	pgStandStart = pgStandStartReal // boot a fresh migrated stand
	pgStandProbe = pgLiveness       // per-use liveness re-check
)

// Bounded liveness probe: a few short pings with backoff so a single dropped
// packet during Docker churn cannot trigger a recreate, while a genuinely
// dead listener is confirmed within ~1s. Shared by both stands (Postgres
// pgxpool pings and Redis client pings return the same dial-class error
// chains on a dead listener).
const (
	standProbeAttempts = 3
	standProbeTimeout  = 2 * time.Second
	standProbeBackoff  = 250 * time.Millisecond
)

// listenerDown reports whether a ping failure means a stand's listener
// itself is unreachable (container/proxy killed — e.g. a Docker VM death
// under parallel churn), as opposed to a live server rejecting the probe.
// Only listener-class failures may justify recreating a stand. Shared by the
// Postgres and Redis probes: both dialers surface the same *net.OpError /
// errno chains on a dead listener.
func listenerDown(err error) bool {
	if err == nil {
		return false
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return true
	}
	return errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH)
}

// pgLiveness confirms the shared stand still answers before it is handed to
// another test (FIX-12): the audited failure mode had one transient Docker VM
// kill leave the sync.Once cache serving a dead DSN for the rest of the test
// binary. Bounded: ping, retry with backoff. Returns nil when the stand is
// usable; a non-nil result is the confirmed listener-down evidence for the
// recreate diagnosis. A live server that rejects probes app-level (auth,
// startup race, closed pooled connection twice in a row) is handed out
// as-is — recreation cannot fix it, and the test's own error stays the
// diagnosable one.
func pgLiveness(pool *pgxpool.Pool) error {
	if pool == nil {
		return errors.New("no disposable postgres pool is live")
	}
	var last error
	nonListener := 0
	for attempt := 0; attempt < standProbeAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), standProbeTimeout)
		last = pool.Ping(ctx)
		cancel()
		switch {
		case last == nil:
			return nil
		case listenerDown(last):
			// A pooled connection that died mid-ping fails with a read
			// error before any fresh dial gets refused; keep probing so a
			// new dial confirms the listener state.
		default:
			nonListener++
			if nonListener >= 2 {
				return nil // live server, repeated app-level rejection
			}
		}
		if attempt+1 < standProbeAttempts {
			time.Sleep(standProbeBackoff)
		}
	}
	return last
}

// pgStandStartReal boots a fresh disposable Postgres container, waits out the
// pgvector first-boot restart, applies the production migration set and hands
// back the live stand. Partial handles are released on every failure path.
func pgStandStartReal(tb testing.TB) (*pgStand, error) {
	tb.Helper()
	ctx := context.Background()
	container, err := testpostgres.Run(ctx, "pgvector/pgvector:pg16",
		testpostgres.WithDatabase("yabanin"),
		testpostgres.WithUsername("yabanin"),
		testpostgres.WithPassword("yabanin"),
	)
	if err != nil {
		return nil, fmt.Errorf("start disposable postgres (is Docker running?): %w", err)
	}
	stand := &pgStand{container: container, started: time.Now()}
	fail := func(err error) (*pgStand, error) {
		tctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		_ = container.Terminate(tctx) // best-effort: the session reaper also reaps orphans
		cancel()
		return nil, err
	}
	uri, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		return fail(err)
	}
	stand.uri = uri
	if u, perr := url.Parse(uri); perr == nil {
		stand.containerID = container.GetContainerID()
		stand.port = u.Port()
	}
	pool, err := pgxpool.New(ctx, uri)
	if err != nil {
		return fail(err)
	}
	stand.pool = pool
	// The image entrypoint restarts the server between first-boot setup
	// and the real start; wait out that window, then migrate — the same
	// set a real deployment applies — before any test sees the pool.
	deadline := time.Now().Add(60 * time.Second)
	for {
		pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		err = pool.Ping(pingCtx)
		cancel()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			pool.Close()
			return fail(fmt.Errorf("disposable postgres never became ready: %w", err))
		}
		time.Sleep(500 * time.Millisecond)
	}
	// A successful Ping can still land in the FIRST-boot server: the
	// entrypoint then restarts the whole cluster and re-initializes the
	// data directory, wiping anything applied in the meantime. Under
	// heavy parallel container churn that window widens enough to swallow
	// the migration pass, so require the postmaster start time to be
	// stable across a settle window before migrating.
	if err := waitStablePostmaster(ctx, pool); err != nil {
		pool.Close()
		return fail(err)
	}
	applyMigrations(tb, pool)
	// Belt and braces: if the restart raced the migration pass, the core
	// table is gone — wait out the restart and apply migrations again.
	if !coreTablesPresent(ctx, pool) {
		if err := waitStablePostmaster(ctx, pool); err != nil {
			pool.Close()
			return fail(err)
		}
		applyMigrations(tb, pool)
		if !coreTablesPresent(ctx, pool) {
			pool.Close()
			return fail(errors.New("migrations did not survive the postgres first-boot restart"))
		}
	}
	return stand, nil
}

// ensurePostgres returns the shared per-binary stand's pool and DSN. FIX-12:
// before handing the stand out, its liveness is re-checked; a confirmed dead
// listener (container/proxy killed mid-binary) triggers exactly one bounded
// recreate instead of poisoning every later caller through the sync.Once
// cache. A non-nil error is terminal for the binary's stand (failed boot, or
// the single recreate attempt also failed) and is fully diagnosable.
func ensurePostgres(tb testing.TB) (*pgxpool.Pool, string, error) {
	tb.Helper()
	requireDocker(tb)
	pgOnce.Do(func() {
		stand, err := pgStandStart(tb)
		if err != nil {
			pgInitErr = err
			return
		}
		pgAdopt(stand)
	})
	pgMu.Lock()
	defer pgMu.Unlock()
	if pgInitErr != nil {
		return nil, "", pgInitErr
	}
	if err := pgStandProbe(pgPool); err != nil {
		pgRecreateLocked(tb, err)
		if pgInitErr != nil {
			return nil, "", pgInitErr
		}
	}
	return pgPool, pgContainerURI, nil
}

// pgAdopt installs a freshly started stand as the shared one. The boot path
// only ever runs inside pgOnce.Do, so every later caller observes it via the
// Once happens-before edge; the recreate path calls it under pgMu.
func pgAdopt(stand *pgStand) {
	pgPool = stand.pool
	pgContainerURI = stand.uri
	pgContainer = stand.container
	pgContainerID = stand.containerID
	pgContainerPort = stand.port
	pgStartedAt = stand.started
}

// pgRecreateLocked retires a confirmed-dead stand and starts exactly one
// replacement: pools bound to the dead DSN are dropped (the region/app-role
// caches point at the dead mapped port), the old container is terminated
// best-effort so the handle never leaks, and on success the fresh stand
// replaces the globals. A failed start degrades to a sticky diagnosable
// pgInitErr — one recreate per detection, no Docker start storm.
// Recreate-once is per death-episode: a stand that dies again later gets its own single bounded recreate (this is not the binary-wide pgOnce).
// Caller holds pgMu.
func pgRecreateLocked(tb testing.TB, probeErr error) {
	tb.Helper()
	deadID, deadPort, deadUp := pgContainerID, pgContainerPort, time.Since(pgStartedAt)
	if pgPool != nil {
		pgPool.Close()
		pgPool = nil
	}
	// Close every cached pool best-effort (nil-guarded, like pgPool above); a dropped-open *pgxpool.Pool leaks background goroutines.
	for _, pool := range pgRegionPools {
		if pool != nil {
			pool.Close()
		}
	}
	pgRegionPools = map[string]*pgxpool.Pool{}
	for _, pool := range pgAppRolePools {
		if pool != nil {
			pool.Close()
		}
	}
	pgAppRolePools = map[string]*pgxpool.Pool{}
	if pgContainer != nil {
		tctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_ = pgContainer.Terminate(tctx) // best-effort: the session reaper also reaps orphans
		cancel()
	}
	stand, err := pgStandStart(tb)
	if err != nil {
		pgInitErr = fmt.Errorf(
			"disposable postgres died (container %s, port %s, up %s; liveness probe: %v) "+
				"and the bounded single recreate failed: %w "+
				"— inspect `docker ps -a` / `docker events` for the kill cause",
			deadID, deadPort, deadUp.Round(time.Second), probeErr, err)
		return
	}
	pgInitErr = nil
	pgAdopt(stand)
}

// Postgres returns a pool bound to a disposable, fully migrated Postgres
// container (one per test binary). Requires Docker outside -short mode.
// FIX-12: the stand's liveness is re-checked per use — a stand killed
// mid-binary (Docker VM restart under parallel churn) is recreated once with
// diagnosable errors instead of poisoning the rest of the test binary with
// connection refused.
func Postgres(tb testing.TB) *pgxpool.Pool {
	tb.Helper()
	pool, _, err := ensurePostgres(tb)
	require.NoError(tb, err)
	return pool
}

// PostgresRegion returns a pool to the same disposable, fully migrated
// Postgres container as Postgres, but with the app.region GUC set on every
// pooled connection via the regionrouter.AfterConnectRegion hook.
//
// Tables whose home_region column defaults to current_setting('app.region',
// true) (request_logs, sessions, messages) resolve to the given region on
// insert, matching a real region deployment. Without this, a plain DSN
// insert hits the home_region NOT NULL constraint (SQLSTATE 23502). One
// region-scoped pool is cached per region; the container is shared.
//
// Deliberately region-GUC only (no SET ROLE): the login is the container
// superuser, which bypasses RLS even under FORCE, so existing suites may
// seed cross-region fixtures. Suites that need the real application posture
// use PostgresApp.
func PostgresRegion(tb testing.TB, region string) *pgxpool.Pool {
	tb.Helper()
	require.NoError(tb, regionrouter.ValidateRegion(region))
	_, uri, err := ensurePostgres(tb) // per-use liveness check, recreate-once on a dead listener
	require.NoError(tb, err)
	pgMu.Lock()
	defer pgMu.Unlock()
	// Known-benign uri TOCTOU: a recreate between the two locks can only hand out the dead stand's DSN — such a pool then fails connections exactly like the death it raced.
	if pool, ok := pgRegionPools[region]; ok {
		return pool
	}
	// pgxpool.ParseConfig (not pgx.ParseConfig + manual wrap) so the config
	// carries the flag pgxpool.NewWithConfig requires in pgx v5.10.
	pc, err := pgxpool.ParseConfig(uri)
	if err != nil {
		require.NoError(tb, err)
	}
	pc.AfterConnect = regionrouter.AfterConnectRegion(region)
	pool, err := pgxpool.NewWithConfig(context.Background(), pc)
	if err != nil {
		require.NoError(tb, err)
	}
	pgRegionPools[region] = pool
	return pool
}

// PostgresApp returns a pool to the same disposable, fully migrated Postgres
// container as Postgres, wired exactly like a production regional pool:
// regionrouter.ConfigurePool downgrades every connection to the non-owner
// yabanin_app role (SET ROLE; the role itself is bootstrapped by
// applyMigrations, mirroring deploy/quickstart/bootstrap-app-role.sql —
// migrations never create cluster roles) and binds the app.region GUC,
// so region RLS applies to every statement — foreign-region rows are hidden
// and cross-region writes rejected. One pool is cached per region; the
// container is shared.
func PostgresApp(tb testing.TB, region string) *pgxpool.Pool {
	tb.Helper()
	require.NoError(tb, regionrouter.ValidateRegion(region))
	_, uri, err := ensurePostgres(tb) // per-use liveness check, recreate-once on a dead listener
	require.NoError(tb, err)
	pgMu.Lock()
	defer pgMu.Unlock()
	if pool, ok := pgAppRolePools[region]; ok {
		return pool
	}
	// pgxpool.ParseConfig (not pgx.ParseConfig + manual wrap) so the config
	// carries the flag pgxpool.NewWithConfig requires in pgx v5.10.
	pc, err := pgxpool.ParseConfig(uri)
	if err != nil {
		require.NoError(tb, err)
	}
	if err := regionrouter.ConfigurePool(pc, region); err != nil {
		require.NoError(tb, err)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), pc)
	if err != nil {
		require.NoError(tb, err)
	}
	pgAppRolePools[region] = pool
	return pool
}

// Shared per-binary Redis stand state (FIX-12 lifecycle parity with the
// Postgres stand). redisInitErr is sticky only for a failed boot or a failed
// bounded recreate; a stand that dies after a successful boot is detected
// per use and recreated once instead of poisoning every later caller through
// the sync.Once cache.
var (
	redisOnce          = new(sync.Once) // pointer: the Fix12 unit tests swap/restore it without copying a lock
	redisClient        *redis.Client
	redisInitErr       error
	redisStandStart    = redisStandStartReal // seam: boot a fresh stand (Fix12 tests inject fakes)
	redisStandProbe    = redisLiveness       // seam: per-use liveness re-check
	redisMu            sync.Mutex
	redisContainer     redisContainerHandle
	redisContainerID   string
	redisContainerPort string
	redisStartedAt     time.Time
)

// redisContainerHandle is the subset of testcontainers.Container the Redis
// stand retains for best-effort cleanup (satisfied by the real RedisContainer).
type redisContainerHandle interface {
	Terminate(ctx context.Context, opts ...testcontainers.TerminateOption) error
}

// redisStand bundles the live handles of one disposable Redis stand.
type redisStand struct {
	client      *redis.Client
	containerID string
	port        string
	started     time.Time
	container   redisContainerHandle
}

// redisLiveness confirms the shared Redis stand still answers before it is
// handed to another test (FIX-12): the audited poisoning scenario applied to
// this stand verbatim — one transient Docker VM kill left the sync.Once cache
// serving a dead client for the rest of the test binary. Bounded: ping,
// retry with backoff, only dial-class failures justify a recreate (the same
// listenerDown classification the Postgres stand uses). A live server that
// rejects pings app-level twice in a row is handed out as-is — recreation
// cannot fix it, and the consumer's own error stays the diagnosable one.
func redisLiveness(client *redis.Client) error {
	if client == nil {
		return errors.New("no disposable redis client is live")
	}
	var last error
	nonListener := 0
	for attempt := 0; attempt < standProbeAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), standProbeTimeout)
		last = client.Ping(ctx).Err()
		cancel()
		switch {
		case last == nil:
			return nil
		case listenerDown(last):
			// Keep probing: a pooled connection killed mid-ping surfaces a
			// read/close error before a fresh dial can confirm the listener
			// state.
		default:
			nonListener++
			if nonListener >= 2 {
				return nil // live server, repeated app-level rejection
			}
		}
		if attempt+1 < standProbeAttempts {
			time.Sleep(standProbeBackoff)
		}
	}
	return last
}

// redisStandStartReal boots a fresh disposable Redis container and hands back
// the live stand. Partial handles are released on every failure path.
func redisStandStartReal(tb testing.TB) (*redisStand, error) {
	tb.Helper()
	ctx := context.Background()
	container, err := testredis.Run(ctx, "redis:7-alpine")
	if err != nil {
		return nil, fmt.Errorf("start disposable redis (is Docker running?): %w", err)
	}
	stand := &redisStand{container: container, started: time.Now()}
	fail := func(err error) (*redisStand, error) {
		tctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		_ = container.Terminate(tctx) // best-effort: the session reaper also reaps orphans
		cancel()
		return nil, err
	}
	uri, err := container.ConnectionString(ctx)
	if err != nil {
		return fail(err)
	}
	if u, perr := url.Parse(uri); perr == nil {
		stand.containerID = container.GetContainerID()
		stand.port = u.Port()
	}
	opt, err := redis.ParseURL(uri)
	if err != nil {
		return fail(err)
	}
	client := redis.NewClient(opt)
	stand.client = client
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		_ = client.Close() // best-effort: the ping error is the actionable failure
		return fail(fmt.Errorf("disposable redis not reachable: %w", err))
	}
	return stand, nil
}

// ensureRedis returns the shared per-binary stand's client. FIX-12: before
// handing the stand out, its liveness is re-checked; a confirmed dead
// listener (container/proxy killed mid-binary) triggers exactly one bounded
// recreate instead of poisoning every later caller through the sync.Once
// cache. A non-nil error is terminal for the binary's stand (failed boot, or
// the single recreate attempt also failed) and is fully diagnosable.
func ensureRedis(tb testing.TB) (*redis.Client, error) {
	tb.Helper()
	requireDocker(tb)
	redisOnce.Do(func() {
		stand, err := redisStandStart(tb)
		if err != nil {
			redisInitErr = err
			return
		}
		redisAdopt(stand)
	})
	redisMu.Lock()
	defer redisMu.Unlock()
	if redisInitErr != nil {
		return nil, redisInitErr
	}
	if err := redisStandProbe(redisClient); err != nil {
		redisRecreateLocked(tb, err)
		if redisInitErr != nil {
			return nil, redisInitErr
		}
	}
	return redisClient, nil
}

// redisAdopt installs a freshly started stand as the shared one. The boot
// path only ever runs inside redisOnce.Do, so every later caller observes it
// via the Once happens-before edge; the recreate path calls it under redisMu.
func redisAdopt(stand *redisStand) {
	redisClient = stand.client
	redisContainer = stand.container
	redisContainerID = stand.containerID
	redisContainerPort = stand.port
	redisStartedAt = stand.started
}

// redisRecreateLocked retires a confirmed-dead stand and starts exactly one
// replacement: the dead client is closed (a dropped-open *redis.Client leaks
// its background goroutines), the old container is terminated best-effort so
// the handle never leaks, and on success the fresh stand replaces the
// globals — freeing ONLY this stand's own resources, never a foreign
// container. A failed start degrades to a sticky diagnosable redisInitErr —
// one recreate per detection, no Docker start storm. Recreate-once is per
// death-episode: a stand that dies again later gets its own single bounded
// recreate (this is not the binary-wide redisOnce).
// Caller holds redisMu.
func redisRecreateLocked(tb testing.TB, probeErr error) {
	tb.Helper()
	deadID, deadPort, deadUp := redisContainerID, redisContainerPort, time.Since(redisStartedAt)
	if redisClient != nil {
		_ = redisClient.Close()
		redisClient = nil
	}
	if redisContainer != nil {
		tctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_ = redisContainer.Terminate(tctx) // best-effort: the session reaper also reaps orphans
		cancel()
	}
	stand, err := redisStandStart(tb)
	if err != nil {
		redisInitErr = fmt.Errorf(
			"disposable redis died (container %s, port %s, up %s; liveness probe: %v) "+
				"and the bounded single recreate failed: %w "+
				"— inspect `docker ps -a` / `docker events` for the kill cause",
			deadID, deadPort, deadUp.Round(time.Second), probeErr, err)
		return
	}
	redisInitErr = nil
	redisAdopt(stand)
}

// Redis returns a client bound to a disposable Redis container (one per test
// binary). Requires Docker outside -short mode.
// FIX-12: the stand's liveness is re-checked per use — a stand killed
// mid-binary (Docker VM restart under parallel churn) is recreated once with
// diagnosable errors instead of poisoning the rest of the test binary with
// connection refused.
func Redis(tb testing.TB) *redis.Client {
	tb.Helper()
	client, err := ensureRedis(tb)
	require.NoError(tb, err)
	return client
}

// FlushDB clears the disposable Redis (helpers may expose it for cleanliness
// between tests sharing the binary-wide container).
func FlushDB(tb testing.TB, c *redis.Client) {
	tb.Helper()
	require.NoError(tb, c.FlushDB(context.Background()).Err())
}

// WaitClockCaughtUp blocks (bounded) until the DATABASE clock is not ahead of
// the HOST clock. Report windows are computed from host time.Now() while row
// created_at values come from the DB clock; under load the Docker-Desktop VM
// clock can drift ahead of the host, silently excluding freshly seeded rows
// from BETWEEN windows (the W-VER 7-vs-0/4/6 report-flake family).
func WaitClockCaughtUp(tb testing.TB, pool *pgxpool.Pool) {
	tb.Helper()
	ctx := context.Background()
	for i := 0; i < 100; i++ {
		var dbNow time.Time
		if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&dbNow); err != nil {
			tb.Fatalf("clock catch-up probe: %v", err)
		}
		if !dbNow.After(time.Now()) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	tb.Log("testdb: DB clock stayed ahead of the host clock for 10s; proceeding (windows may still exclude the newest rows)")
}
