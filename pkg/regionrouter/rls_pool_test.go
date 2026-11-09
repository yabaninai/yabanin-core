package regionrouter

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/sovereign"
	testpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	testredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

// requireDockerRegional mirrors pkg/testdb.requireDocker (cannot import the
// package: testdb imports regionrouter). Outside -short a missing Docker is
// a hard failure — a red gate must mean broken code, not a missing stand.
func requireDockerRegional(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("docker-backed regional pools are skipped in -short mode")
	}
}

// applyRegionalMigrations prepares the container with the schema the RLS
// pool wiring depends on. Since the 2026-10-04 consolidation the historical
// chain (0001 tables, 0006 rollups, 0022 FORCE RLS + policies) ships inside
// the single 0001_init baseline. The yabanin_app role is deploy-layer
// bootstrap (pg_dump does not emit cluster roles, so the baseline does not
// carry it): the stand replays that step with the same NOLOGIN/NOBYPASSRLS
// posture the deployment provisions.
func applyRegionalMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	for _, name := range []string{
		"0001_init.up.sql",
	} {
		sqlBytes, err := os.ReadFile(filepath.Join("..", "..", "migrations", name)) //nolint:gosec // G304: repo-relative migration fixture
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		execCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		_, err = pool.Exec(execCtx, string(sqlBytes))
		cancel()
		if err != nil {
			return fmt.Errorf("apply %s: %w", name, err)
		}
	}
	// Deploy-layer role bootstrap: the historical 0022 migration created the
	// yabanin_app role and granted it the application surface, but pg_dump
	// does not emit cluster roles, so the consolidated baseline does not
	// carry them. This is the same SQL 0022 ran, replayed as the deploy
	// layer would: NOLOGIN (deploy adds LOGIN and the password out-of-band;
	// SET ROLE from the superuser session does not need LOGIN), never
	// BYPASSRLS, DML across public but no DDL and no ownership.
	bootstrap := `DO $$ BEGIN
		IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'yabanin_app') THEN
			CREATE ROLE yabanin_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
		END IF;
	END $$;
	GRANT USAGE ON SCHEMA public TO yabanin_app;
	GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO yabanin_app;
	GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO yabanin_app;
	ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO yabanin_app;
	ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO yabanin_app;
	GRANT yabanin_app TO CURRENT_USER;`
	execCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	_, err := pool.Exec(execCtx, bootstrap)
	cancel()
	if err != nil {
		return fmt.Errorf("bootstrap app role: %w", err)
	}
	return nil
}

// Regional stand singletons (one postgres + one redis per test binary, like
// pkg/testdb; the testcontainers reaper terminates them at binary exit).
var (
	standOnce   sync.Once
	standPool   *pgxpool.Pool
	standURI    string
	standErr    error
	redisOnce   sync.Once
	redisClient *redis.Client
	redisErr    error
)

// startRegionalPostgres returns the shared disposable postgres with the
// RLS-relevant migration subset applied. Waits out the pgvector image's
// first-boot restart (same guard as pkg/testdb) before migrating: a ping can
// land in the FIRST-boot server whose restart then wipes the data directory.
func startRegionalPostgres(t *testing.T) (adminURI string, admin *pgxpool.Pool) {
	t.Helper()
	requireDockerRegional(t)
	standOnce.Do(func() {
		ctx := context.Background()
		container, err := testpostgres.Run(ctx, "pgvector/pgvector:pg16",
			testpostgres.WithDatabase("regionrouter"),
			testpostgres.WithUsername("postgres"),
			testpostgres.WithPassword("postgres"),
		)
		if err != nil {
			standErr = fmt.Errorf("start disposable postgres (is Docker running?): %w", err)
			return
		}
		host, err := container.Host(ctx)
		if err != nil {
			standErr = fmt.Errorf("postgres host: %w", err)
			return
		}
		port, err := container.MappedPort(ctx, "5432")
		if err != nil {
			standErr = fmt.Errorf("postgres port: %w", err)
			return
		}
		standURI = fmt.Sprintf("postgres://postgres:postgres@%s:%s/regionrouter?sslmode=disable", host, port.Port())
		pool, err := pgxpool.New(ctx, standURI)
		if err != nil {
			standErr = fmt.Errorf("connect disposable postgres: %w", err)
			return
		}
		if err := waitReadyAndStable(ctx, pool); err != nil {
			standErr = err
			pool.Close()
			return
		}
		if err := applyRegionalMigrations(ctx, pool); err != nil {
			standErr = err
			pool.Close()
			return
		}
		standPool = pool
	})
	if standErr != nil {
		t.Fatalf("regional postgres stand: %v", standErr)
	}
	return standURI, standPool
}

// waitReadyAndStable pings until the server accepts connections and its
// postmaster start time stops changing across a settle window — anything
// applied before that restart is wiped by the re-initialization.
func waitReadyAndStable(ctx context.Context, pool *pgxpool.Pool) error {
	deadline := time.Now().Add(90 * time.Second)
	for {
		pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := pool.Ping(pingCtx)
		cancel()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("disposable postgres never became ready: %w", err)
		}
		time.Sleep(500 * time.Millisecond)
	}
	var last time.Time
	haveLast := false
	for {
		var cur time.Time
		err := pool.QueryRow(ctx, "SELECT pg_postmaster_start_time()").Scan(&cur)
		if err == nil && haveLast && cur.Equal(last) {
			return nil
		}
		if err == nil {
			last, haveLast = cur, true
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("disposable postgres start time never stabilized: %w", err)
		}
		time.Sleep(2 * time.Second)
	}
}

// TestConfigurePool_AppRoleAndRegionScoping proves the production pool wiring
// end to end: every pooled connection lands on the non-owner yabanin_app role
// with the app.region GUC bound, and the region RLS policies bind (a
// foreign-region INSERT is rejected by WITH CHECK).
func TestConfigurePool_AppRoleAndRegionScoping(t *testing.T) {
	_, admin := startRegionalPostgres(t)
	ctx := context.Background()

	_, err := admin.Exec(ctx, `INSERT INTO request_logs
		(model_requested, model_used, status_code, duration_ms, tokens_in, tokens_out, method, home_region)
		VALUES ('m', 'm', 200, 0, 0, 0, 'POST', 'eu')`)
	if err != nil {
		t.Fatalf("seed eu row as superuser: %v", err)
	}

	cfg, err := pgxpool.ParseConfig(admin.Config().ConnString())
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if err := ConfigurePool(cfg, "eu"); err != nil {
		t.Fatalf("ConfigurePool: %v", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("new pool: %v", err)
	}
	defer pool.Close()

	var role, region string
	if err := pool.QueryRow(ctx, "SELECT current_user, current_setting('app.region')").Scan(&role, &region); err != nil {
		t.Fatalf("identity query through pool: %v", err)
	}
	if role != AppRole {
		t.Fatalf("expected connections as %q, got %q", AppRole, role)
	}
	if region != "eu" {
		t.Fatalf("expected app.region=eu, got %q", region)
	}

	// The RLS policies bind the downgraded role: only the eu row is visible.
	var n int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM request_logs").Scan(&n); err != nil {
		t.Fatalf("count through app role: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 visible row for eu, got %d", n)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO request_logs
		(model_requested, model_used, status_code, home_region) VALUES ('m', 'm', 200, 'us')`); err == nil {
		t.Fatal("foreign-region INSERT must be rejected by WITH CHECK")
	}
}

// TestConfigurePool_FailsClosedWithoutRole proves the pool refuses to serve
// when the login cannot assume the app role — the role is not provisioned
// (deploy bootstrap not run) or the login is not a member and not a
// superuser. Roles are cluster-wide, so the proof uses a bare
// membership-less login on a database without grants: SET ROLE must be
// denied and the pool fails.
func TestConfigurePool_FailsClosedWithoutRole(t *testing.T) {
	adminURI, admin := startRegionalPostgres(t)
	ctx := context.Background()

	var roleCount int
	if err := admin.QueryRow(ctx,
		"SELECT count(*) FROM pg_roles WHERE rolname = 'rls_plain'").Scan(&roleCount); err != nil {
		t.Fatalf("check plain role: %v", err)
	}
	if roleCount == 0 {
		if _, err := admin.Exec(ctx, "CREATE ROLE rls_plain LOGIN PASSWORD 'rls_plain'"); err != nil {
			t.Fatalf("create plain role: %v", err)
		}
	}

	var dbCount int
	if err := admin.QueryRow(ctx,
		"SELECT count(*) FROM pg_database WHERE datname = 'regionrouter_norole'").Scan(&dbCount); err != nil {
		t.Fatalf("check bare database: %v", err)
	}
	if dbCount == 0 {
		if _, err := admin.Exec(ctx, "CREATE DATABASE regionrouter_norole"); err != nil {
			t.Fatalf("create bare database: %v", err)
		}
	}
	bareURI, err := url.Parse(adminURI)
	if err != nil {
		t.Fatalf("parse admin uri: %v", err)
	}
	bareURI.Path = "/regionrouter_norole"
	bareURI.User = url.UserPassword("rls_plain", "rls_plain")

	cfg, err := pgxpool.ParseConfig(bareURI.String())
	if err != nil {
		t.Fatalf("parse bare config: %v", err)
	}
	if err := ConfigurePool(cfg, "sg"); err != nil {
		t.Fatalf("ConfigurePool: %v", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("new pool: %v", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err == nil {
		t.Fatal("pool must fail closed when the login cannot assume the app role")
	}
}

// TestAfterConnectRegion_GUCOnly covers the constrained-reader hook: it binds
// only the GUC (no SET ROLE), and rejects invalid regions before connecting.
func TestAfterConnectRegion_GUCOnly(t *testing.T) {
	adminURI, _ := startRegionalPostgres(t)
	ctx := context.Background()

	cfg, err := pgxpool.ParseConfig(adminURI)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	// Invalid regions are rejected by the hook before any connection is made.
	if err := AfterConnectRegion("INVALID")(ctx, nil); err == nil {
		t.Fatal("invalid region must be rejected by the hook before any connection")
	}
	hook := AfterConnectRegion("sg")
	cfg.AfterConnect = hook
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("new pool: %v", err)
	}
	defer pool.Close()

	var role, region string
	if err := pool.QueryRow(ctx, "SELECT current_user, current_setting('app.region')").Scan(&role, &region); err != nil {
		t.Fatalf("identity query: %v", err)
	}
	if role != "postgres" {
		t.Fatalf("GUC-only hook must not downgrade the role, got %q", role)
	}
	if region != "sg" {
		t.Fatalf("expected app.region=sg, got %q", region)
	}
}

// TestSetGUCHelpers_ErrorPaths covers the direct helper failure branches
// (closed connection) without standing up extra containers.
func TestSetGUCHelpers_ErrorPaths(t *testing.T) {
	_, admin := startRegionalPostgres(t)
	ctx := context.Background()

	conn, err := pgx.Connect(ctx, admin.Config().ConnString())
	if err != nil {
		t.Fatalf("direct connect: %v", err)
	}
	if err := assumeAppRole(ctx, conn); err != nil {
		t.Fatalf("assumeAppRole on live conn: %v", err)
	}
	if err := setRegionGUC(ctx, conn, "eu"); err != nil {
		t.Fatalf("setRegionGUC on live conn: %v", err)
	}
	var role, region string
	if err := conn.QueryRow(ctx, "SELECT current_user, current_setting('app.region')").Scan(&role, &region); err != nil {
		t.Fatalf("identity query: %v", err)
	}
	if role != AppRole || region != "eu" {
		t.Fatalf("expected %s/eu, got %s/%s", AppRole, role, region)
	}
	if err := conn.Close(ctx); err != nil {
		t.Fatalf("close conn: %v", err)
	}
	if err := assumeAppRole(ctx, conn); err == nil {
		t.Fatal("assumeAppRole on closed conn must fail")
	}
	if err := setRegionGUC(ctx, conn, "eu"); err == nil {
		t.Fatal("setRegionGUC on closed conn must fail")
	}
}

// TestPGStore_LookupUpsert covers the DB-backed orgStore/orgWriter.
func TestPGStore_LookupUpsert(t *testing.T) {
	_, admin := startRegionalPostgres(t)
	ctx := context.Background()

	store := NewPGStore(admin)
	if _, _, err := store.LookupRegion(ctx, "00000000-0000-0000-0000-000000000000"); err == nil {
		t.Fatal("unknown org must surface an error (ErrNoRows)")
	}
	if err := store.UpsertRegion(ctx, "00000000-0000-0000-0000-000000000000", "eu", true); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	// Upsert again: the ON CONFLICT path.
	if err := store.UpsertRegion(ctx, "00000000-0000-0000-0000-000000000000", "us", false); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	region, pinned, err := store.LookupRegion(ctx, "00000000-0000-0000-0000-000000000000")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if region != "us" || pinned {
		t.Fatalf("expected us/unpinned after re-upsert, got %q/%v", region, pinned)
	}
}

// startRegionalRedis returns the shared disposable Redis for the test binary.
func startRegionalRedis(t *testing.T) *redis.Client {
	t.Helper()
	requireDockerRegional(t)
	redisOnce.Do(func() {
		ctx := context.Background()
		container, err := testredis.Run(ctx, "redis:7-alpine")
		if err != nil {
			redisErr = fmt.Errorf("start disposable redis (is Docker running?): %w", err)
			return
		}
		uri, err := container.ConnectionString(ctx)
		if err != nil {
			redisErr = fmt.Errorf("redis connection string: %w", err)
			return
		}
		opt, err := redis.ParseURL(uri)
		if err != nil {
			redisErr = fmt.Errorf("parse redis url: %w", err)
			return
		}
		client := redis.NewClient(opt)
		if err := client.Ping(ctx).Err(); err != nil {
			redisErr = fmt.Errorf("ping disposable redis: %w", err)
			return
		}
		redisClient = client
	})
	if redisErr != nil {
		t.Fatalf("regional redis stand: %v", redisErr)
	}
	return redisClient
}

// TestNewWithRedis_RedisKV covers the redis kvStore adapter and the
// NewWithRedis wiring: miss → DB → cache → hit, then Invalidate clears it.
func TestNewWithRedis_RedisKV(t *testing.T) {
	_, admin := startRegionalPostgres(t)
	ctx := context.Background()

	rdb := startRegionalRedis(t)

	// Adapter contract: miss → errCacheMiss, then Set/Get/Del round trip.
	kv := redisKV{rdb: rdb}
	if _, err := kv.Get(ctx, "regionrouter:test"); err != errCacheMiss {
		t.Fatalf("expected errCacheMiss on empty key, got %v", err)
	}
	if err := kv.Set(ctx, "regionrouter:test", "1eu", time.Second); err != nil {
		t.Fatalf("kv set: %v", err)
	}
	if v, err := kv.Get(ctx, "regionrouter:test"); err != nil || v != "1eu" {
		t.Fatalf("kv round trip: %q/%v", v, err)
	}
	if err := kv.Del(ctx, "regionrouter:test"); err != nil {
		t.Fatalf("kv del: %v", err)
	}
	if _, err := kv.Get(ctx, "regionrouter:test"); err != errCacheMiss {
		t.Fatalf("expected errCacheMiss after del, got %v", err)
	}

	orgID := "11111111-1111-1111-1111-111111111111"
	if _, err := admin.Exec(ctx, `INSERT INTO org_home_region (org_id, home_region, residency_pinned)
		VALUES ($1, 'eu', true)`, orgID); err != nil {
		t.Fatalf("seed org mapping: %v", err)
	}
	store := NewPGStore(admin)
	r := NewWithRedis(store, rdb)

	got := r.Resolve(ctx, orgID)
	if got.HomeRegion != "eu" || !got.ResidencyPinned {
		t.Fatalf("expected eu/pinned from DB, got %+v", got)
	}
	// The mapping is now cached in redis: drop the DB row and re-resolve —
	// the cached answer must survive, proving the redis path was used.
	if _, err := admin.Exec(ctx, "DELETE FROM org_home_region WHERE org_id=$1", orgID); err != nil {
		t.Fatalf("drop org mapping: %v", err)
	}
	if got := r.Resolve(ctx, orgID); got.HomeRegion != "eu" || !got.ResidencyPinned {
		t.Fatalf("expected cached eu/pinned, got %+v", got)
	}
	// Invalidate clears the cache: the unknown org falls back to default.
	r.Invalidate(ctx, orgID)
	if got := r.Resolve(ctx, orgID); got.HomeRegion != DefaultRegion {
		t.Fatalf("expected %q after invalidation, got %+v", DefaultRegion, got)
	}
}

// TestSelectBestPeer covers the failover peer selection branches.
func TestSelectBestPeer(t *testing.T) {
	regions := config.RegionMap{
		"sg": {Name: "sg", Priority: 1},
		"eu": {Name: "eu", Priority: 3},
		"in": {Name: "in", Priority: 2},
	}
	f := NewFailoverEvaluator(nil, nil, regions, "sg", nil)
	// Default policy applies no egress constraints: selection is by priority.
	pol := sovereign.DefaultPolicy()

	if got, denied := f.selectBestPeer(context.Background(), "org", []string{"eu", "in", "sg"}, "sg", pol); got != "in" || len(denied) != 0 {
		t.Fatalf("expected in (priority 2), got %q denied=%d", got, len(denied))
	}
	if got, denied := f.selectBestPeer(context.Background(), "org", []string{"sg"}, "sg", pol); got != "" || len(denied) != 0 {
		t.Fatalf("expected no peer when everything is excluded, got %q denied=%d", got, len(denied))
	}
	if got, denied := f.selectBestPeer(context.Background(), "org", nil, "sg", pol); got != "" || len(denied) != 0 {
		t.Fatalf("expected no peer for empty health list, got %q denied=%d", got, len(denied))
	}
	// Unknown regions are not in the RegionMap and must be skipped.
	if got, denied := f.selectBestPeer(context.Background(), "org", []string{"xx", "in"}, "sg", pol); got != "in" || len(denied) != 0 {
		t.Fatalf("expected in after skipping unknown region, got %q denied=%d", got, len(denied))
	}
}

// TestHealthChecker_PingBranches covers the health ping success and failure
// branches (malformed URL, refused connection, non-200).
func TestHealthChecker_PingBranches(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	badStatus := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer badStatus.Close()

	h := NewHealthChecker([]PeerURL{
		{Region: "eu", URL: srv.URL},
		{Region: "us", URL: badStatus.URL},
		{Region: "in", URL: "http://127.0.0.1:1"},
	})
	if h.ping(ctx, "ht tp://bad url") {
		t.Fatal("malformed URL must not be healthy")
	}
	if h.ping(ctx, "http://127.0.0.1:1") {
		t.Fatal("refused connection must not be healthy")
	}
	healthy := h.CheckAll(ctx)
	if len(healthy) != 1 || healthy[0] != "eu" {
		t.Fatalf("expected only eu healthy, got %v", healthy)
	}
	// Second call inside the cache window must return the cached snapshot.
	if healthy2 := h.HealthyRegions(ctx); len(healthy2) != 1 || healthy2[0] != "eu" {
		t.Fatalf("cached snapshot must match, got %v", healthy2)
	}
}
