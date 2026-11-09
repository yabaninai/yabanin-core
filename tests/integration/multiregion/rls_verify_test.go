//go:build integration

// Package multiregion holds the ENT-07 verification suite, extended by
// two rollup tables) is FORCEd, so even the table owner is bound by the
// policies, and the application runs as the dedicated non-owner yabanin_app
// role (SET ROLE in the production AfterConnect hook). Owner privileges stay
// reachable only through controlled elevation: migrations pin the session to
// the login role with SET ROLE NONE.
package multiregion

import (
	"context"
	"database/sql"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // register the pgx database/sql driver
	"github.com/reireirei/yabanin/pkg/migrate"
	"github.com/reireirei/yabanin/pkg/regionrouter"
	"github.com/stretchr/testify/require"
	testpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

// forceTables lists every table carrying a region_isolation policy (0001,
// 0006). Migration 0022 FORCEs RLS on exactly this set; the suite keeps the
// list explicit so a table that silently loses its policy fails here.
var forceTables = []string{
	"messages",
	"request_logs",
	"sessions",
	"analytics_rollup_hourly",
	"label_rollup_hourly",
}

func TestRLS_RegionIsolation(t *testing.T) {
	ctx := context.Background()

	pg, err := testpostgres.Run(ctx, "pgvector/pgvector:pg16",
		testpostgres.WithDatabase("rls"),
		testpostgres.WithUsername("postgres"),
		testpostgres.WithPassword("postgres"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pg.Terminate(ctx) })

	host, err := pg.Host(ctx)
	require.NoError(t, err)
	port, err := pg.MappedPort(ctx, "5432")
	require.NoError(t, err)
	adminURI := fmt.Sprintf("postgres://postgres:postgres@%s:%s/rls?sslmode=disable", host, port.Port())

	cid := pg.GetContainerID()
	require.Eventually(t, func() bool {
		out, err2 := execCommand(cid, "pg_isready", "-h", "localhost", "-U", "postgres", "-d", "rls")
		return err2 == nil && len(out) > 0 && strings.Contains(out, "accepting connections")
	}, 30*time.Second, 500*time.Millisecond)

	// Apply production migrations. Globbed, not hardcoded: the migration set
	// is squashed periodically and the suite must exercise whatever the repo
	// actually ships.
	repoRoot, err := filepath.Abs("../../..")
	require.NoError(t, err)
	migFiles, err := filepath.Glob(filepath.Join(repoRoot, "migrations", "*.up.sql"))
	require.NoError(t, err)
	require.NotEmpty(t, migFiles, "no up-migrations discovered")
	for _, local := range migFiles {
		applySQLFile(t, cid, local)
	}

	// Logins: cluster roles are not carried by the consolidated pg_dump-based
	// baseline (pg_dump never emits them). Replay the deploy-layer bootstrap
	// the historical 0022 migration performed: yabanin_app NOLOGIN, then the
	// deploy step below sets LOGIN + password out-of-band. rls_owner receives
	// the tables below to prove FORCE binds a non-superuser owner (the
	// superuser itself always bypasses RLS — that is the controlled-elevation
	// path migrations rely on).
	admin, err := sql.Open("pgx", adminURI)
	require.NoError(t, err)
	t.Cleanup(func() { _ = admin.Close() })
	for _, stmt := range []string{
		`DO $$ BEGIN
			IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'yabanin_app') THEN
				CREATE ROLE yabanin_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
			END IF;
		END $$`,
		`GRANT USAGE ON SCHEMA public TO yabanin_app`,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO yabanin_app`,
		`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO yabanin_app`,
		`ALTER ROLE yabanin_app LOGIN PASSWORD 'yabanin_app'`,
		`CREATE ROLE rls_owner NOLOGIN`,
	} {
		_, err = admin.ExecContext(ctx, stmt)
		require.NoError(t, err, stmt)
	}
	for _, table := range forceTables {
		_, err = admin.ExecContext(ctx, fmt.Sprintf("ALTER TABLE public.%s OWNER TO rls_owner", table))
		require.NoError(t, err, table)
	}

	// Seed rows in three regions. home_region defaults to
	// current_setting('app.region', true) — set it explicitly per row.
	insert := func(table, region string) {
		var q string
		switch table {
		case "request_logs":
			q = fmt.Sprintf(`INSERT INTO request_logs (model_requested, model_used, status_code, duration_ms, tokens_in, tokens_out, method, home_region)
				VALUES ('m', 'm', 200, 0, 0, 0, 'POST', '%s')`, region)
		case "sessions":
			q = fmt.Sprintf(`INSERT INTO sessions (org_id, home_region)
				VALUES ('11111111-1111-1111-1111-111111111111', '%s')`, region)
		case "messages":
			q = fmt.Sprintf(`INSERT INTO messages (session_id, role, content, home_region)
				VALUES ('22222222-2222-2222-2222-222222222222', 'user', 'hello', '%s')`, region)
		}
		_, err = admin.ExecContext(ctx, q)
		require.NoError(t, err, q)
	}
	// FKs: sessions/messages reference an org and a session — seed parents.
	_, err = admin.ExecContext(ctx, `
		INSERT INTO organizations (id, name, slug)
		VALUES ('11111111-1111-1111-1111-111111111111', 'rls-org', 'rls-org')
		ON CONFLICT (id) DO NOTHING`)
	require.NoError(t, err)
	_, err = admin.ExecContext(ctx, `
		INSERT INTO sessions (id, org_id, home_region)
		VALUES ('22222222-2222-2222-2222-222222222222',
		        '11111111-1111-1111-1111-111111111111', 'sg')`)
	require.NoError(t, err)
	for _, region := range []string{"sg", "us", "eu"} {
		for _, table := range []string{"request_logs", "sessions", "messages"} {
			insert(table, region)
		}
	}

	appURI := fmt.Sprintf("postgres://yabanin_app:yabanin_app@%s:%s/rls?sslmode=disable", host, port.Port())

	count := func(reader *sql.DB, table string) int {
		var n int
		require.NoError(t, reader.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&n))
		return n
	}

	t.Run("app role sees only its region", func(t *testing.T) {
		for region := range map[string]int{"sg": 1, "us": 1, "eu": 1} {
			t.Run(region, func(t *testing.T) {
				app, err := sql.Open("pgx", appURI)
				require.NoError(t, err)
				t.Cleanup(func() { _ = app.Close() })
				var role string
				require.NoError(t, app.QueryRowContext(ctx, "SELECT current_user").Scan(&role))
				require.Equal(t, regionrouter.AppRole, role, "login must be the app role")
				_, err = app.ExecContext(ctx, "SELECT set_config('app.region', $1, false)", region)
				require.NoError(t, err)
				// The FK parent session itself lives in sg, so sg has 2
				// session rows; every other combination is exactly 1.
				wantSessions := 1
				if region == "sg" {
					wantSessions = 2
				}
				require.Equal(t, 1, count(app, "request_logs"), "request_logs for %s", region)
				require.Equal(t, wantSessions, count(app, "sessions"), "sessions for %s", region)
				require.Equal(t, 1, count(app, "messages"), "messages for %s", region)
			})
		}
	})

	t.Run("unset app.region fails closed", func(t *testing.T) {
		app, err := sql.Open("pgx", appURI)
		require.NoError(t, err)
		t.Cleanup(func() { _ = app.Close() })
		for _, table := range []string{"request_logs", "sessions", "messages"} {
			require.Equal(t, 0, count(app, table), "%s must expose nothing without a region", table)
		}
	})

	t.Run("cross-region write is rejected by WITH CHECK", func(t *testing.T) {
		app, err := sql.Open("pgx", appURI)
		require.NoError(t, err)
		t.Cleanup(func() { _ = app.Close() })
		_, err = app.ExecContext(ctx, "SELECT set_config('app.region', 'sg', false)")
		require.NoError(t, err)
		_, err = app.ExecContext(ctx,
			`INSERT INTO request_logs (model_requested, model_used, status_code, home_region)
			 VALUES ('m', 'm', 200, 'us')`)
		require.Error(t, err, "WITH CHECK must reject a foreign-region insert")
	})

	t.Run("production ConfigurePool downgrades to app role and scopes region", func(t *testing.T) {
		// The DSN carries the privileged login; the production hook must
		// still land every connection on yabanin_app with the region bound.
		poolCfg, err := pgxpool.ParseConfig(adminURI)
		require.NoError(t, err)
		require.NoError(t, regionrouter.ConfigurePool(poolCfg, "eu"))
		pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
		require.NoError(t, err)
		t.Cleanup(pool.Close)

		var role, region string
		require.NoError(t, pool.QueryRow(ctx, "SELECT current_user, current_setting('app.region')").Scan(&role, &region))
		require.Equal(t, regionrouter.AppRole, role, "pool hook must SET ROLE yabanin_app")
		require.Equal(t, "eu", region, "pool hook must bind app.region")
		for _, table := range []string{"request_logs", "sessions", "messages"} {
			var n int
			require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n))
			require.Equal(t, 1, n, "%s rows must be scoped to eu by the production hook", table)
		}
	})

	t.Run("FORCE binds the table owner, elevation stays controlled", func(t *testing.T) {
		conn, err := admin.Conn(ctx)
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		// The owner role owns all five region tables. FORCE (0022) must bind
		// it to its own policies: with app.region=sg only the sg row is
		// visible (a pre-FORCE owner would see all three), and a cross-region
		// write violates WITH CHECK.
		_, err = conn.ExecContext(ctx, "SET ROLE rls_owner")
		require.NoError(t, err)
		_, err = conn.ExecContext(ctx, "SELECT set_config('app.region', 'sg', false)")
		require.NoError(t, err)
		require.Equal(t, 1, countConn(ctx, t, conn, "request_logs"), "FORCE must bind the owner to the sg region")
		_, err = conn.ExecContext(ctx,
			`INSERT INTO request_logs (model_requested, model_used, status_code, home_region)
			 VALUES ('m', 'm', 200, 'us')`)
		require.Error(t, err, "owner cross-region write must be rejected under FORCE")

		// Controlled elevation: SET ROLE NONE returns the migration/admin
		// session to its login identity, and the superuser bypass is what
		// migrations and admin operations run through.
		_, err = conn.ExecContext(ctx, "SET ROLE NONE")
		require.NoError(t, err)
		var login string
		require.NoError(t, conn.QueryRowContext(ctx, "SELECT current_user").Scan(&login))
		require.Equal(t, "postgres", login)
		require.Equal(t, 3, countConn(ctx, t, conn, "request_logs"), "superuser keeps the controlled bypass")
	})

	t.Run("migration pool pins the login role", func(t *testing.T) {
		// Simulate a DSN that pre-sets the app role (PG options). The
		// migration path must reset it: DDL/DML runs as the login user, never
		// as the RLS-bound application role.
		migURI := adminURI + "&options=-c%20role%3Dyabanin_app"

		// Precondition: without the hook the session really does start as the
		// injected role (keeps this subtest meaningful if pgx ever changes
		// startup-option handling).
		rawCfg, err := pgxpool.ParseConfig(migURI)
		require.NoError(t, err)
		rawPool, err := pgxpool.NewWithConfig(ctx, rawCfg)
		require.NoError(t, err)
		var injected string
		require.NoError(t, rawPool.QueryRow(ctx, "SELECT current_user").Scan(&injected))
		rawPool.Close()
		require.Equal(t, regionrouter.AppRole, injected, "DSN must pre-set the role for this subtest to bite")

		pool, err := migrate.Connect(ctx, migURI, "sg")
		require.NoError(t, err)
		t.Cleanup(pool.Close)

		var login, region string
		require.NoError(t, pool.QueryRow(ctx, "SELECT current_user, current_setting('app.region')").Scan(&login, &region))
		require.Equal(t, "postgres", login, "SET ROLE NONE must restore the login role")
		require.Equal(t, "sg", region)
	})

	t.Run("consolidated baseline ships the FORCE RLS hardening", func(t *testing.T) {
		// The historical 0022 down/up file cycle died with the 2026-10-04
		// consolidation (the hardening now ships inside 0001_init, and there
		// is no standalone pair to cycle anymore). What must keep holding on
		// the shipped baseline: the app role exists least-privileged, every
		// region table is RLS-enabled AND FORCEd, the region_isolation
		// policy is present, and the seeded data is intact.
		var role string
		require.NoError(t, admin.QueryRowContext(ctx,
			`SELECT rolname FROM pg_roles WHERE rolname = 'yabanin_app'
			 AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole`).Scan(&role),
			"yabanin_app must exist least-privileged (LOGIN is the deploy-layer change)")
		for _, table := range forceTables {
			var enabled, forced bool
			require.NoError(t, admin.QueryRowContext(ctx,
				fmt.Sprintf("SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = 'public.%s'::regclass", table),
			).Scan(&enabled, &forced), table)
			require.True(t, enabled, "%s must be RLS-enabled", table)
			require.True(t, forced, "%s must be FORCEd", table)
		}
		var policies int
		require.NoError(t, admin.QueryRowContext(ctx,
			"SELECT count(*) FROM pg_policies WHERE tablename = 'request_logs'").Scan(&policies))
		require.Equal(t, 1, policies, "region_isolation policy must ship with the baseline")
		require.Equal(t, 3, count(admin, "request_logs"), "request_logs data intact")
		require.Equal(t, 4, count(admin, "sessions"), "sessions data intact")
		require.Equal(t, 3, count(admin, "messages"), "messages data intact")
	})

	t.Run("ValidateRegion rejects injection-shaped ids", func(t *testing.T) {
		for _, bad := range []string{"", "SG", "a_b", "with space", "x'; DROP TABLE request_logs; --"} {
			require.Error(t, regionrouter.ValidateRegion(bad), "%q must be rejected", bad)
		}
	})
}

// countConn counts rows on a single pinned connection (SET ROLE state lives
// per connection, so subtests that switch roles count through *sql.Conn).
func countConn(ctx context.Context, t *testing.T, conn *sql.Conn, table string) int {
	t.Helper()
	var n int
	require.NoError(t, conn.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&n))
	return n
}

// applySQLFile copies a local SQL file into the container and applies it with
// psql as the bootstrap superuser (the controlled-elevation path).
func applySQLFile(t *testing.T, cid, local string) {
	t.Helper()
	out, err := exec.Command("docker", "cp", local, cid+":/tmp/mig.sql").CombinedOutput()
	require.NoError(t, err, "cp %s: %s", filepath.Base(local), out)
	psqlOut, err := execCommand(cid, "psql", "-h", "localhost", "-U", "postgres", "-d", "rls",
		"-v", "ON_ERROR_STOP=1", "-q", "-f", "/tmp/mig.sql")
	require.NoError(t, err, "apply %s: %s", filepath.Base(local), psqlOut)
}

// execCommand runs a command and returns its combined output.
func execCommand(cid string, args ...string) (string, error) {
	out, err := exec.Command("docker", append([]string{"exec", "-i", cid}, args...)...).CombinedOutput()
	return string(out), err
}
