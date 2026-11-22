package migrate_test

// Fixed-source readiness surface for QS-METRICS-1. The shared test stand has
// no schema_migrations table (pkg/testdb applies files directly), so
// migrate.Run is exercised against a dedicated empty database inside the same
// container: the real first-up boundary, twice for the retained-volume
// restart shape. The application posture is a dedicated pool that SET ROLEs
// to the NOBYPASSRLS yabanin_app role.

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/feedback"
	"github.com/reireirei/yabanin/pkg/migrate"
	"github.com/reireirei/yabanin/pkg/testdb"
)

// runLogged runs migrate.Run and, on failure, logs the underlying server
// error (SQLSTATE + message) before failing — golang-migrate wraps the cause
// in the whole migration file, which testify truncates.
func runLogged(t *testing.T, ctx context.Context, dsn string) migrate.Result {
	t.Helper()
	res, err := migrate.Run(ctx, dsn, "sg")
	if err != nil {
		var pe *pgconn.PgError
		if errors.As(err, &pe) {
			t.Logf("migrate.Run failed: SQLSTATE %s: %s", pe.Code, pe.Message)
		} else {
			t.Logf("migrate.Run failed: %v", err)
		}
	}
	require.NoError(t, err)
	return res
}

// dedicatedDB creates an empty database inside the shared stand and returns
// an owner pool plus its DSN. LIFO cleanup closes the pool before the forced
// database drop. pgx ConnConfig.ConnString() returns the ORIGINAL parsed
// string, so the dedicated DSN is built by rewriting the URL path, never by
// mutating ConnConfig.Database, and the pool verifies it truly landed on the
// fresh, ledger-less database before any Run.
func dedicatedDB(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	ctx := context.Background()
	owner := testdb.Postgres(t)
	var standDSN string
	testdb.PostgresPool(t, func(c *pgxpool.Config) { standDSN = c.ConnString() })
	require.NotEmpty(t, standDSN)
	require.True(t, urlSchemeIsPostgres(standDSN), "stand DSN must be a URL-form DSN: %s", redactDSN(standDSN))

	dbName := fmt.Sprintf("probe_mv_%x", time.Now().UnixNano())
	_, err := owner.Exec(ctx, "CREATE DATABASE "+dbName)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = owner.Exec(ctx, "DROP DATABASE "+dbName+" WITH (FORCE)") })

	dsn := withDatabase(t, standDSN, dbName)
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	var cur string
	require.NoError(t, pool.QueryRow(ctx, "SELECT current_database()").Scan(&cur))
	require.Equal(t, dbName, cur, "dedicated pool must land on the fresh database")
	var ledger any
	require.NoError(t, pool.QueryRow(ctx, `SELECT to_regclass('public.schema_migrations')`).Scan(&ledger))
	require.Nil(t, ledger, "fresh database must start without a migration ledger")
	// The disposable stand's owner login, as independently proven by the
	// reference harness: yabanin, superuser.
	var curUser string
	var super bool
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT current_user, rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user`).Scan(&curUser, &super))
	require.Equal(t, "yabanin", curUser, "dedicated pool must use the stand owner login")
	require.True(t, super, "stand owner login is the disposable superuser")
	return pool, dsn
}

// withDatabase rewrites only the URL path of a postgres:// DSN to the given
// database name, preserving credentials-less host/port/params.
func withDatabase(t *testing.T, dsn, dbName string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	require.NoError(t, err)
	u.Path = "/" + dbName
	return u.String()
}

func urlSchemeIsPostgres(dsn string) bool {
	return strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://")
}

func redactDSN(dsn string) string {
	if u, err := url.Parse(dsn); err == nil {
		if u.User != nil {
			u.User = url.User("redacted")
		}
		return u.String()
	}
	return "unparseable"
}

// appPoolOn returns a pool on dsn that adopts the application posture on
// every connection (SET ROLE yabanin_app; SET app.region).
func appPoolOn(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		if _, err := c.Exec(ctx, "SET ROLE yabanin_app"); err != nil {
			return err
		}
		_, err := c.Exec(ctx, "SET app.region = 'sg'")
		return err
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

func TestCheckMetricsViews_ReadyAfterMigrateRun_Integration(t *testing.T) {
	ctx := context.Background()
	_, dsn := dedicatedDB(t)

	res := runLogged(t, ctx, dsn)
	assert.EqualValues(t, 34, res.Version)

	missing, unreadable, err := feedback.CheckMetricsViews(ctx, appPoolOn(t, dsn))
	require.NoError(t, err)
	assert.Empty(t, missing, "views missing after the migrate boundary")
	assert.Empty(t, unreadable, "views unreadable from the app posture after the migrate boundary")
}

func TestMigrateRunFirstUpProvisionsViews_Integration(t *testing.T) {
	ctx := context.Background()
	owner, dsn := dedicatedDB(t)

	// Genuine first up-migration (empty database): one consolidated baseline
	// step to the embedded schema head (reference harness: Applied=1,
	// Version=jointScenario.headVersion on the original checkout), then a
	// second generation over the same database — the retained-volume
	// restart shape.
	first := runLogged(t, ctx, dsn)
	assert.GreaterOrEqual(t, first.Applied, 1, "fresh first-up must apply the consolidated baseline")
	assert.EqualValues(t, 34, first.Version)
	second := runLogged(t, ctx, dsn)
	assert.EqualValues(t, 34, second.Version)

	var n int
	require.NoError(t, owner.QueryRow(ctx,
		`SELECT count(*) FROM pg_catalog.pg_views
		  WHERE schemaname = 'public' AND viewname = ANY($1)`, feedback.MetricsViewNames()).Scan(&n))
	assert.Equal(t, len(feedback.MetricsViewNames()), n,
		"first up-migration into a fresh database must provision the views, idempotently")
}
