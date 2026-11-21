package migrate_test

// QS-METRICS-1 evidence probe. This file must compile unchanged on the
// original (pre-fix) checkout, the fixed checkout, and any single-change
// broken variant (e.g. migrate hook removed): it uses only raw catalog /
// privilege SQL plus the pre-existing migrate.Run / feedback.EnsureMetricsViews
// APIs — never the new CheckMetricsViews surface — so a failure here is always
// a behavioral failure of the up-migration boundary, not a compile artifact.
// It fails wherever Run leaves the seven beta metrics views unprovisioned or
// unreadable from the application posture. It is deliberately self-contained
// (own database, own app-role pool) so it can be copied alone into other
// checkouts.

import (
	"context"
	"errors"
	"fmt"
	"net/url"
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

// probeViews is frozen on purpose: the expected set is the evidence, so it is
// never derived from product code under test.
var probeViews = []string{
	"beta_cache_hit_rate_daily",
	"beta_dau_daily",
	"beta_latency_daily",
	"beta_onboarding_ttfq",
	"beta_provider_distribution",
	"beta_provider_errors",
	"beta_requests_daily",
}

func TestMigrateRunProvisionsAppReadableViews_Raw_Integration(t *testing.T) {
	ctx := context.Background()
	owner := testdb.Postgres(t)
	var standDSN string
	testdb.PostgresPool(t, func(c *pgxpool.Config) { standDSN = c.ConnString() })
	require.NotEmpty(t, standDSN, "test stand DSN capture")

	// A dedicated empty database: migrate.Run needs schema_migrations, which
	// the shared stand (pkg/testdb applies files directly) never creates.
	dbName := fmt.Sprintf("probe_raw_%x", time.Now().UnixNano())
	_, err := owner.Exec(ctx, "CREATE DATABASE "+dbName)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = owner.Exec(ctx, "DROP DATABASE "+dbName+" WITH (FORCE)") })
	// pgx*Config.ConnString() returns the ORIGINAL parsed string, so the
	// dedicated DSN is built by rewriting the URL path — never by mutating
	// ConnConfig.Database — and the pool verifies it landed on the fresh,
	// ledger-less database before Run.
	dsnURL, err := url.Parse(standDSN)
	require.NoError(t, err)
	require.NotEmpty(t, dsnURL.Scheme, "stand DSN must be a URL-form DSN")
	dsnURL.Path = "/" + dbName
	dbDSN := dsnURL.String()
	dbOwner, err := pgxpool.New(ctx, dbDSN)
	require.NoError(t, err)
	t.Cleanup(dbOwner.Close)
	var cur string
	require.NoError(t, dbOwner.QueryRow(ctx, "SELECT current_database()").Scan(&cur))
	require.Equal(t, dbName, cur, "probe pool must land on the fresh database")
	var ledger any
	require.NoError(t, dbOwner.QueryRow(ctx, `SELECT to_regclass('public.schema_migrations')`).Scan(&ledger))
	require.Nil(t, ledger, "fresh probe database must start without a migration ledger")
	var curUser string
	var super bool
	require.NoError(t, dbOwner.QueryRow(ctx,
		`SELECT current_user, rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user`).Scan(&curUser, &super))
	require.Equal(t, "yabanin", curUser, "probe pool must use the stand owner login")
	require.True(t, super, "stand owner login is the disposable superuser")

	// Two independent migrate generations over the same database — the
	// retained-volume restart shape. Both must succeed idempotently.
	for gen := 1; gen <= 2; gen++ {
		res, rerr := migrate.Run(ctx, dbDSN, "sg")
		if rerr != nil {
			var pe *pgconn.PgError
			if errors.As(rerr, &pe) {
				t.Logf("migrate generation %d failed: SQLSTATE %s: %s", gen, pe.Code, pe.Message)
			} else {
				t.Logf("migrate generation %d failed: %v", gen, rerr)
			}
		}
		require.NoError(t, rerr, "migrate generation %d", gen)
		require.NotNil(t, res)
		assert.EqualValues(t, 30, res.Version,
			"generation %d: views are not migrations; schema head must stay 30", gen)
	}

	// Raw catalog truth: exactly the seven views exist after Run.
	var n int
	require.NoError(t, dbOwner.QueryRow(ctx,
		`SELECT count(*) FROM pg_catalog.pg_views
		  WHERE schemaname = 'public' AND viewname = ANY($1)`, probeViews).Scan(&n))
	assert.Equal(t, len(probeViews), n,
		"migrate.Run must provision all seven beta metrics views; got %d", n)
	var extra string
	require.NoError(t, dbOwner.QueryRow(ctx,
		`SELECT coalesce(string_agg(viewname, ' '), '') FROM pg_catalog.pg_views
		  WHERE schemaname = 'public' AND viewname LIKE 'beta\_%%' AND NOT (viewname = ANY($1))`,
		probeViews).Scan(&extra))
	assert.Empty(t, extra, "unexpected extra beta_* views: %s", extra)

	// Two orgs with independently known rows: exact per-org view numbers.
	token := fmt.Sprintf("probe%x", time.Now().UnixNano())
	var orgA, orgB string
	require.NoError(t, dbOwner.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`,
		token+"-org-a").Scan(&orgA))
	require.NoError(t, dbOwner.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`,
		token+"-org-b").Scan(&orgB))
	ins := `INSERT INTO request_logs (org_id, model_requested, model_used, status_code, duration_ms,
		tokens_in, tokens_out, created_at, home_region)
		VALUES ($1::uuid, $2, $2, $3, 10, 10, 5, $4, 'GLOBAL')`
	seed := []struct {
		org    string
		status int
		at     string
	}{
		{orgA, 200, "2026-11-10 10:00:00+00"},
		{orgA, 200, "2026-11-10 10:01:00+00"},
		{orgB, 200, "2026-11-15 12:00:00+00"},
		{orgB, 200, "2026-11-15 12:01:00+00"},
		{orgB, 500, "2026-11-15 12:02:00+00"},
	}
	for i, r := range seed {
		_, err := dbOwner.Exec(ctx, ins, r.org, token+"-model", r.status, r.at)
		require.NoError(t, err, "probe seed row %d", i)
	}

	// Application posture: dedicated pool adopting the NOBYPASSRLS
	// yabanin_app role on every connection.
	appCfg, err := pgxpool.ParseConfig(dbDSN)
	require.NoError(t, err)
	appCfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		if _, err := c.Exec(ctx, "SET ROLE yabanin_app"); err != nil {
			return err
		}
		_, err := c.Exec(ctx, "SET app.region = 'sg'")
		return err
	}
	app, err := pgxpool.NewWithConfig(ctx, appCfg)
	require.NoError(t, err)
	t.Cleanup(app.Close)

	// Every view is readable from the application posture, including the
	// two orgs' exact numbers.
	for _, v := range probeViews {
		var one int
		require.NoError(t, app.QueryRow(ctx, "SELECT count(*) FROM public."+v).Scan(&one),
			"app role must be able to SELECT %s", v)
	}
	var aReq, bReq, bErrs int
	require.NoError(t, app.QueryRow(ctx,
		`SELECT requests FROM beta_dau_daily WHERE org_id::text = $1 AND day::date = '2026-11-10'`,
		orgA).Scan(&aReq))
	require.NoError(t, app.QueryRow(ctx,
		`SELECT requests FROM beta_dau_daily WHERE org_id::text = $1 AND day::date = '2026-11-15'`,
		orgB).Scan(&bReq))
	require.NoError(t, app.QueryRow(ctx,
		`SELECT errors FROM beta_requests_daily WHERE org_id::text = $1 AND day::date = '2026-11-15'`,
		orgB).Scan(&bErrs))
	assert.Equal(t, 2, aReq, "org A known rows on its day")
	assert.Equal(t, 3, bReq, "org B known rows on its day")
	assert.Equal(t, 1, bErrs, "org B single >=400 row")

	// Least privilege from the application posture: no CREATE in public
	// (SQLSTATE 42501), and the original failure class — provisioning
	// attempted as the app role — must fail 42501 rather than silently
	// pass. Assert the server SQLSTATE, never driver string formatting.
	t.Cleanup(func() { _, _ = dbOwner.Exec(ctx, "DROP TABLE IF EXISTS public.probe_app_ddl") })
	_, err = app.Exec(ctx, "CREATE TABLE public.probe_app_ddl(id int)")
	require.Error(t, err, "app role must not CREATE in public")
	var ddlErr *pgconn.PgError
	require.ErrorAs(t, err, &ddlErr, "denial must be a server error, not a transport failure")
	assert.Equal(t, "42501", ddlErr.Code)
	err = feedback.EnsureMetricsViews(ctx, app)
	require.Error(t, err, "app-role view bootstrap must fail, not silently pass")
	var bootErr *pgconn.PgError
	require.ErrorAs(t, err, &bootErr, "wrapped bootstrap error must carry the server cause")
	assert.Equal(t, "42501", bootErr.Code)
}
