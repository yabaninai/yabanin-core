package feedback

// QS-METRICS-1 application-posture coverage: the NOBYPASSRLS yabanin_app role
// reads the seven beta views with exact per-org numbers (PostgresApp is the
// same posture the admin plane uses at startup), and CheckMetricsViews reports
// degraded states explicitly while never attempting DDL or elevation itself.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/testdb"
)

func TestMetricsViews_AppRoleReads_Integration(t *testing.T) {
	ctx := context.Background()
	owner := testdb.Postgres(t)
	require.NoError(t, EnsureMetricsViews(ctx, owner))
	fx := seedViewsFixturePG(t, owner)
	app := testdb.PostgresApp(t, "sg")

	missing, unreadable, err := CheckMetricsViews(ctx, app)
	require.NoError(t, err)
	assert.Empty(t, missing, "the guarded grant must make all seven app-readable")
	assert.Empty(t, unreadable)

	// Exact per-org numbers through the application posture.
	var aActive, aReq, bActive, bReq int
	require.NoError(t, app.QueryRow(ctx,
		`SELECT active_users::bigint, requests::bigint FROM beta_dau_daily
		  WHERE org_id::text = $1 AND day::date = $2::date`, fx.OrgA, fx.Day1).Scan(&aActive, &aReq))
	require.NoError(t, app.QueryRow(ctx,
		`SELECT active_users::bigint, requests::bigint FROM beta_dau_daily
		  WHERE org_id::text = $1 AND day::date = $2::date`, fx.OrgB, fx.Day2).Scan(&bActive, &bReq))
	assert.Equal(t, 4, aActive, "org A day1 principals: u1 twice, u2, k1, anon")
	assert.Equal(t, 5, aReq)
	assert.Equal(t, 1, bActive)
	assert.Equal(t, 1, bReq)

	// Tenant separation from the app posture: org A carries its BYOK row,
	// org B only the global provider. org_id is a random uuidv7 pair, so the
	// org ordering of ORDER BY org_id, provider is NOT deterministic across
	// runs — compare the exact (org, provider, requests) rows as a set,
	// never positionally.
	type provRow struct {
		org      string
		provider string
		requests int
	}
	var provs []provRow
	rows, err := app.Query(ctx,
		`SELECT org_id::text, provider, requests::bigint FROM beta_provider_distribution
		  WHERE org_id::text = ANY($1) ORDER BY org_id, provider`, []string{fx.OrgA, fx.OrgB})
	require.NoError(t, err)
	for rows.Next() {
		var r provRow
		require.NoError(t, rows.Scan(&r.org, &r.provider, &r.requests))
		provs = append(provs, r)
	}
	require.NoError(t, rows.Err())
	assert.ElementsMatch(t, []provRow{
		{fx.OrgA, "anthropic", 3},
		{fx.OrgA, "(unknown)", 1},
		{fx.OrgA, "zai-coding", 1}, // BYOK row
		{fx.OrgB, "anthropic", 1},
	}, provs)

	// Least privilege from the application posture.
	var canCreate bool
	require.NoError(t, app.QueryRow(ctx,
		`SELECT has_schema_privilege(current_user, 'public', 'CREATE')`).Scan(&canCreate))
	assert.False(t, canCreate, "yabanin_app must not hold CREATE on public")
	// If this denial ever regresses, drop what the probe created.
	t.Cleanup(func() { _, _ = owner.Exec(ctx, "DROP TABLE IF EXISTS public.app_probe") })
	_, err = app.Exec(ctx, "CREATE TABLE public.app_probe(id int)")
	require.Error(t, err)
	var ddlErr *pgconn.PgError
	require.ErrorAs(t, err, &ddlErr, "denial must be a server error, not a transport failure")
	assert.Equal(t, "42501", ddlErr.Code)
}

func TestCheckMetricsViews_States_Integration(t *testing.T) {
	ctx := context.Background()
	owner := testdb.Postgres(t)
	app := testdb.PostgresApp(t, "sg")
	t.Cleanup(func() { require.NoError(t, EnsureMetricsViews(ctx, owner)) })

	// Degraded: views absent -> explicit missing list, not an error or a
	// silent pass, and no attempt to create them.
	for _, name := range MetricsViewNames() {
		require.NoError(t, execWFeed(t, owner, "DROP VIEW IF EXISTS public."+name))
	}
	missing, unreadable, err := CheckMetricsViews(ctx, app)
	require.NoError(t, err)
	assert.ElementsMatch(t, MetricsViewNames(), missing)
	assert.Empty(t, unreadable)
	var n int
	require.NoError(t, owner.QueryRow(ctx,
		`SELECT count(*) FROM pg_catalog.pg_views
		  WHERE schemaname = 'public' AND viewname = ANY($1)`, MetricsViewNames()).Scan(&n))
	assert.Zero(t, n, "the check must not create anything")

	// Ready after the (owner) provisioning boundary.
	require.NoError(t, EnsureMetricsViews(ctx, owner))
	missing, unreadable, err = CheckMetricsViews(ctx, app)
	require.NoError(t, err)
	assert.Empty(t, missing)
	assert.Empty(t, unreadable)

	// Degraded: present but revoked -> explicit unreadable. The check must
	// not DDL its way out: a second run stays unreadable until the owner
	// boundary re-grants.
	require.NoError(t, execWFeed(t, owner,
		"REVOKE SELECT ON public.beta_dau_daily FROM yabanin_app"))
	missing, unreadable, err = CheckMetricsViews(ctx, app)
	require.NoError(t, err)
	assert.Empty(t, missing)
	assert.Equal(t, []string{"beta_dau_daily"}, unreadable)
	missing, unreadable, err = CheckMetricsViews(ctx, app)
	require.NoError(t, err)
	assert.Empty(t, missing, "the check itself must not grant or create")
	assert.Equal(t, []string{"beta_dau_daily"}, unreadable, "the check itself must not grant or create")
	require.NoError(t, EnsureMetricsViews(ctx, owner)) // guarded grant restores

	// Degraded: denied execution path — present, still granted, but
	// unreadable in practice (the false-negative readiness defect: a definer's
	// view transferred to a privilege-less owner keeps the app grant while
	// underlying scans run under the new owner's privileges and are denied).
	// Reversibly: capture the original owner, move only the view, prove the
	// denial independently, then restore.
	var origOwner string
	require.NoError(t, owner.QueryRow(ctx,
		`SELECT viewowner FROM pg_catalog.pg_views
		  WHERE schemaname = 'public' AND viewname = 'beta_cache_hit_rate_daily'`).Scan(&origOwner))
	require.NotEmpty(t, origOwner)
	role := "check_probe_owner_" + fmt.Sprintf("%x", time.Now().UnixNano())
	t.Cleanup(func() { _, _ = owner.Exec(ctx, "DROP ROLE IF EXISTS "+role) })
	t.Cleanup(func() {
		_, _ = owner.Exec(ctx, `ALTER VIEW public.beta_cache_hit_rate_daily OWNER TO "`+origOwner+`"`)
	})
	require.NoError(t, execWFeed(t, owner, "CREATE ROLE "+role+" NOLOGIN"))
	require.NoError(t, execWFeed(t, owner,
		"ALTER VIEW public.beta_cache_hit_rate_daily OWNER TO "+role))
	// The grant to the app role survives the owner change — that is what
	// makes a privilege-only (or elided-scan) readiness probe a false pass.
	var granted bool
	require.NoError(t, app.QueryRow(ctx,
		`SELECT has_table_privilege(current_user, 'public.beta_cache_hit_rate_daily', 'SELECT')`).Scan(&granted))
	assert.True(t, granted, "app must still hold the view grant under the privilege-less owner")
	// Independent oracle: an actual app SELECT from that view is denied by
	// the server with SQLSTATE 42501 — read from pgconn.PgError.Code.
	_, selErr := app.Exec(ctx, "SELECT 1 FROM public.beta_cache_hit_rate_daily LIMIT 1")
	require.Error(t, selErr, "app execution of the denied-path view must fail")
	var selPg *pgconn.PgError
	require.ErrorAs(t, selErr, &selPg, "denial must be a server error, not a transport failure")
	assert.Equal(t, "42501", selPg.Code)
	// The behavioral readiness probe must surface the same fact.
	missing, unreadable, err = CheckMetricsViews(ctx, app)
	require.NoError(t, err)
	assert.Empty(t, missing)
	assert.Equal(t, []string{"beta_cache_hit_rate_daily"}, unreadable,
		"a granted view with a denied execution path must surface as unreadable")
	require.NoError(t, execWFeed(t, owner,
		`ALTER VIEW public.beta_cache_hit_rate_daily OWNER TO "`+origOwner+`"`))
	missing, unreadable, err = CheckMetricsViews(ctx, app)
	require.NoError(t, err)
	assert.Empty(t, missing, "owner restoration must restore readiness")
	assert.Empty(t, unreadable, "every degraded fixture must be fully restored")
	// (A broken-definition case is intentionally not constructed here: PG
	// propagates column renames into dependent views, refuses type changes
	// on view-referenced columns (SQLSTATE 0A000), and DROP ... CASCADE
	// collapses to the missing case above — no reversible in-place
	// unplannability fixture exists for these views.)
}
