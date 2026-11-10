//go:build integration

package migrate

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	testpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/services/run"
)

// pgvector stands through the shipped seams only — migrate.Run, the real
// deploy-layer role bootstrap file, and services/run.ApplySeed:
//
//  1. clean install succeeds end-to-end: baseline head applied, role
//     bootstrap, seed, shipped seed scope, regional RLS enforced while the
//     seeded tables stay non-regional ("новая установка успешна");
//  2. a populated head-version stand: migrate is a no-op success and foreign /
//     client rows are never deleted, reseeded or duplicated
//     ("чужие/клиентские данные не удалены");
//  3. the named failure scenario ("RLS seed bootstrap несовместим с чистой
//     БД") as a runtime mutation experiment: the same app-role seed insert
//     succeeds on the shipped baseline, fails with the RLS violation on a
//     mis-baselined schema (a seeded table RLS-locked the way a future bad
//     re-squash would), and succeeds again after rollback — broken is
//     observably different from fixed. The static arm of the same
//     broken/fixed proof lives in baseline_seed_rls_test.go.
//
// External prerequisites (Docker) are hard requirements here: the stands are
// not skipped and no green mock stands in for the database.

// r059FixedUUIDs are stable uuid literals for canary rows (hex-safe).
const (
	r059ForeignOrg   = "a0000000-0000-0000-0000-000000000001"
	r059ForeignTeam  = "a0000000-0000-0000-0000-000000000002"
	r059ForeignKey   = "a0000000-0000-0000-0000-000000000003"
	r059ForeignAgent = "a0000000-0000-0000-0000-000000000004"
)

// spinBaselineStand boots a fresh disposable pgvector Postgres and returns
// the owner DSN, an owner pool (the same superuser posture the compose
// migrate/seed services use) and the container handle (for in-container
// tooling such as pg_dump).
func spinBaselineStand(t *testing.T, ctx context.Context) (string, *pgxpool.Pool, *testpostgres.PostgresContainer) {
	t.Helper()
	container, err := testpostgres.Run(ctx, "pgvector/pgvector:pg16",
		testpostgres.WithDatabase("yabanin"),
		testpostgres.WithUsername("postgres"),
		testpostgres.WithPassword("postgres"),
	)
	require.NoError(t, err, "docker/testcontainers must be available for the baseline regression stand")
	t.Cleanup(func() { _ = container.Terminate(context.Background()) })

	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "5432")
	require.NoError(t, err)
	parts := strings.Split(port.Port(), "/")
	connStr := fmt.Sprintf("postgres://postgres:postgres@%s:%s/yabanin?sslmode=disable", host, parts[0])

	pool, err := pgxpool.New(ctx, connStr)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	waitForDBReady(t, ctx, pool)
	return connStr, pool, container
}

// bootstrapAppRole applies the real deploy-layer role bootstrap file
// (deploy/quickstart/bootstrap-app-role.sql) with the simple protocol so the
// multi-statement file executes exactly as psql would in the quickstart
// stack — not a paraphrased inline subset.
func bootstrapAppRole(t *testing.T, ctx context.Context, connStr string) {
	t.Helper()
	body, err := os.ReadFile(
		filepath.Join("..", "..", "deploy", "quickstart", "bootstrap-app-role.sql"))
	require.NoError(t, err, "the deploy-layer role bootstrap file must be readable")
	require.Contains(t, string(body), "yabanin_app", "unexpected bootstrap file content")

	pc, err := pgxpool.ParseConfig(connStr)
	require.NoError(t, err)
	pc.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	require.NoError(t, err)
	defer pool.Close()
	_, err = pool.Exec(ctx, string(body))
	require.NoError(t, err, "bootstrap-app-role.sql must apply cleanly on the migrated baseline")
}

// appRoleConn opens a session bound to the least-privileged app role
// (NOBYPASSRLS) with the app.region GUC set — the RLS posture the gateway's
// region pools run under.
func appRoleConn(t *testing.T, ctx context.Context, connStr, region string) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(ctx, connStr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	_, err = conn.Exec(ctx, "SET ROLE yabanin_app")
	require.NoError(t, err, "SET ROLE to the non-owner app role must succeed")
	_, err = conn.Exec(ctx, "SELECT set_config('app.region', $1, false)", region)
	require.NoError(t, err)
	return conn
}

// TestRun_CleanInstallSeedRegression — contract example 1: a clean DB
// converges to the baseline head (0001 unified baseline + follow-ups), the
// deploy-layer role
// bootstrap applies, the real seed bootstraps the stand with the shipped
// seed scope, and regional RLS is enforced end-to-end while the seeded
// tables stay non-regional.
func TestRun_CleanInstallSeedRegression(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	connStr, ownerPool, _ := spinBaselineStand(t, ctx)

	// The baseline records the embedded set at the head version on a fresh
	// DB (Applied counts the single-row schema_migrations record; Version
	// is the head).
	up, err := Run(ctx, connStr, "sg")
	require.NoError(t, err, "fresh-DB baseline apply must succeed")
	require.Equal(t, 1, up.Applied)
	require.Equal(t, int64(27), up.Version)

	// Shipped seed scope before any seed run: 21 disabled model templates
	// (incl. the I18N-14 regional set pinned by
	// TestRegionalModelsMigration_PresentAndHonest).
	var baselineModels int
	require.NoError(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM models_registry`).Scan(&baselineModels))
	require.Equal(t, 21, baselineModels, "baseline must ship only the disabled model templates")
	require.Equal(t, int64(0), countTable(t, ctx, ownerPool,
		`SELECT count(*) FROM models_registry WHERE enabled`),
		"a fresh install must not advertise unconfigured models as enabled")
	require.Equal(t, int64(0), countTable(t, ctx, ownerPool,
		`SELECT count(*) FROM models_registry WHERE model_name IN
		 ('smart', 'cheap', 'turbo', 'gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo',
		  'claude-3-5-sonnet', 'claude-3-opus')`),
		"unconfigured example models must be absent, not merely disabled")

	// Deploy layer: the real role bootstrap file.
	bootstrapAppRole(t, ctx, connStr)
	var roleSuper, roleBypassRLS bool
	require.NoError(t, ownerPool.QueryRow(ctx,
		`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'yabanin_app'`).
		Scan(&roleSuper, &roleBypassRLS))
	require.False(t, roleSuper, "the app role must stay non-superuser")
	require.False(t, roleBypassRLS, "the app role must stay NOBYPASSRLS")

	// Seed through the real ApplySeed (mock-profile parity with the compose
	// seed service; the pool DSN is the owner secret, like prod compose).
	t.Setenv(credits.StarterGrantEnvVar, strconv.FormatInt(credits.DefaultStarterGrantCents, 10))
	opts := run.SeedOptions{
		OrgName:       "Regression Stand",
		Slug:          "regression-stand",
		ModelName:     "mock-model",
		Provider:      "openai-compat",
		UpstreamURL:   "http://mock-openai:8081",
		AdminEmail:    "regression-admin@example.com",
		AdminPassword: strPtrR059("pw-regression"),
	}
	var out strings.Builder
	res, err := run.ApplySeed(ctx, ownerPool, nil, opts, slog.Default(), &out)
	require.NoError(t, err, "seed must bootstrap the stand on the clean migrated baseline")
	require.True(t, res.KeyIssued)
	require.True(t, strings.HasPrefix(res.KeyPlaintext, "yb_"), "seed key must use the yb_ format")
	require.Equal(t, 1, strings.Count(out.String(), "API key (shown once, store it now):"),
		"the plaintext key is printed exactly once: %s", out.String())
	require.Contains(t, out.String(), "seed ok")

	// Shipped outputs: org, default team, $50 hard-stop budget, seed model,
	// $1,000 credits + one beta starter grant, seed key, root admin.
	require.Equal(t, int64(1), countTable(t, ctx, ownerPool,
		`SELECT count(*) FROM organizations WHERE slug = 'regression-stand'`))
	require.Equal(t, int64(1), countTable(t, ctx, ownerPool,
		`SELECT count(*) FROM organizations_teams WHERE org_id = $1::uuid AND slug = 'default'`, res.OrgID))
	var monthly string
	var hardLimit bool
	require.NoError(t, ownerPool.QueryRow(ctx,
		`SELECT monthly_limit_usd::text, hard_limit FROM team_budgets WHERE team_id = $1::uuid`,
		res.TeamID).Scan(&monthly, &hardLimit))
	require.Equal(t, "50.00", monthly)
	require.True(t, hardLimit)
	require.Equal(t, int64(1), countTable(t, ctx, ownerPool,
		`SELECT count(*) FROM models_registry WHERE model_name = 'mock-model' AND provider = 'openai-compat'
		 AND upstream_url = 'http://mock-openai:8081' AND upstream_api_key IS NULL AND enabled`))
	require.Equal(t, int64(1), countTable(t, ctx, ownerPool,
		`SELECT count(*) FROM models_registry WHERE enabled`),
		"the mock seed must enable only its explicitly configured model")
	require.Equal(t, int64(1), countTable(t, ctx, ownerPool,
		`SELECT count(*) FROM org_credits WHERE org_id = $1 AND balance_cents = 105000`, res.OrgID),
		"seed credits are the $1,000 grant plus the beta starter grant, applied once")
	require.Equal(t, int64(1), countTable(t, ctx, ownerPool,
		`SELECT count(*) FROM credit_transactions WHERE org_id = $1 AND type = 'topup'
		 AND invoice_ref = $2`, res.OrgID, credits.StarterGrantReason))
	require.Equal(t, int64(1), countTable(t, ctx, ownerPool,
		`SELECT count(*) FROM api_keys WHERE org_id = $1::uuid AND name = 'seed'`, res.OrgID))
	var isRoot, active bool
	require.NoError(t, ownerPool.QueryRow(ctx,
		`SELECT is_root, active FROM admin_users WHERE email = $1`, opts.AdminEmail).
		Scan(&isRoot, &active))
	require.True(t, isRoot)
	require.True(t, active)

	// schema_migrations carries the head record (golang-migrate keeps the
	// single current-version row).
	var version int64
	var dirty bool
	var recorded int
	require.NoError(t, ownerPool.QueryRow(ctx,
		`SELECT version, dirty, (SELECT count(*) FROM schema_migrations) FROM schema_migrations`).
		Scan(&version, &dirty, &recorded))
	require.Equal(t, int64(27), version)
	require.False(t, dirty)
	require.Equal(t, 1, recorded)

	// Regional RLS end-to-end (contract example 1, final clause): canary
	// rows in two regions, the app-role session sees and writes only its
	// own region.
	_, err = ownerPool.Exec(ctx, `
		INSERT INTO analytics_rollup_hourly
			(home_region, org_id, hour, model_used, endpoint, team_id, agent_id, status_class, cache_type)
		VALUES
			('sg', $1::uuid, now(), 'mock-model', '/v1/chat', $2::uuid, $3::uuid, '2xx', 'none'),
			('us', $1::uuid, now(), 'mock-model', '/v1/chat', $2::uuid, $3::uuid, '2xx', 'none')`,
		res.OrgID, res.TeamID, r059ForeignAgent)
	require.NoError(t, err, "owner canary inserts must succeed")
	app := appRoleConn(t, ctx, connStr, "sg")
	var visible int
	require.NoError(t, app.QueryRow(ctx,
		`SELECT count(*) FROM analytics_rollup_hourly`).Scan(&visible))
	require.Equal(t, 1, visible, "the sg app-role session must see only the sg canary row")
	require.Equal(t, int64(0), countTableConn(t, ctx, app,
		`SELECT count(*) FROM analytics_rollup_hourly WHERE home_region = 'us'`))
	crossRegion := app.QueryRow(ctx, `
		INSERT INTO analytics_rollup_hourly
			(home_region, org_id, hour, model_used, endpoint, team_id, agent_id, status_class, cache_type)
		VALUES ('us', $1::uuid, now(), 'mock-model', '/v1/chat', $2::uuid, $3::uuid, '2xx', 'none')
		RETURNING home_region`, res.OrgID, res.TeamID, r059ForeignAgent)
	err = crossRegion.Scan(new(string))
	require.Error(t, err, "the app role must not write outside its app.region")
	var rlErr *pgconn.PgError
	require.ErrorAs(t, err, &rlErr)
	require.Equal(t, "42501", rlErr.Code, "expected the RLS violation error class, got: %s", err.Error())

	// The seeded tables are non-regional: the same RLS-bound session seeds
	// fine under any app.region — the exact property a mis-baseline breaks.
	_, err = app.Exec(ctx, "SELECT set_config('app.region', 'de', false)")
	require.NoError(t, err)
	var seededUnderOtherRegion string
	require.NoError(t, app.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('Non-Regional', 'non-regional')
		 RETURNING id::text`).Scan(&seededUnderOtherRegion),
		"seeded tables must stay non-regional under the app role")
	require.NotEmpty(t, seededUnderOtherRegion)
}

// TestRun_PopulatedBaselineNoopPreservesForeignData — contract example 3: a
// populated version-1 stand (operator/customer data on top of the baseline)
// gets a no-op success from migrate, and neither the baseline nor a seed run
// on top deletes, re-applies or duplicates foreign rows.
func TestRun_PopulatedBaselineNoopPreservesForeignData(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	connStr, ownerPool, _ := spinBaselineStand(t, ctx)

	up, err := Run(ctx, connStr, "sg")
	require.NoError(t, err)
	require.Equal(t, int64(27), up.Version)

	// Foreign/client data on the stand: org, team, API key, credits balance
	// and a custom registered model.
	for _, stmt := range []string{
		`INSERT INTO organizations (id, name, slug) VALUES ('` + r059ForeignOrg + `', 'Client Corp', 'client-corp')`,
		`INSERT INTO organizations_teams (id, org_id, name, slug)
		 VALUES ('` + r059ForeignTeam + `', '` + r059ForeignOrg + `', 'Corp', 'corp')`,
		`INSERT INTO api_keys (id, key_hash, org_id, name, active, team_id)
		 VALUES ('` + r059ForeignKey + `', 'canary-key-hash-corp', '` + r059ForeignOrg + `', 'corp-root', true, '` + r059ForeignTeam + `')`,
		`INSERT INTO org_credits (org_id, balance_cents) VALUES ('` + r059ForeignOrg + `', 777777)`,
		`INSERT INTO models_registry
			(model_name, display_name, tier, provider, upstream_url, failover_models, tier_pool, upstream_timeout_ms, enabled)
		 VALUES ('client-custom-model', 'Client Custom', 'smart', 'openai-compat', 'https://client.example.com/v1', '{}', '{easy}', 1000, true)`,
	} {
		_, err := ownerPool.Exec(ctx, stmt)
		require.NoError(t, err, "canary insert must succeed: %s", stmt)
	}

	// Migrate again on the populated stand: no-op success, version stays at
	// the head.
	again, err := Run(ctx, connStr, "sg")
	require.NoError(t, err, "migrate on a populated head-version stand must be a no-op success")
	require.Equal(t, int64(27), again.Version)

	// Every foreign row survives byte-identical; the baseline did not
	// re-apply or regenerate seeds.
	var name string
	require.NoError(t, ownerPool.QueryRow(ctx,
		`SELECT name FROM organizations WHERE id = $1::uuid`, r059ForeignOrg).Scan(&name))
	require.Equal(t, "Client Corp", name)
	var keyHash string
	require.NoError(t, ownerPool.QueryRow(ctx,
		`SELECT key_hash FROM api_keys WHERE id = $1::uuid`, r059ForeignKey).Scan(&keyHash))
	require.Equal(t, "canary-key-hash-corp", keyHash)
	require.Equal(t, int64(777777), countTable(t, ctx, ownerPool,
		`SELECT balance_cents FROM org_credits WHERE org_id = $1`, r059ForeignOrg))
	require.Equal(t, int64(1), countTable(t, ctx, ownerPool,
		`SELECT count(*) FROM models_registry WHERE model_name = 'client-custom-model'
		 AND upstream_url = 'https://client.example.com/v1'`))
	require.Equal(t, int64(22), countTable(t, ctx, ownerPool,
		`SELECT count(*) FROM models_registry`),
		"21 baseline templates + the client model: migrate must not re-apply baseline seeds")

	// A seed run on the populated stand adds its own org and touches none of
	// the foreign rows.
	t.Setenv(credits.StarterGrantEnvVar, "0") // keep the canary balance frozen
	opts := run.SeedOptions{
		OrgName:       "Second Tenant",
		Slug:          "second-tenant",
		ModelName:     "mock-model",
		Provider:      "openai-compat",
		UpstreamURL:   "http://mock-openai:8081",
		AdminEmail:    "second-admin@example.com",
		AdminPassword: strPtrR059("pw-second"),
	}
	var out strings.Builder
	_, err = run.ApplySeed(ctx, ownerPool, nil, opts, slog.Default(), &out)
	require.NoError(t, err, "seed on a populated stand must succeed")
	require.NoError(t, ownerPool.QueryRow(ctx,
		`SELECT name FROM organizations WHERE id = $1::uuid`, r059ForeignOrg).Scan(&name))
	require.Equal(t, "Client Corp", name)
	require.NoError(t, ownerPool.QueryRow(ctx,
		`SELECT key_hash FROM api_keys WHERE id = $1::uuid`, r059ForeignKey).Scan(&keyHash))
	require.Equal(t, "canary-key-hash-corp", keyHash)
	require.Equal(t, int64(777777), countTable(t, ctx, ownerPool,
		`SELECT balance_cents FROM org_credits WHERE org_id = $1`, r059ForeignOrg))
	require.Equal(t, int64(1), countTable(t, ctx, ownerPool,
		`SELECT count(*) FROM api_keys WHERE org_id = $1::uuid AND name = 'corp-root'`, r059ForeignOrg),
		"seed must not duplicate or replace foreign keys")
	var version int64
	require.NoError(t, ownerPool.QueryRow(ctx,
		`SELECT version FROM schema_migrations`).Scan(&version))
	require.Equal(t, int64(27), version)
}

// TestRun_MisBaselineRLSBreaksSeedBootstrap — runtime negative evidence for
// the named failure scenario. The same least-privileged seed insert is
// exercised three times on one stand: it succeeds on the shipped baseline,
// fails with the RLS violation after a mis-baseline locks a seeded table
// (the shape a future bad re-squash would ship), and succeeds again after
// the mis-baseline is rolled back. Broken behavior is observably distinct
// from fixed, which is what makes the structural audit in
// baseline_seed_rls_test.go meaningful.
func TestRun_MisBaselineRLSBreaksSeedBootstrap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	connStr, ownerPool, _ := spinBaselineStand(t, ctx)

	up, err := Run(ctx, connStr, "sg")
	require.NoError(t, err)
	require.Equal(t, int64(27), up.Version)
	bootstrapAppRole(t, ctx, connStr)

	app := appRoleConn(t, ctx, connStr, "sg")

	// Fixed arm: the shipped baseline lets the app-role seed insert through.
	var orgID string
	require.NoError(t, app.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('Fixed Arm', 'fixed-arm')
		 RETURNING id::text`).Scan(&orgID),
		"seed insert must succeed on the shipped baseline")
	require.NotEmpty(t, orgID)

	// Broken arm: simulate the mis-baseline (RLS seed bootstrap failure
	// mode) — a seeded table RLS-locked with a deny policy.
	_, err = ownerPool.Exec(ctx, `
		ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;
		ALTER TABLE public.organizations FORCE ROW LEVEL SECURITY;
		CREATE POLICY mis_baseline_deny ON public.organizations
			USING (false) WITH CHECK (false);`)
	require.NoError(t, err, "owner can apply the simulated mis-baseline")
	_, err = app.Exec(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('Broken Arm', 'broken-arm')`)
	require.Error(t, err, "seed insert must fail on the mis-baselined schema")
	var rlErr *pgconn.PgError
	require.ErrorAs(t, err, &rlErr)
	require.Equal(t, "42501", rlErr.Code, "expected the RLS violation error class, got: %s", err.Error())
	require.Contains(t, err.Error(), "row-level security policy")
	require.Equal(t, int64(0), countTable(t, ctx, ownerPool,
		`SELECT count(*) FROM organizations WHERE slug = 'broken-arm'`),
		"the refused insert must not leave partial state")

	// Rollback arm: reverting the mis-baseline restores the fixed behavior —
	// the check separates the two worlds, it does not just fail everything.
	_, err = ownerPool.Exec(ctx, `
		DROP POLICY mis_baseline_deny ON public.organizations;
		ALTER TABLE public.organizations NO FORCE ROW LEVEL SECURITY;
		ALTER TABLE public.organizations DISABLE ROW LEVEL SECURITY;`)
	require.NoError(t, err)
	var recovered string
	require.NoError(t, app.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('Recovered Arm', 'recovered-arm')
		 RETURNING id::text`).Scan(&recovered),
		"seed insert must succeed again after the mis-baseline rollback")
	require.NotEmpty(t, recovered)
}

// countTable is a tiny count helper over the owner pool.
func countTable(t *testing.T, ctx context.Context, pool *pgxpool.Pool, query string, args ...any) int64 {
	t.Helper()
	var n int64
	require.NoError(t, pool.QueryRow(ctx, query, args...).Scan(&n))
	return n
}

// countTableConn is countTable over a single connection (the app-role
// session).
func countTableConn(t *testing.T, ctx context.Context, conn *pgx.Conn, query string, args ...any) int64 {
	t.Helper()
	var n int64
	require.NoError(t, conn.QueryRow(ctx, query, args...).Scan(&n))
	return n
}

func strPtrR059(s string) *string { return &s }
