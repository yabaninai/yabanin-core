package adminstore

// QA-01: DB-gated CRUD coverage for the remaining store families — models,
// routing rules, teams, team budgets, whitelists, agent keys, request
// stats — on the package-wide disposable stand (QG2-B3).

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// qaOrg seeds a fresh org and returns its id (unique per call).
func qaOrg(t *testing.T, store *Store, ctx context.Context) string {
	t.Helper()
	slug := fmt.Sprintf("qa-org-%d", time.Now().UnixNano())
	org, err := store.CreateOrganization(ctx, "QA Org "+slug, slug)
	require.NoError(t, err)
	t.Cleanup(func() { //nolint:contextcheck // teardown outlives the helper's ctx by design
		_, _ = store.db.Exec(context.Background(), "DELETE FROM organizations WHERE id = $1", org.ID)
	})
	return org.ID
}

func TestStore_ModelsCRUD_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()

	name := fmt.Sprintf("qa-model-%d", time.Now().UnixNano())
	created, err := store.CreateModel(ctx, name, "QA Model", "smart", nil, nil)
	require.NoError(t, err)
	assert.Equal(t, name, created.ModelName)
	assert.True(t, created.Enabled)

	got, err := store.GetModelByName(ctx, name)
	require.NoError(t, err)
	assert.Equal(t, "QA Model", got.DisplayName)

	list, total, err := store.ListModels(ctx, NewPageFilter(1, 200))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, total, int64(1))
	found := false
	for _, m := range list {
		if m.ModelName == name {
			found = true
		}
	}
	assert.True(t, found)

	require.NoError(t, store.UpdateModelEnabled(ctx, name, false))
	got, err = store.GetModelByName(ctx, name)
	require.NoError(t, err)
	assert.False(t, got.Enabled)

	newTier := "premium"
	newDisplay := "QA Model v2"
	require.NoError(t, store.UpdateModel(ctx, name, newDisplay, &newTier, nil, nil, nil))
	got, err = store.GetModelByName(ctx, name)
	require.NoError(t, err)
	assert.Equal(t, newDisplay, got.DisplayName)

	// BumpModelVersion raises the DB version column (not exposed on the
	// struct); assert via the raw column.
	var v1 int
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT version FROM models_registry WHERE model_name = $1", name).Scan(&v1))
	require.NoError(t, store.BumpModelVersion(ctx, name))
	var v2 int
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT version FROM models_registry WHERE model_name = $1", name).Scan(&v2))
	assert.Greater(t, v2, v1, "bump must raise the version")

	require.NoError(t, store.DeleteModel(ctx, name))
	_, err = store.GetModelByName(ctx, name)
	require.Error(t, err)
}

func TestStore_RoutingRulesCRUD_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()
	orgID := qaOrg(t, store, ctx)

	rule, err := store.CreateRoutingRule(ctx, orgID, "model~gpt-4", "cheap", 10)
	require.NoError(t, err)
	require.NotEmpty(t, rule.ID)

	got, err := store.GetRoutingRuleByID(ctx, rule.ID)
	require.NoError(t, err)
	assert.Equal(t, "model~gpt-4", got.MatchExpr)

	rules, total, err := store.ListRoutingRulesByOrg(ctx, orgID, NewPageFilter(1, 50))
	require.NoError(t, err)
	assert.EqualValues(t, 1, total)
	require.Len(t, rules, 1)

	require.NoError(t, store.UpdateRoutingRuleEnabled(ctx, rule.ID, false))
	got, err = store.GetRoutingRuleByID(ctx, rule.ID)
	require.NoError(t, err)
	assert.False(t, got.Enabled)

	newPriority := 42
	newTarget := "turbo"
	require.NoError(t, store.UpdateRoutingRule(ctx, rule.ID, "model~gpt-5", newTarget, &newPriority))
	got, err = store.GetRoutingRuleByID(ctx, rule.ID)
	require.NoError(t, err)
	assert.Equal(t, newTarget, got.TargetModel)

	require.NoError(t, store.DeleteRoutingRule(ctx, rule.ID))
	_, err = store.GetRoutingRuleByID(ctx, rule.ID)
	require.Error(t, err)
}

func TestStore_TeamsAndBudgets_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()
	orgID := qaOrg(t, store, ctx)

	team, err := store.CreateTeam(ctx, orgID, "QA Team", "qa-team", nil)
	require.NoError(t, err)
	require.NotEmpty(t, team.ID)

	got, err := store.GetTeamByID(ctx, team.ID)
	require.NoError(t, err)
	assert.Equal(t, "QA Team", got.Name)

	teams, total, err := store.ListTeamsByOrg(ctx, orgID, NewPageFilter(1, 50))
	require.NoError(t, err)
	assert.EqualValues(t, 1, total)
	require.Len(t, teams, 1)

	// Budget lifecycle.
	_, err = store.GetTeamBudget(ctx, team.ID)
	require.Error(t, err, "no budget row yet")
	require.NoError(t, store.UpsertTeamBudget(ctx, team.ID, 123.45, true))
	budget, err := store.GetTeamBudget(ctx, team.ID)
	require.NoError(t, err)
	assert.InDelta(t, 123.45, budget.MonthlyLimitUSD, 1e-9)
	assert.True(t, budget.HardLimit)

	require.NoError(t, store.UpsertTeamBudget(ctx, team.ID, 200, false))
	budget, err = store.GetTeamBudget(ctx, team.ID)
	require.NoError(t, err)
	assert.InDelta(t, 200, budget.MonthlyLimitUSD, 1e-9)

	byOrg, err := store.ListTeamBudgetsByOrg(ctx, orgID)
	require.NoError(t, err)
	require.Len(t, byOrg, 1)

	summary, err := store.GetTeamSpendSummary(ctx, team.ID)
	require.NoError(t, err)
	require.NotNil(t, summary)

	require.NoError(t, store.DeleteTeamBudget(ctx, team.ID))
	_, err = store.GetTeamBudget(ctx, team.ID)
	require.Error(t, err)

	require.NoError(t, store.UpdateTeam(ctx, team.ID, "QA Team 2", "qa-team-2", nil))
	got, err = store.GetTeamByID(ctx, team.ID)
	require.NoError(t, err)
	assert.Equal(t, "QA Team 2", got.Name)

	require.NoError(t, store.DeleteTeam(ctx, team.ID))
	_, err = store.GetTeamByID(ctx, team.ID)
	require.Error(t, err)
}

func TestStore_Whitelists_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()
	orgID := qaOrg(t, store, ctx)

	var teamID string
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO organizations_teams (org_id, name, slug)
		VALUES ($1, 'qa-wl-team', 'qa-wl-team') RETURNING id::text`, orgID).Scan(&teamID))

	hash := fmt.Sprintf("qa-wl-hash-%d", time.Now().UnixNano())
	key, err := store.CreateAPIKey(ctx, hash, "qa-wl-key", &orgID, &teamID)
	require.NoError(t, err)

	entry, err := store.AddKeyWhitelist(ctx, key.ID, "cheap", true)
	require.NoError(t, err)
	assert.True(t, entry.Allowed)

	list, total, err := store.ListKeyWhitelist(ctx, key.ID, NewPageFilter(1, 50))
	require.NoError(t, err)
	assert.EqualValues(t, 1, total)
	require.Len(t, list, 1)

	_, err = store.AddTeamWhitelist(ctx, teamID, "smart", false)
	require.NoError(t, err)
	teamList, _, err := store.ListTeamWhitelist(ctx, teamID, NewPageFilter(1, 50))
	require.NoError(t, err)
	require.Len(t, teamList, 1)

	require.NoError(t, store.DeleteKeyWhitelist(ctx, key.ID, "cheap"))
	_, total, err = store.ListKeyWhitelist(ctx, key.ID, NewPageFilter(1, 50))
	require.NoError(t, err)
	assert.EqualValues(t, 0, total)

	require.NoError(t, store.DeleteTeamWhitelist(ctx, teamID, "smart"))
}

func TestStore_AgentKeys_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()
	orgID := qaOrg(t, store, ctx)

	hash := fmt.Sprintf("qa-agent-hash-%d", time.Now().UnixNano())
	key, err := store.CreateAgentKey(ctx, hash, "qa-agent", orgID)
	require.NoError(t, err)
	require.NotEmpty(t, key.ID)

	got, err := store.GetAgentKeyByID(ctx, key.ID)
	require.NoError(t, err)
	assert.True(t, got.Active)

	keys, err := store.ListAgentKeys(ctx, orgID)
	require.NoError(t, err)
	require.Len(t, keys, 1)

	require.NoError(t, store.RevokeAgentKey(ctx, key.ID))
	got, err = store.GetAgentKeyByID(ctx, key.ID)
	require.NoError(t, err)
	assert.False(t, got.Active)
	assert.NotNil(t, got.RevokedAt)
}

func TestStore_RequestStats_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()
	orgID := qaOrg(t, store, ctx)

	// Seed a couple of request rows for the analytics surface.
	for i, status := range []int{200, 500} {
		_, err := pool.Exec(ctx, `
			INSERT INTO request_logs (org_id, model_requested, model_used, status_code, duration_ms, tokens_in, tokens_out, method, home_region)
			VALUES ($1, $2, $2, $3, $4, 10, 5, 'POST', 'sg')`,
			orgID, fmt.Sprintf("qa-stats-model-%d", i), status, 100+i)
		require.NoError(t, err)
	}

	stats, err := store.GetRequestLogStats(ctx, &orgID, time.Now().Add(-time.Hour))
	require.NoError(t, err)
	require.NotNil(t, stats)
	assert.GreaterOrEqual(t, stats.TotalRequests, int64(2), "seeded rows must be counted")

	top, err := store.TopModels(ctx, &orgID, 5)
	require.NoError(t, err)
	assert.NotEmpty(t, top)

	series, err := store.RequestTimeSeries(ctx, &orgID, time.Now().Add(-time.Hour), "minute")
	require.NoError(t, err)
	require.NotNil(t, series)

	errs, err := store.ErrorBreakdown(ctx, &orgID, time.Now().Add(-time.Hour))
	require.NoError(t, err)
	assert.NotEmpty(t, errs, "one seeded 500 must appear")

	lat, err := store.LatencyPercentiles(ctx, &orgID, time.Now().Add(-time.Hour))
	require.NoError(t, err)
	require.NotNil(t, lat)

	recent, err := store.RecentErrors(ctx, &orgID, 10)
	require.NoError(t, err)
	assert.NotEmpty(t, recent)

	orgsTop, err := store.TopOrgs(ctx, 5)
	require.NoError(t, err)
	assert.NotEmpty(t, orgsTop)
}

func TestStore_OrgRoles_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()
	orgID := qaOrg(t, store, ctx)

	userID := fmt.Sprintf("qa-user-%d", time.Now().UnixNano())
	_, err := pool.Exec(ctx, `
		INSERT INTO admin_users (email, password_hash, is_root)
		VALUES ($1, 'x', false) RETURNING id::text`, userID)
	require.NoError(t, err)
	var adminUserID string
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT id::text FROM admin_users WHERE email = $1", userID).Scan(&adminUserID))
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM admin_users WHERE id = $1", adminUserID)
	})

	m, err := store.CreateOrgMembership(ctx, OrgMembership{
		UserID: adminUserID, OrgID: orgID, Role: RoleOperator,
	})
	require.NoError(t, err)
	assert.Equal(t, RoleOperator, m.Role)

	roles, err := store.GetUserOrgRoles(ctx, adminUserID)
	require.NoError(t, err)
	assert.Equal(t, RoleOperator, roles[orgID])

	m, err = store.SetOrgMembership(ctx, adminUserID, orgID, RoleReader)
	require.NoError(t, err)
	assert.Equal(t, RoleReader, m.Role)
	roles, err = store.GetUserOrgRoles(ctx, adminUserID)
	require.NoError(t, err)
	assert.Equal(t, RoleReader, roles[orgID])

	members, err := store.ListOrgMembers(ctx, orgID)
	require.NoError(t, err)
	require.Len(t, members, 1)

	require.NoError(t, store.DeleteOrgMembership(ctx, adminUserID, orgID))
	roles, err = store.GetUserOrgRoles(ctx, adminUserID)
	require.NoError(t, err)
	assert.NotContains(t, roles, orgID)
}

func TestStore_SpendAlerts_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()
	orgID := qaOrg(t, store, ctx)

	// Default settings materialize on first read.
	settings, err := store.GetOrgSpendAlertSettings(ctx, orgID)
	require.NoError(t, err)
	require.NotNil(t, settings)

	threshold := 42.5
	hook := "https://hooks.example/qa"
	require.NoError(t, store.UpdateOrgSpendAlertSettings(ctx, orgID, &threshold, &hook))
	settings, err = store.GetOrgSpendAlertSettings(ctx, orgID)
	require.NoError(t, err)
	require.NotNil(t, settings.ThresholdUSD)
	assert.InDelta(t, 42.5, *settings.ThresholdUSD, 1e-9)

	orgs, err := store.ListOrgsWithSpendAlerts(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, orgs)

	spend, err := store.SpendToday(ctx, orgID)
	require.NoError(t, err)
	assert.InDelta(t, 0, spend, 1e-9, "no request rows seeded for this org")

	now := time.Now().UTC()
	require.NoError(t, store.UpdateLastAlertAt(ctx, orgID, now))
	settings, err = store.GetOrgSpendAlertSettings(ctx, orgID)
	require.NoError(t, err)
	require.NotNil(t, settings.LastAlertAt)
}

func TestStore_AgentBudgets_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()
	orgID := qaOrg(t, store, ctx)

	key, err := store.CreateAgentKey(ctx, fmt.Sprintf("qa-ab-hash-%d", time.Now().UnixNano()), "qa-ab", orgID)
	require.NoError(t, err)

	_, err = store.GetAgentBudget(ctx, key.ID)
	require.Error(t, err, "no budget yet")

	b, err := store.UpsertAgentBudget(ctx, key.ID, 500)
	require.NoError(t, err)
	assert.Equal(t, int64(500), b.DailyLimitCents)

	b, err = store.UpsertAgentBudget(ctx, key.ID, 900)
	require.NoError(t, err)
	assert.Equal(t, int64(900), b.DailyLimitCents, "upsert replaces")

	require.NoError(t, store.DeleteAgentBudget(ctx, key.ID))
	_, err = store.GetAgentBudget(ctx, key.ID)
	require.Error(t, err)
}

func TestStore_OrgUpdateDelete_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()
	orgID := qaOrg(t, store, ctx)

	orgs, total, err := store.ListOrganizations(ctx, NewPageFilter(1, 200))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, total, int64(1))
	assert.NotEmpty(t, orgs)

	require.NoError(t, store.UpdateOrganization(ctx, orgID, "QA Renamed", "qa-renamed-x", "", "", nil))
	got, err := store.GetOrganizationByID(ctx, orgID)
	require.NoError(t, err)
	assert.Equal(t, "QA Renamed", got.Name)

	require.NoError(t, store.DeleteOrganization(ctx, orgID))
	_, err = store.GetOrganizationByID(ctx, orgID)
	require.Error(t, err)
}

func TestStore_LineageQueries_Integration(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	ctx := context.Background()
	orgID := qaOrg(t, store, ctx)

	reqID := fmt.Sprintf("qa-req-%d", time.Now().UnixNano())
	raw := `{"request_id":"` + reqID + `","org_id":"` + orgID + `","model_used":"m","inference_region":"sg"}`
	_, err := pool.Exec(ctx, `
		INSERT INTO request_lineage (request_id, org_id, model_used, inference_region,
			model_origin_country, log_storage_region, provider_entity_jurisdiction,
			attestation_hash, raw_attestation)
		VALUES ($1, $2, 'm', 'sg', 'SG', 'sg', 'Example Pte Ltd', 'deadbeef', $3)`,
		reqID, orgID, raw)
	require.NoError(t, err)

	att, err := store.GetLineageByRequestID(ctx, reqID)
	require.NoError(t, err)
	assert.Equal(t, reqID, att.RequestID)

	list, err := store.ListLineageByOrg(ctx, orgID, 10)
	require.NoError(t, err)
	require.Len(t, list, 1)

	filtered, err := store.ListLineageByOrgFiltered(ctx, orgID, "m",
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour), 10)
	require.NoError(t, err)
	require.Len(t, filtered, 1)

	_, err = store.GetLineageByRequestID(ctx, "does-not-exist")
	require.Error(t, err, "missing attestation must not resolve")
}
