package handlers_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	adminstore "github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/cache"
	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/reireirei/yabanin/services/admin/handlers"
)

var errStub = errors.New("stub")

// TestSetupRouter_NoPanic verifies that SetupRouter does not panic when all
// optional handlers are set — matching the exact wiring used in services/admin/cmd/main.go.
// This catches chi duplicate-param panics (e.g., {id}/{id}) before they reach production.
func TestSetupRouter_NoPanic(t *testing.T) {
	store := &stubStore{}
	h := handlers.New(store, "test-session-key", "localhost", nil)

	// Wire vertical handlers (store.Log() returns nil — safe no-op).
	vh := handlers.NewVerticalHandlers(store, store.Log())
	h.SetVerticalHandlers(vh)

	router := h.SetupRouter()
	if router == nil {
		t.Fatal("SetupRouter returned nil handler")
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("GET /health returned %d, want 200", w.Code)
	}

	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/login", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("GET /auth/login returned %d, want 200", w.Code)
	}
}

// stubStore implements handlers.StoreInterface with no-op methods.
type stubStore struct{}

func (s *stubStore) Log() *slog.Logger { return nil }
func (s *stubStore) GetDefaultTeam(_ context.Context, _ string) (*adminstore.Team, error) {
	return &adminstore.Team{}, nil
}
func (s *stubStore) InsertAuditLog(context.Context, string, string, string, string, string, string, string) error {
	return errStub
}
func (s *stubStore) CreateAdminUser(ctx context.Context, email, displayName, passwordHash string, isRoot bool) (*adminstore.AdminUser, error) {
	return nil, errStub
}

// GetAdminUserByID answers session revalidation (TP-02): the stub user is
// always active, and its role is derived from the fixture user ID ("test-root"
// vs "test-admin") so one store instance can serve both matrix rows. Every
// other store surface keeps returning errStub (the 500 path).
func (s *stubStore) GetAdminUserByID(_ context.Context, id string) (*adminstore.AdminUser, error) {
	return &adminstore.AdminUser{ID: id, Email: "stub@x.test", IsRoot: id == "test-root", Active: true}, nil
}
func (s *stubStore) GetAdminUserByEmailWithHash(ctx context.Context, email string) (*adminstore.AdminUserWithHash, error) {
	return nil, errStub
}
func (s *stubStore) ListAdminUsers(ctx context.Context, onlyActive bool, f adminstore.PageFilter) ([]*adminstore.AdminUser, int64, error) {
	return nil, 0, errStub
}
func (s *stubStore) UpdateAdminUser(ctx context.Context, id string, displayName *string, isRoot *bool) error {
	return errStub
}
func (s *stubStore) DeleteAdminUser(ctx context.Context, id string) error { return errStub }
func (s *stubStore) CreateOrganization(ctx context.Context, name, slug string) (*adminstore.Organization, error) {
	return nil, errStub
}
func (s *stubStore) GetOrganizationByID(ctx context.Context, id string) (*adminstore.Organization, error) {
	return nil, errStub
}
func (s *stubStore) ListOrganizations(ctx context.Context, f adminstore.PageFilter) ([]*adminstore.Organization, int64, error) {
	return nil, 0, errStub
}
func (s *stubStore) UpdateOrganization(ctx context.Context, id, name, slug, currency, timezone string, issueURL *string) error {
	return errStub
}
func (s *stubStore) DeleteOrganization(ctx context.Context, id string) error { return errStub }
func (s *stubStore) GetOrgCacheSettings(ctx context.Context, orgID string) (*adminstore.OrgCacheSettings, error) {
	return nil, errStub
}
func (s *stubStore) UpdateOrgCacheSettings(ctx context.Context, orgID string, enabled bool, mode string) error {
	return errStub
}
func (s *stubStore) GetOrgRoutingSettings(ctx context.Context, orgID string) (*adminstore.OrgRoutingSettings, error) {
	return nil, errStub
}
func (s *stubStore) UpdateOrgRoutingSettings(ctx context.Context, orgID string, mode string, threshold float64) error {
	return errStub
}
func (s *stubStore) BumpModelVersion(ctx context.Context, modelName string) error { return errStub }
func (s *stubStore) GetCacheAnalytics(ctx context.Context, orgID string, from, to time.Time) (*adminstore.CacheAnalytics, error) {
	return nil, errStub
}
func (s *stubStore) CreateExperiment(ctx context.Context, name, orgID string, trafficPct int) (*cache.Experiment, error) {
	return nil, errStub
}
func (s *stubStore) GetExperiment(ctx context.Context, id string) (*cache.Experiment, error) {
	return nil, errStub
}
func (s *stubStore) ListExperiments(ctx context.Context, orgID string, onlyEnabled bool) ([]*cache.Experiment, error) {
	return nil, errStub
}
func (s *stubStore) UpdateExperiment(ctx context.Context, id string, trafficPct *int, enabled *bool) error {
	return errStub
}
func (s *stubStore) DeleteExperiment(ctx context.Context, id string) error { return errStub }
func (s *stubStore) GetCacheResults(ctx context.Context, experimentID string) (map[string]float64, error) {
	return nil, errStub
}
func (s *stubStore) CreateTeam(ctx context.Context, orgID, name, slug string, parentTeamID *string) (*adminstore.Team, error) {
	return nil, errStub
}
func (s *stubStore) GetTeamByID(ctx context.Context, id string) (*adminstore.Team, error) {
	return nil, errStub
}
func (s *stubStore) ListTeamsByOrg(ctx context.Context, orgID string, f adminstore.PageFilter) ([]*adminstore.Team, int64, error) {
	return nil, 0, errStub
}
func (s *stubStore) UpdateTeam(ctx context.Context, id, name, slug string, parentTeamID *string) error {
	return errStub
}
func (s *stubStore) DeleteTeam(ctx context.Context, id string) error { return errStub }
func (s *stubStore) CreateAPIKey(ctx context.Context, keyHash, name string, orgID *string, teamID *string) (*adminstore.APIKey, error) {
	return nil, errStub
}
func (s *stubStore) GetAPIKeyByID(ctx context.Context, id string) (*adminstore.APIKey, error) {
	return nil, errStub
}
func (s *stubStore) ListAPIKeys(ctx context.Context, orgID *string, f adminstore.PageFilter) ([]*adminstore.APIKey, int64, error) {
	return nil, 0, errStub
}
func (s *stubStore) UpdateAPIKeyActive(ctx context.Context, id string, active bool) error {
	return errStub
}
func (s *stubStore) RotateAPIKey(ctx context.Context, id, newHash string) error { return errStub }
func (s *stubStore) DeleteAPIKey(ctx context.Context, id string) error          { return errStub }
func (s *stubStore) UpdateAPIKeyLabels(ctx context.Context, id string, labels map[string]string, locked, mint, usage bool) error {
	return errStub
}
func (s *stubStore) RevokeSessionKeysByParent(ctx context.Context, parentID string) ([]string, error) {
	return nil, errStub
}
func (s *stubStore) CreateAgentKey(ctx context.Context, keyHash, name, orgID string) (*adminstore.AgentKey, error) {
	return nil, errStub
}
func (s *stubStore) CreateAgentKeyDelegated(ctx context.Context, p adminstore.AgentKeyCreateParams) (*adminstore.AgentKey, error) {
	return nil, errStub
}
func (s *stubStore) GetAgentKeyByID(ctx context.Context, id string) (*adminstore.AgentKey, error) {
	return nil, errStub
}
func (s *stubStore) ListAgentKeys(ctx context.Context, orgID string) ([]*adminstore.AgentKey, error) {
	return nil, errStub
}
func (s *stubStore) GetAgentBudget(ctx context.Context, agentID string) (*adminstore.AgentBudget, error) {
	return nil, errStub
}
func (s *stubStore) UpsertAgentBudget(ctx context.Context, agentID string, cents int64) (*adminstore.AgentBudget, error) {
	return nil, errStub
}
func (s *stubStore) DeleteAgentBudget(ctx context.Context, agentID string) error { return errStub }
func (s *stubStore) RevokeAgentKey(ctx context.Context, id string) error         { return errStub }
func (s *stubStore) CreateModel(ctx context.Context, modelName, displayName, tier string, upstreamURL, upstreamAPIKey *string) (*adminstore.ModelRegistry, error) {
	return nil, errStub
}
func (s *stubStore) CreateModelWithParams(ctx context.Context, p adminstore.CreateModelParams) (*adminstore.ModelRegistry, error) {
	return nil, errStub
}
func (s *stubStore) GetModelByName(ctx context.Context, modelName string) (*adminstore.ModelRegistry, error) {
	return nil, errStub
}
func (s *stubStore) ListModels(ctx context.Context, f adminstore.PageFilter) ([]*adminstore.ModelRegistry, int64, error) {
	return nil, 0, errStub
}
func (s *stubStore) UpdateModel(ctx context.Context, modelName, displayName string, tier *string, upstreamURL *string, upstreamAPIKey *string, enabled *bool) error {
	return errStub
}
func (s *stubStore) UpdateModelWithParams(ctx context.Context, p adminstore.UpdateModelParams) error {
	return errStub
}
func (s *stubStore) UpdateModelEnabled(ctx context.Context, modelName string, enabled bool) error {
	return errStub
}
func (s *stubStore) DeleteModel(ctx context.Context, modelName string) error { return errStub }
func (s *stubStore) CreateRoutingRule(ctx context.Context, orgID, matchExpr, targetModel string, priority int) (*adminstore.RoutingRule, error) {
	return nil, errStub
}
func (s *stubStore) GetRoutingRuleByID(ctx context.Context, id string) (*adminstore.RoutingRule, error) {
	return nil, errStub
}
func (s *stubStore) ListRoutingRulesByOrg(ctx context.Context, orgID string, f adminstore.PageFilter) ([]*adminstore.RoutingRule, int64, error) {
	return nil, 0, errStub
}
func (s *stubStore) UpdateRoutingRule(ctx context.Context, id, matchExpr, targetModel string, priority *int) error {
	return errStub
}
func (s *stubStore) UpdateRoutingRuleEnabled(ctx context.Context, id string, enabled bool) error {
	return errStub
}
func (s *stubStore) DeleteRoutingRule(ctx context.Context, id string) error { return errStub }
func (s *stubStore) AddKeyWhitelist(ctx context.Context, apiKeyID, modelName string, allowed bool) (*adminstore.WhitelistEntry, error) {
	return nil, errStub
}
func (s *stubStore) ListKeyWhitelist(ctx context.Context, apiKeyID string, f adminstore.PageFilter) ([]*adminstore.WhitelistEntry, int64, error) {
	return nil, 0, errStub
}
func (s *stubStore) DeleteKeyWhitelist(ctx context.Context, apiKeyID, modelName string) error {
	return errStub
}
func (s *stubStore) AddTeamWhitelist(ctx context.Context, teamID, modelName string, allowed bool) (*adminstore.WhitelistEntry, error) {
	return nil, errStub
}
func (s *stubStore) ListTeamWhitelist(ctx context.Context, teamID string, f adminstore.PageFilter) ([]*adminstore.WhitelistEntry, int64, error) {
	return nil, 0, errStub
}
func (s *stubStore) DeleteTeamWhitelist(ctx context.Context, teamID, modelName string) error {
	return errStub
}
func (s *stubStore) GetRequestLogStats(ctx context.Context, orgID *string, since time.Time) (*adminstore.RequestLogStats, error) {
	return nil, errStub
}
func (s *stubStore) TopModels(ctx context.Context, orgID *string, limit int) ([]adminstore.TopModelCount, error) {
	return nil, errStub
}
func (s *stubStore) TopOrgs(ctx context.Context, limit int) ([]adminstore.TopOrgCount, error) {
	return nil, errStub
}
func (s *stubStore) RequestTimeSeries(ctx context.Context, orgID *string, since time.Time, interval string) ([]adminstore.TimeSeriesPoint, error) {
	return nil, errStub
}
func (s *stubStore) ErrorBreakdown(ctx context.Context, orgID *string, since time.Time) ([]adminstore.ErrorBreakdownEntry, error) {
	return nil, errStub
}
func (s *stubStore) LatencyPercentiles(ctx context.Context, orgID *string, since time.Time) (*adminstore.LatencyPercentile, error) {
	return nil, errStub
}
func (s *stubStore) RecentErrors(ctx context.Context, orgID *string, limit int) ([]adminstore.RecentErrorLog, error) {
	return nil, errStub
}
func (s *stubStore) GetCostAnalytics(ctx context.Context, orgID string, from, to time.Time, provider string) (*adminstore.CostReport, error) {
	return nil, errStub
}
func (s *stubStore) GetGlobalCostStats(ctx context.Context, from, to time.Time) (*adminstore.CostReport, error) {
	return nil, errStub
}
func (s *stubStore) ListRequests(ctx context.Context, f adminstore.RequestListFilters) ([]adminstore.RequestListRow, int, error) {
	return nil, 0, errStub
}
func (s *stubStore) GetToolCallsReport(ctx context.Context, orgID string, days int) (*adminstore.ToolCallsReport, error) {
	return &adminstore.ToolCallsReport{}, nil
}

func (s *stubStore) RequestStats(ctx context.Context, f adminstore.RequestListFilters) (*adminstore.RequestListStats, error) {
	return nil, errStub
}
func (s *stubStore) GetRequestDetail(ctx context.Context, orgID, requestID string) (*adminstore.RequestDetail, error) {
	return nil, errStub
}
func (s *stubStore) GetTaskAnalytics(ctx context.Context, orgID string, from, to time.Time, groupBy string, limit int) (*adminstore.TaskAnalyticsReport, error) {
	return nil, errStub
}
func (s *stubStore) GetShadowComparison(ctx context.Context, orgID string, days int) (*adminstore.ShadowComparison, error) {
	return &adminstore.ShadowComparison{
		PrimaryModel: "gpt-4o-mini",
		ShadowModel:  "gpt-4o",
		Overlap:      5,
		Verdict:      "insufficient_data",
		ByModel:      []adminstore.ShadowModelCompare{},
	}, nil
}
func (s *stubStore) RunAnalyticsQuery(ctx context.Context, q *adminstore.AnalyticsQuery) (*adminstore.AnalyticsResult, error) {
	return nil, errStub
}
func (s *stubStore) ListLabelKeys(ctx context.Context, orgID string, from, to time.Time) ([]adminstore.LabelKeyStat, error) {
	return nil, errStub
}
func (s *stubStore) GetQualityScores(ctx context.Context, orgID string, from, to time.Time) (*adminstore.QualityReport, error) {
	return &adminstore.QualityReport{Verdict: "insufficient_data", ByModel: []adminstore.QualityModelScore{}, ByTaskClass: []adminstore.QualityTaskClassScore{}}, nil
}
func (s *stubStore) CreateAgentProfile(ctx context.Context, p adminstore.AgentProfileCreateParams) (*adminstore.AgentProfile, error) {
	return nil, errStub
}
func (s *stubStore) GetAgentProfile(ctx context.Context, id string) (*adminstore.AgentProfile, error) {
	return nil, errStub
}
func (s *stubStore) ListAgentProfiles(ctx context.Context, orgID string) ([]*adminstore.AgentProfile, error) {
	return nil, errStub
}
func (s *stubStore) UpdateAgentProfile(ctx context.Context, id string, p adminstore.AgentProfileUpdateParams) (*adminstore.AgentProfile, error) {
	return nil, errStub
}
func (s *stubStore) DeleteAgentProfile(ctx context.Context, id string) error {
	return errStub
}
func (s *stubStore) CreateOrgMembership(ctx context.Context, m adminstore.OrgMembership) (*adminstore.OrgMembership, error) {
	return nil, errStub
}
func (s *stubStore) SetOrgMembership(ctx context.Context, userID, orgID string, role adminstore.OrgRole) (*adminstore.OrgMembership, error) {
	return nil, errStub
}
func (s *stubStore) DeleteOrgMembership(ctx context.Context, userID, orgID string) error {
	return errStub
}
func (s *stubStore) GetUserOrgRoles(ctx context.Context, userID string) (map[string]adminstore.OrgRole, error) {
	return nil, errStub
}
func (s *stubStore) ListOrgMembers(ctx context.Context, orgID string) ([]*adminstore.OrgMembership, error) {
	return nil, errStub
}

func (s *stubStore) GetSavingsReport(ctx context.Context, orgID string, days int, provider string) (*adminstore.SavingsReport, error) {
	return nil, errStub
}
func (s *stubStore) CreatePricing(ctx context.Context, p adminstore.CreatePricingParams) (*adminstore.PricingEntry, error) {
	return nil, errStub
}
func (s *stubStore) UpdatePricing(ctx context.Context, p adminstore.UpdatePricingParams) (*adminstore.PricingEntry, error) {
	return nil, errStub
}
func (s *stubStore) DeletePricing(ctx context.Context, id int64) error { return errStub }
func (s *stubStore) ListPricing(ctx context.Context, opts adminstore.ListPricingOptions) ([]adminstore.PricingEntry, error) {
	return nil, errStub
}
func (s *stubStore) ImportCatalogPricing(context.Context, pricing.PriceFile, []adminstore.CatalogPriceMap, bool, bool, string) (adminstore.CatalogImportResult, error) {
	return adminstore.CatalogImportResult{}, errStub
}
func (s *stubStore) ListModelAliases(context.Context) ([]adminstore.ModelAlias, error) {
	return nil, errStub
}
func (s *stubStore) CreateModelAlias(context.Context, string, string) (*adminstore.ModelAlias, error) {
	return nil, errStub
}
func (s *stubStore) DeleteModelAlias(context.Context, string) error { return errStub }
func (s *stubStore) GetOrgSpendAlertSettings(ctx context.Context, orgID string) (*adminstore.OrgSpendAlertSettings, error) {
	return nil, errStub
}
func (s *stubStore) UpdateOrgSpendAlertSettings(ctx context.Context, orgID string, threshold *float64, webhookURL *string) error {
	return errStub
}
func (s *stubStore) ListOrgsWithSpendAlerts(ctx context.Context) ([]adminstore.SpendAlertOrg, error) {
	return nil, errStub
}
func (s *stubStore) SpendToday(ctx context.Context, orgID string) (float64, error) { return 0, errStub }
func (s *stubStore) UpdateLastAlertAt(ctx context.Context, orgID string, at time.Time) error {
	return errStub
}
func (s *stubStore) GetTeamSpendSummary(ctx context.Context, teamID string) (*adminstore.TeamSpendSummary, error) {
	return nil, errStub
}
func (s *stubStore) UpsertTeamBudget(ctx context.Context, teamID string, monthlyLimit float64, hardLimit bool) error {
	return errStub
}
func (s *stubStore) DeleteTeamBudget(ctx context.Context, teamID string) error { return errStub }
func (s *stubStore) ListTeamBudgetsByOrg(ctx context.Context, orgID string) ([]adminstore.TeamSpendSummary, error) {
	return nil, errStub
}
