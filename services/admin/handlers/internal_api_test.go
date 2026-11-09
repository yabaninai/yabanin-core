package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// internalFakeStore implements only the two methods the /internal group uses;
// the embedded nil StoreInterface would panic if anything else were called.
type internalFakeStore struct {
	StoreInterface
	keys     []*adminstore.APIKey
	savings  *adminstore.SavingsReport
	cost     *adminstore.CostReport
	lastOrg  string
	lastDays int
}

func (f *internalFakeStore) ListAPIKeys(_ context.Context, orgID *string, _ adminstore.PageFilter) ([]*adminstore.APIKey, int64, error) {
	if orgID != nil {
		f.lastOrg = *orgID
	}
	return f.keys, int64(len(f.keys)), nil
}

func (f *internalFakeStore) GetShadowComparison(_ context.Context, _ string, _ int) (*adminstore.ShadowComparison, error) {
	return &adminstore.ShadowComparison{Verdict: "insufficient_data", ByModel: []adminstore.ShadowModelCompare{}}, nil
}

func (f *internalFakeStore) GetQualityScores(_ context.Context, _ string, _, _ time.Time) (*adminstore.QualityReport, error) {
	return &adminstore.QualityReport{Verdict: "insufficient_data", ByModel: []adminstore.QualityModelScore{}, ByTaskClass: []adminstore.QualityTaskClassScore{}}, nil
}
func (f *internalFakeStore) CreateAgentProfile(_ context.Context, p adminstore.AgentProfileCreateParams) (*adminstore.AgentProfile, error) {
	return &adminstore.AgentProfile{ID: "profile-1", OrgID: p.OrgID, Name: p.Name}, nil
}
func (f *internalFakeStore) GetAgentProfile(_ context.Context, id string) (*adminstore.AgentProfile, error) {
	return nil, fmt.Errorf("profile not found")
}
func (f *internalFakeStore) ListAgentProfiles(_ context.Context, orgID string) ([]*adminstore.AgentProfile, error) {
	return nil, nil
}
func (f *internalFakeStore) UpdateAgentProfile(_ context.Context, id string, p adminstore.AgentProfileUpdateParams) (*adminstore.AgentProfile, error) {
	return nil, fmt.Errorf("profile not found")
}
func (f *internalFakeStore) DeleteAgentProfile(_ context.Context, id string) error {
	return fmt.Errorf("profile not found")
}
func (f *internalFakeStore) CreateOrgMembership(_ context.Context, m adminstore.OrgMembership) (*adminstore.OrgMembership, error) {
	return &adminstore.OrgMembership{ID: "mem-1", UserID: m.UserID, OrgID: m.OrgID, Role: m.Role}, nil
}
func (f *internalFakeStore) SetOrgMembership(_ context.Context, userID, orgID string, role adminstore.OrgRole) (*adminstore.OrgMembership, error) {
	return &adminstore.OrgMembership{ID: "mem-1", UserID: userID, OrgID: orgID, Role: role}, nil
}
func (f *internalFakeStore) DeleteOrgMembership(_ context.Context, userID, orgID string) error {
	return nil
}
func (f *internalFakeStore) GetUserOrgRoles(_ context.Context, userID string) (map[string]adminstore.OrgRole, error) {
	return map[string]adminstore.OrgRole{}, nil
}
func (f *internalFakeStore) ListOrgMembers(_ context.Context, orgID string) ([]*adminstore.OrgMembership, error) {
	return nil, nil
}

func (f *internalFakeStore) GetSavingsReport(_ context.Context, orgID string, days int, _ string) (*adminstore.SavingsReport, error) {
	f.lastOrg = orgID
	f.lastDays = days
	return f.savings, nil
}

func (f *internalFakeStore) GetCostAnalytics(_ context.Context, orgID string, _, _ time.Time, _ string) (*adminstore.CostReport, error) {
	f.lastOrg = orgID
	return f.cost, nil
}

func newInternalTestServer(t *testing.T, store *internalFakeStore, key string) *httptest.Server {
	t.Helper()
	h := New(store, "test-secret-32-bytes-long-here!!", "", []string{})
	if key != "" {
		h.SetInternalServiceKey(key)
	}
	srv := httptest.NewServer(h.SetupRouter())
	t.Cleanup(srv.Close)
	return srv
}

func TestInternalAPI_RequiresKey(t *testing.T) {
	store := internalFakeStore{keys: []*adminstore.APIKey{{ID: "k1", Name: "deploy-key"}}}
	srv := newInternalTestServer(t, &store, "svc-test-key")

	get := func(key string) int {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/internal/api-keys?org_id=o1", nil)
		require.NoError(t, err)
		if key != "" {
			req.Header.Set("X-Admin-Key", key)
		}
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		code := resp.StatusCode
		require.NoError(t, resp.Body.Close())
		return code
	}

	assert.Equal(t, http.StatusUnauthorized, get(""), "missing header must be rejected")
	assert.Equal(t, http.StatusUnauthorized, get("wrong-key"), "wrong key must be rejected")
	assert.Equal(t, http.StatusOK, get("svc-test-key"), "configured key must pass")
}

func TestInternalAPI_OrgIDRequired(t *testing.T) {
	srv := newInternalTestServer(t, &internalFakeStore{}, "svc-test-key")

	for _, path := range []string{"/internal/api-keys", "/internal/analytics/savings", "/internal/analytics/cost"} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+path, nil)
		require.NoError(t, err)
		req.Header.Set("X-Admin-Key", "svc-test-key")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)

		raw, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "path %s without org_id must be 400", path)
		assert.Contains(t, string(raw), "org_id")
	}
}

func TestInternalAPI_ListKeysSuccess(t *testing.T) {
	store := internalFakeStore{keys: []*adminstore.APIKey{
		{ID: "k1", Name: "deploy-key", Active: true},
		{ID: "k2", Name: "ci-key", Active: false},
	}}
	srv := newInternalTestServer(t, &store, "svc-test-key")

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/internal/api-keys?org_id=o1", nil)
	require.NoError(t, err)
	req.Header.Set("X-Admin-Key", "svc-test-key")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var out paginatedResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, int64(2), out.Pagination.Total)
	assert.Len(t, out.Data.([]interface{}), 2)
	assert.Equal(t, "o1", store.lastOrg, "store must receive the requested org only")
}

func TestInternalAPI_SavingsSuccess(t *testing.T) {
	store := internalFakeStore{savings: &adminstore.SavingsReport{Period: "7d", TotalRequests: 42}}
	srv := newInternalTestServer(t, &store, "svc-test-key")

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/internal/analytics/savings?org_id=o9&days=30", nil)
	require.NoError(t, err)
	req.Header.Set("X-Admin-Key", "svc-test-key")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Contains(t, string(raw), `"total_requests":42`)
	assert.Equal(t, "o9", store.lastOrg)
	assert.Equal(t, 30, store.lastDays, "days query param must be forwarded")
}

func TestInternalAPI_CostSuccess(t *testing.T) {
	store := internalFakeStore{cost: &adminstore.CostReport{TotalCostUSD: 1.25, RequestCount: 7}}
	srv := newInternalTestServer(t, &store, "svc-test-key")

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/internal/analytics/cost?org_id=o7&days=14", nil)
	require.NoError(t, err)
	req.Header.Set("X-Admin-Key", "svc-test-key")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Contains(t, string(raw), `"total_cost_usd":1.25`, "cost report must surface the cost field")
	assert.Contains(t, string(raw), `"request_count":7`)
	assert.Equal(t, "o7", store.lastOrg, "store must receive the requested org only")
}

func TestInternalAPI_NotMountedWithoutKey(t *testing.T) {
	srv := newInternalTestServer(t, &internalFakeStore{}, "")

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/internal/api-keys?org_id=o1", nil)
	require.NoError(t, err)
	req.Header.Set("X-Admin-Key", "anything")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	// No service key → no standalone /internal group: the path falls through to
	// the session-authenticated SPA catch-all (r.Mount("/", protected)) and is
	// rejected for lacking a session cookie. The header-only surface must not
	// exist, so a plausible X-Admin-Key value never yields 200 here.
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "request must fail session auth, not reach a service group")
}

// AF-07: one fixture through the handler — unknown coverage must reach the
// wire as explicit metadata (coverage_status + null share), never as an
// unmarked fully-priced report. (client.ts + pages consume it in a separate
// UI slice.)
func TestInternalAPI_PricingCoverageFixture(t *testing.T) {
	share := 0.4
	store := internalFakeStore{
		savings: &adminstore.SavingsReport{Period: "7d", TotalRequests: 42,
			Pricing: adminstore.PricingMetadata{
				PricingAsOf:    "file 2026-09-30 sha256:abc",
				CoverageStatus: adminstore.CoverageUnknown,
				CoverageError:  "coverage query failed",
				UnpricedModels: []string{},
			}},
		cost: &adminstore.CostReport{TotalCostUSD: 1.25, RequestCount: 5,
			Pricing: adminstore.PricingMetadata{
				PricingAsOf:    "file 2026-09-30 sha256:abc",
				CoverageStatus: adminstore.CoveragePartial,
				UnpricedShare:  &share,
				UnpricedModels: []string{"m1"},
			}},
	}
	srv := newInternalTestServer(t, &store, "svc-test-key")

	get := func(path string) string {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+path, nil)
		require.NoError(t, err)
		req.Header.Set("X-Admin-Key", "svc-test-key")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		raw, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return string(raw)
	}

	savings := get("/internal/analytics/savings?org_id=o9&days=30")
	assert.Contains(t, savings, `"coverage_status":"unknown"`)
	assert.Contains(t, savings, `"unpriced_share":null`,
		"unmeasured coverage must serialize as explicit null, not 0")
	assert.Contains(t, savings, `"coverage_error":"coverage query failed"`)
	assert.NotContains(t, savings, `"unpriced_share":0`,
		"a failed measurement must not look like fully priced")
	assert.Contains(t, savings, `"pricing_as_of":"file 2026-09-30 sha256:abc"`,
		"provenance travels separately from the failure marker")

	cost := get("/internal/analytics/cost?org_id=o7&days=14")
	assert.Contains(t, cost, `"coverage_status":"partial"`)
	assert.Contains(t, cost, `"unpriced_share":0.4`)
	assert.NotContains(t, cost, `"coverage_error"`,
		"a successful measurement carries no failure marker")
}
