package handlers

// W-CAPS acceptance: rights matrix (root; org-admin with budgets.manage;
// member without budgets.manage → 403; foreign org → 404 without leaking
// existence), range validation, null-clears-override semantics, mandatory
// reason, the audit journal before/after fact, and the org-scope isolation
// contract (another org's caps are neither readable nor writable here).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
)

func capsTestRouter(t *testing.T, h *AdminHandlers) chi.Router {
	t.Helper()
	r := chi.NewRouter()
	h.mountOrgCapsRoutes(r)
	return r
}

// ---- mockStore capability methods (mockStore satisfies StoreInterface in
// handler_test.go; the W-CAPS methods live here with the card that needs
// them). State rides package-level maps because mockStore's struct lives in
// another test file; package tests run sequentially (no t.Parallel). ----

var (
	orgCapsRows   = map[string]*adminstore.OrgCaps{}
	orgCapsSpends = map[string]int64{}
)

func resetOrgCapsState() {
	orgCapsRows = map[string]*adminstore.OrgCaps{}
	orgCapsSpends = map[string]int64{}
}

func (m *mockStore) EffectiveOrgCaps(_ context.Context, orgID string) (*adminstore.EffectiveOrgCaps, error) {
	if _, ok := m.orgs[orgID]; !ok {
		return nil, fmt.Errorf("org not found: %s: %w", orgID, adminstore.ErrNotFound)
	}
	eff := &adminstore.EffectiveOrgCaps{
		OrgID:              orgID,
		RPM:                adminstore.DefaultOrgCapsRPM,
		TPM:                adminstore.DefaultOrgCapsTPM,
		MonthlyBudgetCents: adminstore.DefaultOrgCapsMonthlyBudgetCents,
		InputTPM:           0,
		OutputTPM:          0,
		KeyTPM:             0,
	}
	if row, ok := orgCapsRows[orgID]; ok {
		eff.RPMOverride, eff.TPMOverride, eff.BudgetOverrideCents = row.RPM, row.TPM, row.MonthlyBudgetCents
		eff.InputTPMOverride, eff.OutputTPMOverride, eff.KeyTPMOverride =
			row.InputTokensPerMin, row.OutputTokensPerMin, row.KeyTokensPerMin
		if row.RPM != nil {
			eff.RPM = *row.RPM
		}
		if row.TPM != nil {
			eff.TPM = *row.TPM
		}
		if row.MonthlyBudgetCents != nil {
			eff.MonthlyBudgetCents = *row.MonthlyBudgetCents
		}
		if row.InputTokensPerMin != nil {
			eff.InputTPM = *row.InputTokensPerMin
		}
		if row.OutputTokensPerMin != nil {
			eff.OutputTPM = *row.OutputTokensPerMin
		}
		if row.KeyTokensPerMin != nil {
			eff.KeyTPM = *row.KeyTokensPerMin
		}
	}
	return eff, nil
}

func (m *mockStore) UpdateOrgCaps(_ context.Context, orgID string, u adminstore.OrgCapsUpdate) error {
	if _, ok := m.orgs[orgID]; !ok {
		return fmt.Errorf("org not found: %s: %w", orgID, adminstore.ErrNotFound)
	}
	if err := adminstore.ValidateOrgCapsUpdate(u); err != nil {
		return err
	}
	orgCapsRows[orgID] = &adminstore.OrgCaps{
		OrgID:              orgID,
		RPM:                u.RPM,
		TPM:                u.TPM,
		MonthlyBudgetCents: u.MonthlyBudgetCents,
		InputTokensPerMin:  u.InputTPM,
		OutputTokensPerMin: u.OutputTPM,
		KeyTokensPerMin:    u.KeyTPM,
	}
	return nil
}

func (m *mockStore) OrgMonthSpendCents(_ context.Context, orgID string) (int64, error) {
	if _, ok := m.orgs[orgID]; !ok {
		return 0, fmt.Errorf("org not found: %s: %w", orgID, adminstore.ErrNotFound)
	}
	return orgCapsSpends[orgID], nil
}

func capsFixture(t *testing.T) (*mockStore, *testAdminHandlers, chi.Router) {
	t.Helper()
	resetOrgCapsState()
	store := newMockStore()
	store.orgs["org-1"] = &adminstore.Organization{ID: "org-1", Name: "Org One", Slug: "org-one"}
	store.orgs["org-2"] = &adminstore.Organization{ID: "org-2", Name: "Org Two", Slug: "org-two"}
	store.orgMembers["u-admin/org-1"] = &adminstore.OrgMembership{UserID: "u-admin", OrgID: "org-1", Role: adminstore.RoleOrgAdmin}
	store.orgMembers["u-reader/org-1"] = &adminstore.OrgMembership{UserID: "u-reader", OrgID: "org-1", Role: adminstore.RoleReader}
	h := newTestAdminH(store)
	return store, h, capsTestRouter(t, h.AdminHandlers)
}

func capsRequest(r chi.Router, userID string, root bool, method, target, body, orgHeader string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if orgHeader != "" {
		req.Header.Set(OrgHeader, orgHeader)
	}
	if userID != "" {
		ctx := req.Context()
		ctx = context.WithValue(ctx, adminauth.ContextKeyUserID{}, userID)
		ctx = context.WithValue(ctx, adminauth.ContextKeyEmail{}, userID+"@x.test")
		ctx = context.WithValue(ctx, adminauth.ContextKeyIsRoot{}, root)
		req = req.WithContext(ctx)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestOrgCaps_RightsMatrix(t *testing.T) {
	_, _, r := capsFixture(t)

	t.Run("root reads and writes any org", func(t *testing.T) {
		rec := capsRequest(r, "admin-root", true, http.MethodGet, "/api/orgs/org-2/caps", "", "")
		require.Equal(t, http.StatusOK, rec.Code)
		var out orgCapsResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
		assert.Equal(t, adminstore.DefaultOrgCapsRPM, out.RPM, "no overrides yet — the beta default applies")
		assert.Equal(t, adminstore.DefaultOrgCapsTPM, out.TPM)
		assert.Equal(t, adminstore.DefaultOrgCapsMonthlyBudgetCents, out.MonthlyBudgetCents)
		assert.False(t, out.BudgetExceeded)

		rec = capsRequest(r, "admin-root", true, http.MethodPut, "/api/orgs/org-2/caps",
			`{"rpm": 120, "tpm": 400000, "monthly_budget_cents": 10000000, "reason": "scale-up"}`, "")
		require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
		assert.Equal(t, int64(120), out.RPM)
		assert.Equal(t, int64(400000), out.TPM)
		assert.Equal(t, int64(10000000), out.MonthlyBudgetCents)
		require.NotNil(t, out.RPMOverride)
	})

	t.Run("org-admin with budgets.manage manages own org", func(t *testing.T) {
		rec := capsRequest(r, "u-admin", false, http.MethodGet, "/api/orgs/org-1/caps", "", "org-1")
		require.Equal(t, http.StatusOK, rec.Code)

		rec = capsRequest(r, "u-admin", false, http.MethodPut, "/api/orgs/org-1/caps",
			`{"monthly_budget_cents": 25000000, "reason": "pilot tier"}`, "org-1")
		require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
		var out orgCapsResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
		assert.Equal(t, int64(25000000), out.MonthlyBudgetCents)
		assert.Equal(t, adminstore.DefaultOrgCapsRPM, out.RPM, "untouched dimensions stay on the beta default")
	})

	t.Run("member without budgets.manage gets 403", func(t *testing.T) {
		rec := capsRequest(r, "u-reader", false, http.MethodGet, "/api/orgs/org-1/caps", "", "org-1")
		assert.Equal(t, http.StatusForbidden, rec.Code)

		rec = capsRequest(r, "u-reader", false, http.MethodPut, "/api/orgs/org-1/caps",
			`{"rpm": 1, "reason": "should not pass"}`, "org-1")
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("foreign org gets 404 without leaking existence (org-scope)", func(t *testing.T) {
		// u-admin belongs to org-1 only: org-2's caps are neither visible
		// nor mutable through any identity u-admin holds.
		rec := capsRequest(r, "u-admin", false, http.MethodGet, "/api/orgs/org-2/caps", "", "org-1")
		assert.Equal(t, http.StatusNotFound, rec.Code)

		prev := orgCapsRows["org-2"]
		rec = capsRequest(r, "u-admin", false, http.MethodPut, "/api/orgs/org-2/caps",
			`{"rpm": 1, "reason": "cross-org probe"}`, "org-1")
		assert.Equal(t, http.StatusNotFound, rec.Code)
		assert.NotContains(t, rec.Body.String(), "org-2", "the org id must not be echoed back")
		if prev == nil {
			assert.Nil(t, orgCapsRows["org-2"], "a foreign-org PUT must not create a row")
		} else {
			assert.Same(t, prev, orgCapsRows["org-2"], "a foreign-org PUT must not mutate anything")
		}

		rec = capsRequest(r, "", false, http.MethodGet, "/api/orgs/org-1/caps", "", "")
		assert.Equal(t, http.StatusNotFound, rec.Code, "anonymous is blind")
	})
}

func TestOrgCaps_ValidationAndReason(t *testing.T) {
	_, _, r := capsFixture(t)

	tests := []struct {
		name string
		body string
		want int
	}{
		{"rpm below range", `{"rpm": 0, "reason": "x"}`, http.StatusBadRequest},
		{"rpm above range", `{"rpm": 10000001, "reason": "x"}`, http.StatusBadRequest},
		{"tpm below range", `{"tpm": -1, "reason": "x"}`, http.StatusBadRequest},
		{"budget below range", `{"monthly_budget_cents": 0, "reason": "x"}`, http.StatusBadRequest},
		{"budget above range", `{"monthly_budget_cents": 1000000001, "reason": "x"}`, http.StatusBadRequest},
		{"input tpm below range", `{"input_tokens_per_min": 0, "reason": "x"}`, http.StatusBadRequest},
		{"output tpm above range", `{"output_tokens_per_min": 10000001, "reason": "x"}`, http.StatusBadRequest},
		{"per-key tpm below range", `{"key_tokens_per_min": -3, "reason": "x"}`, http.StatusBadRequest},
		{"min bounds valid", `{"rpm": 1, "tpm": 1, "monthly_budget_cents": 1, "input_tokens_per_min": 1, "output_tokens_per_min": 1, "key_tokens_per_min": 1, "reason": "x"}`, http.StatusOK},
		{"null clears overrides", `{"rpm": null, "tpm": null, "monthly_budget_cents": null, "input_tokens_per_min": null, "output_tokens_per_min": null, "key_tokens_per_min": null, "reason": "reset"}`, http.StatusOK},
		{"empty reason rejected", `{"rpm": 60}`, http.StatusBadRequest},
		{"whitespace reason rejected", `{"rpm": 60, "reason": "   "}`, http.StatusBadRequest},
		{"malformed body", `{not json}`, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := capsRequest(r, "u-admin", false, http.MethodPut, "/api/orgs/org-1/caps", tt.body, "org-1")
			assert.Equal(t, tt.want, rec.Code, "body: %s", rec.Body.String())
		})
	}

	// Unknown org stays a 404, never a 500.
	rec := capsRequest(r, "admin-root", true, http.MethodGet, "/api/orgs/nope/caps", "", "")
	assert.Equal(t, http.StatusNotFound, rec.Code)
	rec = capsRequest(r, "admin-root", true, http.MethodPut, "/api/orgs/nope/caps",
		`{"rpm": 60, "reason": "x"}`, "")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestOrgCaps_SplitTokenDimensionsRoundTrip(t *testing.T) {
	_, _, r := capsFixture(t)

	rec := capsRequest(r, "u-admin", false, http.MethodGet, "/api/orgs/org-1/caps", "", "org-1")
	require.Equal(t, http.StatusOK, rec.Code)
	var out orgCapsResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	assert.Zero(t, out.InputTokensPerMin, "no beta default — off until set")
	assert.Zero(t, out.OutputTokensPerMin)
	assert.Zero(t, out.KeyTokensPerMin)
	assert.Nil(t, out.InputTPMOverride)

	// Set all three; the response echoes effective + override.
	rec = capsRequest(r, "u-admin", false, http.MethodPut, "/api/orgs/org-1/caps",
		`{"input_tokens_per_min": 300000, "output_tokens_per_min": 100000, "key_tokens_per_min": 50000, "reason": "fair-share pilot"}`, "org-1")
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	assert.Equal(t, int64(300000), out.InputTokensPerMin)
	assert.Equal(t, int64(100000), out.OutputTokensPerMin)
	assert.Equal(t, int64(50000), out.KeyTokensPerMin)
	require.NotNil(t, out.InputTPMOverride)
	require.NotNil(t, out.OutputTPMOverride)
	require.NotNil(t, out.KeyTPMOverride)

	// Clearing lands back on OFF (never unlimited).
	rec = capsRequest(r, "u-admin", false, http.MethodPut, "/api/orgs/org-1/caps",
		`{"input_tokens_per_min": null, "output_tokens_per_min": null, "key_tokens_per_min": null, "reason": "disable split windows"}`, "org-1")
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	assert.Zero(t, out.InputTokensPerMin)
	assert.Zero(t, out.OutputTokensPerMin)
	assert.Zero(t, out.KeyTokensPerMin)
	assert.Nil(t, out.InputTPMOverride)
}

func TestOrgCaps_BudgetExceededFlag(t *testing.T) {
	_, _, r := capsFixture(t)
	orgCapsSpends["org-1"] = adminstore.DefaultOrgCapsMonthlyBudgetCents + 1

	rec := capsRequest(r, "u-admin", false, http.MethodGet, "/api/orgs/org-1/caps", "", "org-1")
	require.Equal(t, http.StatusOK, rec.Code)
	var out orgCapsResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	assert.True(t, out.BudgetExceeded)
	assert.Equal(t, out.MonthSpendCents, orgCapsSpends["org-1"])
}

func TestOrgCaps_AuditJournal(t *testing.T) {
	store, _, r := capsFixture(t)

	rec := capsRequest(r, "u-admin", false, http.MethodPut, "/api/orgs/org-1/caps",
		`{"rpm": 90, "reason": "pilot headroom"}`, "org-1")
	require.Equal(t, http.StatusOK, rec.Code)

	store.auditMu.Lock()
	entry := store.auditRecords[len(store.auditRecords)-1]
	store.auditMu.Unlock()
	assert.Equal(t, "update", entry.Action)
	assert.Equal(t, "org_caps", entry.Resource)
	assert.Equal(t, "pilot headroom", entry.Reason)
	assert.Contains(t, entry.Details, "org-1")

	var before, after map[string]any
	require.NoError(t, json.Unmarshal([]byte(entry.Before), &before))
	require.NoError(t, json.Unmarshal([]byte(entry.After), &after))
	assert.InDelta(t, float64(adminstore.DefaultOrgCapsRPM), before["rpm"], 1e-9, "before: the beta default")
	assert.InDelta(t, float64(90), after["rpm"], 1e-9)
}
