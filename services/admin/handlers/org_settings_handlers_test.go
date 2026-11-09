package handlers

// NEXT-18f acceptance: rights matrix (root; org-admin with budgets.manage;
// member without budgets.manage; foreign org → 404 without leaking
// existence), range validation, NULL vs explicit 0 (AF-01 zero preserved),
// mandatory reason, and the audit-journal before/after + reason fact. The
// routes are exercised through mountOrgBudgetSettingsRoutes on a local chi

import (
	"context"
	"encoding/json"
	"errors"
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
	"github.com/reireirei/yabanin/pkg/credits"
)

// orgSettingsTestRouter mounts the NEXT-18f routes exactly as the hot-patched
// SetupRouter will (authenticated group, no extra middleware — the gates live
// in the handlers).
func orgSettingsTestRouter(t *testing.T, h *AdminHandlers) chi.Router {
	t.Helper()
	r := chi.NewRouter()
	h.mountOrgBudgetSettingsRoutes(r)
	return r
}

// orgSettingsRequest builds an authenticated request (same context keys the
// ChiAuthMiddleware sets) and runs it through the router.
func orgSettingsRequest(r chi.Router, userID string, root bool, method, target, body, orgHeader string) *httptest.ResponseRecorder {
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

// ---- mockStore capability methods (mockStore satisfies StoreInterface in
// handler_test.go; the NEXT-18f methods live here with the card that needs
// them). The org check mirrors the SQL gate: unknown org → ErrNotFound.
// Settings state rides package-level maps because mockStore's struct lives
// in another test file; package tests run sequentially (no t.Parallel). ----

var (
	orgSettingsGraceFloors = map[string]int64{}
	orgSettingsOutputCaps  = map[string]int64{}
	orgSettingsModes       = map[string]string{}
)

func resetOrgSettingsState() {
	orgSettingsGraceFloors = map[string]int64{}
	orgSettingsOutputCaps = map[string]int64{}
	orgSettingsModes = map[string]string{}
}

func (m *mockStore) GetOrgBudgetSettings(_ context.Context, orgID string) (*adminstore.OrgBudgetSettings, error) {
	if m.orgSettingsErr != nil {
		return nil, m.orgSettingsErr
	}
	if _, ok := m.orgs[orgID]; !ok {
		return nil, fmt.Errorf("organization not found: %s: %w", orgID, adminstore.ErrNotFound)
	}
	s := &adminstore.OrgBudgetSettings{
		OrgID:            orgID,
		ReservationsMode: adminstore.ReservationsOff,
	}
	if floor, ok := orgSettingsGraceFloors[orgID]; ok {
		v := floor
		s.GraceFloorCents = &v
	}
	if capTokens, ok := orgSettingsOutputCaps[orgID]; ok {
		v := capTokens
		s.DefaultOutputCapTokens = &v
	}
	if mode, ok := orgSettingsModes[orgID]; ok {
		s.ReservationsMode = mode
	}
	return s, nil
}

func (m *mockStore) UpdateOrgGraceFloor(_ context.Context, orgID string, floorCents *int64) error {
	if m.orgSettingsErr != nil {
		return m.orgSettingsErr
	}
	if _, ok := m.orgs[orgID]; !ok {
		return fmt.Errorf("organization not found: %s: %w", orgID, adminstore.ErrNotFound)
	}
	if floorCents == nil {
		delete(orgSettingsGraceFloors, orgID)
		return nil
	}
	orgSettingsGraceFloors[orgID] = *floorCents
	return nil
}

func (m *mockStore) UpdateOrgReservationsMode(_ context.Context, orgID, mode string) error {
	if _, ok := m.orgs[orgID]; !ok {
		return fmt.Errorf("organization not found: %s: %w", orgID, adminstore.ErrNotFound)
	}
	orgSettingsModes[orgID] = mode
	return nil
}

func (m *mockStore) UpdateOrgDefaultOutputCap(_ context.Context, orgID string, capTokens *int64) error {
	if _, ok := m.orgs[orgID]; !ok {
		return fmt.Errorf("organization not found: %s: %w", orgID, adminstore.ErrNotFound)
	}
	if capTokens == nil {
		delete(orgSettingsOutputCaps, orgID)
		return nil
	}
	orgSettingsOutputCaps[orgID] = *capTokens
	return nil
}

// orgSettingsFixture wires a mock store with two orgs and an org-admin of
// org-1 (u-admin), a reader on org-1 (u-reader) and root (admin-root, from
// newMockStore).
func orgSettingsFixture(t *testing.T) (*mockStore, *testAdminHandlers, chi.Router) {
	t.Helper()
	resetOrgSettingsState()
	store := newMockStore()
	store.orgs["org-1"] = &adminstore.Organization{ID: "org-1", Name: "Org One", Slug: "org-one"}
	store.orgs["org-2"] = &adminstore.Organization{ID: "org-2", Name: "Org Two", Slug: "org-two"}
	store.orgMembers["u-admin/org-1"] = &adminstore.OrgMembership{UserID: "u-admin", OrgID: "org-1", Role: adminstore.RoleOrgAdmin}
	store.orgMembers["u-reader/org-1"] = &adminstore.OrgMembership{UserID: "u-reader", OrgID: "org-1", Role: adminstore.RoleReader}
	h := newTestAdminH(store)
	return store, h, orgSettingsTestRouter(t, h.AdminHandlers)
}

func TestOrgGraceFloor_RightsMatrix(t *testing.T) {
	_, _, r := orgSettingsFixture(t)

	t.Run("root may read and write any org", func(t *testing.T) {
		rec := orgSettingsRequest(r, "admin-root", true, http.MethodGet, "/api/orgs/org-2/credits/grace", "", "")
		require.Equal(t, http.StatusOK, rec.Code)

		rec = orgSettingsRequest(r, "admin-root", true, http.MethodPut, "/api/orgs/org-2/credits/grace",
			`{"grace_floor_cents": -500, "reason": "contract allows overdraft"}`, "")
		require.Equal(t, http.StatusOK, rec.Code)
		var out orgBudgetSettingsResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
		require.NotNil(t, out.GraceFloorCents)
		assert.Equal(t, int64(-500), *out.GraceFloorCents)
		assert.Equal(t, int64(-500), out.EffectiveGraceFloorCents)
		assert.Nil(t, out.BalanceCents, "no credits store wired — balance stays unknown, never fabricated")
	})

	t.Run("org-admin with budgets.manage on own org", func(t *testing.T) {
		rec := orgSettingsRequest(r, "u-admin", false, http.MethodGet, "/api/orgs/org-1/credits/grace", "", "org-1")
		require.Equal(t, http.StatusOK, rec.Code)

		rec = orgSettingsRequest(r, "u-admin", false, http.MethodPut, "/api/orgs/org-1/credits/grace",
			`{"grace_floor_cents": 0, "reason": "no overdraft allowed"}`, "org-1")
		require.Equal(t, http.StatusOK, rec.Code)
		var out orgBudgetSettingsResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
		// AF-01: explicit 0 is preserved, not coerced to the default.
		require.NotNil(t, out.GraceFloorCents)
		assert.Equal(t, int64(0), *out.GraceFloorCents)
		assert.Equal(t, int64(0), out.EffectiveGraceFloorCents)
	})

	t.Run("member without budgets.manage gets 403", func(t *testing.T) {
		rec := orgSettingsRequest(r, "u-reader", false, http.MethodGet, "/api/orgs/org-1/credits/grace", "", "org-1")
		assert.Equal(t, http.StatusForbidden, rec.Code)

		rec = orgSettingsRequest(r, "u-reader", false, http.MethodPut, "/api/orgs/org-1/credits/grace",
			`{"grace_floor_cents": -1, "reason": "should not pass"}`, "org-1")
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("foreign org gets 404 without leaking existence", func(t *testing.T) {
		rec := orgSettingsRequest(r, "u-admin", false, http.MethodGet, "/api/orgs/org-2/credits/grace", "", "org-1")
		assert.Equal(t, http.StatusNotFound, rec.Code)

		rec = orgSettingsRequest(r, "u-admin", false, http.MethodPut, "/api/orgs/org-2/credits/grace",
			`{"grace_floor_cents": -1, "reason": "cross-org probe"}`, "org-1")
		assert.Equal(t, http.StatusNotFound, rec.Code)
		assert.NotContains(t, rec.Body.String(), "org-2", "the org id must not be echoed back")
	})

	t.Run("anonymous gets 404", func(t *testing.T) {
		rec := orgSettingsRequest(r, "", false, http.MethodGet, "/api/orgs/org-1/credits/grace", "", "")
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestOrgGraceFloor_Validation(t *testing.T) {
	_, _, r := orgSettingsFixture(t)

	tests := []struct {
		name string
		body string
		want int
	}{
		{"below range", `{"grace_floor_cents": -100001, "reason": "x"}`, http.StatusBadRequest},
		{"above range", `{"grace_floor_cents": 1, "reason": "x"}`, http.StatusBadRequest},
		{"min bound valid", `{"grace_floor_cents": -100000, "reason": "x"}`, http.StatusOK},
		{"zero valid", `{"grace_floor_cents": 0, "reason": "x"}`, http.StatusOK},
		{"null resets to default", `{"grace_floor_cents": null, "reason": "x"}`, http.StatusOK},
		{"empty reason rejected", `{"grace_floor_cents": -100}`, http.StatusBadRequest},
		{"whitespace reason rejected", `{"grace_floor_cents": -100, "reason": "   "}`, http.StatusBadRequest},
		{"malformed body", `{not json}`, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := orgSettingsRequest(r, "u-admin", false, http.MethodPut, "/api/orgs/org-1/credits/grace", tt.body, "org-1")
			assert.Equal(t, tt.want, rec.Code)
		})
	}

	// The X-Audit-Reason header satisfies the mandatory reason for API
	// consumers that keep the reason out of the body.
	rec := orgSettingsRequest(r, "u-admin", false, http.MethodPut, "/api/orgs/org-1/credits/grace",
		`{"grace_floor_cents": -200}`, "org-1")
	require.Equal(t, http.StatusBadRequest, rec.Code, "no header, no body reason → rejected")

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/api/orgs/org-1/credits/grace",
		strings.NewReader(`{"grace_floor_cents": -200}`))
	req.Header.Set(OrgHeader, "org-1")
	req.Header.Set(auditReasonHeader, "ops ticket 42")
	ctx := req.Context()
	ctx = context.WithValue(ctx, adminauth.ContextKeyUserID{}, "u-admin")
	ctx = context.WithValue(ctx, adminauth.ContextKeyEmail{}, "u-admin@x.test")
	req = req.WithContext(ctx)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestOrgReservationsMode_RootOnlyAndValidation(t *testing.T) {
	_, h, r := orgSettingsFixture(t)
	h.SetReservationsGate("shadow")

	// Org-admin (even with budgets.manage) may read but not switch.
	rec := orgSettingsRequest(r, "u-admin", false, http.MethodGet, "/api/orgs/org-1/credits/grace", "", "org-1")
	require.Equal(t, http.StatusOK, rec.Code)
	var out orgBudgetSettingsResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	assert.Equal(t, adminstore.ReservationsOff, out.ReservationsMode)
	assert.Equal(t, adminstore.ReservationsOff, out.SavedReservationsMode)
	assert.Equal(t, adminstore.ReservationsOff, out.EffectiveReservationsMode)

	rec = orgSettingsRequest(r, "u-admin", false, http.MethodPut, "/api/orgs/org-1/reservations-mode",
		`{"mode": "shadow", "reason": "x"}`, "org-1")
	assert.Equal(t, http.StatusForbidden, rec.Code)

	// Root switches with a reason; the response echoes the mode; rolling
	// back to off is accepted (immediate, nothing to drain).
	for _, mode := range []string{adminstore.ReservationsShadow, adminstore.ReservationsEnforce, adminstore.ReservationsOff} {
		rec := orgSettingsRequest(r, "admin-root", true, http.MethodPut, "/api/orgs/org-1/reservations-mode",
			`{"mode": "`+mode+`", "reason": "rollout step"}`, "")
		require.Equal(t, http.StatusOK, rec.Code)
		var out orgBudgetSettingsResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
		assert.Equal(t, mode, out.ReservationsMode)
		assert.Equal(t, mode, out.SavedReservationsMode)
		wantEffective := mode
		if mode == adminstore.ReservationsEnforce {
			wantEffective = adminstore.ReservationsShadow
		}
		assert.Equal(t, wantEffective, out.EffectiveReservationsMode)
	}

	// Invalid mode and empty reason are rejected.
	rec = orgSettingsRequest(r, "admin-root", true, http.MethodPut, "/api/orgs/org-1/reservations-mode",
		`{"mode": "enforce_now", "reason": "x"}`, "")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	rec = orgSettingsRequest(r, "admin-root", true, http.MethodPut, "/api/orgs/org-1/reservations-mode",
		`{"mode": "enforce"}`, "")
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// The root-only switch answers 403 to any non-root caller (a blanket
	// refusal leaks nothing about the org).
	rec = orgSettingsRequest(r, "u-admin", false, http.MethodPut, "/api/orgs/org-2/reservations-mode",
		`{"mode": "off", "reason": "x"}`, "org-1")
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// TestOrgReservationsMode_EffectiveModeSemantics pins the N06-P03/T06 API
// contract: saved_reservations_mode carries the stored column verbatim,
// effective_reservations_mode is what runtime admission applies after the
// deployment gate — the gate only clamps DOWN (enforce→shadow→off), an
// unknown stored value fails closed to off, and the legacy reservations_mode
// field keeps its stored meaning (backward compatibility).
func TestOrgReservationsMode_EffectiveModeSemantics(t *testing.T) {
	tests := []struct {
		name          string
		gate          string
		stored        string
		wantEffective string
	}{
		{"no clamp: enforce gate keeps stored enforce", adminstore.ReservationsEnforce, adminstore.ReservationsEnforce, adminstore.ReservationsEnforce},
		{"no clamp: enforce gate keeps stored shadow", adminstore.ReservationsEnforce, adminstore.ReservationsShadow, adminstore.ReservationsShadow},
		{"clamp down: shadow gate degrades stored enforce", adminstore.ReservationsShadow, adminstore.ReservationsEnforce, adminstore.ReservationsShadow},
		{"clamp down: off gate degrades stored enforce (nothing denied)", adminstore.ReservationsOff, adminstore.ReservationsEnforce, adminstore.ReservationsOff},
		{"clamp down: off gate degrades stored shadow", adminstore.ReservationsOff, adminstore.ReservationsShadow, adminstore.ReservationsOff},
		{"fail-closed: unknown stored value resolves to off", adminstore.ReservationsEnforce, "enforce_mistyped", adminstore.ReservationsOff},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, h, r := orgSettingsFixture(t)
			h.SetReservationsGate(tt.gate)
			orgSettingsModes["org-1"] = tt.stored

			rec := orgSettingsRequest(r, "admin-root", true, http.MethodGet, "/api/orgs/org-1/credits/grace", "", "")
			require.Equal(t, http.StatusOK, rec.Code)
			var out orgBudgetSettingsResponse
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
			assert.Equal(t, tt.stored, out.SavedReservationsMode, "saved echoes the stored column verbatim")
			assert.Equal(t, tt.stored, out.ReservationsMode, "legacy field keeps the stored meaning")
			assert.Equal(t, tt.wantEffective, out.EffectiveReservationsMode)
		})
	}

	// Unwired gate (zero value): clamps to off — the config default and the
	// admission fail-safe, never an upgrade of the stored mode.
	t.Run("unwired gate behaves as off", func(t *testing.T) {
		_, _, r := orgSettingsFixture(t)
		orgSettingsModes["org-1"] = adminstore.ReservationsEnforce
		rec := orgSettingsRequest(r, "admin-root", true, http.MethodGet, "/api/orgs/org-1/credits/grace", "", "")
		require.Equal(t, http.StatusOK, rec.Code)
		var out orgBudgetSettingsResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
		assert.Equal(t, adminstore.ReservationsOff, out.EffectiveReservationsMode)
	})
}

func TestOrgOutputCap_Validation(t *testing.T) {
	_, _, r := orgSettingsFixture(t)

	rec := orgSettingsRequest(r, "u-admin", false, http.MethodPut, "/api/orgs/org-1/output-cap",
		`{"default_output_cap_tokens": 4096, "reason": "stream cap"}`, "org-1")
	require.Equal(t, http.StatusOK, rec.Code)
	var out orgBudgetSettingsResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	require.NotNil(t, out.DefaultOutputCapTokens)
	assert.Equal(t, int64(4096), *out.DefaultOutputCapTokens)

	// Zero and negative are invalid; null clears the override.
	rec = orgSettingsRequest(r, "u-admin", false, http.MethodPut, "/api/orgs/org-1/output-cap",
		`{"default_output_cap_tokens": 0, "reason": "x"}`, "org-1")
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	rec = orgSettingsRequest(r, "u-admin", false, http.MethodPut, "/api/orgs/org-1/output-cap",
		`{"default_output_cap_tokens": null, "reason": "clear"}`, "org-1")
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	assert.Nil(t, out.DefaultOutputCapTokens)

	// Reader (no budgets.manage) is 403.
	rec = orgSettingsRequest(r, "u-reader", false, http.MethodPut, "/api/orgs/org-1/output-cap",
		`{"default_output_cap_tokens": 10, "reason": "x"}`, "org-1")
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestOrgBudgetSettings_AuditJournal(t *testing.T) {
	store, _, r := orgSettingsFixture(t)

	rec := orgSettingsRequest(r, "u-admin", false, http.MethodPut, "/api/orgs/org-1/credits/grace",
		`{"grace_floor_cents": -700, "reason": "contracted overdraft"}`, "org-1")
	require.Equal(t, http.StatusOK, rec.Code)

	store.auditMu.Lock()
	records := append([]adminstore.AuditLogEntryRecord(nil), store.auditRecords...)
	store.auditMu.Unlock()
	require.Len(t, records, 1)
	entry := records[0]
	assert.Equal(t, "update", entry.Action)
	assert.Equal(t, "org_grace_floor", entry.Resource)
	assert.Equal(t, "contracted overdraft", entry.Reason)
	assert.Contains(t, entry.Details, "org-1")

	var before, after map[string]any
	require.NoError(t, json.Unmarshal([]byte(entry.Before), &before))
	require.NoError(t, json.Unmarshal([]byte(entry.After), &after))
	assert.Nil(t, before["grace_floor_cents"], "before: no floor was set")
	require.NotNil(t, after["grace_floor_cents"])
	assert.InDelta(t, -700, after["grace_floor_cents"], 1e-9)

	// A second mutation records the previous value as before.
	rec = orgSettingsRequest(r, "u-admin", false, http.MethodPut, "/api/orgs/org-1/credits/grace",
		`{"grace_floor_cents": -300, "reason": "tightened"}`, "org-1")
	require.Equal(t, http.StatusOK, rec.Code)
	store.auditMu.Lock()
	entry = store.auditRecords[len(store.auditRecords)-1]
	store.auditMu.Unlock()
	require.NoError(t, json.Unmarshal([]byte(entry.Before), &before))
	assert.InDelta(t, -700, before["grace_floor_cents"], 1e-9)
}

func TestOrgBudgetSettings_UnknownOrg(t *testing.T) {
	_, _, r := orgSettingsFixture(t)

	// Root on a nonexistent org: the store returns not-found → 404, not 500.
	rec := orgSettingsRequest(r, "admin-root", true, http.MethodGet, "/api/orgs/nope/credits/grace", "", "")
	assert.Equal(t, http.StatusNotFound, rec.Code)

	rec = orgSettingsRequest(r, "admin-root", true, http.MethodPut, "/api/orgs/nope/credits/grace",
		`{"grace_floor_cents": -1, "reason": "x"}`, "")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestOrgGraceFloor_StoreOutage_NotSuccessNoJournal: a settings
// store outage on the grace-floor mutation answers 500, journals nothing
// and changes nothing (partial/unknown is never success); the same request
// retried after recovery answers 200 and journals exactly once. The GET
// outage answers 500 too — a settings block is never fabricated.
func TestOrgGraceFloor_StoreOutage_NotSuccessNoJournal(t *testing.T) {
	store, _, r := orgSettingsFixture(t)
	store.orgSettingsErr = errors.New("injected settings outage")

	rec := orgSettingsRequest(r, "u-admin", false, http.MethodPut, "/api/orgs/org-1/credits/grace",
		`{"grace_floor_cents": -500, "reason": "ops ticket"}`, "org-1")
	require.Equal(t, http.StatusInternalServerError, rec.Code, "an outage is a 500, not a fake success")

	store.auditMu.Lock()
	journaled := len(store.auditRecords)
	store.auditMu.Unlock()
	assert.Zero(t, journaled, "a failed mutation journals nothing")
	_, set := orgSettingsGraceFloors["org-1"]
	assert.False(t, set, "the floor is unchanged")

	rec = orgSettingsRequest(r, "u-admin", false, http.MethodGet, "/api/orgs/org-1/credits/grace", "", "org-1")
	assert.Equal(t, http.StatusInternalServerError, rec.Code, "a read outage is a 500, not a fabricated block")

	// Recovery retry: the same mutation succeeds and journals once.
	store.orgSettingsErr = nil
	rec = orgSettingsRequest(r, "u-admin", false, http.MethodPut, "/api/orgs/org-1/credits/grace",
		`{"grace_floor_cents": -500, "reason": "ops ticket"}`, "org-1")
	require.Equal(t, http.StatusOK, rec.Code)
	store.auditMu.Lock()
	journaled = len(store.auditRecords)
	store.auditMu.Unlock()
	assert.Equal(t, 1, journaled, "the retried mutation journals exactly once")
}

// (ratified 2026-10-16) — «нет настройки» on the grace floor means the
// platform default −$1.00, surfaced explicitly as
// effective_grace_floor_cents (an explicit outcome, not a silent value);
// an explicit 0 overrides it (AF-01).
func TestOrgBudgetSettings_NullFloorSurfacesPlatformDefault(t *testing.T) {
	_, _, r := orgSettingsFixture(t)

	rec := orgSettingsRequest(r, "admin-root", true, http.MethodGet, "/api/orgs/org-1/credits/grace", "", "")
	require.Equal(t, http.StatusOK, rec.Code)
	var out orgBudgetSettingsResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	assert.Nil(t, out.GraceFloorCents, "no per-org floor is set")
	assert.Equal(t, credits.DefaultConfig().GracePeriodCents, out.EffectiveGraceFloorCents)
	assert.Equal(t, int64(-100), out.EffectiveGraceFloorCents, "D1: the platform default stays −$1.00")

	// A null PUT resets to the same explicit default.
	rec = orgSettingsRequest(r, "admin-root", true, http.MethodPut, "/api/orgs/org-1/credits/grace",
		`{"grace_floor_cents": null, "reason": "reset to platform default"}`, "")
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	assert.Nil(t, out.GraceFloorCents)
	assert.Equal(t, int64(-100), out.EffectiveGraceFloorCents)
}
