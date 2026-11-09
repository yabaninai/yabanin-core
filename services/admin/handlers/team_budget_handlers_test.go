package handlers

// ratified 2026-10-16):
//   - D2 (decrease below current spend = allow + deny-next): PUT
//     /api/teams/{id}/budget lowering the limit below the team's live spend
//     is accepted (200) and journalled before/after — the settings surface
//     carries no below-spend guard; the denial happens on the NEXT
//     admission (free < 0 refuses the grant), pinned in pkg/budget
//     (TestR040_TeamLimitDecreasedBelowSpend_AllowThenDenyNext).
//   - Negative scenario «нет настройки»: a team without a budget row
//     surfaces fail-closed defaults (limit 0, hard), never a hidden
//     unlimited.
//   - D3 (advisory-soft = acceptable explicit unlimited): the summary API
//     carries hard_limit verbatim, so a soft budget reads as advisory on
//     the wire — the explicit label, not a hidden unlimited.
//
// The routes are exercised on a local chi router (same pattern as
// orgSettingsTestRouter: the gates live in the handlers).

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// teamBudgetTestRouter mounts only the team budget routes.
func teamBudgetTestRouter(t *testing.T, h *AdminHandlers) chi.Router {
	t.Helper()
	r := chi.NewRouter()
	r.Get("/api/teams/{id}/budget", h.GetTeamBudget())
	r.Put("/api/teams/{id}/budget", h.UpsertTeamBudget())
	return r
}

// teamBudgetFixture wires a mock store with one team of org-1.
func teamBudgetFixture(t *testing.T) (*mockStore, chi.Router) {
	t.Helper()
	store := newMockStore()
	store.orgs["org-1"] = &adminstore.Organization{ID: "org-1", Name: "Org One", Slug: "org-one"}
	store.teams["team-r040"] = &adminstore.Team{ID: "team-r040", OrgID: "org-1", Name: "R040", Slug: "r040"}
	h := newTestAdminH(store)
	return store, teamBudgetTestRouter(t, h.AdminHandlers)
}

// TestUpsertTeamBudget_DecreaseBelowSpend_AllowedAndAudited: the D2 allow
// half — a $200 → $100 decrease under $120 of live spend is accepted and
// journalled; the deny-next half lives in the reservation grant (pinned in
// pkg/budget).
func TestUpsertTeamBudget_DecreaseBelowSpend_AllowedAndAudited(t *testing.T) {
	store, r := teamBudgetFixture(t)
	store.teamBudgets["team-r040"] = &adminstore.TeamBudget{TeamID: "team-r040", MonthlyLimitUSD: 200, HardLimit: true}
	store.teamSpends["team-r040"] = 120 // $120 live spend > the incoming $100

	rec := orgSettingsRequest(r, "admin-root", true, http.MethodPut, "/api/teams/team-r040/budget",
		`{"monthly_limit_usd": 100, "hard_limit": true}`, "")
	require.Equal(t, http.StatusOK, rec.Code, "a decrease below current spend is allowed (D2)")
	require.NotNil(t, store.teamBudgets["team-r040"])
	assert.InDelta(t, 100.0, store.teamBudgets["team-r040"].MonthlyLimitUSD, 1e-9)

	store.auditMu.Lock()
	records := append([]adminstore.AuditLogEntryRecord(nil), store.auditRecords...)
	store.auditMu.Unlock()
	require.Len(t, records, 1, "the accepted decrease is journalled")
	entry := records[0]
	assert.Equal(t, "update", entry.Action)
	assert.Equal(t, "team_budget", entry.Resource)

	var before, after map[string]any
	require.NoError(t, json.Unmarshal([]byte(entry.Before), &before))
	require.NoError(t, json.Unmarshal([]byte(entry.After), &after))
	assert.InDelta(t, 200.0, before["monthly_limit_usd"], 1e-9, "journal before carries the pre-decrease limit")
	assert.InDelta(t, 100.0, after["monthly_limit_usd"], 1e-9, "journal after carries the decreased limit")
}

// decrease surface under a store outage: 500, no journal entry, the stored
// budget unchanged (partial/unknown is never success); the retry after
// recovery succeeds and journals the decrease.
func TestUpsertTeamBudget_StoreOutage_NotSuccessNoJournal(t *testing.T) {
	store, r := teamBudgetFixture(t)
	store.teamBudgets["team-r040"] = &adminstore.TeamBudget{TeamID: "team-r040", MonthlyLimitUSD: 200, HardLimit: true}
	store.teamBudgetUpsert = errors.New("injected budget outage")

	rec := orgSettingsRequest(r, "admin-root", true, http.MethodPut, "/api/teams/team-r040/budget",
		`{"monthly_limit_usd": 100, "hard_limit": true}`, "")
	require.Equal(t, http.StatusInternalServerError, rec.Code, "an outage is a 500, not a fake success")

	store.auditMu.Lock()
	journaled := len(store.auditRecords)
	store.auditMu.Unlock()
	assert.Zero(t, journaled, "a failed mutation journals nothing")
	require.NotNil(t, store.teamBudgets["team-r040"])
	assert.InDelta(t, 200.0, store.teamBudgets["team-r040"].MonthlyLimitUSD, 1e-9, "the limit is unchanged")

	// Recovery retry: the same decrease succeeds and journals once.
	store.teamBudgetUpsert = nil
	rec = orgSettingsRequest(r, "admin-root", true, http.MethodPut, "/api/teams/team-r040/budget",
		`{"monthly_limit_usd": 100, "hard_limit": true}`, "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.InDelta(t, 100.0, store.teamBudgets["team-r040"].MonthlyLimitUSD, 1e-9)
	store.auditMu.Lock()
	journaled = len(store.auditRecords)
	store.auditMu.Unlock()
	assert.Equal(t, 1, journaled, "the retried decrease journals exactly once")
}

// TestGetTeamBudget_NoBudgetRowIsFailClosedNotUnlimited: the «нет
// настройки» surface — a team without a budget row reads limit 0 / hard,
// the fail-closed contract, never a soft or unlimited default.
func TestGetTeamBudget_NoBudgetRowIsFailClosedNotUnlimited(t *testing.T) {
	_, r := teamBudgetFixture(t)

	rec := orgSettingsRequest(r, "admin-root", true, http.MethodGet, "/api/teams/team-r040/budget", "", "")
	require.Equal(t, http.StatusOK, rec.Code)

	var out adminstore.TeamSpendSummary
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	assert.InDelta(t, 0.0, out.MonthlyLimitUSD, 1e-9)
	assert.True(t, out.HardLimit, "an unbudgeted team surfaces fail-closed, never soft/unlimited")
}

// TestGetTeamBudget_SoftBudgetIsExplicitlyLabeled: the D3 pin at the API
// surface — hard_limit rides the wire verbatim, so a soft (advisory)
// budget is an explicit unlimited (the UI renders the advisory label from
// this field; see web i18n budgets.impactSoft), never a hidden one.
func TestGetTeamBudget_SoftBudgetIsExplicitlyLabeled(t *testing.T) {
	store, r := teamBudgetFixture(t)
	store.teamBudgets["team-r040"] = &adminstore.TeamBudget{TeamID: "team-r040", MonthlyLimitUSD: 1, HardLimit: false}

	rec := orgSettingsRequest(r, "admin-root", true, http.MethodGet, "/api/teams/team-r040/budget", "", "")
	require.Equal(t, http.StatusOK, rec.Code)

	var out adminstore.TeamSpendSummary
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	assert.False(t, out.HardLimit, "soft budget labeled advisory on the wire")
	assert.InDelta(t, 1.0, out.MonthlyLimitUSD, 1e-9)
	assert.Contains(t, rec.Body.String(), `"hard_limit":false`, "the label is part of the wire contract")
}
