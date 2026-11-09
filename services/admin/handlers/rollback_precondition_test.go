package handlers

// AF-09 (audit F07): a stale rollback must never overwrite a newer state.
// The audit page replays the recorded reverse call on the existing mutation
// route; without a server-side atomic precondition that replay blindly
// restores the recorded before value and cancels every later decision
// (10→20→100, rollback of the first → 10 wins, 100 is lost).
//
// The rollback request therefore carries the entry's recorded AFTER state as
// an expectation; the store compares it in the same atomic statement and the
// handler answers 409 {"error":"conflict","current":{…}} on divergence.
//
// The first two tests are the red reproduction: they are written against the
// pre-fix behavior and fail (200 + overwritten state) until the CAS
// precondition exists. Unknown JSON fields are currently ignored, so the
// expectation below is silently dropped by the old handler — the rollback
// succeeds where it must conflict.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// TestRollback_StaleBudgetUpdate_Conflicts_NewValueSurvives — the audit F07
// scenario: 10→20→100, rollback of the first change. The recorded after
// (20) no longer matches the current limit (100), so the rollback must be
// rejected with 409 and the 100 must survive.
func TestRollback_StaleBudgetUpdate_Conflicts_NewValueSurvives(t *testing.T) {
	ms := newMockStore()
	ms.teams["team-1"] = &adminstore.Team{ID: "team-1", OrgID: "org-1", Name: "Team"}
	h := New(ms, auditTestSecret, "", nil)
	router := h.SetupRouter()

	// The two sequential changes. The first records after={20}; the second
	// moves the limit to 100.
	code, body := rootCall(t, router, http.MethodPut, "/api/teams/team-1/budget",
		`{"monthly_limit_usd":20,"hard_limit":true}`, map[string]string{"X-Audit-Reason": "raise to 20"})
	require.Equal(t, http.StatusOK, code, body)
	code, body = rootCall(t, router, http.MethodPut, "/api/teams/team-1/budget",
		`{"monthly_limit_usd":100,"hard_limit":true}`, map[string]string{"X-Audit-Reason": "raise to 100"})
	require.Equal(t, http.StatusOK, code, body)

	entriesBefore := auditLogCount(t, h)

	// Rollback of the FIRST change: restore 10, expecting the recorded after
	// state (limit 20) to still be current. It is not — 100 is.
	code, body = rootCall(t, router, http.MethodPut, "/api/teams/team-1/budget",
		`{"monthly_limit_usd":10,"hard_limit":true,"expected":{"monthly_limit_usd":20,"hard_limit":true}}`,
		map[string]string{"X-Audit-Reason": "rollback to 10"})
	require.Equal(t, http.StatusConflict, code, "stale rollback must conflict, got: %s", body)
	assert.Contains(t, body, `"error":"conflict"`)
	assert.Contains(t, body, `"current"`)

	// The newer 100 survives and the failed rollback writes no journal entry.
	assert.InDelta(t, 100.0, ms.teamBudgets["team-1"].MonthlyLimitUSD, 1e-9)
	assert.Equal(t, entriesBefore, auditLogCount(t, h), "a conflicted rollback must not journal")
}

// TestRollback_OldEnableToggle_DoesNotCancelNewSecurityDecision — an old
// "enable" rollback must not re-enable a key that was later deactivated by a
// newer decision.
func TestRollback_OldEnableToggle_DoesNotCancelNewSecurityDecision(t *testing.T) {
	org := "org-1"
	ms := newMockStore()
	ms.apiKeys["key-1"] = &adminstore.APIKey{ID: "key-1", KeyHash: "hash-1", Name: "demo", OrgID: &org, Active: false}
	h := New(ms, auditTestSecret, "", nil)
	router := h.SetupRouter()

	// Old change: the key was enabled (recorded after.active=true).
	code, body := rootCall(t, router, http.MethodPut, "/api/api-keys/key-1",
		`{"active":true}`, map[string]string{"X-Audit-Reason": "restore service"})
	require.Equal(t, http.StatusOK, code, body)

	// Newer security decision: the key is deactivated again.
	code, body = rootCall(t, router, http.MethodPut, "/api/api-keys/key-1",
		`{"active":false}`, map[string]string{"X-Audit-Reason": "key suspected leaked"})
	require.Equal(t, http.StatusOK, code, body)

	entriesBefore := auditLogCount(t, h)

	// Stale rollback of the old enable: expects the recorded after
	// (active=true) — but the newer deactivation is current. Must conflict
	// and leave the key deactivated.
	code, body = rootCall(t, router, http.MethodPut, "/api/api-keys/key-1",
		`{"active":true,"expected_active":true}`, map[string]string{"X-Audit-Reason": "rollback enable"})
	require.Equal(t, http.StatusConflict, code, "stale enable rollback must conflict, got: %s", body)
	assert.Contains(t, body, `"error":"conflict"`)
	assert.False(t, ms.apiKeys["key-1"].Active, "the newer deactivation must survive")
	assert.Equal(t, entriesBefore, auditLogCount(t, h), "a conflicted rollback must not journal")
}

// auditLogCount returns the current journal depth.
func auditLogCount(t *testing.T, h *AdminHandlers) int {
	t.Helper()
	return auditJournalDepth(h)
}

// TestRollback_ConcurrentMutationBetweenPreviewAndSave_Conflicts — the
// recorded expectation is compared atomically at save time, so a mutation
// that lands between the journal preview and the rollback save conflicts.
// The handler does not trust a client-side GET: the only read that matters
// is the one inside the CAS statement.
func TestRollback_ConcurrentMutationBetweenPreviewAndSave_Conflicts(t *testing.T) {
	org := "org-1"
	ms := newMockStore()
	ms.apiKeys["key-1"] = &adminstore.APIKey{ID: "key-1", KeyHash: "hash-1", Name: "demo", OrgID: &org, Active: true}
	h := New(ms, auditTestSecret, "", nil)
	router := h.SetupRouter()

	// Audited change: the key is enabled (after.active=true).
	code, body := rootCall(t, router, http.MethodPut, "/api/api-keys/key-1",
		`{"active":true}`, map[string]string{"X-Audit-Reason": "enable"})
	require.Equal(t, http.StatusOK, code, body)

	// A concurrent admin decision lands before the rollback save (what the
	// operator would otherwise have seen via a fresh GET and ignored).
	ms.apiKeys["key-1"].Active = false

	code, body = rootCall(t, router, http.MethodPut, "/api/api-keys/key-1",
		`{"active":true,"expected_active":true}`, map[string]string{"X-Audit-Reason": "rollback"})
	require.Equal(t, http.StatusConflict, code, body)
	assert.Contains(t, body, `"error":"conflict"`)
	assert.Contains(t, body, `"active":false`)
}

// TestRollback_PlainPUTWithoutExpectation_StillOverwrites — proves WHY the
// client-side GET-before-PUT is not a fix: without the expectation field the
// endpoint keeps its historical unconditional behavior and a stale caller
// overwrites the newer state. The CAS is what closes it, not a re-fetch.
func TestRollback_PlainPUTWithoutExpectation_StillOverwrites(t *testing.T) {
	org := "org-1"
	ms := newMockStore()
	ms.apiKeys["key-1"] = &adminstore.APIKey{ID: "key-1", KeyHash: "hash-1", Name: "demo", OrgID: &org, Active: false}
	h := New(ms, auditTestSecret, "", nil)
	router := h.SetupRouter()

	ms.apiKeys["key-1"].Active = true // newer decision already applied

	// A plain GET+PUT caller (no expected_active) still toggles blindly —
	// documented historical behavior, unchanged by AF-09.
	code, body := rootCall(t, router, http.MethodPut, "/api/api-keys/key-1",
		`{"active":false}`, nil)
	require.Equal(t, http.StatusOK, code, body)
	assert.False(t, ms.apiKeys["key-1"].Active)
}

// TestRollback_AllFamilies_MismatchConflicts — every safe family rejects a
// stale rollback with 409 + current state: label, enable (rule), budget
// (agent + team delete-restore) and allowlist (key + team, both directions).
func TestRollback_AllFamilies_MismatchConflicts(t *testing.T) {
	t.Run("labels", func(t *testing.T) {
		org := "org-1"
		ms := newMockStore()
		ms.apiKeys["key-1"] = &adminstore.APIKey{
			ID: "key-1", KeyHash: "hash-1", Name: "demo", OrgID: &org,
			Labels: map[string]string{"team": "payments"}, LabelsLocked: true,
		}
		h := New(ms, auditTestSecret, "", nil)
		router := h.SetupRouter()

		code, body := rootCall(t, router, http.MethodPut, "/api/api-keys/key-1/labels",
			`{"labels":{"team":"platform"},"labels_locked":false,"can_mint_sessions":true,"can_read_usage":true}`,
			map[string]string{"X-Audit-Reason": "re-org"})
		require.Equal(t, http.StatusOK, code, body)

		// A newer labels change lands; the old rollback expects the recorded
		// after set and must conflict without touching the newer labels.
		code, body = rootCall(t, router, http.MethodPut, "/api/api-keys/key-1/labels",
			`{"labels":{"team":"sec"},"labels_locked":true,"can_mint_sessions":false,"can_read_usage":true}`,
			map[string]string{"X-Audit-Reason": "lockdown"})
		require.Equal(t, http.StatusOK, code, body)

		code, body = rootCall(t, router, http.MethodPut, "/api/api-keys/key-1/labels",
			`{"labels":{"team":"payments"},"labels_locked":true,"can_mint_sessions":false,"can_read_usage":false,`+
				`"expected":{"labels":{"team":"platform"},"labels_locked":false,"can_mint_sessions":true,"can_read_usage":true}}`,
			map[string]string{"X-Audit-Reason": "rollback re-org"})
		require.Equal(t, http.StatusConflict, code, body)
		assert.Equal(t, "sec", ms.apiKeys["key-1"].Labels["team"], "newer labels survive")
	})

	t.Run("rule enable", func(t *testing.T) {
		ms := newMockStore()
		ms.rules["rule-1"] = &adminstore.RoutingRule{ID: "rule-1", OrgID: "org-1", Enabled: false}
		h := New(ms, auditTestSecret, "", nil)
		router := h.SetupRouter()

		code, body := rootCall(t, router, http.MethodPut, "/api/rules/rule-1/enable",
			`{"enabled":true}`, map[string]string{"X-Audit-Reason": "turn on"})
		require.Equal(t, http.StatusOK, code, body)
		code, body = rootCall(t, router, http.MethodPut, "/api/rules/rule-1/enable",
			`{"enabled":false}`, map[string]string{"X-Audit-Reason": "newer decision"})
		require.Equal(t, http.StatusOK, code, body)

		code, body = rootCall(t, router, http.MethodPut, "/api/rules/rule-1/enable",
			`{"enabled":true,"expected_enabled":true}`, map[string]string{"X-Audit-Reason": "rollback"})
		require.Equal(t, http.StatusConflict, code, body)
		assert.False(t, ms.rules["rule-1"].Enabled, "the newer disable survives")
	})

	t.Run("agent budget", func(t *testing.T) {
		ms := newMockStore()
		ms.agentKeys["agent-1"] = &adminstore.AgentKey{ID: "agent-1", KeyHash: "hash-1", OrgID: "org-1", Name: "agent"}
		h := New(ms, auditTestSecret, "", nil)
		router := h.SetupRouter()

		// 5000→7000 (recorded after 7000), then 7000→9000 (newer).
		code, body := rootCall(t, router, http.MethodPut, "/api/agent-keys/agent-1/budget",
			`{"daily_limit_cents":7000}`, map[string]string{"X-Audit-Reason": "raise"})
		require.Equal(t, http.StatusOK, code, body)
		code, body = rootCall(t, router, http.MethodPut, "/api/agent-keys/agent-1/budget",
			`{"daily_limit_cents":9000}`, map[string]string{"X-Audit-Reason": "raise more"})
		require.Equal(t, http.StatusOK, code, body)

		code, body = rootCall(t, router, http.MethodPut, "/api/agent-keys/agent-1/budget",
			`{"daily_limit_cents":5000,"expected":{"daily_limit_cents":7000}}`,
			map[string]string{"X-Audit-Reason": "rollback first raise"})
		require.Equal(t, http.StatusConflict, code, body)
		assert.Contains(t, body, `"daily_limit_cents":9000`)
		assert.EqualValues(t, 9000, ms.agentBudgets["agent-1"].DailyLimitCents)
	})

	t.Run("team budget restore after delete", func(t *testing.T) {
		ms := newMockStore()
		ms.teams["team-1"] = &adminstore.Team{ID: "team-1", OrgID: "org-1", Name: "Team"}
		h := New(ms, auditTestSecret, "", nil)
		router := h.SetupRouter()

		// Audited deletion of a {50, hard} budget; a newer budget {75} is set.
		code, body := rootCall(t, router, http.MethodDelete, "/api/teams/team-1/budget", `{}`, nil)
		require.Equal(t, http.StatusOK, code, body)
		code, body = rootCall(t, router, http.MethodPut, "/api/teams/team-1/budget",
			`{"monthly_limit_usd":75,"hard_limit":false}`, map[string]string{"X-Audit-Reason": "newer cap"})
		require.Equal(t, http.StatusOK, code, body)

		// Rollback of the deletion expects "absent" — the newer cap conflicts.
		code, body = rootCall(t, router, http.MethodPut, "/api/teams/team-1/budget",
			`{"monthly_limit_usd":50,"hard_limit":true,"expected":{"absent":true}}`,
			map[string]string{"X-Audit-Reason": "restore deleted budget"})
		require.Equal(t, http.StatusConflict, code, body)
		assert.Contains(t, body, `"monthly_limit_usd":75`)
		assert.InDelta(t, 75.0, ms.teamBudgets["team-1"].MonthlyLimitUSD, 1e-9)
	})

	t.Run("allowlist key", func(t *testing.T) {
		ms := newMockStore()
		h := New(ms, auditTestSecret, "", nil)
		router := h.SetupRouter()

		// Audited add (after.allowed=true); a newer decision removes the entry.
		code, body := rootCall(t, router, http.MethodPost, "/api/whitelist/api-keys/key-1",
			`{"model_name":"m-1","allowed":true}`, map[string]string{"X-Audit-Reason": "grant"})
		require.Equal(t, http.StatusCreated, code, body)
		code, body = rootCall(t, router, http.MethodDelete, "/api/whitelist/api-keys/key-1/m-1", `{}`, nil)
		require.Equal(t, http.StatusNoContent, code, body)

		// Rollback of the add: conditional delete expecting allowed=true —
		// but a newer decision already removed the entry → mismatch.
		code, body = rootCall(t, router, http.MethodDelete, "/api/whitelist/api-keys/key-1/m-1",
			`{"expected_allowed":true}`, map[string]string{"X-Audit-Reason": "rollback grant"})
		require.Equal(t, http.StatusConflict, code, body)
		assert.Empty(t, ms.keyWhitelist["key-1"])

		// Rollback of the removal restores the entry only while absent.
		code, body = rootCall(t, router, http.MethodPost, "/api/whitelist/api-keys/key-1",
			`{"model_name":"m-1","allowed":true,"expected_absent":true}`,
			map[string]string{"X-Audit-Reason": "rollback removal"})
		require.Equal(t, http.StatusCreated, code, body)
		require.Len(t, ms.keyWhitelist["key-1"], 1)

		// A second restore-add with expected_absent conflicts — the entry is
		// no longer absent (and the stored one survives untouched).
		code, body = rootCall(t, router, http.MethodPost, "/api/whitelist/api-keys/key-1",
			`{"model_name":"m-1","allowed":true,"expected_absent":true}`,
			map[string]string{"X-Audit-Reason": "double rollback"})
		require.Equal(t, http.StatusConflict, code, body)
		assert.Contains(t, body, `"error":"conflict"`)
		assert.Len(t, ms.keyWhitelist["key-1"], 1)
	})

	t.Run("allowlist team", func(t *testing.T) {
		ms := newMockStore()
		h := New(ms, auditTestSecret, "", nil)
		router := h.SetupRouter()

		code, body := rootCall(t, router, http.MethodPost, "/api/whitelist/teams/team-1",
			`{"model_name":"m-1","allowed":false}`, map[string]string{"X-Audit-Reason": "deny team"})
		require.Equal(t, http.StatusCreated, code, body)
		code, body = rootCall(t, router, http.MethodDelete, "/api/whitelist/teams/team-1/m-1", `{}`, nil)
		require.Equal(t, http.StatusNoContent, code, body)

		// Conditional delete expecting the recorded deny survives a re-add
		// with a different value only as a conflict.
		code, body = rootCall(t, router, http.MethodPost, "/api/whitelist/teams/team-1",
			`{"model_name":"m-1","allowed":false,"expected_absent":true}`, nil)
		require.Equal(t, http.StatusCreated, code, body)
		code, body = rootCall(t, router, http.MethodDelete, "/api/whitelist/teams/team-1/m-1",
			`{"expected_allowed":true}`, map[string]string{"X-Audit-Reason": "rollback deny"})
		require.Equal(t, http.StatusConflict, code, body)
		require.Len(t, ms.teamWhitelist["team-1"], 1)
		assert.False(t, ms.teamWhitelist["team-1"][0].Allowed, "stored deny survives")
	})
}

// TestRollback_Success_WritesOwnAuditEntry — a preconditioned rollback that
// matches applies the reverse call and journals it as its own entry with its
// own diff and reason (AUX-14b contract preserved on the CAS path).
func TestRollback_Success_WritesOwnAuditEntry(t *testing.T) {
	org := "org-1"
	ms := newMockStore()
	ms.apiKeys["key-1"] = &adminstore.APIKey{ID: "key-1", KeyHash: "hash-1", Name: "demo", OrgID: &org, Active: true}
	h := New(ms, auditTestSecret, "", nil)
	router := h.SetupRouter()

	code, body := rootCall(t, router, http.MethodPut, "/api/api-keys/key-1",
		`{"active":false}`, map[string]string{"X-Audit-Reason": "suspected leak"})
	require.Equal(t, http.StatusOK, code, body)

	code, body = rootCall(t, router, http.MethodPut, "/api/api-keys/key-1",
		`{"active":true,"expected_active":false}`, map[string]string{"X-Audit-Reason": "false alarm"})
	require.Equal(t, http.StatusOK, code, body)
	assert.True(t, ms.apiKeys["key-1"].Active)

	entry := lastAuditEntry(t, h)
	assert.Equal(t, "update", entry.Action)
	assert.Equal(t, "false alarm", entry.Reason)
	before := decodedSnapshot(t, entry.Before)
	after := decodedSnapshot(t, entry.After)
	assert.Equal(t, false, before["active"])
	assert.Equal(t, true, after["active"])
}

// TestRollback_PreconditionDoesNotReplaceAuth — the CAS never bypasses the
// permission model: a scoped non-root admin cannot rollback a foreign org's
// key even with a perfectly matching expectation.
func TestRollback_PreconditionDoesNotReplaceAuth(t *testing.T) {
	foreign := "org-9"
	ms := newMockStore()
	ms.apiKeys["key-9"] = &adminstore.APIKey{ID: "key-9", KeyHash: "hash-9", Name: "foreign", OrgID: &foreign, Active: false}
	h := New(ms, auditTestSecret, "", nil)
	router := h.SetupRouter()

	// Non-root session (admin-1, no org membership): the foreign key is
	// 403/404 exactly as without the precondition — the CAS never widens
	// what the caller may touch.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/api/api-keys/key-9", strings.NewReader(`{"active":true,"expected_active":false}`))
	req.AddCookie(makeSessionCookie(false, auditTestSecret))
	req.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()
	router.ServeHTTP(rw, req)
	assert.Contains(t, []int{http.StatusForbidden, http.StatusNotFound}, rw.Code, rw.Body.String())
	assert.False(t, ms.apiKeys["key-9"].Active, "foreign key untouched")
}
