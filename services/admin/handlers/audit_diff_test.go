package handlers

// AUX-14b: mutating admin actions journal before/after entity snapshots and
// the operator reason (X-Audit-Reason header). The snapshots are sanitized —
// secret-like fields are redacted before anything is stored. Rollback is not
// a new endpoint: the journal page replays the recorded reverse call through
// the existing mutation routes, and that call lands in the journal like any
// other action.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

const auditTestSecret = "test-secret-32-bytes-long-here!!" // #nosec G101 -- test-only HMAC key

// testCSRF is the double-submit CSRF value: the middleware only requires the
// cookie and the header to match.
const testCSRF = "csrf-token-value" // #nosec G101 -- test-only value

// lastAuditEntry returns the most recent journal entry. With a capable
// (mock) store the entry comes from the captured persisted records (the
// AF-10 path); with a nil/degraded store from the legacy in-memory buffer.
func lastAuditEntry(t *testing.T, h *AdminHandlers) AuditLogEntry {
	t.Helper()
	if ms, ok := h.store.(*mockStore); ok {
		rec := ms.lastAuditRecord(t)
		return AuditLogEntry{
			ID: rec.ID, Action: rec.Action, Resource: rec.Resource, Details: rec.Details,
			AdminID: rec.AdminID, AdminName: rec.AdminName, IPAddress: rec.IPAddress,
			Timestamp: rec.CreatedAt, Before: json.RawMessage(rec.Before),
			After: json.RawMessage(rec.After), Reason: rec.Reason,
		}
	}
	h.auditMu.RLock()
	defer h.auditMu.RUnlock()
	require.NotEmpty(t, h.auditLogBuffer)
	return h.auditLogBuffer[len(h.auditLogBuffer)-1]
}

// auditJournalDepth returns the current journal depth (persisted records for
// a capable mock store, buffer depth otherwise).
func auditJournalDepth(h *AdminHandlers) int {
	if ms, ok := h.store.(*mockStore); ok {
		return ms.auditRecordCount()
	}
	h.auditMu.RLock()
	defer h.auditMu.RUnlock()
	return len(h.auditLogBuffer)
}

// rootCall performs an authenticated root request against the router
// (session cookie + matching CSRF double-submit for mutations).
func rootCall(t *testing.T, router http.Handler, method, path, body string, headers map[string]string) (int, string) {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
	req.AddCookie(makeSessionCookie(true, auditTestSecret))
	req.AddCookie(&http.Cookie{Name: "yabanin_csrf_token", Value: testCSRF, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", testCSRF)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rw := httptest.NewRecorder()
	router.ServeHTTP(rw, req)
	return rw.Code, rw.Body.String()
}

// decodedSnapshot unmarshals a stored snapshot into a generic map.
func decodedSnapshot(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	require.NotEmpty(t, raw, "expected a stored snapshot")
	var out map[string]any
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

func TestAuditDiff_LabelsRecorded(t *testing.T) {
	org := "org-1"
	ms := newMockStore()
	ms.apiKeys["key-1"] = &adminstore.APIKey{
		ID: "key-1", KeyHash: "hash-1", Name: "demo", OrgID: &org,
		Labels: map[string]string{"team": "old"},
	}
	h := New(ms, auditTestSecret, "", nil)
	router := h.SetupRouter()

	code, body := rootCall(t, router, http.MethodPut, "/api/api-keys/key-1/labels?org_id=org-1",
		`{"labels":{"team":"payments"},"labels_locked":true,"can_mint_sessions":false,"can_read_usage":true}`,
		map[string]string{"X-Audit-Reason": "team handover"})
	require.Equal(t, http.StatusOK, code, body)

	entry := lastAuditEntry(t, h)
	assert.Equal(t, "api_key.labels_update", entry.Action)
	assert.Equal(t, "team handover", entry.Reason)

	before := decodedSnapshot(t, entry.Before)
	after := decodedSnapshot(t, entry.After)
	assert.Equal(t, "old", before["labels"].(map[string]any)["team"])
	assert.Equal(t, "payments", after["labels"].(map[string]any)["team"])
	assert.Equal(t, false, before["labels_locked"])
	assert.Equal(t, true, after["labels_locked"])
	assert.Equal(t, true, after["can_read_usage"])
}

func TestAuditDiff_EnableTogglesRecorded(t *testing.T) {
	org := "org-1"
	ms := newMockStore()
	ms.apiKeys["key-1"] = &adminstore.APIKey{ID: "key-1", KeyHash: "hash-1", Name: "demo", OrgID: &org, Active: true}
	ms.rules["rule-1"] = &adminstore.RoutingRule{ID: "rule-1", OrgID: org, Enabled: true}
	h := New(ms, auditTestSecret, "", nil)
	router := h.SetupRouter()

	// API key deactivation — the audit-page rollback replays exactly this
	// route with the inverted body.
	code, body := rootCall(t, router, http.MethodPut, "/api/api-keys/key-1", `{"active":false}`,
		map[string]string{"X-Audit-Reason": "key suspected leaked"})
	require.Equal(t, http.StatusOK, code, body)
	entry := lastAuditEntry(t, h)
	assert.Equal(t, "update", entry.Action)
	assert.Equal(t, "key suspected leaked", entry.Reason)
	before := decodedSnapshot(t, entry.Before)
	after := decodedSnapshot(t, entry.After)
	assert.Equal(t, true, before["active"])
	assert.Equal(t, false, after["active"])

	// Routing rule disable.
	code, body = rootCall(t, router, http.MethodPut, "/api/rules/rule-1/enable", `{"enabled":false}`,
		map[string]string{"X-Audit-Reason": "rule misroutes"})
	require.Equal(t, http.StatusOK, code, body)
	entry = lastAuditEntry(t, h)
	assert.Equal(t, "update", entry.Action)
	assert.Equal(t, "routing_rule", entry.Resource)
	assert.Equal(t, "rule misroutes", entry.Reason)
	before = decodedSnapshot(t, entry.Before)
	after = decodedSnapshot(t, entry.After)
	assert.Equal(t, true, before["enabled"])
	assert.Equal(t, false, after["enabled"])
}

func TestAuditDiff_BudgetsRecorded(t *testing.T) {
	ms := newMockStore()
	ms.agentKeys["agent-1"] = &adminstore.AgentKey{ID: "agent-1", KeyHash: "hash-1", OrgID: "org-1", Name: "agent"}
	ms.teams["team-1"] = &adminstore.Team{ID: "team-1", OrgID: "org-1", Name: "Team"}
	h := New(ms, auditTestSecret, "", nil)
	router := h.SetupRouter()

	// Agent budget upsert — the mock pre-seeds a 5000c budget, so before must
	// carry it and after the new cap.
	code, body := rootCall(t, router, http.MethodPut, "/api/agent-keys/agent-1/budget", `{"daily_limit_cents":7000}`,
		map[string]string{"X-Audit-Reason": "raising daily cap"})
	require.Equal(t, http.StatusOK, code, body)
	entry := lastAuditEntry(t, h)
	assert.Equal(t, "upsert", entry.Action)
	assert.Equal(t, "raising daily cap", entry.Reason)
	before := decodedSnapshot(t, entry.Before)
	after := decodedSnapshot(t, entry.After)
	assert.InDelta(t, 5000, before["daily_limit_cents"], 0.0001)
	assert.InDelta(t, 7000, after["daily_limit_cents"], 0.0001)

	// Team budget upsert — no budget configured yet (mock summary limit is 0),
	// so before is honestly absent.
	code, body = rootCall(t, router, http.MethodPut, "/api/teams/team-1/budget", `{"monthly_limit_usd":250,"hard_limit":true}`,
		map[string]string{"X-Audit-Reason": "new team cap"})
	require.Equal(t, http.StatusOK, code, body)
	entry = lastAuditEntry(t, h)
	assert.Equal(t, "update", entry.Action)
	assert.Equal(t, "team_budget", entry.Resource)
	assert.Empty(t, entry.Before, "no previous budget → no before snapshot")
	after = decodedSnapshot(t, entry.After)
	assert.InDelta(t, 250, after["monthly_limit_usd"], 0.0001)
	assert.Equal(t, true, after["hard_limit"])
}

func TestAuditDiff_AllowlistRecorded(t *testing.T) {
	ms := newMockStore()
	h := New(ms, auditTestSecret, "", nil)
	router := h.SetupRouter()

	code, body := rootCall(t, router, http.MethodPost, "/api/whitelist/api-keys/key-1",
		`{"model_name":"m-1","allowed":true}`, map[string]string{"X-Audit-Reason": "grant model"})
	require.Equal(t, http.StatusCreated, code, body)
	entry := lastAuditEntry(t, h)
	assert.Equal(t, "add_key_whitelist", entry.Action)
	assert.Equal(t, "grant model", entry.Reason)
	assert.Empty(t, entry.Before)
	after := decodedSnapshot(t, entry.After)
	assert.Equal(t, "m-1", after["model_name"])
	assert.Equal(t, true, after["allowed"])

	// Removal journals the removed entry's allowed value — the reverse add
	// needs it to restore the same state.
	code, body = rootCall(t, router, http.MethodDelete, "/api/whitelist/api-keys/key-1/m-1", "",
		map[string]string{"X-Audit-Reason": "revoke model"})
	require.Equal(t, http.StatusNoContent, code, body)
	entry = lastAuditEntry(t, h)
	assert.Equal(t, "remove_key_whitelist", entry.Action)
	removedBefore := decodedSnapshot(t, entry.Before)
	assert.Equal(t, true, removedBefore["allowed"])
	assert.Empty(t, entry.After)
}

func TestAuditDiff_SecretsMaskedInSnapshots(t *testing.T) {
	snapshot := auditSnapshot(map[string]any{
		"id":               "key-1",
		"key_hash":         "sha256-leak",
		"password_hash":    "argon2-leak",
		"upstream_api_key": "sk-leak",
		"session_token":    "tok-leak",
		"Authorization":    "Bearer leak",
		"note":             "keep me",
		"nested":           map[string]any{"secret_value": "x", "label": "y"},
		"list":             []any{map[string]any{"token": "t"}, "plain"},
	})
	var out map[string]any
	require.NoError(t, json.Unmarshal(snapshot, &out))
	assert.Equal(t, "[redacted]", out["key_hash"])
	assert.Equal(t, "[redacted]", out["password_hash"])
	assert.Equal(t, "[redacted]", out["upstream_api_key"])
	assert.Equal(t, "[redacted]", out["session_token"])
	assert.Equal(t, "[redacted]", out["Authorization"])
	assert.Equal(t, "keep me", out["note"])
	nested := out["nested"].(map[string]any)
	assert.Equal(t, "[redacted]", nested["secret_value"])
	assert.Equal(t, "y", nested["label"])
	list := out["list"].([]any)
	assert.Equal(t, "[redacted]", list[0].(map[string]any)["token"])
	assert.Equal(t, "plain", list[1])

	// Masking also holds on the journal write path: a snapshot handed to
	// auditLogActionDiff never carries the raw secret.
	h := New(nil, auditTestSecret, "", []string{})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/x", nil)
	h.auditLogActionDiff(req, "update", "api_key", "id=k",
		map[string]any{"id": "k", "key_hash": "sha256-leak"},
		map[string]any{"id": "k", "key_hash": "sha256-new"})
	entry := lastAuditEntry(t, h)
	assert.NotContains(t, string(entry.Before), "sha256-leak")
	assert.NotContains(t, string(entry.After), "sha256-new")
	assert.Contains(t, string(entry.Before), "[redacted]")
}

func TestAuditReason_TrimmedAndCapped(t *testing.T) {
	long := strings.Repeat("ё", 600)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/x", nil)
	r.Header.Set("X-Audit-Reason", "  "+long+"  ")
	got := auditReason(r)
	assert.Len(t, []rune(got), 512, "reason is capped, multibyte-safe")
	assert.False(t, strings.HasPrefix(got, " "), "trimmed")

	r.Header.Set("X-Audit-Reason", "   ")
	assert.Empty(t, auditReason(r))
}

func TestListAuditLogs_ServesSnapshotsAndReason(t *testing.T) {
	h := New(nil, auditTestSecret, "", []string{})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/x", nil)
	req.Header.Set("X-Audit-Reason", "why not")
	h.auditLogActionDiff(req, "update", "api_key", "id=k",
		map[string]any{"id": "k", "active": true},
		map[string]any{"id": "k", "active": false})

	code, body := func() (int, string) {
		rw := httptest.NewRecorder()
		listReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/audit-logs", nil)
		h.ListAuditLogs()(rw, listReq)
		return rw.Code, rw.Body.String()
	}()
	require.Equal(t, http.StatusOK, code)

	var resp struct {
		AuditLogs []struct {
			Action string          `json:"action"`
			Before json.RawMessage `json:"before"`
			After  json.RawMessage `json:"after"`
			Reason string          `json:"reason"`
		} `json:"audit_logs"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &resp))
	require.Len(t, resp.AuditLogs, 1)
	served := resp.AuditLogs[0]
	assert.Equal(t, "update", served.Action)
	assert.Equal(t, "why not", served.Reason)
	assert.Contains(t, string(served.Before), `"active":true`)
	assert.Contains(t, string(served.After), `"active":false`)

	// Entries without snapshots/reason keep the fields absent, not null.
	h.auditLogAction(httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/x", nil), "create", "org", "id=o")
	_, body = func() (int, string) {
		rw := httptest.NewRecorder()
		listReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/audit-logs", nil)
		h.ListAuditLogs()(rw, listReq)
		return rw.Code, rw.Body.String()
	}()
	assert.NotContains(t, body, `"reason":null`)
	assert.Contains(t, body, `"action":"create"`)
}

// TestRollback_ThroughExistingEndpoint_WritesNewJournalEntry pins the AUX-14b
// rollback contract: the journal page does not get a rollback endpoint — it
// replays the recorded reverse call on the existing route, and that call is
// journalled like any other action (its own before/after/reason).
func TestRollback_ThroughExistingEndpoint_WritesNewJournalEntry(t *testing.T) {
	org := "org-1"
	ms := newMockStore()
	ms.apiKeys["key-1"] = &adminstore.APIKey{ID: "key-1", KeyHash: "hash-1", Name: "demo", OrgID: &org, Active: true}
	h := New(ms, auditTestSecret, "", nil)
	router := h.SetupRouter()

	// Original action: deactivate with a reason.
	code, body := rootCall(t, router, http.MethodPut, "/api/api-keys/key-1", `{"active":false}`,
		map[string]string{"X-Audit-Reason": "suspected leak"})
	require.Equal(t, http.StatusOK, code, body)
	require.Equal(t, 1, auditJournalDepth(h))

	// Rollback = the reverse call on the SAME endpoint (no new route).
	code, body = rootCall(t, router, http.MethodPut, "/api/api-keys/key-1", `{"active":true}`,
		map[string]string{"X-Audit-Reason": "rollback of suspected-leak deactivation"})
	require.Equal(t, http.StatusOK, code, body)

	require.Equal(t, 2, auditJournalDepth(h), "the rollback call writes its own journal entry")
	originalRec := ms.auditRecordByIndex(t, 0)
	original := AuditLogEntry{
		ID: originalRec.ID, Reason: originalRec.Reason,
		Before: json.RawMessage(originalRec.Before), After: json.RawMessage(originalRec.After),
	}
	rollback := lastAuditEntry(t, h)

	originalAfter := decodedSnapshot(t, original.After)
	assert.Equal(t, false, originalAfter["active"])
	rollbackBefore := decodedSnapshot(t, rollback.Before)
	rollbackAfter := decodedSnapshot(t, rollback.After)
	assert.Equal(t, false, rollbackBefore["active"], "rollback sees the state the original action left")
	assert.Equal(t, true, rollbackAfter["active"])
	assert.Equal(t, "rollback of suspected-leak deactivation", rollback.Reason)
	assert.NotEqual(t, original.ID, rollback.ID)
}

// TestAuditLog_RootOnlyPreserved: the journal (now carrying snapshots) is
// still fenced against plain admins — a non-root admin without the global
// gets through.
func TestAuditLog_RootOnlyPreserved(t *testing.T) {
	h := New(newMockStore(), auditTestSecret, "", nil)
	router := h.SetupRouter()

	nonRoot := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/audit-logs", nil)
	nonRoot.AddCookie(makeSessionCookie(false, auditTestSecret))
	rw := httptest.NewRecorder()
	router.ServeHTTP(rw, nonRoot)
	require.Equal(t, http.StatusForbidden, rw.Code)

	root := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/audit-logs", nil)
	root.AddCookie(makeSessionCookie(true, auditTestSecret))
	rw = httptest.NewRecorder()
	router.ServeHTTP(rw, root)
	require.Equal(t, http.StatusOK, rw.Code)
}

func TestAuditSnapshot_OversizedDegradesToTruncatedMarker(t *testing.T) {
	big := strings.Repeat("a", auditSnapshotMaxBytes+1)
	raw := auditSnapshot(map[string]any{"blob": big})
	assert.Equal(t, `{"truncated":true}`, string(raw))

	assert.Nil(t, auditSnapshot(nil))
	assert.Nil(t, auditSnapshot(make(chan int)), "unencodable payload → no snapshot")
}
