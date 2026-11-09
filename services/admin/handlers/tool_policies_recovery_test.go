package handlers

// N07-P07-T08 — recovery contract for the tool-policy surface: interruption
// (degraded 503 → ready), restart/resume (durable store-backed state, not
// handler memory), retry of the input command within the contract (create
// retry is a typed 409 with state unchanged — NOT a silent exactly-once;
// preset apply is idempotent per row and converges on retry, including from
// a partial prior apply), and the observable post-mutation state (engine
// cache invalidated per org — edits land immediately, without TTL staleness).
// Uncertain external effects are reported honestly: a retry after an
// uncertain create answers 409 and the client confirms via GET — nothing
// here claims exactly-once.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/reireirei/yabanin/pkg/toolpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// storeLoader is a live Loader over the mock store: every ListEnabled reads
// current rows, so an engine Decide after a mutation observes exactly what a
// post-invalidation reload would.
type storeLoader struct{ s *toolPolicyTestStore }

func (l *storeLoader) ListEnabled(_ context.Context, orgID string) ([]toolpolicy.Policy, error) {
	var out []toolpolicy.Policy
	for _, p := range l.s.byName {
		if p.OrgID == orgID && p.Enabled {
			out = append(out, *p)
		}
	}
	return out, nil
}

// TestToolPolicyRecoveryDegradedToReady — interruption boundary: without a
// wired registry the surface answers the documented 503; wiring the store
// (the deployment recovery event) flips the SAME handler instance to serving
// creates — no restart required, and the degraded answers never partially
// wrote (the store stays empty).
func TestToolPolicyRecoveryDegradedToReady(t *testing.T) {
	store := newToolPolicyTestStore()
	h := New(nil, "", "", []string{})

	w := httptest.NewRecorder()
	h.CreateToolPolicy()(w, rootRequest("POST", "/api/tool-policies",
		`{"org_id":"org-1","name":"late","subject":"*","tool":"web_*","action":"deny"}`))
	require.Equal(t, http.StatusServiceUnavailable, w.Code)
	require.Empty(t, store.byName, "a degraded 503 must not leave a partial row")

	// Recovery: wire the registry; the same instance serves immediately.
	h.SetToolPolicyStore(toolpolicy.NewStore(store), nil)
	w2 := httptest.NewRecorder()
	h.CreateToolPolicy()(w2, rootRequest("POST", "/api/tool-policies",
		`{"org_id":"org-1","name":"late","subject":"*","tool":"web_*","action":"deny"}`))
	require.Equal(t, http.StatusCreated, w2.Code, w2.Body.String())
}

// TestToolPolicyRecoveryRestartResume — the policy state lives in the store,
// not in the handler: a "restarted" process (a fresh handler over the same
// store) resumes serving the exact rows, and the engine built after the
// restart decides from them.
func TestToolPolicyRecoveryRestartResume(t *testing.T) {
	store := newToolPolicyTestStore()
	h1 := newToolPolicyTestH(store)
	w := httptest.NewRecorder()
	h1.CreateToolPolicy()(w, rootRequest("POST", "/api/tool-policies",
		`{"org_id":"org-1","name":"resume-deny","subject":"*","server":"*","tool":"web_*","action":"deny","priority":7,"enabled":true}`))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	// Restart: fresh handler, same durable store.
	h2 := newToolPolicyTestH(store)
	listReq := rootRequest("GET", "/api/organizations/org-1/tool-policies", "")
	listReq.SetPathValue("id", "org-1")
	w2 := httptest.NewRecorder()
	h2.ListToolPolicies()(w2, listReq)
	require.Equal(t, http.StatusOK, w2.Code)
	var list []*toolpolicy.Policy
	require.NoError(t, json.Unmarshal(w2.Body.Bytes(), &list))
	require.Len(t, list, 1)
	require.Equal(t, "resume-deny", list[0].Name)
	require.Equal(t, 7, list[0].Priority)

	// The chat path resumes under the restored policy.
	d := toolpolicy.NewEngine(&storeLoader{s: store}, 0).Decide(context.Background(), "org-1", "any-agent", "web_fetch")
	assert.Equal(t, toolpolicy.ActionDeny, d.Action)
}

// TestToolPolicyRecoveryRetrySemantics — retry of the input command within
// the contract: a blind create retry answers the typed 409 and changes
// nothing (the original row survives intact — the client confirms via GET
// rather than assuming either outcome); after an explicit delete the name is
// reusable and the stale-name mutations answer 404.
func TestToolPolicyRecoveryRetrySemantics(t *testing.T) {
	store := newToolPolicyTestStore()
	h := newToolPolicyTestH(store)
	body := `{"org_id":"org-1","name":"retry","subject":"*","tool":"web_*","action":"deny","priority":5,"enabled":true}`

	w1 := httptest.NewRecorder()
	h.CreateToolPolicy()(w1, rootRequest("POST", "/api/tool-policies", body))
	require.Equal(t, http.StatusCreated, w1.Code, w1.Body.String())

	// Blind retry: typed conflict, zero mutation.
	w2 := httptest.NewRecorder()
	h.CreateToolPolicy()(w2, rootRequest("POST", "/api/tool-policies", body))
	require.Equal(t, http.StatusConflict, w2.Code)
	require.Len(t, store.byName, 1, "a blind retry must not duplicate or overwrite")

	// The client's confirm path: GET returns the ORIGINAL row (first write
	// wins — the retry never replaced it).
	get := rootRequest("GET", "/api/organizations/org-1/tool-policies/retry", "")
	get.SetPathValue("id", "org-1")
	get.SetPathValue("name", "retry")
	w3 := httptest.NewRecorder()
	h.GetToolPolicy()(w3, get)
	require.Equal(t, http.StatusOK, w3.Code)
	var p toolpolicy.Policy
	require.NoError(t, json.Unmarshal(w3.Body.Bytes(), &p))
	require.Equal(t, 5, p.Priority, "the surviving row is the first create, untouched by the retry")

	// Delete → the name is reusable (a fresh create succeeds), while
	// stale-name reads and mutations answer 404, not ghost rows.
	del := rootRequest("DELETE", "/api/organizations/org-1/tool-policies/retry", "")
	del.SetPathValue("id", "org-1")
	del.SetPathValue("name", "retry")
	w4 := httptest.NewRecorder()
	h.DeleteToolPolicy()(w4, del)
	require.Equal(t, http.StatusOK, w4.Code)

	w5 := httptest.NewRecorder()
	h.GetToolPolicy()(w5, get)
	require.Equal(t, http.StatusNotFound, w5.Code)

	w6 := httptest.NewRecorder()
	h.CreateToolPolicy()(w6, rootRequest("POST", "/api/organizations/org-1/tool-policies", body))
	require.Equal(t, http.StatusCreated, w6.Code, "the name is reusable after an explicit delete")
}

// TestToolPolicyRecoveryPresetRetryConverges — the preset apply is
// idempotent per row (documented created/skipped observable state): a retry
// after an uncertain outcome converges without duplicates, including from a
// PARTIAL prior apply (one row already present from an interrupted run) —
// resume semantics, not exactly-once claims.
func TestToolPolicyRecoveryPresetRetryConverges(t *testing.T) {
	store := newToolPolicyTestStore()
	h := newToolPolicyTestH(store)

	apply := func() (int, int) {
		req := rootRequest("POST", "/api/organizations/org-1/tool-policies/presets/network-off", "")
		req.SetPathValue("id", "org-1")
		req.SetPathValue("preset", "network-off")
		w := httptest.NewRecorder()
		h.ApplyToolPolicyPreset()(w, req)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var res map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
		return int(res["created"].(float64)), int(res["skipped_existing"].(float64))
	}

	// A partial prior apply: one row the preset would create already exists
	// (an interrupted earlier run, honest uncertain outcome).
	partial := httptest.NewRecorder()
	h.CreateToolPolicy()(partial, rootRequest("POST", "/api/organizations/org-1/tool-policies",
		`{"org_id":"org-1","name":"network-off-web_fetch-a","subject":"*","tool":"web_fetch","action":"deny","priority":100,"enabled":true}`))
	require.Equal(t, http.StatusCreated, partial.Code, partial.Body.String())

	created, skipped := apply()
	require.Equal(t, 11, created, "only the missing rows are created")
	require.Equal(t, 1, skipped, "the pre-existing row is kept, never duplicated")

	// Full retry after the (now certain) apply: nothing new.
	created2, skipped2 := apply()
	assert.Equal(t, 0, created2, "retry must converge: no duplicates")
	assert.Equal(t, 12, skipped2)

	// The converged state is complete and denies the preset's tool.
	require.Len(t, store.byName, 12)
	d := toolpolicy.NewEngine(&storeLoader{s: store}, 0).Decide(context.Background(), "org-1", "any-agent", "web_fetch")
	assert.Equal(t, toolpolicy.ActionDeny, d.Action)
}

// TestToolPolicyRecoveryEditLandsImmediately — observable post-mutation
// state: the admin CRUD drops the org's engine cache, so an edit lands on
// the next Decide without TTL staleness (create → deny; disable via PATCH →
// allow), on the same wired engine instance.
func TestToolPolicyRecoveryEditLandsImmediately(t *testing.T) {
	store := newToolPolicyTestStore()
	engine := toolpolicy.NewEngine(&storeLoader{s: store}, 0) // default 5s TTL on purpose
	h := newToolPolicyTestH(store)
	h.SetToolPolicyStore(toolpolicy.NewStore(store), engine)

	allow := func() bool {
		return toolpolicy.ActionAllow == engine.Decide(context.Background(), "org-1", "any-agent", "web_fetch").Action
	}
	require.True(t, allow(), "no rows: implicit allow")

	w := httptest.NewRecorder()
	h.CreateToolPolicy()(w, rootRequest("POST", "/api/tool-policies",
		`{"org_id":"org-1","name":"live-deny","subject":"*","server":"*","tool":"web_*","action":"deny","enabled":true}`))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	require.False(t, allow(), "create must land on the engine immediately (cache invalidated), not after the TTL")

	// Disable the row via PATCH: the deny must lift immediately too.
	patch := rootRequest("PATCH", "/api/organizations/org-1/tool-policies/live-deny", `{"enabled":false}`)
	patch.SetPathValue("id", "org-1")
	patch.SetPathValue("name", "live-deny")
	w2 := httptest.NewRecorder()
	h.UpdateToolPolicy()(w2, patch)
	require.Equal(t, http.StatusOK, w2.Code, w2.Body.String())
	require.True(t, allow(), "disable must lift the deny immediately (cache invalidated)")
}
