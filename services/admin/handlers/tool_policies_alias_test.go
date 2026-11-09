package handlers

// N07-P07-T06 — the dashboard create alias parity. The console's
// ToolPolicyPage posts POST /api/tool-policies (org addressed via the body
// org_id); before this card the server only registered the org-scoped
// POST /api/organizations/{id}/tool-policies, so the UI create was a live
// broken capability (the T02 unserved pin). The alias mounts the SAME
// handler in the SAME root group: one capability, one guard chain, one
// store — no privileged shortcut in either direction.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/reireirei/yabanin/pkg/toolpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToolPolicyAliasParity(t *testing.T) {
	store := newToolPolicyTestStore()
	h := newToolPolicyTestH(store)

	// The alias creates the same row shape (org addressed via body org_id).
	w := httptest.NewRecorder()
	h.CreateToolPolicy()(w, rootRequest("POST", "/api/tool-policies",
		`{"org_id":"org-1","name":"alias-deny","subject":"*","tool":"web_*","action":"deny","priority":7,"enabled":true}`))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var p toolpolicy.Policy
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &p))
	require.Equal(t, "org-1", p.OrgID)
	require.Equal(t, "alias-deny", p.Name)

	// One capability, one store: the org-scoped route sees the alias's row
	// (duplicate (org, name) → 409) — not a parallel implementation.
	w2 := httptest.NewRecorder()
	h.CreateToolPolicy()(w2, rootRequest("POST", "/api/organizations/org-1/tool-policies",
		`{"org_id":"org-1","name":"alias-deny","subject":"*","tool":"web_*","action":"deny"}`))
	require.Equal(t, http.StatusConflict, w2.Code)

	// Identical input validation on the alias — including the missing org
	// target (requireOrgScope answers 400 for a root caller without one).
	for _, body := range []string{
		`{"org_id":"org-1","name":"Bad Name","subject":"*","tool":"web_*","action":"deny"}`,
		`{"name":"ok","subject":"*","tool":"*","action":"deny"}`,
	} {
		wv := httptest.NewRecorder()
		h.CreateToolPolicy()(wv, rootRequest("POST", "/api/tool-policies", body))
		require.Equal(t, http.StatusBadRequest, wv.Code, "body: %s → %s", body, wv.Body.String())
	}

	// Same unwired-store failure shape as the scoped route.
	hn := New(nil, "", "", []string{})
	w3 := httptest.NewRecorder()
	hn.CreateToolPolicy()(w3, rootRequest("POST", "/api/tool-policies", `{}`))
	assert.Equal(t, http.StatusServiceUnavailable, w3.Code)
}

// TestToolPolicyAliasGuardParity asserts the ROUTER-level parity: the alias
// and the org-scoped create carry the identical middleware chain from the
// fully-wired golden walk, and the drift gate is quiet on the real tree —
// the documented root class matches the walked guard class on both
// surfaces, so the alias cannot be a weaker shortcut.
func TestToolPolicyAliasGuardParity(t *testing.T) {
	golden := goldenChainsByRoute(t)
	alias, ok := golden["POST /api/tool-policies"]
	require.True(t, ok, "alias route missing from the fully-wired golden walk")
	scoped, ok := golden["POST /api/organizations/{id}/tool-policies"]
	require.True(t, ok)
	require.Equal(t, scoped.Chain, alias.Chain,
		"alias must mount in the same guarded group (session+csrf+root+orgscope)")

	walked := inventoryRoutes(t)
	documented := parseOpenAPIRoutes(t, adminOpenAPISpec)
	require.Empty(t, routeInventoryProblems(t, walked, documented, goldenChainsByRoute))
}
