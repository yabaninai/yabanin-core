package handlers

// N07-P07-T05 — negative-contract probes. The packet acceptance names three
// negative scenarios that block acceptance: a hidden UI-only endpoint, a
// privileged API shortcut, and a mismatched archived-original payload
// prohibition. Each probe below drives the REAL comparators (the extracted
// routeInventoryProblems / permissionProblems detectors and the live HTTP
// handler boundary) with a deliberately violated input and asserts the
// violation is reported — and that the clean state reports nothing, so a
// probe cannot pass by false success in either direction. The committed
// record documents the same detections executed end-to-end against the
// shipped gates by temporarily mutating the sources (RED) and restoring
// them (GREEN).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
)

func cloneDocumented(in map[string]routeSpec) map[string]routeSpec {
	out := make(map[string]routeSpec, len(in)+1)
	for k, v := range in {
		out[k] = v
	}
	return out
}

// TestNegativeHiddenRouteIsDetected drives the undocumented-route direction:
// a route registered by SetupRouter but missing from admin.openapi.yaml (the
// hidden UI-only endpoint shape) must fail the inventory comparator, while
// the untouched walked/document pair reports nothing.
func TestNegativeHiddenRouteIsDetected(t *testing.T) {
	walked := inventoryRoutes(t)
	require.NotEmpty(t, walked)
	documented := parseOpenAPIRoutes(t, adminOpenAPISpec)

	// Clean state: no false positive — the probes below are meaningful only
	// against a comparator that is quiet on the real tree.
	require.Empty(t, routeInventoryProblems(t, walked, documented, goldenChainsByRoute))

	// Registered-but-undocumented route (the negative scenario verbatim).
	hidden := append(append([]routeSpec{}, walked...), routeSpec{
		Method: "POST", Pattern: "/api/organizations/{id}/__hidden_probe", Permission: "root",
	})
	problems := routeInventoryProblems(t, hidden, documented, goldenChainsByRoute)
	require.Len(t, problems, 1)
	require.Contains(t, problems[0], "undocumented route POST /api/organizations/{id}/__hidden_probe")

	// Symmetric direction: documentation removed while the route still
	// serves — the spec behind the code's back.
	documented = cloneDocumented(documented)
	delete(documented, walked[0].key())
	problems = routeInventoryProblems(t, walked, documented, goldenChainsByRoute)
	require.Len(t, problems, 1)
	require.Contains(t, problems[0], "undocumented route "+walked[0].key())
}

// TestNegativePrivilegedShortcutIsDetected drives permission-drift
// detection: a documented guard weakened on paper, or a privileged surface
// mounted outside its root group, must fail the inventory comparator; a
// fabricated org permission must fail the permission matrix.
func TestNegativePrivilegedShortcutIsDetected(t *testing.T) {
	walked := inventoryRoutes(t)
	require.NotEmpty(t, walked)
	documented := parseOpenAPIRoutes(t, adminOpenAPISpec)

	// A privileged surface whose spec entry quietly claims a weaker class —
	// the exact shortcut shape the criterion forbids: the API would look
	// documented while bypassing the real guard contract. The walked guard
	// class comes from the router walk itself (the router truth).
	var walkedMe routeSpec
	for _, spec := range walked {
		if spec.key() == "GET /api/me" {
			walkedMe = spec
			break
		}
	}
	require.NotEmpty(t, walkedMe.Permission, "GET /api/me must be walked by the inventory")
	mutated := cloneDocumented(documented)
	mutated["GET /api/me"] = routeSpec{Method: "GET", Pattern: "/api/me", Permission: "public", Summary: "probe mutation"}
	problems := routeInventoryProblems(t, walked, mutated, goldenChainsByRoute)
	require.Len(t, problems, 1)
	require.Contains(t, problems[0],
		fmt.Sprintf(`GET /api/me: permission drift — router guards %q, spec says "public"`, walkedMe.Permission))

	// An alias mounted OUTSIDE its privileged group: the walk class is the
	// router truth (public = no auth middleware beyond the global chain),
	// the spec honestly says root — the comparator must flag the shortcut.
	// A fresh doc clone keeps this sub-case independent of the /api/me
	// mutation above.
	aliasDocumented := cloneDocumented(documented)
	aliasDocumented["POST /api/__probe_alias"] = routeSpec{Method: "POST", Pattern: "/api/__probe_alias", Permission: "root", Summary: "probe alias"}
	aliasWalked := append(append([]routeSpec{}, walked...), routeSpec{
		Method: "POST", Pattern: "/api/__probe_alias", Permission: "public",
	})
	problems = routeInventoryProblems(t, aliasWalked, aliasDocumented, goldenChainsByRoute)
	require.Len(t, problems, 1)
	require.Contains(t, problems[0], `POST /api/__probe_alias: permission drift — router guards "public", spec says "root"`)

	// A fabricated org permission (policies.grant is not in the matrix) is
	// rejected — a spec entry can invent neither classes nor permissions.
	require.Equal(t,
		[]string{`GET /api/__probe_alias: unknown org permission "policies.grant" (see pkg/adminstore/permissions.go)`},
		permissionProblems("GET /api/__probe_alias", "org:policies.grant"))
}

// TestNegativeUIOnlyActionResolvesUnserved drives the UI-action tier
// detector: an action whose (method, path) matches NO served route on any
// surface classifies as unserved, and the inventory gate fails it unless it
// carries an explicit pin with a reason. A synthetic probe action must
// never be pinnable, and the pinned-hole invariant must hold for real
// dashboard actions (unserved ⇒ pinned, documented ⇒ unpinned).
func TestNegativeUIOnlyActionResolvesUnserved(t *testing.T) {
	adminSpec := parseOpenAPIRoutes(t, adminOpenAPISpec)
	gatewaySpec := gatewaySideOps(t, parseOpenAPIRoutes(t, gatewayOpenAPISpec))
	adminGolden := parseGoldenRoutes(t, adminRoutesGolden)
	gatewayGolden := parseGoldenRoutes(t, gatewayRoutesGolden)

	probe := uiAction{Method: "POST", Path: "/api/__ui_only_probe"}
	require.Equal(t, "unserved", classifyUIAction(probe, adminSpec, gatewaySpec, adminGolden, gatewayGolden))
	_, pinned := uiActionBaselines.unserved[probe.key()]
	require.False(t, pinned, "a synthetic probe action must never be pinned as a tolerated hole")

	// A real dashboard action is either served by a documented surface or,
	// while unserved, explicitly pinned as a known contract hole with a
	// reason — the "hidden UI-only endpoint blocks acceptance" invariant.
	tp := uiAction{Method: "POST", Path: "/api/tool-policies"}
	tier := classifyUIAction(tp, adminSpec, gatewaySpec, adminGolden, gatewayGolden)
	if tier == "unserved" {
		require.NotEmpty(t, uiActionBaselines.unserved[tp.key()],
			"unserved dashboard action must be pinned with an explicit reason (known contract hole)")
	} else {
		_, pinned = uiActionBaselines.unserved[tp.key()]
		require.False(t, pinned,
			"action now resolves as %q — retire its unserved pin (the hole is closed)", tier)
	}
}

// payloadProbeStore wraps the shared mock with request-list rows that carry
// payload material the prohibition must strip (raw error text and recorded
// tool calls) unless the caller owns the row. SearchRequestArchive mirrors
// the production archive store: until N10 the archive search reads the same
// hot request_logs table.
type payloadProbeStore struct {
	*mockStore
	rows []adminstore.RequestListRow
}

func (s *payloadProbeStore) ListRequests(_ context.Context, f adminstore.RequestListFilters) ([]adminstore.RequestListRow, int, error) {
	if f.ContentSearch != "" && f.PayloadAuthorizationSet && !f.PayloadSearchAllowed {
		return []adminstore.RequestListRow{}, 0, nil
	}
	// Fresh row copies per query, like the database hands out — the two
	// handler invocations must observe independent row data, or one
	// handler's redaction could mask the other's divergence.
	out := make([]adminstore.RequestListRow, len(s.rows))
	copy(out, s.rows)
	return out, len(out), nil
}

func (s *payloadProbeStore) SearchRequestArchive(ctx context.Context, f adminstore.RequestListFilters) ([]adminstore.RequestListRow, int, error) {
	return s.ListRequests(ctx, f)
}

// probePayloadError/probePayloadTool are decoy marker material planted into
// fixture rows: the payload-prohibition contract must either strip them
// (denied verdict) or keep them (owned row). They are assertable markers,
// not credentials — the names use the domain term ("payload") on purpose.
const (
	probePayloadError = "upstream 500: internal sqlstate secret-sauce-token"
	probePayloadTool  = "shell: rm -rf /tmp/secret-sauce"
)

// TestArchiveSearchPayloadProhibitionParity pins the archived-original
// prohibition at the handler boundary. The two surfaces enforce the SAME
// payload verdict with deliberately different admission strictness: the hot
// list is the metadata explorer (a denied caller still gets 200 with fully
// redacted rows), while the archive search denies at the boundary (403, no
// rows at all). Both behaviors honor §5 — no payload material ever escapes
// the grant/ownership verdict — and any divergence on the admitted path is
// the "search must not bypass the payload mode" mismatch the packet
// criterion forbids (PRODUCT-CONTRACT §5).
func TestArchiveSearchPayloadProhibitionParity(t *testing.T) {
	mkRows := func(owned bool) []adminstore.RequestListRow {
		return []adminstore.RequestListRow{{
			RequestID: "req-probe", OrgID: "org-1", ModelUsed: "gpt-4o-mini",
			StatusCode: 200, CostUSD: 0.002, TokensIn: 100, TokensOut: 50,
			CreatedAt: time.Now().UTC(),
			ErrorMsg:  probePayloadError,
			ToolCalls: []string{probePayloadTool},
			// PayloadOwned simulates the store's ownership verdict for the
			// calling principal (the DB pins that comparison; the handler
			// contract under test is to honor it).
			PayloadOwned: owned,
		}}
	}
	for _, tc := range []struct {
		name       string
		ctx        context.Context
		owned      bool
		wantKept   bool
		wantDenied bool // archive search answers 403 (stricter boundary); hot list stays 200 metadata-only
	}{
		// Bare root session: no org membership, no own-history, no
		// org-wide metadata — the archive boundary refuses (403), the hot
		// list answers metadata-only with fully redacted rows.
		{name: "root foreign row", ctx: rootRequest("GET", "/", "").Context(), owned: false, wantDenied: true},
		{name: "root owned row", ctx: rootRequest("GET", "/", "").Context(), owned: true, wantDenied: true},
		// Org members with an own-history verdict: kept rows carry payload
		// material only when the row is owned by the caller (the store pins
		// the ownership lookup; the handler honors its verdict).
		{name: "org-admin owned row", ctx: WithOrgRole(context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, "probe-admin"), "org-1", adminstore.RoleOrgAdmin), owned: true, wantKept: true},
		{name: "org-admin foreign row", ctx: WithOrgRole(context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, "probe-admin"), "org-1", adminstore.RoleOrgAdmin), owned: false, wantKept: false},
		{name: "reader foreign row", ctx: WithOrgRole(context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, "probe-reader"), "org-1", adminstore.RoleReader), owned: false, wantKept: false},
		// Own-history admission is user-scoped, not org-scoped: a caller
		// whose membership is elsewhere may still read rows the store
		// attributes to them (ownership scope is the store's pin, see
		// N04-P05 delegation precedent).
		{name: "own-history read across orgs", ctx: WithOrgRole(context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, "probe-admin"), "org-2", adminstore.RoleOrgAdmin), owned: true, wantKept: true},
		// Explicit policy deny (WithRequestPayloadDenyOwnHistory overrides
		// grants and roles): the verdict denies payloads, metadata remains
		// visible to the member (requests.read) — both surfaces strip.
		{name: "policy deny own history", ctx: adminstore.WithRequestPayloadDenyOwnHistory(WithOrgRole(context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, "probe-admin"), "org-1", adminstore.RoleOrgAdmin), true), owned: true, wantKept: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows := mkRows(tc.owned)
			newProbe := func() *testAdminHandlers {
				probe := &payloadProbeStore{mockStore: newMockStore(), rows: rows}
				return &testAdminHandlers{AdminHandlers: New(probe, "", "", []string{}), store: probe.mockStore}
			}
			hotH, archH := newProbe(), newProbe()

			hotReq := httptest.NewRequestWithContext(tc.ctx, http.MethodGet, "/api/organizations/org-1/requests", nil)
			hotRec := httptest.NewRecorder()
			// wrapWithParams injects the {id} URL parameter the production
			// chi router resolves, so parseRequestListFilters sees the real
			// org scope (metadata admission depends on it).
			wrapWithParams(hotH.apiOrgRequests(), "/api/organizations/{id}/requests")(hotRec, hotReq)

			archReq := httptest.NewRequestWithContext(tc.ctx, http.MethodGet, "/api/organizations/org-1/requests", nil)
			archRec := httptest.NewRecorder()
			wrapWithParams(archH.apiOrgArchiveSearch(), "/api/organizations/{id}/requests/archive-search")(archRec, archReq)

			require.Equal(t, http.StatusOK, hotRec.Code)
			if tc.wantDenied {
				// The archive boundary refuses callers without content
				// access or org-wide metadata: no rows, no payload material,
				// no false success status.
				require.Equal(t, http.StatusForbidden, archRec.Code)
				require.NotContains(t, archRec.Body.String(), "secret-sauce")
				require.NotContains(t, hotRec.Body.String(), "secret-sauce")
				return
			}
			require.Equal(t, http.StatusOK, archRec.Code)

			// The redaction verdict must be identical: same rows, same
			// filters, same strip/keep decision — the row arrays must be
			// byte-equal after decoding.
			var hotBody, archBody map[string]any
			require.NoError(t, json.Unmarshal(hotRec.Body.Bytes(), &hotBody))
			require.NoError(t, json.Unmarshal(archRec.Body.Bytes(), &archBody))
			require.Equal(t, hotBody["data"], archBody["data"],
				"archive search must redact exactly like the hot list for the same verdict")

			// The sensitive material itself confirms the decision (no false
			// success: kept rows really carry the material, stripped rows
			// really lose it on both surfaces).
			if tc.wantKept {
				require.Contains(t, hotRec.Body.String(), probePayloadError)
				require.Contains(t, archRec.Body.String(), probePayloadTool)
			} else {
				require.NotContains(t, hotRec.Body.String(), "secret-sauce")
				require.NotContains(t, archRec.Body.String(), "secret-sauce")
			}
		})
	}
}
