package handlers

// N07-P07-T07 — boundary corpus (regression). The card asks for a corpus of
// boundary examples over the packet's named aspects and confirmation that
// the previously supported contract did not regress. The corpus complements
// (does not duplicate) the T05 negative probes: where T05 proved the
// DETECTORS fire on violated inputs, this corpus fixes the BOUNDARY VALUES
// of the surfaces those detectors guard:
//
//  1. create-route boundary parity — every validation edge answers the same
//     status on the dashboard alias (POST /api/tool-policies, org via body)
//     and the scoped route (POST /api/organizations/{id}/tool-policies):
//     one capability, one contract, no weaker alias;
//  2. org-scope boundary — root consumes the body org_id (empty → 400), a
//     non-root caller is bound to their middleware-pinned scope (empty →
//     403, cross-org → 403, role-less → 403): the alias cannot become a
//     privileged shortcut at the boundary either;
//  3. UI-surface regression tripwires — the pin set is exactly the two MC-4
//     holes, the T06 alias is served through the documented spec, and the
//     walked inventory stays at the accepted size (280 + the adopted alias);
//  4. archived/original payload prohibition — the T05 keep/strip verdict
//     parity between the hot list and the archive search holds for boundary
//     payload shapes (empty, unicode, 10 KiB, multiline, JSON-like, control
//     chars), not just the probe shape.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/stretchr/testify/require"
)

// TestBoundaryCorpusToolPolicyCreateRouteParity runs every boundary input of
// the create contract against BOTH registered create routes and requires the
// identical status — the alias and the scoped surface are one contract.
func TestBoundaryCorpusToolPolicyCreateRouteParity(t *testing.T) {
	bigRules := `{"args":{"deny_regex":["` + strings.Repeat("a", 64<<10) + `"]}}` // > MaxRulesBytes (64 KiB)
	cases := []struct {
		name string
		body string
		want int
	}{
		// Name boundary (ValidateName: [a-z0-9_-], head alnum, ≤64).
		{name: "name empty", body: `{"org_id":"org-1","name":"","subject":"*","tool":"web_*","action":"deny"}`, want: 400},
		{name: "name leading dash", body: `{"org_id":"org-1","name":"-lead","subject":"*","tool":"web_*","action":"deny"}`, want: 400},
		{name: "name leading underscore", body: `{"org_id":"org-1","name":"_lead","subject":"*","tool":"web_*","action":"deny"}`, want: 400},
		{name: "name uppercase", body: `{"org_id":"org-1","name":"Bad","subject":"*","tool":"web_*","action":"deny"}`, want: 400},
		{name: "name space", body: `{"org_id":"org-1","name":"bad name","subject":"*","tool":"web_*","action":"deny"}`, want: 400},
		{name: "name max 64", body: fmt.Sprintf(`{"org_id":"org-1","name":"%s","subject":"*","tool":"web_*","action":"deny"}`, strings.Repeat("a", 64)), want: 201},
		{name: "name 65", body: fmt.Sprintf(`{"org_id":"org-1","name":"%s","subject":"*","tool":"web_*","action":"deny"}`, strings.Repeat("a", 65)), want: 400},
		{name: "name digit head", body: `{"org_id":"org-1","name":"9lives","subject":"*","tool":"web_*","action":"deny"}`, want: 201},
		// Priority boundary (documented 0..1000).
		{name: "priority 0", body: `{"org_id":"org-1","name":"p0","subject":"*","tool":"web_*","action":"deny","priority":0}`, want: 201},
		{name: "priority 1000", body: `{"org_id":"org-1","name":"p1000","subject":"*","tool":"web_*","action":"deny","priority":1000}`, want: 201},
		{name: "priority 1001", body: `{"org_id":"org-1","name":"p1001","subject":"*","tool":"web_*","action":"deny","priority":1001}`, want: 400},
		{name: "priority -1", body: `{"org_id":"org-1","name":"pneg","subject":"*","tool":"web_*","action":"deny","priority":-1}`, want: 400},
		// Action enum boundary (exactly the two documented actions).
		{name: "action allow", body: `{"org_id":"org-1","name":"a-allow","subject":"*","tool":"web_*","action":"allow"}`, want: 201},
		{name: "action log", body: `{"org_id":"org-1","name":"a-log","subject":"*","tool":"web_*","action":"log"}`, want: 400},
		{name: "action empty", body: `{"org_id":"org-1","name":"a-empty","subject":"*","tool":"web_*","action":""}`, want: 400},
		{name: "action DENY", body: `{"org_id":"org-1","name":"a-upper","subject":"*","tool":"web_*","action":"DENY"}`, want: 400},
		// Pattern boundary ('*' alone or trailing star on a sane base).
		{name: "subject star", body: `{"org_id":"org-1","name":"s-star","subject":"*","tool":"web_*","action":"deny"}`, want: 201},
		{name: "subject trailing star", body: `{"org_id":"org-1","name":"s-trail","subject":"web_*","tool":"web_search","action":"deny"}`, want: 201},
		{name: "subject interior star", body: `{"org_id":"org-1","name":"s-inter","subject":"web_*x","tool":"*","action":"deny"}`, want: 400},
		{name: "subject double star", body: `{"org_id":"org-1","name":"s-dbl","subject":"**","tool":"*","action":"deny"}`, want: 400},
		{name: "subject empty", body: `{"org_id":"org-1","name":"s-empty","subject":"","tool":"*","action":"deny"}`, want: 400},
		{name: "tool empty", body: `{"org_id":"org-1","name":"t-empty","subject":"*","tool":"","action":"deny"}`, want: 400},
		{name: "server interior star", body: `{"org_id":"org-1","name":"sv-inter","subject":"*","server":"a*b","tool":"*","action":"deny"}`, want: 400},
		// Rules boundary (bounds + shape).
		{name: "rules omitted", body: `{"org_id":"org-1","name":"r-omit","subject":"*","tool":"web_*","action":"deny"}`, want: 201},
		{name: "rules null", body: `{"org_id":"org-1","name":"r-null","subject":"*","tool":"web_*","action":"deny","rules":null}`, want: 201},
		{name: "rules valid args", body: `{"org_id":"org-1","name":"r-args","subject":"*","tool":"web_*","action":"deny","rules":{"args":{"max_bytes":1024}}}`, want: 201},
		{name: "rules empty object", body: `{"org_id":"org-1","name":"r-empty","subject":"*","tool":"web_*","action":"deny","rules":{}}`, want: 400},
		{name: "rules not json", body: `{"org_id":"org-1","name":"r-bad","subject":"*","tool":"web_*","action":"deny","rules":"nope"}`, want: 400},
		{name: "rules over 64KiB", body: `{"org_id":"org-1","name":"r-big","subject":"*","tool":"web_*","action":"deny","rules":` + bigRules + `}`, want: 400},
		// Body boundary.
		{name: "malformed json", body: `{"org_id":`, want: 400},
		// Org-target boundary: root consumes the body org_id; absent → 400.
		{name: "alias org missing", body: `{"name":"no-org","subject":"*","tool":"web_*","action":"deny"}`, want: 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The alias surface (fresh store: the two probes compare
			// behavior, not shared rows — the shared-store property has its
			// own dedicated boundary below).
			wAlias := httptest.NewRecorder()
			newToolPolicyTestH(newToolPolicyTestStore()).CreateToolPolicy()(
				wAlias, rootRequest("POST", "/api/tool-policies", tc.body))
			// The org-scoped surface (root: body org_id still resolves the target).
			wScoped := httptest.NewRecorder()
			newToolPolicyTestH(newToolPolicyTestStore()).CreateToolPolicy()(
				wScoped, rootRequest("POST", "/api/organizations/org-1/tool-policies", tc.body))

			require.Equal(t, tc.want, wAlias.Code, "alias: %s", wAlias.Body.String())
			require.Equal(t, tc.want, wScoped.Code,
				"route parity violated: alias=%d scoped=%d (%s)", wAlias.Code, wScoped.Code, wScoped.Body.String())
		})
	}

	// Duplicate boundary: the second create of the same (org, name) is a 409
	// from EITHER route (one store, not a parallel implementation), and the
	// documented retry (a different name) succeeds — a blind retry does not.
	h := newToolPolicyTestH(newToolPolicyTestStore())
	w1 := httptest.NewRecorder()
	h.CreateToolPolicy()(w1, rootRequest("POST", "/api/tool-policies",
		`{"org_id":"org-1","name":"dup","subject":"*","tool":"web_*","action":"deny"}`))
	require.Equal(t, http.StatusCreated, w1.Code, w1.Body.String())

	w2 := httptest.NewRecorder()
	h.CreateToolPolicy()(w2, rootRequest("POST", "/api/organizations/org-1/tool-policies",
		`{"org_id":"org-1","name":"dup","subject":"*","tool":"web_*","action":"deny"}`))
	require.Equal(t, http.StatusConflict, w2.Code)

	w3 := httptest.NewRecorder()
	h.CreateToolPolicy()(w3, rootRequest("POST", "/api/organizations/org-1/tool-policies",
		`{"org_id":"org-1","name":"dup2","subject":"*","tool":"web_*","action":"deny"}`))
	require.Equal(t, http.StatusCreated, w3.Code)

	w4 := httptest.NewRecorder()
	h.CreateToolPolicy()(w4, rootRequest("POST", "/api/tool-policies",
		`{"org_id":"org-1","name":"dup2","subject":"*","tool":"web_*","action":"deny"}`))
	require.Equal(t, http.StatusConflict, w4.Code)

	w5 := httptest.NewRecorder()
	h.CreateToolPolicy()(w5, rootRequest("POST", "/api/tool-policies",
		`{"org_id":"org-1","name":"dup3","subject":"*","tool":"web_*","action":"deny"}`))
	require.Equal(t, http.StatusCreated, w5.Code)

	// Root cross-target boundary (observable, documented): on the scoped
	// route the root operator's body org_id wins over the path org — the
	// alias contract makes the body the target selector for operators.
	wc := httptest.NewRecorder()
	h.CreateToolPolicy()(wc, rootRequest("POST", "/api/organizations/org-1/tool-policies",
		`{"org_id":"org-2","name":"cross","subject":"*","tool":"web_*","action":"deny"}`))
	require.Equal(t, http.StatusCreated, wc.Code, wc.Body.String())
	var created struct {
		OrgID string `json:"org_id"`
	}
	require.NoError(t, json.Unmarshal(wc.Body.Bytes(), &created))
	require.Equal(t, "org-2", created.OrgID)
}

// TestBoundaryCorpusOrgScopeMutations pins the non-root boundary of the
// create mutation: middleware-pinned scope only, cross-org refused, a
// role-less member refused — the alias cannot lower the mutation gate.
func TestBoundaryCorpusOrgScopeMutations(t *testing.T) {
	h := newToolPolicyTestH(newToolPolicyTestStore())

	member := func(body, scopeOrg string, withScope, withRole bool) *http.Request {
		r := httptest.NewRequestWithContext(context.Background(), "POST", "/api/tool-policies", strings.NewReader(body))
		ctx := r.Context()
		if withScope {
			ctx = context.WithValue(ctx, ctxKeyOrgScope{}, scopeOrg)
		}
		if withRole {
			ctx = WithOrgRole(ctx, scopeOrg, adminstore.RoleOrgAdmin)
		}
		return r.WithContext(ctx)
	}
	const body = `{"org_id":"org-1","name":"member-made","subject":"*","tool":"web_*","action":"deny"}`

	// In-scope member with a role: the create succeeds for their org.
	wOK := httptest.NewRecorder()
	h.CreateToolPolicy()(wOK, member(body, "org-1", true, true))
	require.Equal(t, http.StatusCreated, wOK.Code, wOK.Body.String())
	var created struct {
		OrgID string `json:"org_id"`
	}
	require.NoError(t, json.Unmarshal(wOK.Body.Bytes(), &created))
	require.Equal(t, "org-1", created.OrgID, "a member cannot target another org even by body")

	// Cross-org body vs pinned scope → 403.
	wCross := httptest.NewRecorder()
	h.CreateToolPolicy()(wCross, member(`{"org_id":"org-2","name":"cross-member","subject":"*","tool":"web_*","action":"deny"}`, "org-1", true, true))
	require.Equal(t, http.StatusForbidden, wCross.Code)

	// No middleware-pinned scope → 403 (the alias hands org via body, but a
	// non-root caller has no operator privilege to spend it).
	wNoScope := httptest.NewRecorder()
	h.CreateToolPolicy()(wNoScope, member(body, "", false, false))
	require.Equal(t, http.StatusForbidden, wNoScope.Code)
	require.Contains(t, wNoScope.Body.String(), "org scope is not set")

	// Scoped but role-less → 403 (the org-scoped MUTATION gate).
	wNoRole := httptest.NewRecorder()
	h.CreateToolPolicy()(wNoRole, member(body, "org-1", true, false))
	require.Equal(t, http.StatusForbidden, wNoRole.Code)
	require.Contains(t, wNoRole.Body.String(), "do not have a role")
}

// TestBoundaryCorpusUIOnlyPinsRegression — UI-surface tripwires: the pin set
// is exactly the two MC-4 contract holes (still unserved), the T06 alias is
// served through the documented spec, and the walked inventory stays at the
// accepted size.
func TestBoundaryCorpusUIOnlyPinsRegression(t *testing.T) {
	// The accepted admin golden inventory size: 280 at T05 + the one adopted
	// alias + the two additive routing views (/api/routing/actual and
	// /api/routing/snapshot; the walked⇄golden⇄spec consistency is the drift
	// gate's job — this tripwire pins the accepted SIZE so drift cannot pass
	// silently). +6 for the currencies surfaces (units spend, budgets
	// caps, credits ledger view, rates catalog/diff/promote), added
	// consciously with handler-level rights matrices; +1 for the policies
	// validate arbiter endpoint (N16-P01-T02, owner decision 2026-11-04 (a);
	// the drift report endpoint is inside the base count); +2 for the E06-P01
	// security-inbox reads (list + detail, org:security.read, W01-C03);
	// +3 for the E02-P01 asset-registry SPI (inventory read + MCP import
	// + models import — golden-tracked, root-only, OPENAPI-DELTA 2026-11-08;
	// union combine: E06 lanes pin 292, E02-P01 wiring card pins 293 on the
	// 290 base — both additions ride the same golden, 292+3 = 295)
	// +1 for the E01-P05 W04-C02 entitlement diagnostics read (root-only,
	// snapshot interface — the handler plane stays license-free);
	// entry-6 re-pin to the union-combined reality: 295 + 1 = 296,
	// machine-counted on the merged golden.
	// +1 for the E06-P01 security-inbox operator write (PATCH incident,
	// org:security.manage — org_admin only, W04-C02).
	// batch-B entry re-pin to the machine-counted merged truth:
	// 296 + 1 = 297 (union 296 + the disjoint PATCH add above),
	// machine-counted on the merged golden.
	// +2 for the E03-P01 W04-C03 fleet-registry reads (list + detail,
	// root-only, read-only plane — the TEXT license-org coordinate is
	// the path org).
	// Union combine of the two additions: 297 + 2 = 299 (the union
	// inventory plus the disjoint fleet reads), machine-counted on the
	// merged golden.
	require.Len(t, parseGoldenRoutes(t, adminRoutesGolden), 299,
		"admin route inventory changed — update the golden/spec consciously, never silently")

	// The T06 dashboard alias is served by the documented admin surface.
	adminSpec := parseOpenAPIRoutes(t, adminOpenAPISpec)
	gatewaySpec := gatewaySideOps(t, parseOpenAPIRoutes(t, gatewayOpenAPISpec))
	adminGolden := parseGoldenRoutes(t, adminRoutesGolden)
	gatewayGolden := parseGoldenRoutes(t, gatewayRoutesGolden)
	require.Equal(t, "admin-spec",
		classifyUIAction(uiAction{Method: "POST", Path: "/api/tool-policies"}, adminSpec, gatewaySpec, adminGolden, gatewayGolden),
		"the dashboard create must resolve through the documented API, not a golden-only surface")

	// The remaining holes are exactly the pinned MC-4 pair, still unserved.
	require.Len(t, uiActionBaselines.unserved, 2, "the pin set is the two MC-4 holes")
	for _, probe := range []uiAction{
		{Method: "GET", Path: "/api/organizations/{}/mcp/user-credentials"},
		{Method: "DELETE", Path: "/api/organizations/{}/mcp/user-credentials/{}/{}"},
	} {
		require.Equal(t, "unserved",
			classifyUIAction(probe, adminSpec, gatewaySpec, adminGolden, gatewayGolden),
			"pinned hole became served — retire the pin consciously")
		require.NotEmpty(t, uiActionBaselines.unserved[probe.key()],
			"unserved action must keep its pin with a reason")
	}
}

// TestBoundaryCorpusPayloadProhibitionShapes extends the T05 hot/archive
// verdict-parity probe to boundary payload shapes: whatever the row carries,
// the two surfaces answer identically (byte-equal rows on the admitted path;
// no material anywhere on the denied path).
func TestBoundaryCorpusPayloadProhibitionShapes(t *testing.T) {
	// Every shape embeds the same marker so kept/stripped assertions stay
	// uniform; shapes cover the redaction-relevant input space edges.
	shapes := []struct {
		name    string
		errMsg  string
		toolAsk string
	}{
		{name: "empty fields", errMsg: "secret-sauce", toolAsk: "secret-sauce"},
		{name: "unicode", errMsg: "ошибка upstream: secret-sauce 🔥", toolAsk: "shell: secret-sauce /tmp/секрет"},
		{name: "long 10k", errMsg: strings.Repeat("A", 10_000) + " secret-sauce", toolAsk: strings.Repeat("t", 5_000) + " secret-sauce"},
		{name: "multiline", errMsg: "line1\nline2\tsecret-sauce", toolAsk: "call1\ncall2 secret-sauce"},
		{name: "json-like", errMsg: `{"err":"secret-sauce"}`, toolAsk: `{"cmd":"secret-sauce"}`},
		{name: "control chars", errMsg: "err\x01\x02secret-sauce\x7f", toolAsk: "call\x1b[31msecret-sauce"},
	}
	verdicts := []struct {
		name     string
		ctx      context.Context
		wantKept bool
	}{
		{
			name:     "org-admin owned row",
			ctx:      WithOrgRole(context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, "probe-admin"), "org-1", adminstore.RoleOrgAdmin),
			wantKept: true,
		},
		{
			name: "org-admin foreign row",
			ctx:  WithOrgRole(context.WithValue(context.Background(), adminauth.ContextKeyUserID{}, "probe-admin"), "org-1", adminstore.RoleOrgAdmin),
		},
	}
	for _, shape := range shapes {
		for _, verdict := range verdicts {
			t.Run(shape.name+"/"+verdict.name, func(t *testing.T) {
				rows := []adminstore.RequestListRow{{
					RequestID: "req-shape", OrgID: "org-1", ModelUsed: "gpt-4o-mini",
					StatusCode: 200, CostUSD: 0.002, TokensIn: 100, TokensOut: 50,
					ErrorMsg: shape.errMsg, ToolCalls: []string{shape.toolAsk},
					PayloadOwned: verdict.wantKept,
				}}
				newProbe := func() *testAdminHandlers {
					probe := &payloadProbeStore{mockStore: newMockStore(), rows: rows}
					return &testAdminHandlers{AdminHandlers: New(probe, "", "", []string{}), store: probe.mockStore}
				}
				hotH, archH := newProbe(), newProbe()

				hotRec := httptest.NewRecorder()
				wrapWithParams(hotH.apiOrgRequests(), "/api/organizations/{id}/requests")(
					hotRec, httptest.NewRequestWithContext(verdict.ctx, http.MethodGet, "/api/organizations/org-1/requests", nil))
				archRec := httptest.NewRecorder()
				wrapWithParams(archH.apiOrgArchiveSearch(), "/api/organizations/{id}/requests/archive-search")(
					archRec, httptest.NewRequestWithContext(verdict.ctx, http.MethodGet, "/api/organizations/org-1/requests/archive-search", nil))

				require.Equal(t, http.StatusOK, hotRec.Code)
				if !verdict.wantKept {
					// Denied verdict at this admission (org member, foreign
					// row): both surfaces answer 200 with stripped rows and
					// the arrays stay byte-equal — search does not bypass
					// the payload mode (the 403 refusal is the stricter
					// root-without-content-access boundary, pinned by T05).
					require.Equal(t, http.StatusOK, archRec.Code)
					var hotBody, archBody map[string]any
					require.NoError(t, json.Unmarshal(hotRec.Body.Bytes(), &hotBody))
					require.NoError(t, json.Unmarshal(archRec.Body.Bytes(), &archBody))
					require.Equal(t, hotBody["data"], archBody["data"])
					require.NotContains(t, hotRec.Body.String(), "secret-sauce")
					require.NotContains(t, archRec.Body.String(), "secret-sauce")
					return
				}
				require.Equal(t, http.StatusOK, archRec.Code)
				var hotBody, archBody map[string]any
				require.NoError(t, json.Unmarshal(hotRec.Body.Bytes(), &hotBody))
				require.NoError(t, json.Unmarshal(archRec.Body.Bytes(), &archBody))
				require.Equal(t, hotBody["data"], archBody["data"],
					"archive must redact exactly like the hot list at this boundary shape")
				require.Contains(t, hotRec.Body.String(), "secret-sauce")
				require.Contains(t, archRec.Body.String(), "secret-sauce")
			})
		}
	}
}
