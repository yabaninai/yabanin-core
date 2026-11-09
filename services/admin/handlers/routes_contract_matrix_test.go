package handlers

//
// N01-P01 T06 — route×auth-contract matrix for the admin control plane.
//
// TestAdminRoutesInventory pins walked router ↔ OpenAPI documentation and
// TestAdminRoutesGolden pins walked router ↔ golden chain inventory. Both are
// drift gates: they record what the router does. This matrix is the
// ENFORCEMENT gate the packet criterion asks for: every published route must
// map to one DECLARED auth contract — identity (admin session, portal
// session, X-Admin-Key service key, SCIM bearer, or explicitly declared
// public), tenant binding (org permission gate / org scope where
// applicable), and policy attachment (CSRF) — derived from the router
// declaration (chi.Walk middleware chains), not from per-handler ad hoc
// checks.
//
// Enforceability comes from two fail-closed rules:
//
//  1. "public" is not a fallback. A walked route with NO guard middleware is
//     accepted only if its (method, pattern) is declared in
//     declaredPublicAdminRoutes with a written reason — and the declaration
//     set must match the walked public set exactly (stale declarations fail
//     too). A new route mounted without a guard fails the test until its
//     contract is declared (or a guard is added).
//  2. Any middleware combination that does not map to a contract class below
//     fails the test — a new guard composition (or a renamed middleware that
//     silently drops out of chainClasses) cannot ship undeclared.
//
// The anon probe half proves the contracts are ENFORCED at the boundary:
// every non-public route must reject an anonymous request with exactly 401
// (SCIM may answer 503 while its token store is unwired — fail-closed), and
// handler-gated public routes must show their declared in-handler boundary
// (portal pages redirect to login, /v1/feedback answers 401 before any org
// attribution). The authenticated deny side (memberless/role matrix) stays
// with TestPrivilegedRoutes_DenyWithoutRights and
// TestOrgRoutes_RoleMatrixSweep; this file adds the classes they do not
// sweep (session, service, scim, portal) plus the public-closure rule.
//
// /metrics is out of the walk (skipWalkPatterns): it is a methodless scrape
// registration guarded by httpmw.MethodGuard at the process level, not an
// API route; its contract is pinned by metrics_route_test.go.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// contract describes the declared auth contract of one walked route class.
type contract struct {
	Name    string   // stable contract id (record/matrix output)
	Classes []string // chain classes the router declaration MUST carry
	// Identity is the authentication fact the contract rests on.
	Identity string
	// Tenant is the org binding the contract enforces ("none" = not
	// org-scoped by design).
	Tenant string
	// Policy names the additional request-integrity requirements wired in the chain.
	Policy string
	// AnonCode is the status an anonymous request must get (0 = probed via
	// anonContractProbe below; the class is handler-gated or public).
	AnonCode int
}

// contracts is the declared matrix. Chain sets are matched exactly against
// the classes produced by chainClasses (routes_golden_test.go); adding a
// class to a group (e.g. wiring OrgScopeMiddleware onto a new group) creates
// a new combination and FAILS here until a row is declared — the intended
// forcing function.
var contracts = []contract{
	{Name: "admin-root-orgscoped", Classes: []string{"session", "csrf", "root", "orgscope"},
		Identity: "admin session cookie (TP-02 revalidated)", Tenant: "OrgScopeMiddleware (X-Yabanin-Org-Id bound to the target org)",
		Policy: "CSRF double-submit", AnonCode: http.StatusUnauthorized},
	{Name: "admin-root", Classes: []string{"session", "csrf", "root"},
		Identity: "admin session cookie + root flag", Tenant: "none (root operator, cross-org by design)",
		Policy: "CSRF double-submit", AnonCode: http.StatusUnauthorized},
	{Name: "admin-org-permission", Classes: []string{"session", "csrf", "org"},
		Identity: "admin session cookie", Tenant: "RequireOrgPermission (membership + org:<perm> in the target org)",
		Policy: "CSRF double-submit", AnonCode: http.StatusUnauthorized},
	{Name: "admin-global-audit", Classes: []string{"session", "csrf", "global"},
		Identity: "admin session cookie", Tenant: "RequireGlobalAuditRead (root or global security_auditor)",
		Policy: "CSRF double-submit", AnonCode: http.StatusUnauthorized},
	{Name: "admin-session", Classes: []string{"session", "csrf"},
		Identity: "admin session cookie", Tenant: "handler-resolved org surfaces keep their RightsMatrix tests",
		Policy: "CSRF double-submit", AnonCode: http.StatusUnauthorized},
	{Name: "internal-service-key", Classes: []string{"service"},
		Identity: "X-Admin-Key service key (constant-time)", Tenant: "org_id is a caller parameter, scoped by the key's grant",
		Policy: "read-only surface", AnonCode: http.StatusUnauthorized},
	{Name: "scim-bearer", Classes: []string{"scim"},
		Identity: "org SCIM bearer token", Tenant: "token is org-scoped by issuance",
		Policy: "fail-closed 503 while the token store is unwired", AnonCode: 0},
	{Name: "portal-session", Classes: []string{"portal", "portal-csrf"},
		Identity: "developer-portal session cookie (separate issuer from admin sessions)", Tenant: "portal user's own org, resolved server-side",
		Policy: "portal CSRF", AnonCode: http.StatusUnauthorized},
}

// declaredExceptions are the two deliberate one-class chains. They are not
// free space: the (method, pattern) is pinned.
var declaredExceptions = map[string]contract{
	"GET /auth/csrf": {Name: "csrf-issuer", Classes: []string{"session"},
		Identity: "admin session cookie", Tenant: "none", Policy: "issues the CSRF token, so CSRF validation cannot precede it",
		AnonCode: http.StatusUnauthorized},
	"POST /auth/logout": {Name: "logout", Classes: []string{"csrf"},
		Identity: "none (logout must work for an expired session)", Tenant: "none",
		Policy: "CSRF double-submit still required (logout CSRF)", AnonCode: http.StatusForbidden},
}

// declaredPublicAdminRoutes closes the public class: a walked route with an
// empty guard chain is accepted ONLY here, with a written reason. The set is
// matched bidirectionally against the walk, so both an undeclared public
// route and a stale declaration fail the test.
var declaredPublicAdminRoutes = map[string]string{
	"GET /health":                   "liveness probe for the admin process; no data",
	"GET /auth/login":               "login form render",
	"POST /auth/login":              "login submit (rate-limited per IP; credential check inside)",
	"GET /auth/logout":              "logout page/reset; clears (never grants) state",
	"GET /auth/oidc/login":          "OIDC redirect to the configured IdP",
	"GET /auth/oidc/callback":       "OIDC code exchange; state cookie is the capability",
	"POST /auth/saml/acs":           "SAML assertion consumer; assertion signature is the capability",
	"GET /auth/saml/login":          "SAML redirect to the configured IdP",
	"GET /auth/saml/metadata":       "SAML SP metadata (public by SAML design)",
	"GET /auth/saml/slo":            "SAML single-logout redirect binding",
	"POST /auth/saml/slo":           "SAML single-logout POST binding",
	"GET /invite/{token}":           "invite acceptance; the signed token IS the credential",
	"POST /invite/{token}":          "invite completion; the signed token IS the credential",
	"GET /portal/login":             "developer-portal login page",
	"GET /portal/callback":          "portal OAuth callback; state parameter is the capability",
	"GET /portal":                   "portal page — handler-gated: missing session redirects to /portal/login",
	"POST /portal/keys":             "portal key-create form — handler-gated: missing session redirects to /portal/login",
	"POST /portal/keys/{id}/revoke": "portal key-revoke form — handler-gated: missing session redirects to /portal/login",
	"POST /v1/feedback":             "classifier feedback — handler-gated: Bearer org/agent API key, org derived server-side (NEXT-15-F2)",
}

// portalPageRedirects are the handler-gated public routes whose anon boundary
// is a redirect to the portal login (never a 2xx).
var portalPageRedirects = map[string]bool{
	"GET /portal":                   true,
	"POST /portal/keys":             true,
	"POST /portal/keys/{id}/revoke": true,
}

// contractForChain maps a walked chain to its declared contract. ok=false
// means the combination is undeclared — a hard failure.
func contractForChain(method, pattern, chain string) (contract, bool) {
	classes := map[string]bool{}
	if chain != "public" {
		for _, c := range strings.Split(chain, "+") {
			classes[c] = true
		}
	}
	if len(classes) == 0 {
		return contract{}, false // public — must be declared explicitly by the caller
	}
	for _, c := range contracts {
		if len(c.Classes) != len(classes) {
			continue
		}
		match := true
		for _, want := range c.Classes {
			if !classes[want] {
				match = false
				break
			}
		}
		if match {
			return c, true
		}
	}
	if c, ok := declaredExceptions[method+" "+pattern]; ok && len(c.Classes) == len(classes) {
		for _, want := range c.Classes {
			if !classes[want] {
				return contract{}, false
			}
		}
		return c, true
	}
	return contract{}, false
}

// TestRouteContractMatrix walks the fully-wired golden router and asserts
// every route maps to a declared contract; public routes must be declared
// exactly (both directions). This is the enforceable "every published route
// has an auth contract" gate.
func TestRouteContractMatrix(t *testing.T) {
	routes := goldenChains(t)
	if len(routes) < 250 {
		t.Fatalf("walked only %d routes — the walk helper is broken", len(routes))
	}

	perContract := make(map[string]int)
	publicWalked := make(map[string]bool)
	for _, rc := range routes {
		if rc.Chain == "public" {
			publicWalked[rc.key()] = true
			reason, declared := declaredPublicAdminRoutes[rc.key()]
			if !declared {
				t.Errorf("%s: public route without a declared contract — add it to declaredPublicAdminRoutes with a reason (or guard it)", rc.key())
				continue
			}
			if reason == "" {
				t.Errorf("%s: public declaration must carry a reason", rc.key())
			}
			perContract["public(declared)"]++
			continue
		}
		c, ok := contractForChain(rc.Method, rc.Pattern, rc.Chain)
		if !ok {
			t.Errorf("%s: middleware chain %q does not map to a declared contract — declare it in the contracts table (or fix the guard)", rc.key(), rc.Chain)
			continue
		}
		perContract[c.Name]++
	}
	for key := range declaredPublicAdminRoutes {
		if !publicWalked[key] {
			t.Errorf("stale public declaration %s — no such public route is registered (remove the declaration in the same commit)", key)
		}
	}

	// Floor guards: a classification regression must not silently empty a
	// class (counts mirror testdata/routes_admin.golden at declaration time).
	floors := map[string]int{
		"admin-org-permission": 80, "admin-root-orgscoped": 100, "admin-root": 3,
		"admin-session": 10, "internal-service-key": 3, "scim-bearer": 10,
		"portal-session": 5, "admin-global-audit": 1, "public(declared)": 15,
	}
	for name, floor := range floors {
		if perContract[name] < floor {
			t.Errorf("contract %s covers only %d routes (floor %d) — the walk or the matrix is broken", name, perContract[name], floor)
		}
	}
	t.Logf("route×contract matrix: %d routes over %d contracts: %v", len(routes), len(perContract), perContract)
}

// anonContractProbe sends the anonymous request a contract must reject.
// Portal page routes are expected to redirect to the login instead.
func anonContractProbe(t *testing.T, router http.Handler, rc routeChain) int {
	t.Helper()
	path := sweepPlaceholder.ReplaceAllString(rc.Pattern, "matrix-target")
	req := httptest.NewRequestWithContext(t.Context(), rc.Method, path, nil)
	req.Host = "matrix.test"
	if rc.Method != http.MethodGet && rc.Method != http.MethodHead {
		req.Header.Set("Content-Type", "application/json")
		req.Body = http.NoBody
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w.Code
}

// TestRouteContract_AnonRejectedOnEveryGatedRoute proves the matrix is
// enforceable: every non-public route answers the anonymous probe exactly as
// its contract declares, and the handler-gated public routes show their
// declared in-handler boundary.
func TestRouteContract_AnonRejectedOnEveryGatedRoute(t *testing.T) {
	router := goldenHandlers(t).SetupRouter()
	routes := goldenChains(t)

	var failures []string
	probed := 0
	for _, rc := range routes {
		switch {
		case rc.Chain != "public":
			c, ok := contractForChain(rc.Method, rc.Pattern, rc.Chain)
			if !ok {
				continue // already reported by TestRouteContractMatrix
			}
			want := c.AnonCode
			if want == 0 { // scim: fail-closed 401 or 503 while unwired
				want = http.StatusUnauthorized
			}
			got := anonContractProbe(t, router, rc)
			accepted := got == want || (c.Name == "scim-bearer" && got == http.StatusServiceUnavailable)
			if !accepted {
				failures = append(failures, fmt.Sprintf("%s [%s]: anon = %d, want %d", rc.key(), c.Name, got, want))
			}
			probed++
		case portalPageRedirects[rc.key()]:
			path := sweepPlaceholder.ReplaceAllString(rc.Pattern, "matrix-target")
			req := httptest.NewRequestWithContext(t.Context(), rc.Method, path, nil)
			req.Host = "matrix.test"
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != http.StatusFound || w.Header().Get("Location") != "/portal/login" {
				failures = append(failures, fmt.Sprintf("%s [portal-page]: anon = %d (Location=%q), want 302 → /portal/login",
					rc.key(), w.Code, w.Header().Get("Location")))
			}
			probed++
		case rc.key() == "POST /v1/feedback":
			// The handler parses the body before the auth check; a
			// well-formed anonymous submission must still hit the 401
			// boundary before any org attribution or persistence.
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/feedback",
				strings.NewReader(`{"action":"thumbs_up"}`))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != http.StatusUnauthorized {
				failures = append(failures, fmt.Sprintf("POST /v1/feedback [handler-api-key]: anon = %d, want 401", w.Code))
			}
			probed++
		}
	}
	// Floor: the probe sweep must actually cover the gated surface.
	if probed < 200 {
		t.Fatalf("anon contract probe covered only %d routes — the walk or the filter is broken", probed)
	}
	t.Logf("anon contract probe: %d gated routes verified", probed)
	if len(failures) > 0 {
		t.Errorf("%d routes do not enforce their declared contract against anonymous callers:\n%s",
			len(failures), strings.Join(failures, "\n"))
	}
}
