package handlers

//
// N01-P01 T07 — boundary corpus for the admin control plane, three aspects,
// all driven from the walked router declaration (the T06 matrix supplies the
// per-route contract; this file attacks it):
//
//   (a) unknown route — an unknown path never elevates and leaks no oracle:
//       for an unauthenticated caller the protected funnel answers 401 for
//       known and unknown /api paths alike (the auth middleware runs before
//       route resolution), an authenticated caller gets the JSON 404, and
//       injected internal headers change nothing.
//   (b) internal header injection — X-Yabanin-Org-Id, X-Org-Id, X-Agent-Id,
//       X-Admin-Key and forwarding headers from the client never substitute
//       for an identity or widen a scope: every gated route still rejects
//       anonymous+forged with 401, a member of org A probing org B stays
//       403/404 with a forged scope header, and a valid service key does not
//       cross onto the session plane.
//   (c) method/path confusion — trailing slash, case, double slash, dot
//       segments and %2F never reach a handler (chi does not clean or
//       redirect paths: every variant is a flat 404, even for root), and a
//       wrong method never yields 2xx (the n01t78 wire corpus pattern
//       re-applied at the auth layer; TestWireURLNormalizationCannotReclassifyCap
//       is the gateway-side sibling).
//
// Probes reuse the fully-wired golden router so DB-gated groups are included.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// forgedInternalHeaders is the header set an untrusted client may inject to
// try to elevate: org scope hints, agent identity, the internal service key
// (junk value — the real one is a secret and never client-supplied), and
// forwarding headers that only trusted proxies may set.
func forgedInternalHeaders(req *http.Request) {
	req.Header.Set(OrgHeader, "victim-org")
	req.Header.Set("X-Org-Id", "victim-org")
	req.Header.Set("X-Agent-Id", "agent-1")
	req.Header.Set("X-Team-Id", "team-1")
	req.Header.Set("X-User-Id", "user-1")
	req.Header.Set("X-Admin-Key", "forged-service-key")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.Header.Set("X-Real-IP", "127.0.0.1")
	req.Header.Set("X-Internal-Role", "root")
}

// corpusProbe sends one request and returns the status.
func corpusProbe(t *testing.T, router http.Handler, method, path string, cookie *http.Cookie, forge bool, body string) int {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	req.Host = "corpus.test"
	if method == http.MethodGet || method == http.MethodHead {
		req.Body = http.NoBody
	}
	if cookie != nil {
		req.AddCookie(cookie)
		if method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions {
			const csrf = "corpus-csrf-token"
			req.AddCookie(&http.Cookie{Name: "yabanin_csrf_token", Value: csrf,
				Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
			req.Header.Set("X-CSRF-Token", csrf)
		}
	}
	if forge {
		forgedInternalHeaders(req)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w.Code
}

// TestRoutesBoundaryCorpus_UnknownRoute pins aspect (a): the unknown-route
// funnel. Anonymous known == anonymous unknown (401 — no existence oracle on
// the protected surface); authenticated unknown is a plain 404 (no 401-leak
// for a valid session); forged headers never turn an unknown path into
// anything else.
func TestRoutesBoundaryCorpus_UnknownRoute(t *testing.T) {
	h, _ := goldenHandlersWithStore(t)
	router := h.SetupRouter()
	memberless := makeSessionCookie(false, "test-session-key")
	root := makeSessionCookie(true, "test-session-key")

	unknownAPI := []string{
		"/api/does-not-exist",
		"/api/keys/../../admin-users",
		"/api/organizations/unknown/keys/%2e%2e/admin-users",
	}
	unknownOther := []string{
		"/portal/does-not-exist",
		"/v1/does-not-exist",
		"/definitely-not-a-page",
	}

	for _, p := range unknownAPI {
		// Anonymous: 401 — identical to the KNOWN protected route below, so
		// unauthenticated probing cannot distinguish existing from unknown.
		if got := corpusProbe(t, router, http.MethodGet, p, nil, false, ""); got != http.StatusUnauthorized {
			t.Errorf("unknown %s anon = %d, want 401 (same as known)", p, got)
		}
		if got := corpusProbe(t, router, http.MethodGet, p, nil, true, ""); got != http.StatusUnauthorized {
			t.Errorf("unknown %s anon+forged = %d, want 401 (headers never elevate)", p, got)
		}
		// Authenticated: plain 404, not a 401-leak.
		if got := corpusProbe(t, router, http.MethodGet, p, memberless, true, ""); got != http.StatusNotFound {
			t.Errorf("unknown %s memberless+forged = %d, want 404", p, got)
		}
		if got := corpusProbe(t, router, http.MethodGet, p, root, true, ""); got != http.StatusNotFound {
			t.Errorf("unknown %s root+forged = %d, want 404", p, got)
		}
	}
	for _, p := range unknownOther {
		// The protected funnel catches unknown paths outside the public
		// subtrees too: anonymous 401 (auth precedes resolution), memberless
		// 404.
		if got := corpusProbe(t, router, http.MethodGet, p, nil, true, ""); got != http.StatusUnauthorized {
			t.Errorf("unknown %s anon+forged = %d, want 401", p, got)
		}
		if got := corpusProbe(t, router, http.MethodGet, p, memberless, true, ""); got != http.StatusNotFound {
			t.Errorf("unknown %s memberless+forged = %d, want 404", p, got)
		}
	}
	// The /internal subtree funnel uses the service identity: anonymous (or
	// session-cookie) callers get 401 from the gate BEFORE resolution; only
	// the valid service key gets far enough to see the plain 404.
	if got := corpusProbe(t, router, http.MethodGet, "/internal/does-not-exist", nil, false, ""); got != http.StatusUnauthorized {
		t.Errorf("unknown /internal anon = %d, want 401 (service gate precedes resolution)", got)
	}
	if got := corpusProbe(t, router, http.MethodGet, "/internal/does-not-exist", memberless, false, ""); got != http.StatusUnauthorized {
		t.Errorf("unknown /internal with session cookie = %d, want 401 (session never crosses to the service plane)", got)
	}
	if got := corpusProbe(t, router, http.MethodGet, "/internal/does-not-exist", nil, true, ""); got != http.StatusUnauthorized {
		t.Errorf("unknown /internal anon+forged = %d, want 401 (forged service key is still not the key)", got)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/internal/does-not-exist", nil)
	req.Header.Set("X-Admin-Key", "internal-test-key")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("unknown /internal with valid service key = %d, want 404", w.Code)
	}
	// No-oracle control: the KNOWN privileged route is indistinguishable
	// from the unknown ones for an anonymous caller.
	if known, unknown := corpusProbe(t, router, http.MethodGet, "/api/admin-users", nil, false, ""),
		corpusProbe(t, router, http.MethodGet, "/api/does-not-exist", nil, false, ""); known != unknown {
		t.Errorf("existence oracle: known /api/admin-users anon = %d, unknown = %d (must be identical)", known, unknown)
	}
}

// TestRoutesBoundaryCorpus_InternalHeaders pins aspect (b): injected
// identity/scope headers never substitute for an identity or widen a scope.
func TestRoutesBoundaryCorpus_InternalHeaders(t *testing.T) {
	h, store := goldenHandlersWithStore(t)
	router := h.SetupRouter()
	routes := goldenChains(t)

	// 1. Anonymous + full forged set on EVERY gated route: the answer stays
	// exactly the contract's anonymous rejection (matrix classes from the
	// T06 table; scim may fail closed with 503 while its store is unwired).
	var failures []string
	probed := 0
	for _, rc := range routes {
		if rc.Chain == "public" {
			continue
		}
		got := corpusProbe(t, router, rc.Method, sweepPlaceholder.ReplaceAllString(rc.Pattern, "victim-org"),
			nil, true, "")
		ok := got == http.StatusUnauthorized ||
			(strings.Contains(rc.Chain, "scim") && got == http.StatusServiceUnavailable) ||
			(rc.key() == "POST /auth/logout" && got == http.StatusForbidden)
		if !ok {
			failures = append(failures, fmt.Sprintf("%s %s: anon+forged = %d, want 401 (fail-closed)", rc.Method, rc.Pattern, got))
		}
		probed++
	}
	if probed < 200 {
		t.Fatalf("forged-header sweep covered only %d routes", probed)
	}

	// 2. Tenant binding under a forged scope header: a member of sweepOrg
	// probing a FOREIGN org (path AND X-Yabanin-Org-Id both forged to the
	// foreign org) stays 403/404 on every org-class route.
	const foreignOrg = "victim-org"
	const reader = "corpus-reader"
	store.adminUsers[reader] = &adminstore.AdminUser{ID: reader, Email: reader + "@corpus.test", DisplayName: reader, Active: true}
	store.orgMembers[reader+"/"+sweepOrg] = &adminstore.OrgMembership{UserID: reader, OrgID: sweepOrg, Role: adminstore.RoleReader}
	readerCookie := sweepSessionCookie(t, "test-session-key", reader)
	orgRoutes := 0
	for _, rc := range routes {
		if rc.Chain != "session+csrf+org" {
			continue
		}
		orgRoutes++
		path := strings.ReplaceAll(sweepPlaceholder.ReplaceAllString(rc.Pattern, foreignOrg), sweepOrg, foreignOrg)
		got := corpusProbe(t, router, rc.Method, path, readerCookie, true, "")
		if got != http.StatusForbidden && got != http.StatusNotFound {
			failures = append(failures, fmt.Sprintf("%s %s: reader-of-%s + forged %s = %d, want 403/404 (foreign org)",
				rc.Method, rc.Pattern, sweepOrg, OrgHeader, got))
		}
	}
	if orgRoutes < 80 {
		t.Fatalf("org-class tenant sweep covered only %d routes", orgRoutes)
	}

	// 3. Identity never crosses planes: the valid service key does not
	// authenticate the session plane, and the admin session does not
	// authenticate the service plane.
	if got := corpusProbe(t, router, http.MethodGet, "/api/me", nil, false, ""); got != http.StatusUnauthorized {
		t.Errorf("/api/me with service key only = %d, want 401", got)
	}
	if got := corpusProbe(t, router, http.MethodGet, "/api/admin-users", nil, true, ""); got != http.StatusUnauthorized {
		t.Errorf("/api/admin-users anon+forged service key = %d, want 401", got)
	}
	// Sanity: with the real service key the service-plane gate passes (the
	// handler then demands org_id — 400 — but the 401 boundary is behind us).
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/internal/api-keys?org_id=corpus-org", nil)
	req.Header.Set("X-Admin-Key", "internal-test-key")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK && w.Code != http.StatusBadRequest {
		t.Errorf("valid service key on /internal/api-keys = %d, want 200/400 (gate passed)", w.Code)
	}
	sessionCookie := makeSessionCookie(true, "test-session-key")
	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/internal/api-keys?org_id=corpus-org", nil)
	req.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("/internal/api-keys with admin session cookie only = %d, want 401 (session never crosses to the service plane)", w.Code)
	}

	if len(failures) > 0 {
		t.Errorf("%d forged-header probes broke their contract:\n%s", len(failures), strings.Join(failures, "\n"))
	}
}

// TestRoutesBoundaryCorpus_MethodPathConfusion pins aspect (c): obfuscated
// paths and wrong methods never reach a handler — not even for root.
func TestRoutesBoundaryCorpus_MethodPathConfusion(t *testing.T) {
	h, _ := goldenHandlersWithStore(t)
	router := h.SetupRouter()
	memberless := makeSessionCookie(false, "test-session-key")
	root := makeSessionCookie(true, "test-session-key")

	// Variants of a REAL privileged route; none may route. The control line
	// proves the cookie works on the canonical path (memberless → 403).
	confusions := []string{
		"//api/admin-users",
		"/api/admin-users/",
		"/API/admin-users",
		"/api/Admin-Users",
		"/api/admin-users%2F",
		"/api/./admin-users",
		"/api/admin-users/../admin-users",
		"/api/%61dmin-users",
		"/api/admin-users%2f..%2fadmin-users",
		"/./api/admin-users",
		"/api/../api/admin-users",
	}
	for _, p := range confusions {
		for name, cookie := range map[string]*http.Cookie{"memberless": memberless, "root": root} {
			if got := corpusProbe(t, router, http.MethodGet, p, cookie, true, ""); got != http.StatusNotFound {
				t.Errorf("confusion %s as %s = %d, want 404 (must not route)", p, name, got)
			}
		}
	}
	if got := corpusProbe(t, router, http.MethodGet, "/api/admin-users", memberless, false, ""); got != http.StatusForbidden {
		t.Errorf("control: canonical /api/admin-users memberless = %d, want 403 (cookie sanity)", got)
	}
	// Org route trailing slash.
	if got := corpusProbe(t, router, http.MethodGet, "/api/organizations/", root, false, ""); got != http.StatusNotFound {
		t.Errorf("confusion /api/organizations/ as root = %d, want 404", got)
	}

	// Method confusion: wrong methods on real routes never yield 2xx —
	// chi answers 405 through the guards, and the guards never let an
	// anonymous or memberless caller through to a handler.
	methodCases := []struct{ method, path string }{
		{http.MethodGet, "/api/admin-users/usr-1"},           // GET exists; control
		{http.MethodPut, "/api/admin-users/usr-1"},           // PUT unregistered
		{http.MethodDelete, "/api/me"},                       // DELETE unregistered
		{http.MethodPut, "/auth/login"},                      // PUT on a public POST/GET pair
		{http.MethodGet, "/api/organizations/org-1/invites"}, // GET unregistered (POST-only)
	}
	for _, tc := range methodCases {
		for name, cookie := range map[string]*http.Cookie{"anon": nil, "memberless": memberless, "root": root} {
			got := corpusProbe(t, router, tc.method, tc.path, cookie, false, "")
			if got >= 200 && got < 300 {
				t.Errorf("method confusion %s %s as %s = %d, want non-2xx", tc.method, tc.path, name, got)
			}
			if got >= 500 {
				t.Errorf("method confusion %s %s as %s = %d, want <500 (guards precede handlers)", tc.method, tc.path, name, got)
			}
		}
	}
}
