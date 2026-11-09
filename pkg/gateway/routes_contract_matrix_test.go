package cli

//
// N01-P01 T06 — route×auth-contract matrix for the gateway data plane and
// the gateway debug/admin listener.
//
// TestGatewayRoutesGolden records the walked router ↔ golden inventory.
// This matrix is the ENFORCEMENT gate: every published gateway route must
// map to one DECLARED auth contract derived from the router declaration
// (chi middleware chains on the walk-safe mirror):
//
//	inference     /v1/* (except /v1/yabanin/*)  agent API key or agent JWT,
//	              tenant bound by the resolver (X-Org-Id is set only by the
//	              auth middleware), policy attachment = labels + CreditGuard
//	session-keys  /v1/yabanin/*                 agent auth only (AT-14:
//	              label merge for mint is explicit — labels/credit absent
//	              by design, pinned exact)
//	agent-tooling /api/mcp/*, /mcp, /api/a2a/*  agent auth; tool policy and
//	              agent grants are enforced after auth in the handlers
//	public        HEAD /api/hello, GET /healthz, the MCP OAuth browser
//	              callback — declared explicitly, never a fallback
//
// "public" is not a fallback here either: a walked route with no
// authMiddlewareFunc in its chain is accepted only if it is declared in
// declaredPublicGatewayRoutes (matched bidirectionally), and a route whose
// chain carries NO recognized class at all fails. A new route (or a guard
// renamed out of gatewayChainClasses) cannot ship undeclared.
//
// The gateway admin/debug listener (startGatewayServers) is a separate
// chi router whose /metrics and /debug/pprof/* routes are registered
// methodlessly (mSTUB) and are therefore invisible to chi.Walk. Its matrix
// enumerates the router declaration with chi Mux.Match over a (method ×
// path) cross-product instead — every registered pair must be declared and
// every declared pair must be registered — and probes each gate:
// requireDebugAuth (localhost + admin API key, X-Forwarded-For honored only
// from trusted proxies), the metrics bearer, and the fail-closed shadow
// admin bearer.

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/shadow"
)

// Declared gateway public routes (main listener). Matched bidirectionally
// against the walked public set.
var declaredPublicGatewayRoutes = map[string]string{
	"HEAD /api/hello":                     "liveness canary; no data",
	"GET /healthz":                        "health probe (redis state only)",
	"GET /api/mcp/auth/{server}/callback": "MCP OAuth browser callback (MC-3): the IdP redirects a human here — no agent key exists; the flow-state nonce is the capability and the org query param is only a routing hint",
}

// gatewayContract is one declared data-plane contract.
type gatewayContract struct {
	Name     string
	Prefixes []string // route patterns this contract owns
	Require  []string // chain classes that MUST be present
	Exact    string   // when non-empty the chain must equal exactly this
	Identity string
	Tenant   string
	Policy   string
}

// gatewayContracts is the declared matrix for the main listener.
var gatewayContracts = []gatewayContract{
	{Name: "inference", Prefixes: []string{"/v1/"}, Require: []string{"auth", "labels", "credit"},
		Identity: "agent API key (yag_/ypk_/ybs_) or agent JWT — authMiddlewareFunc",
		Tenant:   "X-Org-Id set only by the auth middleware from the verified principal (client copies stripped)",
		Policy:   "labels (label policy) + CreditGuard (credit policy) after auth, before any handler"},
	{Name: "session-keys", Prefixes: []string{"/v1/yabanin/"}, Exact: "auth",
		Identity: "agent API key / JWT — authMiddlewareFunc",
		Tenant:   "key's own scope; session keys carry their own caps",
		Policy:   "deliberately NO labels/credit hop (AT-14: label merge for mint is explicit)"},
	{Name: "agent-tooling", Prefixes: []string{"/api/mcp/", "/mcp", "/api/a2a/"}, Require: []string{"auth"},
		Identity: "agent-principal (yag_) key — authMiddlewareFunc (agent-only gates in the handlers)",
		Tenant:   "org from the resolved key; per-agent grants stay under the server ceiling (MCP-03)",
		Policy:   "org tool policy + SSRF allow-list enforced per call inside the proxy path"},
}

// contractForGatewayRoute maps a walked (method, pattern, chain) to its
// declared contract; the most specific owning prefix wins so /v1/yabanin/*
// is not swallowed by /v1/. ok=false ⇒ undeclared (test failure).
func contractForGatewayRoute(pattern, chain string) (gatewayContract, bool) {
	best, bestLen := -1, -1
	for i, c := range gatewayContracts {
		for _, p := range c.Prefixes {
			if !strings.HasPrefix(pattern, p) {
				continue
			}
			if len(p) > bestLen {
				best, bestLen = i, len(p)
			}
		}
	}
	if best == -1 {
		return gatewayContract{}, false
	}
	c := gatewayContracts[best]
	for _, want := range c.Require {
		if !strings.Contains("+"+chain+"+", "+"+want+"+") {
			return gatewayContract{}, false
		}
	}
	if c.Exact != "" && chain != c.Exact {
		return gatewayContract{}, false
	}
	return c, true
}

// TestGatewayRouteAuthContractMatrix walks the production-shaped router and
// asserts every route maps to a declared contract; public routes must be
// declared exactly (both directions).
func TestGatewayRouteAuthContractMatrix(t *testing.T) {
	routes := goldenWalkRoutes(t)

	perContract := make(map[string]int)
	publicWalked := make(map[string]bool)
	for _, r := range routes {
		if r.Chain == "public" {
			publicWalked[r.Method+" "+r.Pattern] = true
			if _, ok := declaredPublicGatewayRoutes[r.Method+" "+r.Pattern]; !ok {
				t.Errorf("%s %s: public route without a declared contract — declare it in declaredPublicGatewayRoutes (or guard it)", r.Method, r.Pattern)
				continue
			}
			perContract["public(declared)"]++
			continue
		}
		c, ok := contractForGatewayRoute(r.Pattern, r.Chain)
		if !ok {
			t.Errorf("%s %s: chain %q does not map to a declared contract — declare it in gatewayContracts (or fix the guard)", r.Method, r.Pattern, r.Chain)
			continue
		}
		perContract[c.Name]++
	}
	for key := range declaredPublicGatewayRoutes {
		if !publicWalked[key] {
			t.Errorf("stale public declaration %q — no such public route is registered (remove the declaration in the same commit)", key)
		}
	}

	// Floor guards (mirror the golden inventory at declaration time).
	floors := map[string]int{"inference": 20, "session-keys": 6, "agent-tooling": 8, "public(declared)": 3}
	for name, floor := range floors {
		if perContract[name] < floor {
			t.Errorf("contract %s covers only %d routes (floor %d) — the walk or the matrix is broken", name, perContract[name], floor)
		}
	}
	t.Logf("gateway route×contract matrix: %d routes over %v", len(routes), perContract)
}

// --- gateway admin/debug listener ---------------------------------------------

// adminListenerRouter mirrors the router startGatewayServers builds for
// cfg.AdminListen (metrics + shadow kill-switch + gated pprof). The gates
// themselves are production code (requireDebugAuth, metrics wrapper,
// shadowAdminBearer); only the assembly is mirrored, like newGatedPprofRouter.
func adminListenerRouter(t *testing.T, gw *gateway, metrics bool) chi.Router {
	t.Helper()
	r := chi.NewRouter()
	r.Get("/debug/vars", gw.debugVars)
	if metrics {
		gw.registerMetrics(r, slog.New(slog.DiscardHandler))
	}
	gw.registerShadowAdmin(r, slog.New(slog.DiscardHandler))
	gw.registerGatedPprof(r)
	return r
}

// listenerContract is one declared admin-listener route contract.
type listenerContract struct {
	Method   string
	Pattern  string
	Name     string
	Identity string
	Tenant   string
	Policy   string
}

// listenerContracts declares every route the admin listener may publish.
var listenerContracts = []listenerContract{
	{Method: "GET", Pattern: "/debug/vars", Name: "debug-gate",
		Identity: "localhost peer + admin API key (requireDebugAuth, constant-time)",
		Tenant:   "none (process ops)", Policy: "X-Forwarded-For honored only from trusted proxies; 403 writes itself"},
	{Method: "ANY", Pattern: "/debug/pprof/", Name: "debug-gate",
		Identity: "localhost peer + admin API key (requireDebugAuth)", Tenant: "none (process ops)",
		Policy: "named profiles not mounted; index+/profile only"},
	{Method: "ANY", Pattern: "/debug/pprof/cmdline", Name: "debug-gate",
		Identity: "localhost peer + admin API key", Tenant: "none (process ops)", Policy: "requireDebugAuth"},
	{Method: "ANY", Pattern: "/debug/pprof/profile", Name: "debug-gate",
		Identity: "localhost peer + admin API key", Tenant: "none (process ops)", Policy: "requireDebugAuth"},
	{Method: "ANY", Pattern: "/debug/pprof/symbol", Name: "debug-gate",
		Identity: "localhost peer + admin API key", Tenant: "none (process ops)", Policy: "requireDebugAuth"},
	{Method: "ANY", Pattern: "/debug/pprof/trace", Name: "debug-gate",
		Identity: "localhost peer + admin API key", Tenant: "none (process ops)", Policy: "requireDebugAuth"},
	{Method: "ANY", Pattern: "/metrics", Name: "optional-bearer",
		Identity: "Prometheus bearer when YABANIN_METRICS_BEARER_KEY is set; otherwise the network-restricted listener is the boundary (documented posture)",
		Tenant:   "none (process metrics)", Policy: "constant-time compare; scrape endpoint; mounted methodlessly (chi Handle) so every verb answers"},
	{Method: "GET", Pattern: "/admin/shadow/status", Name: "metrics-bearer",
		Identity: "YABANIN_METRICS_BEARER_KEY bearer (shadowAdminBearer); fail-closed 403 when unset; 409 config-status when shadow itself is unwired",
		Tenant:   "none (process ops)", Policy: "never returns the key"},
	{Method: "POST", Pattern: "/admin/shadow/toggle", Name: "metrics-bearer",
		Identity: "YABANIN_METRICS_BEARER_KEY bearer (shadowAdminBearer); fail-closed 403 when unset; 409 config-status when shadow itself is unwired",
		Tenant:   "none (process ops)", Policy: "process-local kill-switch"},
}

// matchRegistered probes the mux declaration: is (method, path) routed?
func matchRegistered(r chi.Router, method, path string) bool {
	rctx := chi.NewRouteContext()
	return r.Match(rctx, method, path)
}

// TestGatewayAdminListenerAuthContractMatrix asserts the listener publishes
// exactly the declared routes (Match cross-product) and that each gate
// behaves as declared.
func TestGatewayAdminListenerAuthContractMatrix(t *testing.T) {
	const metricsKey = "metrics-secret"
	const adminKey = "admin-key"

	newGW := func(shadowWired bool) *gateway {
		gw := &gateway{cfg: config.Gateway{MetricsBearerKey: metricsKey, APIKey: adminKey}, log: slog.New(slog.DiscardHandler)}
		if shadowWired {
			vc, err := shadow.Config{Enabled: true, Model: "gpt-4o", SampleRate: 1.0,
				Timeout: 30 * time.Second, MaxConcurrent: 4}.Validate()
			if err != nil {
				t.Fatalf("shadow config: %v", err)
			}
			gw.shadow = shadow.NewDispatcher(vc, slog.New(slog.DiscardHandler))
		}
		return gw
	}

	r := adminListenerRouter(t, newGW(true), true)

	// Declaration closure: every declared (method,path) is registered, and
	// no undeclared (method,path) from the cross-product is.
	declared := make(map[string]bool, len(listenerContracts))
	for _, c := range listenerContracts {
		methods := []string{c.Method}
		if c.Method == "ANY" { // mSTUB Handle registrations answer every verb
			methods = []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodHead}
		}
		for _, m := range methods {
			if !matchRegistered(r, m, c.Pattern) {
				t.Errorf("%s %s is declared but NOT registered by the admin listener — the assembly drifted from startGatewayServers", m, c.Pattern)
			}
			declared[m+" "+c.Pattern] = true
		}
	}
	for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodHead} {
		for _, p := range []string{"/debug/vars", "/metrics", "/admin/shadow/status", "/admin/shadow/toggle",
			"/debug/pprof/", "/debug/pprof/cmdline", "/debug/pprof/heap", "/debug/pprof/goroutine",
			"/debug/unknown", "/admin/unknown"} {
			if declared[m+" "+p] {
				continue
			}
			if matchRegistered(r, m, p) {
				t.Errorf("%s %s is registered on the admin listener but has NO declared contract — add it to listenerContracts (or remove the registration)", m, p)
			}
		}
	}

	probe := func(gw *gateway, method, path, bearer, remote string, hdrs map[string]string) int {
		t.Helper()
		req := httptest.NewRequestWithContext(context.Background(), method, path, nil)
		req.RemoteAddr = remote
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		for k, v := range hdrs {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}
	const localhost = "127.0.0.1:999"
	const remote = "192.0.2.1:4444" // httptest default peer — off-box

	// debug-gate: localhost+key passes, everything else fails; a spoofed
	// X-Forwarded-For from an untrusted peer must not conjure localhost.
	gw := newGW(true)
	if got := probe(gw, http.MethodGet, "/debug/vars", "", localhost, nil); got != http.StatusForbidden {
		t.Errorf("/debug/vars localhost without key = %d, want 403", got)
	}
	if got := probe(gw, http.MethodGet, "/debug/vars", "wrong", localhost, nil); got != http.StatusForbidden {
		t.Errorf("/debug/vars localhost wrong key = %d, want 403", got)
	}
	if got := probe(gw, http.MethodGet, "/debug/vars", adminKey, localhost, nil); got != http.StatusOK {
		t.Errorf("/debug/vars localhost+key = %d, want 200", got)
	}
	if got := probe(gw, http.MethodGet, "/debug/vars", adminKey, remote, map[string]string{"X-Forwarded-For": "127.0.0.1", "X-Real-Ip": "127.0.0.1"}); got != http.StatusForbidden {
		t.Errorf("/debug/vars remote+key+spoofed XFF = %d, want 403 (forwarded headers never grant localhost)", got)
	}
	if got := probe(gw, http.MethodGet, "/debug/pprof/", adminKey, remote, nil); got != http.StatusForbidden {
		t.Errorf("/debug/pprof/ remote+key = %d, want 403", got)
	}
	if got := probe(gw, http.MethodGet, "/debug/pprof/", adminKey, localhost, nil); got != http.StatusOK {
		t.Errorf("/debug/pprof/ localhost+key = %d, want 200", got)
	}
	for _, m := range []string{http.MethodGet, http.MethodPost} {
		if got := probe(gw, m, "/debug/pprof/heap", adminKey, localhost, nil); got != http.StatusNotFound {
			t.Errorf("%s /debug/pprof/heap (undeclared named profile) localhost+key = %d, want 404 (named profiles are not mounted at all)", m, got)
		}
	}

	// metrics-bearer: fail-closed without the key, constant-time with it.
	probeBody := func(gw *gateway, method, path, bearer, remote string, body string) int {
		t.Helper()
		req := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
		req.RemoteAddr = remote
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}
	if got := probe(gw, http.MethodGet, "/admin/shadow/status", "", localhost, nil); got != http.StatusForbidden {
		t.Errorf("/admin/shadow/status without key = %d, want 403 (fail-closed)", got)
	}
	if got := probe(gw, http.MethodGet, "/admin/shadow/status", "wrong", localhost, nil); got != http.StatusForbidden {
		t.Errorf("/admin/shadow/status wrong key = %d, want 403", got)
	}
	if got := probe(gw, http.MethodGet, "/admin/shadow/status", metricsKey, remote, nil); got != http.StatusOK {
		t.Errorf("/admin/shadow/status valid key from remote = %d, want 200 (bearer, not localhost-bound)", got)
	}
	if got := probeBody(gw, http.MethodPost, "/admin/shadow/toggle", metricsKey, remote, `{"enabled":false}`); got != http.StatusOK {
		t.Errorf("/admin/shadow/toggle valid key = %d, want 200", got)
	}
	if got := probeBody(gw, http.MethodPost, "/admin/shadow/toggle", "", remote, `{"enabled":false}`); got != http.StatusForbidden {
		t.Errorf("/admin/shadow/toggle without key = %d, want 403 (fail-closed)", got)
	}
	if got := probe(gw, http.MethodGet, "/metrics", "", remote, nil); got != http.StatusUnauthorized {
		t.Errorf("/metrics without bearer (key configured) = %d, want 401", got)
	}
	if got := probe(gw, http.MethodGet, "/metrics", metricsKey, remote, nil); got != http.StatusOK {
		t.Errorf("/metrics with bearer = %d, want 200", got)
	}

	// Unwired shadow: the routes still answer — 409 config-status, no data,
	// no state change, no auth bypass (nothing to authenticate to).
	unwired := adminListenerRouter(t, newGW(false), true)
	probeUnwired := func(method, path, bearer string) int {
		req := httptest.NewRequestWithContext(context.Background(), method, path, nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		unwired.ServeHTTP(w, req)
		return w.Code
	}
	for _, bearer := range []string{"", metricsKey} {
		if got := probeUnwired(http.MethodGet, "/admin/shadow/status", bearer); got != http.StatusConflict {
			t.Errorf("/admin/shadow/status unwired shadow (bearer=%q) = %d, want 409 config-status", bearer, got)
		}
		if got := probeUnwired(http.MethodPost, "/admin/shadow/toggle", bearer); got != http.StatusConflict {
			t.Errorf("/admin/shadow/toggle unwired shadow (bearer=%q) = %d, want 409 (no state change)", bearer, got)
		}
	}

	// Metrics without a configured key: the documented network-restriction-
	// only posture — the listener route exists, no bearer is enforced.
	unkeyed := adminListenerRouter(t, &gateway{cfg: config.Gateway{}, log: slog.New(slog.DiscardHandler)}, true)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	unkeyed.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("/metrics unkeyed config = %d, want 200 (documented network-restricted posture)", w.Code)
	}
}
