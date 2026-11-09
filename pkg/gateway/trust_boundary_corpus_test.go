package cli

//
// N01-P01 T07 — boundary corpus for the gateway data plane, three aspects.
// The route contract comes from TestGatewayRouteAuthContractMatrix; this
// file attacks it from outside:
//
//   (a) unknown route — an unknown path (and every obfuscated variant of a
//       known one) never reaches a handler or the upstream: chi answers a
//       flat 404, forged identity headers change nothing, and a valid key
//       gets the same 404 (no 401-leak for an authenticated caller). The
//       admin control plane funnel (uniform anon 401 on the protected
//       surface) is pinned in services/admin/handlers; the gateway is a
//       public API surface where chi's flat 404 for unknown paths is the
//       documented design — the invariant here is "nothing behind it".
//   (b) internal header injection — X-Org-Id, X-API-Key-Id, X-Team-Id,
//       X-Agent-Id, X-User-Id, X-Session-Key-Id plus X-Forwarded-For /
//       X-Real-Ip from the client never elevate: the auth middleware strips
//       the identity headers before resolution, so no/bad credentials still
//       get 401 on every route class, and a valid static key with a forged
//       agent identity never passes the agent-only tooling gates.
//   (c) method/path confusion — the n01t78 wire corpus pattern
//       (TestWireURLNormalizationCannotReclassifyCap) re-applied at the auth
//       layer: with VALID credentials, obfuscated paths must not route (404,
//       zero upstream calls) and a wrong method must not yield 2xx.
//

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"
)

// corpusGatewayRouter builds the production-shaped router (health + all
// MCP/A2A mounts) the same way the golden walk does.
func corpusGatewayRouter(tb testing.TB) (chi.Router, *gateway) {
	tb.Helper()
	gw := goldenGatewayDeps(tb)
	router := chi.NewRouter()
	healthHandler(gw, router, slog.New(slog.DiscardHandler))
	gw.routes(router)
	return router, gw
}

// forgedIdentityHeaders sets every header the auth middleware owns, plus
// forwarding headers only trusted proxies may set.
func forgedIdentityHeaders(req *http.Request) {
	req.Header.Set("X-Org-Id", "victim-org")
	req.Header.Set("X-API-Key-Id", "key-1")
	req.Header.Set("X-Team-Id", "team-1")
	req.Header.Set("X-Agent-Id", "agent-1")
	req.Header.Set("X-User-Id", "user-1")
	req.Header.Set("X-Session-Key-Id", "session-1")
	req.Header.Set("X-Internal-Role", "root")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.Header.Set("X-Real-Ip", "127.0.0.1")
}

// gatewayCorpusProbe sends one request; bearer may be empty.
func gatewayCorpusProbe(t *testing.T, router http.Handler, method, path, bearer string, forge bool) int {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if forge {
		forgedIdentityHeaders(req)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w.Code
}

// TestGatewayRoutesBoundaryCorpus_UnknownRoute pins aspect (a): unknown and
// obfuscated paths are flat 404s regardless of identity headers or a valid
// key; they never execute a handler.
func TestGatewayRoutesBoundaryCorpus_UnknownRoute(t *testing.T) {
	router, _ := corpusGatewayRouter(t)
	const key = "golden-test-key"

	paths := []string{
		"/unknown/path",
		"/v1/unknown",
		"/v1/chat/completions/extra",
		"/api/mcp/unknown",
		"/api/a2a/unknown",
		"/api/mcp/auth/unknown-server/callback/extra",
		// Former chi self-mount aliases (unprefixed MCP/A2A group routes,
		// live on chi v5.3.0's inline-tree quirk). chi v5.4.0 fixed the
		// quirk (gateway.go mounts /api/mcp and /api/a2a via Route); the
		// unprefixed spellings must stay flat 404s — they never come back.
		"/invoke",
		"/yabanin/tools",
		"/send",
	}
	for _, p := range paths {
		if got := gatewayCorpusProbe(t, router, http.MethodPost, p, "", true); got != http.StatusNotFound {
			t.Errorf("unknown %s anon+forged = %d, want 404", p, got)
		}
		if got := gatewayCorpusProbe(t, router, http.MethodPost, p, key, true); got != http.StatusNotFound {
			t.Errorf("unknown %s valid-key+forged = %d, want 404", p, got)
		}
	}
	// The /v1/yabanin subtree applies its auth middleware to unknown paths
	// INSIDE the subtree as well (chi Route-level Use): an anonymous probe
	// gets 401, a valid key gets the flat 404 — the guard covers the whole
	// subtree, not only the registered leaves.
	if got := gatewayCorpusProbe(t, router, http.MethodPost, "/v1/yabanin/unknown", "", true); got != http.StatusUnauthorized {
		t.Errorf("unknown /v1/yabanin/unknown anon+forged = %d, want 401 (subtree guard)", got)
	}
	if got := gatewayCorpusProbe(t, router, http.MethodPost, "/v1/yabanin/unknown", key, true); got != http.StatusNotFound {
		t.Errorf("unknown /v1/yabanin/unknown valid-key+forged = %d, want 404", got)
	}
}

// TestGatewayRoutesBoundaryCorpus_InternalHeaders pins aspect (b): the
// identity headers are stripped by the auth middleware — forged values plus
// missing or invalid credentials still answer exactly 401 on every route
// class, including the MCP OAuth callback's siblings. (The unprefixed
// self-mount aliases this corpus used to probe are gone with chi v5.4.0 and
// are pinned as flat 404s in the UnknownRoute corpus above.)
func TestGatewayRoutesBoundaryCorpus_InternalHeaders(t *testing.T) {
	router, _ := corpusGatewayRouter(t)

	cases := []struct{ method, path string }{
		{http.MethodPost, "/v1/chat/completions"},
		{http.MethodPost, "/v1/messages"},
		{http.MethodGet, "/v1/models"},
		{http.MethodPost, "/v1/yabanin/session-keys"},
		{http.MethodGet, "/v1/yabanin/usage"},
		{http.MethodPost, "/api/mcp/invoke"},
		{http.MethodGet, "/api/mcp/yabanin/tools"},
		{http.MethodPost, "/api/mcp/credentials/srv"},
		{http.MethodPost, "/api/mcp/auth/srv/begin"},
		{http.MethodPost, "/mcp"},
		{http.MethodGet, "/mcp"},
		{http.MethodDelete, "/mcp"},
		{http.MethodPost, "/api/a2a/send"},
	}
	var failures []string
	for _, tc := range cases {
		for name, bearer := range map[string]string{"noauth": "", "badkey": "wrong-key"} {
			if got := gatewayCorpusProbe(t, router, tc.method, tc.path, bearer, true); got != http.StatusUnauthorized {
				failures = append(failures, fmt.Sprintf("%s %s %s = %d, want 401", name, tc.method, tc.path, got))
			}
		}
		// Each identity header individually must not substitute for the key.
		for _, h := range []string{"X-Org-Id", "X-Agent-Id", "X-Team-Id", "X-User-Id", "X-API-Key-Id", "X-Session-Key-Id"} {
			req := httptest.NewRequestWithContext(context.Background(), tc.method, tc.path, nil)
			req.Header.Set(h, "forged")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != http.StatusUnauthorized {
				failures = append(failures, fmt.Sprintf("%s %s with only %s forged = %d, want 401", tc.method, tc.path, h, w.Code))
			}
		}
	}
	if len(failures) > 0 {
		t.Errorf("%d forged-header probes broke the auth boundary:\n%s", len(failures), strings.Join(failures, "\n"))
	}

	// With a VALID static key the forged agent identity is stripped before
	// the handler: the agent-only MCP/A2A gates never see it (no org
	// resolution for the static key → 401; never 2xx, never the proxy).
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/api/mcp/invoke"},
		{http.MethodPost, "/api/a2a/send"},
		{http.MethodGet, "/api/mcp/yabanin/tools"},
	} {
		if got := gatewayCorpusProbe(t, router, tc.method, tc.path, "golden-test-key", true); got >= 200 && got < 300 {
			t.Errorf("%s %s valid-key+forged-agent = %d, want non-2xx (forged agent identity must not pass)", tc.method, tc.path, got)
		}
	}
	// The public MCP OAuth callback stays public by declaration — but it
	// must not become an oracle with forged headers either (the flow-state
	// nonce is the capability; headers grant nothing).
	if got := gatewayCorpusProbe(t, router, http.MethodGet, "/api/mcp/auth/srv/callback?code=x&state=forged", "", true); got >= 200 && got < 300 {
		t.Errorf("mcp oauth callback with forged state+headers = %d, want non-2xx without a real flow", got)
	}
}

// TestGatewayRoutesBoundaryCorpus_MethodPathConfusion pins aspect (c) with
// real credentials: obfuscated paths must not route (404, zero upstream
// calls) and wrong methods must not yield 2xx.
func TestGatewayRoutesBoundaryCorpus_MethodPathConfusion(t *testing.T) {
	var calls atomic.Int64
	gw := wireImagesGateway(t, &calls)
	router := chi.NewRouter()
	healthHandler(gw, router, slog.New(slog.DiscardHandler))
	gw.routes(router)
	const key = "test-key"

	// Control: the canonical path with valid creds and a real body reaches
	// the upstream exactly once.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/images/generations",
		strings.NewReader(`{"model":"m","prompt":"x"}`))
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if calls.Load() != 1 {
		t.Fatalf("control: upstream calls = %d, want 1 (harness sanity, status %d)", calls.Load(), w.Code)
	}

	confusions := []string{
		"/v1/images/generations/",
		"//v1/images/generations",
		"/v1/images/./generations",
		"/v1/images/../images/generations",
		"/v1/IMAGES/generations",
		"/v1/images/generations%2F",
		"/v1/images%2fgenerations",
		"/v1/../v1/images/generations",
	}
	for _, p := range confusions {
		for name, bearer := range map[string]string{"anon": "", "valid-key": key} {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, p, nil)
			if bearer != "" {
				req.Header.Set("Authorization", "Bearer "+bearer)
			}
			forgedIdentityHeaders(req)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != http.StatusNotFound {
				t.Errorf("confusion %s as %s+forged = %d, want 404", p, name, w.Code)
			}
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("upstream called %d times after the confusion corpus, want 1 (control only)", got)
	}

	// Method confusion on the production-shaped router: wrong methods on
	// real routes answer 405 (chi MethodNotAllowed) — never 2xx, and the
	// 2xx-capable handler never runs.
	router2, _ := corpusGatewayRouter(t)
	methodCases := []struct{ method, path string }{
		{http.MethodGet, "/v1/chat/completions"},
		{http.MethodPost, "/v1/models"},
		{http.MethodPost, "/v1/yabanin/usage"},
		{http.MethodGet, "/api/hello"}, // only HEAD is mounted
		{http.MethodPost, "/healthz"},
	}
	for _, tc := range methodCases {
		for name, bearer := range map[string]string{"anon": "", "valid-key": "golden-test-key"} {
			if got := gatewayCorpusProbe(t, router2, tc.method, tc.path, bearer, true); got >= 200 && got < 300 {
				t.Errorf("method confusion %s %s as %s+forged = %d, want non-2xx", tc.method, tc.path, name, got)
			}
		}
	}
}
