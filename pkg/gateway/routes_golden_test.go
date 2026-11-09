package cli

//
// The gateway router (healthHandler + gw.routes) is pinned, per route, to
// testdata/routes_gateway.golden: method, path and the middleware chain in
// request-guard classes:
//
//	public | auth | auth+labels | auth+labels+credit
//	| anthropic-envelope+auth+labels+credit
//
// The router is built the production-shaped DB deployment way: the credits
// store and the MCP/A2A proxies are wired over nil pools (constructors store
// the handle; routes register and would degrade at request time), so the
// golden includes /api/mcp, /api/a2a and the CreditGuard hop. Single-region
// deployments keep the failover hop out of the chain (it only wires with
// region config). Chains are matched by middleware-name fragments, not
//
// chi.Walk cannot traverse the production router directly: chi Route()/()
// Group() create inline subrouters sharing the parent tree, and their
// Mount()'d stubs make the walk recurse forever. TestGatewayRoutesGolden
// therefore re-runs gw.routes through goldenRouter — a walk-safe mirror that
// gives Route()/Group() independent subrouters (flushed at /@gN synthetic
// prefixes that are stripped from the golden lines) with identical routes
// and middleware chains. The MCP/A2A group mounts are prefixed Mount()
// calls, so the historical UNPREFIXED self-mount aliases (POST /invoke,
// GET /yabanin/tools, POST /send) are gone: the router now answers them
// with flat 404s, and the corpus test pins that absence.
//
// A route added, removed, or reguarded turns the test red with a line diff.
// Golden files are data: update only with the explicit env gate and commit
// the diff for review:
//
//	ROUTES_GOLDEN_UPDATE=1 go test ./pkg/cli/ -run TestGatewayRoutesGolden

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/a2aagg"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/mcpagg"
	"github.com/reireirei/yabanin/pkg/mcpserver"
	"github.com/reireirei/yabanin/pkg/ssrf"
)

const (
	gatewayGoldenPath = "testdata/routes_gateway.golden"
	envGoldenUpdate   = "ROUTES_GOLDEN_UPDATE"
	// goldenSynthetic is the prefix of the flush mount points for inline
	// groups ("/@g0", "/@g1", …); it never reaches the golden file.
	goldenSynthetic = "/@g"
)

// goldenRoute is one walked gateway route with its middleware chain (classes).
type goldenRoute struct {
	Method  string
	Pattern string
	Chain   string
}

func (r goldenRoute) line() string { return r.Method + " " + r.Pattern + " " + r.Chain }

// gatewayChainClasses maps middleware name fragments to chain classes. Only
// request-guard hops are recorded; process middleware (timeouts, body limits,
// rate limits, recoverer) is out of scope.
func gatewayChainClasses(middlewares []func(http.Handler) http.Handler) []string {
	var out []string
	seen := make(map[string]bool)
	add := func(class string) {
		if !seen[class] {
			seen[class] = true
			out = append(out, class)
		}
	}
	for _, mw := range middlewares {
		name := runtime.FuncForPC(reflect.ValueOf(mw).Pointer()).Name()
		switch {
		case strings.Contains(name, "anthropicErrorEnvelope"):
			add("anthropic-envelope")
		case strings.Contains(name, "authMiddlewareFunc"):
			add("auth")
		case strings.Contains(name, "labelsMiddleware"):
			add("labels")
		case strings.Contains(name, "CreditGuard"):
			add("credit")
		case strings.Contains(name, "failoverMiddlewareFunc"):
			add("failover")
		}
	}
	return out
}

// goldenRouter is a chi.Router mirror used only for walking: Route() and
// Group() get independent subrouters (with the parent middleware stack
// copied, mirroring chi's With() inheritance) instead of inline shared-tree
// muxes, so chi.Walk terminates. Groups their caller never Mount()s are
// flushed at unique synthetic prefixes by flushWalkMounts.
type goldenRouter struct {
	*chi.Mux
	groups []*goldenRouter // Group() results not (yet) Mount()ed by the caller
	routes []*goldenRouter // Route() subrouters, for cascade flushing
}

func newGoldenRouter() *goldenRouter { return &goldenRouter{Mux: chi.NewRouter()} }

func (g *goldenRouter) With(middlewares ...func(http.Handler) http.Handler) chi.Router {
	sub := g.inherited()
	sub.Use(middlewares...)
	// chi's With() shares the caller's routing tree, so registrations on the
	// returned router serve at the caller's prefix — keep them walkable the
	// same way (flush at g's level, synthetic prefix stripped later).
	g.groups = append(g.groups, sub)
	return sub
}

func (g *goldenRouter) Group(fn func(r chi.Router)) chi.Router {
	sub := g.inherited()
	if fn != nil {
		fn(sub)
	}
	g.groups = append(g.groups, sub)
	return sub
}

func (g *goldenRouter) Route(pattern string, fn func(r chi.Router)) chi.Router {
	sub := g.inherited()
	if fn != nil {
		fn(sub)
	}
	g.Mux.Mount(pattern, sub.Mux)
	g.routes = append(g.routes, sub)
	return sub
}

// inherited builds an independent subrouter carrying the parent's middleware
// stack — the chain a chi inline (With-based) subrouter would bake in.
func (g *goldenRouter) inherited() *goldenRouter {
	sub := &goldenRouter{Mux: chi.NewRouter()}
	for _, mw := range g.Middlewares() {
		sub.Use(mw)
	}
	return sub
}

// Mount delegates to the real mux and, when the mounted handler is a pending
// group, takes it off the flush list (it is reachable at its explicit prefix).
func (g *goldenRouter) Mount(pattern string, h http.Handler) {
	if sub, ok := h.(*goldenRouter); ok {
		for i, pending := range g.groups {
			if pending == sub {
				g.groups = append(g.groups[:i], g.groups[i+1:]...)
				break
			}
		}
	}
	g.Mux.Mount(pattern, h)
}

// flushWalkMounts mounts every group the caller never mounted at a unique
// synthetic prefix so chi.Walk enumerates it; the prefix is stripped from
// golden lines afterwards.
func (g *goldenRouter) flushWalkMounts() {
	for _, sub := range g.routes {
		sub.flushWalkMounts()
	}
	for i, sub := range g.groups {
		sub.flushWalkMounts()
		g.Mux.Mount(goldenSynthetic+strconv.Itoa(i), sub.Mux)
	}
	g.groups = nil
}

// stripSynthetic removes the flush mount prefix from a walked route.
func stripSynthetic(route string) string {
	at := strings.Index(route, goldenSynthetic)
	if at < 0 {
		return route
	}
	rest := route[at:] // "/@gN/…" — skip the "@gN" segment itself
	if end := strings.Index(rest[1:], "/"); end >= 0 {
		return route[:at] + rest[1+end:]
	}
	return route[:at]
}

// goldenGatewayDeps wires the gateway the production DB deployment way.
func goldenGatewayDeps(tb testing.TB) *gateway {
	tb.Helper()
	log := slog.New(slog.DiscardHandler)
	gw, err := buildGateway(config.Gateway{
		ListenAddr:    ":0",
		Provider:      "127.0.0.1:1",
		AuthMode:      "header",
		APIKey:        "golden-test-key",
		FallbackModel: "smart",
	}, nil, nil, log, context.Background(), JWTWiring{}, CircuitScopeWiring{})
	if err != nil {
		tb.Fatalf("buildGateway: %v", err)
	}
	// Production parity for pool-backed deployments: the CreditGuard hop on
	// the inference group and the MCP/A2A route groups. Nil pools keep the
	// walk offline; the proxies only need non-nil handles for the gates in
	// gw.routes.
	gw.creditStore = credits.NewStore(nil, nil)
	allow, err := ssrf.NewAllowList(nil)
	if err != nil {
		tb.Fatalf("ssrf allow list: %v", err)
	}
	gw.mcpProxy = mcpagg.NewProxy(mcpagg.NewStore(nil), mcpagg.NewDefaultConfig(), allow,
		&mcpParamGuard{gw: gw}, &mcpAuditLogger{log: log})
	// session secret keeps the wiring deterministic.
	gw.mcpStore = mcpagg.NewStore(nil)
	gw.mcpStreamable = mcpserver.New(mcpserver.Config{Principal: mcpStreamablePrincipal(gw)},
		mcpServerBackend{gw: gw}, log, []byte("golden-test-session-secret"))
	gw.a2aProxy = a2aagg.NewProxy(a2aagg.NewStore(nil), a2aagg.NewDefaultConfig(), allow,
		&mcpParamGuard{gw: gw}, &a2aAuditLogger{log: log})
	return gw
}

// goldenWalkRoutes mounts healthHandler + gw.routes into the walk-safe
// mirror and walks it (same conventions as the admin walkRoutes helper:
// methodless registrations skipped, duplicates keep the first registration,
// output sorted by pattern then method).
func goldenWalkRoutes(tb testing.TB) []goldenRoute {
	tb.Helper()
	gw := goldenGatewayDeps(tb)

	mirror := newGoldenRouter()
	healthHandler(gw, mirror, slog.New(slog.DiscardHandler))
	gw.routes(mirror)
	mirror.flushWalkMounts()

	var out []goldenRoute
	seen := make(map[string]bool)
	err := chi.Walk(mirror.Mux, func(method, route string, _ http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		if method == "" || method == "*" {
			return nil
		}
		pattern := stripSynthetic(route)
		key := method + " " + pattern
		if seen[key] {
			return nil
		}
		seen[key] = true
		classes := gatewayChainClasses(middlewares)
		chain := "public"
		if len(classes) > 0 {
			chain = strings.Join(classes, "+")
		}
		out = append(out, goldenRoute{Method: method, Pattern: pattern, Chain: chain})
		return nil
	})
	if err != nil {
		tb.Fatalf("chi.Walk: %v", err)
	}
	if len(out) == 0 {
		tb.Fatal("chi.Walk found no routes — the walk mirror is broken")
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Pattern != out[j].Pattern {
			return out[i].Pattern < out[j].Pattern
		}
		return out[i].Method < out[j].Method
	})
	return out
}

// renderGatewayGolden renders the golden file body: the walked routes.
func renderGatewayGolden(routes []goldenRoute) string {
	var b strings.Builder
	b.WriteString("# IMP-60 golden gateway route inventory (healthHandler + gw.routes, DB deployment shape).\n")
	b.WriteString("# Format: <METHOD> <pattern> <chain>; chain classes: public|auth|labels|credit|failover|anthropic-envelope.\n")
	b.WriteString("# Regenerate ONLY with: ROUTES_GOLDEN_UPDATE=1 go test ./pkg/cli/ -run TestGatewayRoutesGolden\n")
	fmt.Fprintf(&b, "# %d walked routes\n", len(routes))
	for _, r := range routes {
		b.WriteString(r.line() + "\n")
	}
	return b.String()
}

// TestGatewayRoutesGolden is the drift gate: gateway router ↔ golden file.
func TestGatewayRoutesGolden(t *testing.T) {
	got := renderGatewayGolden(goldenWalkRoutes(t))
	if os.Getenv(envGoldenUpdate) != "" {
		if err := os.MkdirAll(filepath.Dir(gatewayGoldenPath), 0o750); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(gatewayGoldenPath, []byte(got), 0o600); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("updated %s — commit the diff for review", gatewayGoldenPath)
		return
	}
	want, err := os.ReadFile(gatewayGoldenPath) // #nosec G304 -- path is the compile-time testdata constant
	if err != nil {
		t.Fatalf("read golden (generate with %s=1): %v", envGoldenUpdate, err)
	}
	wantLines := strings.Split(strings.TrimSuffix(string(want), "\n"), "\n")
	gotLines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	if !reflect.DeepEqual(wantLines, gotLines) {
		t.Errorf("gateway route inventory drifted from %s (%d golden lines vs %d walked). Diff (golden → walked):",
			gatewayGoldenPath, len(wantLines), len(gotLines))
		for _, d := range goldenLineDiff(wantLines, gotLines) {
			t.Errorf("  %s", d)
		}
	}
}

// goldenLineDiff renders a compact sorted line diff (up to 20 entries).
func goldenLineDiff(want, got []string) []string {
	wantSet := make(map[string]int, len(want))
	for _, l := range want {
		wantSet[l]++
	}
	gotSet := make(map[string]int, len(got))
	for _, l := range got {
		gotSet[l]++
	}
	var out []string
	for _, l := range want {
		if wantSet[l] > gotSet[l] {
			out = append(out, "- "+l)
			wantSet[l] = 0
		}
	}
	for _, l := range got {
		if gotSet[l] > 0 && wantSet[l] == 0 {
			out = append(out, "+ "+l)
			gotSet[l] = 0
		}
	}
	sort.Strings(out)
	if len(out) > 20 {
		out = append(out[:20], fmt.Sprintf("… (%d more diff lines)", len(out)-20))
	}
	return out
}
