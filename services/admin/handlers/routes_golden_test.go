package handlers

//
// cross-checks docs/api/admin.openapi.yaml, this test walks a router with
// OIDC SSO, reseller credits, resale pricing, sovereign marketplace, region
// routing, policy templates, feedback export, retrain status, developer
// management, the classifier feedback collector) and pins, per route, the
// complete middleware chain in auth/CSRF/permission classes:
//
//	public | service | portal+portal-csrf | session[+csrf][+root][+global][+orgscope][+org]
//
// A route added, removed, remounted, or moved to a different guard group
// turns the test red with a line diff. Golden files are data: update them
// only with the explicit env gate and commit the diff for review:
//
//	ROUTES_GOLDEN_UPDATE=1 go test ./services/admin/handlers/ -run TestAdminRoutesGolden
//
// Chains are matched by middleware-name fragments (not package paths), so

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/feedback"
	"github.com/reireirei/yabanin/pkg/inventory"
	"github.com/reireirei/yabanin/pkg/mcpagg"
	"github.com/reireirei/yabanin/pkg/policy"
	"github.com/reireirei/yabanin/pkg/ssrf"
)

// envGoldenUpdate gates golden rewrites; without it the goldens are read-only.
const envGoldenUpdate = "ROUTES_GOLDEN_UPDATE"

const adminGoldenPath = "testdata/routes_admin.golden"

// routeChain is one walked route with its full middleware chain (classes).
type routeChain struct {
	Method  string
	Pattern string
	Chain   string
}

func (c routeChain) key() string { return c.Method + " " + c.Pattern }

func (c routeChain) line() string { return c.Method + " " + c.Pattern + " " + c.Chain }

// goldenHandlers builds the fully-wired router: every optional group that
// SetupRouter mounts is on. The DB-gated stores are constructed over a nil
// pool — the constructors only store the handle, the routes register (and
// would answer 503 at request time), which is all the walk needs: the golden
// pins registration and guarding, not handler behavior.
func goldenHandlers(tb testing.TB) *AdminHandlers {
	tb.Helper()
	h, _ := goldenHandlersWithStore(tb)
	return h
}

// goldenHandlersWithStore is goldenHandlers with the fixture store handle
// store the fully-wired router serves from, so its probes exercise the real
// membership gates rather than a parallel fixture.
func goldenHandlersWithStore(tb testing.TB) (*AdminHandlers, *mockStore) {
	tb.Helper()
	store := newMockStore()
	h := New(store, "test-session-key", "golden.test", nil)
	h.SetVerticalHandlers(NewVerticalHandlers(newMockStore(), nil))
	h.SetInternalServiceKey("internal-test-key")
	h.SetPortal(PortalOptions{Enabled: true, Store: newMemPortal()})
	h.SetOIDCClient(&adminauth.OIDCClient{})
	// The SAML SSO routes are walked the same way; a zero-value SP
	// flips the mount gate without touching the network (the walk pins
	// registration and guarding, not handler behavior).
	h.SetSAMLSP(&adminauth.SAMLSP{})
	h.SetSovereignHandlers(NewSovereignHandlers(nil, nil))
	h.SetRegionHandlers(NewRegionHandlers(nil, nil))
	h.SetTemplateHandlers(NewPolicyTemplateHandlers(policy.NewTemplateMarketplace(nil), nil))
	h.SetFeedbackExporter(feedback.NewExporter(nil))
	h.SetRetrainHandlers(NewRetrainHandlers(feedback.NewExporter(nil), nil))
	// The resale-pricing group mounts only when the DB pool is non-nil; a
	// zero-value pool flips the gate without touching the database (the
	// handlers store the pool and only use it when serving).
	h.SetCreditStore(credits.NewStore(nil, nil), &pgxpool.Pool{})
	h.SetFeedbackCollector(feedback.NewCollector(nil, nil), nil)
	// W-FEED: the owner feedback list/export routes are DB-gated too; a
	// nil-pool lister registers them (503 at request time) so the golden pins
	// registration and guarding.
	h.SetFeedbackLister(feedback.NewLister(nil))
	// E02-P01: the asset-registry SPI (read + MCP import + model import) is
	// wired as a unit with golden-constructible seams — nil-DB stores and a
	// no-upstream proxy register the routes (503 at request time), so the
	// golden pins the mount and its root+orgscope guards. The no-DB spec
	// walk stays lock-stepped with the frozen OpenAPI file; these routes are
	// delta-documented in docs/api/OPENAPI-DELTA.md.
	invStore := inventory.NewStore(nil)
	invProxy := mcpagg.NewProxy(mcpagg.NewStore(nil), mcpagg.NewDefaultConfig(), ssrf.AllowList{}, nil, nil)
	invMCP, err := inventory.NewImportRunner(invStore, mcpagg.NewStore(nil), &inventory.ProxyToolSource{Proxy: invProxy})
	if err != nil {
		tb.Fatalf("golden inventory importer: %v", err)
	}
	invModels, err := inventory.NewModelImportRunner(invStore, inventory.NewDBModelRegistrySource(nil), inventory.ProviderCatalog{Cat: nil}, nil)
	if err != nil {
		tb.Fatalf("golden model importer: %v", err)
	}
	h.SetInventory(invStore, invMCP, invModels)
	tb.Cleanup(h.Stop)
	return h, store
}

// chainClasses maps middleware name fragments to the chain classes the
// golden records. Only auth/CSRF/permission guards are recorded; process
// middleware (timeout, body limits, security headers, rate limits) is out of
// scope. Case order matters: PortalCSRFValidation contains CSRFValidation.
func chainClasses(middlewares []func(http.Handler) http.Handler) []string {
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
		case strings.Contains(name, "PortalAuthMiddleware"):
			add("portal")
		case strings.Contains(name, "PortalCSRFValidation"):
			add("portal-csrf")
		case strings.Contains(name, "ChiAuthMiddleware"):
			add("session")
		case strings.Contains(name, "CSRFValidation"):
			add("csrf")
		case strings.Contains(name, "MustBeRoot"):
			add("root")
		case strings.Contains(name, "RequireGlobalAuditRead"):
			add("global")
		case strings.Contains(name, "OrgScopeMiddleware"):
			add("orgscope")
		case strings.Contains(name, "RequireOrgPermission"):
			add("org")
		case strings.Contains(name, "AuthFromHeader"):
			add("service")
		case strings.Contains(name, "scimAuthMiddleware"):
			add("scim")
		}
	}
	return out
}

// walkChains enumerates the router like walkRoutes (same skip list, dedup
// keep-first for the double-mounted portal /api/me, and pattern/method sort)
// but records the full middleware chain per route instead of a single class.
func walkChains(handler http.Handler) ([]routeChain, error) {
	r, ok := handler.(chi.Router)
	if !ok {
		return nil, fmt.Errorf("SetupRouter returned %T, want a chi.Router", handler)
	}
	var out []routeChain
	seen := make(map[string]bool)
	err := chi.Walk(r, func(method, pattern string, _ http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		if method == "" || method == "*" || skipWalkPatterns[pattern] {
			return nil
		}
		key := method + " " + pattern
		if seen[key] {
			return nil
		}
		seen[key] = true
		classes := chainClasses(middlewares)
		chain := "public"
		if len(classes) > 0 {
			chain = strings.Join(classes, "+")
		}
		out = append(out, routeChain{Method: method, Pattern: pattern, Chain: chain})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("chi.Walk: %w", err)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Pattern != out[j].Pattern {
			return out[i].Pattern < out[j].Pattern
		}
		return out[i].Method < out[j].Method
	})
	return out, nil
}

// goldenChains walks the fully-wired SetupRouter.
func goldenChains(tb testing.TB) []routeChain {
	tb.Helper()
	routes, err := walkChains(goldenHandlers(tb).SetupRouter())
	if err != nil {
		tb.Fatalf("walk routes: %v", err)
	}
	if len(routes) == 0 {
		tb.Fatal("chi.Walk found no routes — the walk helper is broken")
	}
	return routes
}

// renderGolden renders the golden file body: header + one line per route.
func renderGolden(routes []routeChain) string {
	var b strings.Builder
	b.WriteString("# IMP-60 golden admin route inventory (fully-wired SetupRouter).\n")
	b.WriteString("# Format: <METHOD> <pattern> <chain>; chain classes: public|service|portal+portal-csrf|session+csrf[+root][+global][+orgscope][+org]|scim.\n")
	b.WriteString("# Regenerate ONLY with: ROUTES_GOLDEN_UPDATE=1 go test ./services/admin/handlers/ -run TestAdminRoutesGolden\n")
	fmt.Fprintf(&b, "# %d routes\n", len(routes))
	for _, c := range routes {
		b.WriteString(c.line() + "\n")
	}
	return b.String()
}

// compareGolden diffs got against the golden file. With envGoldenUpdate set
// it rewrites the file instead (the update itself is the review artifact).
func compareGolden(tb testing.TB, path, got string, count int) {
	tb.Helper()
	if os.Getenv(envGoldenUpdate) != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			tb.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			tb.Fatalf("write golden: %v", err)
		}
		tb.Logf("updated %s (%d routes) — commit the diff for review", path, count)
		return
	}
	want, err := os.ReadFile(path) // #nosec G304 -- path is the compile-time testdata constant
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			tb.Fatalf("golden %s missing — generate it with %s=1 and review the diff", path, envGoldenUpdate)
		}
		tb.Fatalf("read golden: %v", err)
	}
	if wantLines, gotLines := splitLines(string(want)), splitLines(got); !reflect.DeepEqual(wantLines, gotLines) {
		tb.Errorf("route inventory drifted from %s (%d golden lines vs %d walked). Diff (golden → walked):",
			path, len(wantLines), len(gotLines))
		for _, d := range goldenDiff(wantLines, gotLines) {
			tb.Errorf("  %s", d)
		}
	}
}

func splitLines(s string) []string {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// goldenDiff renders a compact line diff (up to maxDiffLines entries).
func goldenDiff(want, got []string) []string {
	const maxDiffLines = 20
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
	if len(out) > maxDiffLines {
		out = append(out[:maxDiffLines], fmt.Sprintf("… (%d more diff lines)", len(out)-maxDiffLines))
	}
	return out
}

// TestAdminRoutesGolden is the drift gate: fully-wired router ↔ golden file.
func TestAdminRoutesGolden(t *testing.T) {
	routes := goldenChains(t)
	compareGolden(t, adminGoldenPath, renderGolden(routes), len(routes))
}

// helper: every route the no-DB inventory router registers must also appear
// on the fully-wired golden router with the same method and pattern.
func TestGoldenWalkSupersetOfInventory(t *testing.T) {
	golden := walkedChainKeys(t)
	inventory := walkedByKey(inventoryRoutes(t))
	for key := range inventory {
		if _, ok := golden[key]; !ok {
			t.Errorf("route %s is registered by the inventory router (IMP-50 walkRoutes) but missing from the fully-wired golden walk — the walks disagree", key)
		}
	}
}

func walkedChainKeys(tb testing.TB) map[string]bool {
	tb.Helper()
	routes, err := walkChains(goldenHandlers(tb).SetupRouter())
	if err != nil {
		tb.Fatalf("walk routes: %v", err)
	}
	keys := make(map[string]bool, len(routes))
	for _, c := range routes {
		keys[c.key()] = true
	}
	return keys
}
