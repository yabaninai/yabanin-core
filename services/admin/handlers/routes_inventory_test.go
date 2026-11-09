package handlers

//
// TestAdminRoutesInventory walks the router built by SetupRouter (chi.Walk)
// and compares the (method, pattern, permission-middleware class) set with
// docs/api/admin.openapi.yaml. A route added without documentation, a route
// removed without updating the spec, or a change of the guarding middleware
// class turns the test red. The same technique cross-checks the admin paths
// of the pre-existing docs/api/openapi.yaml (gateway contract) in
// TestGatewayOpenAPIRoutesExist.
//
// docs/api/admin.openapi.yaml is the single documentation source for the
// admin control plane. Regenerate stub entries for new routes with:
//
//	ROUTES_INVENTORY_GENERATE=1 go test ./services/admin/handlers/ -run TestRoutesInventoryGenerate
//
// and fill in the summaries. TS type generation is out of scope (OD-04).

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"gopkg.in/yaml.v3"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

const (
	adminOpenAPISpec   = "../../../docs/api/admin.openapi.yaml"
	gatewayOpenAPISpec = "../../../docs/api/openapi.yaml"
	// envGenerate enables the stub generator (TestRoutesInventoryGenerate).
	envGenerate = "ROUTES_INVENTORY_GENERATE"
)

// routeSpec is one walked route: the HTTP method, the registered chi
// template and the permission class derived from the middleware chain.
type routeSpec struct {
	Method      string
	Pattern     string
	Permission  string
	Summary     string
	PathServers []string
}

func (s routeSpec) key() string { return s.Method + " " + s.Pattern }

// Permission classes recorded in the spec as x-permission:
//
//	public  — no auth middleware beyond the global chain (health, login)
//	session — admin cookie session (ChiAuthMiddleware) + CSRF
//	portal  — developer-portal session (PortalAuthMiddleware)
//	service — X-Admin-Key header auth (AuthFromHeader, /internal)
//	root    — MustBeRoot
//	global  — RequireGlobalAuditRead (root or the global security auditor,
//	          against adminstore.GlobalRoleSecurityAuditor
//	org:<p> — RequireOrgPermission(p); the walk identifies the class, the
//	          specific permission name is documentation data validated
//	          against adminstore.AllPermissions()
func classifyRoute(middlewares []func(http.Handler) http.Handler) string {
	has := func(fragment string) bool {
		for _, mw := range middlewares {
			name := runtime.FuncForPC(reflect.ValueOf(mw).Pointer()).Name()
			if strings.Contains(name, fragment) {
				return true
			}
		}
		return false
	}
	switch {
	case has("scimAuthMiddleware"):
		return "scim"
	case has(".RequireOrgPermission"):
		return "org"
	case has(".RequireGlobalAuditRead"):
		return "global"
	case has("MustBeRoot"):
		return "root"
	case has("AuthFromHeader"):
		return "service"
	case has("PortalAuthMiddleware"):
		return "portal"
	case has("ChiAuthMiddleware"):
		return "session"
	default:
		return "public"
	}
}

// inventoryHandlers builds the canonical no-DB router used by the inventory
// tests: every route group that mounts without a live Postgres pool is on
// (portal, verticals, internal service API). DB-gated groups (credits,
// resale pricing, sovereign, regions, templates, feedback export, retrain,
// OIDC SSO) stay unmounted here; they are tracked by the golden-route
func inventoryHandlers(tb testing.TB) *AdminHandlers {
	tb.Helper()
	store := newMockStore()
	h := New(store, "test-session-key", "inventory.test", nil)
	h.SetVerticalHandlers(NewVerticalHandlers(newMockStore(), nil))
	h.SetInternalServiceKey("internal-test-key")
	h.SetPortal(PortalOptions{Enabled: true, Store: newMemPortal()})
	tb.Cleanup(h.Stop)
	return h
}

// skipWalkPatterns lists methodless operational registrations (chi "Handle"
// without a method) that chi.Walk expands into every HTTP verb. They are
// process infrastructure, not API surface: GET /metrics is the Prometheus
// scrape endpoint guarded by httpmw.MethodGuard.
var skipWalkPatterns = map[string]bool{"/metrics": true}

// walkRoutes enumerates every method-registered route of the router.
// A pattern registered more than once (portal mounts a static /api/me before
// the dashboard subrouter) keeps its first registration — chi serves the
// first match.
func walkRoutes(handler http.Handler) ([]routeSpec, error) {
	r, ok := handler.(chi.Router)
	if !ok {
		return nil, fmt.Errorf("SetupRouter returned %T, want a chi.Router", handler)
	}
	var out []routeSpec
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
		out = append(out, routeSpec{Method: method, Pattern: pattern, Permission: classifyRoute(middlewares)})
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

func inventoryRoutes(tb testing.TB) []routeSpec {
	tb.Helper()
	specs, err := walkRoutes(inventoryHandlers(tb).SetupRouter())
	if err != nil {
		tb.Fatalf("walk routes: %v", err)
	}
	return specs
}

// parseOpenAPIRoutes reads paths → {method: {x-permission, summary}} from an
// OpenAPI spec file and returns a method+path keyed map.
func parseOpenAPIRoutes(tb testing.TB, path string) map[string]routeSpec {
	tb.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- path is the compile-time spec constant passed by the tests
	if err != nil {
		tb.Fatalf("read spec: %v", err)
	}
	var doc struct {
		Paths map[string]struct {
			Servers []struct {
				URL string `yaml:"url"`
			} `yaml:"servers"`
			Operations map[string]yaml.Node `yaml:",inline"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		tb.Fatalf("parse spec %s: %v", path, err)
	}
	httpMethods := map[string]bool{
		http.MethodGet: true, http.MethodPost: true, http.MethodPut: true,
		http.MethodPatch: true, http.MethodDelete: true, http.MethodHead: true,
		http.MethodOptions: true, http.MethodTrace: true,
	}
	out := make(map[string]routeSpec)
	for pattern, item := range doc.Paths {
		for method, opNode := range item.Operations {
			method = strings.ToUpper(method)
			if !httpMethods[method] {
				continue
			}
			var op struct {
				Permission  string `yaml:"x-permission"`
				Summary     string `yaml:"summary"`
				OperationID string `yaml:"operationId"`
			}
			if err := opNode.Decode(&op); err != nil {
				tb.Fatalf("decode %s %s in %s: %v", method, pattern, path, err)
			}
			servers := make([]string, 0, len(item.Servers))
			for _, s := range item.Servers {
				servers = append(servers, s.URL)
			}
			out[method+" "+pattern] = routeSpec{Method: method, Pattern: pattern, Permission: op.Permission, Summary: op.Summary, PathServers: servers}
		}
	}
	return out
}

// permissionProblems returns every defect of an x-permission value (unknown
// class, unknown global role, unknown org permission). It returns the
// problems as plain strings instead of failing a testing.TB so both the
// inventory sweep and the negative-contract probes can assert the detection
// itself (N07-P07-T05).
func permissionProblems(key, perm string) []string {
	var problems []string
	switch {
	case perm == "public", perm == "session", perm == "portal", perm == "service", perm == "root", perm == "scim":
	case strings.HasPrefix(perm, "global:"):
		name := strings.TrimPrefix(perm, "global:")
		if name != string(adminstore.GlobalRoleSecurityAuditor) {
			problems = append(problems, fmt.Sprintf("%s: unknown global role %q (see pkg/adminstore/permissions.go)", key, name))
		}
	case strings.HasPrefix(perm, "org:"):
		name := strings.TrimPrefix(perm, "org:")
		valid := false
		for _, p := range adminstore.AllPermissions() {
			if string(p) == name {
				valid = true
				break
			}
		}
		if !valid {
			problems = append(problems, fmt.Sprintf("%s: unknown org permission %q (see pkg/adminstore/permissions.go)", key, name))
		}
	default:
		problems = append(problems, fmt.Sprintf("%s: invalid x-permission %q (want public|session|portal|service|root|scim|global:<role>|org:<perm>)", key, perm))
	}
	return problems
}

// dbGatedAdminRoutes are admin.openapi.yaml routes whose handler group
// mounts only with a live Postgres pool (credits PR1/W-CRED wallet + top-up
// + low-balance, the W-FEED owner feedback list, PB2.7 org region routing),
// so the no-DB lock-step walk cannot see them. A spec entry may document
// one of these, but ONLY while it is listed here AND the fully-wired
// golden router still serves it under the same permission class — the
// lock-step stays transitive (spec ↔ no-DB walk ∪ DB-gated golden walk)
// instead of decaying into a free-form allowlist. Closed both ways: a route
// removed from the golden walk fails the inventory, and a DB-gated spec
// route missing from this list fails as stale.
var dbGatedAdminRoutes = map[string]bool{
	"GET /api/credits/low-balance":            true,
	"GET /api/feedback":                       true,
	"GET /api/organizations/{id}/region":      true,
	"PUT /api/organizations/{id}/region":      true,
	"GET /api/orgs/{id}/credits/balance":      true,
	"POST /api/orgs/{id}/credits/topup":       true,
	"GET /api/orgs/{id}/credits/transactions": true,
}

// TestAdminRoutesInventory is the drift gate: walked router ↔ admin.openapi.yaml.
func TestAdminRoutesInventory(t *testing.T) {
	walked := inventoryRoutes(t)
	if len(walked) == 0 {
		t.Fatal("chi.Walk found no routes — the walk helper is broken")
	}
	documented := parseOpenAPIRoutes(t, adminOpenAPISpec)
	for _, problem := range routeInventoryProblems(t, walked, documented, goldenChainsByRoute) {
		t.Error(problem)
	}
}

// routeInventoryProblems is the drift detector shared by the drift gate and
// the negative-contract probes (N07-P07-T05): every walked route must be
// documented with a matching permission class, every documented route must
// be walked (or DB-gated AND served by the fully-wired golden router under
// the same class), every x-permission value must be real, and every
// operation must carry a summary. Problems are sorted so probe mutations
// yield stable assertions. The golden resolver is consulted lazily and may
// be nil when a caller knows no DB-gated exception can apply.
func routeInventoryProblems(tb testing.TB, walked []routeSpec, documented map[string]routeSpec, golden func(testing.TB) map[string]routeChain) []string {
	tb.Helper()
	var problems []string
	problemf := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	for _, spec := range walked {
		key := spec.key()
		doc, ok := documented[key]
		if !ok {
			problemf("undocumented route %s — add it to %s (or regenerate stubs via %s=1)",
				key, adminOpenAPISpec, envGenerate)
			continue
		}
		// The walk identifies the middleware class ("org"); the spec carries
		// the concrete org permission ("org:members.manage"). Classes must
		// match; the concrete permission is validated by permissionProblems.
		if permissionClass(doc.Permission) != spec.Permission {
			problemf("%s: permission drift — router guards %q, spec says %q", key, spec.Permission, doc.Permission)
		}
	}
	walkedSet := walkedByKey(walked)
	var goldenChains map[string]routeChain // built lazily: only consulted for DB-gated exceptions
	for key, doc := range documented {
		if _, ok := walkedSet[key]; !ok {
			// DB-gated groups mount only with a live Postgres pool, so the
			// no-DB walk cannot see them. The spec may document such a
			// route, but only when it is allow-listed above and the
			// fully-wired golden router serves it with the same permission
			// class — otherwise the documented surface would drift away
			// from the code behind the spec's back.
			if !dbGatedAdminRoutes[key] {
				problemf("stale spec route %s in %s — no such route is registered by SetupRouter",
					key, adminOpenAPISpec)
				continue
			}
			if goldenChains == nil && golden != nil {
				goldenChains = golden(tb)
			}
			chain, ok := goldenChains[key]
			if !ok {
				problemf("stale spec route %s in %s — not served by the fully-wired golden router either (the DB-gated group was removed?)",
					key, adminOpenAPISpec)
				continue
			}
			if class := classFromChain(chain.Chain); class != permissionClass(doc.Permission) {
				problemf("%s: permission drift — golden chain %q guards %q, spec says %q",
					key, chain.Chain, class, doc.Permission)
			}
		}
		problems = append(problems, permissionProblems(key, doc.Permission)...)
		if strings.TrimSpace(doc.Summary) == "" {
			problemf("%s: empty summary in %s — describe the operation", key, adminOpenAPISpec)
		}
	}
	sort.Strings(problems)
	return problems
}

// goldenChainsByRoute walks the fully-wired golden router (the same fixture
// TestRoutesGolden pins) and indexes the middleware chains by
// method+pattern. Used by TestAdminRoutesInventory to keep DB-gated spec
// routes in transitive lock-step: the no-DB walk cannot see them, but the
// golden walk can.
func goldenChainsByRoute(tb testing.TB) map[string]routeChain {
	tb.Helper()
	routes, err := walkChains(goldenHandlers(tb).SetupRouter())
	if err != nil {
		tb.Fatalf("walk golden routes: %v", err)
	}
	out := make(map[string]routeChain, len(routes))
	for _, c := range routes {
		out[c.key()] = c
	}
	return out
}

// classFromChain reduces a golden middleware chain ("session+csrf+root")
// to the comparable permission class, mirroring chainClasses' class set and
// permissionClass's mapping. Tokens are matched exactly — "org" and
// "orgscope" are different classes, and "portal-csrf" is not "csrf".
// Precedence: a named scoped guard (scim/org/global) wins over the
// positional guards; every chain in the golden walk carries at most one
// scoped guard, so the order only matters for hypothetical multi-guard
// chains.
func classFromChain(chain string) string {
	has := func(class string) bool {
		for _, tok := range strings.Split(chain, "+") {
			if tok == class {
				return true
			}
		}
		return false
	}
	switch {
	case has("scim"):
		return "scim"
	case has("org"):
		return "org"
	case has("global"):
		return "global"
	case has("root"):
		return "root"
	case has("service"):
		return "service"
	case has("portal"):
		return "portal"
	case has("session"):
		return "session"
	default:
		return "public"
	}
}

// permissionClass reduces a spec x-permission value to the comparable walk
// class: "org:keys.manage" → "org", "global:security_auditor" → "global",
// everything else maps to itself.
func permissionClass(perm string) string {
	if name, ok := strings.CutPrefix(perm, "org:"); ok && name != "" {
		return "org"
	}
	if name, ok := strings.CutPrefix(perm, "global:"); ok && name != "" {
		return "global"
	}
	return perm
}

// walkedByKey indexes the walked set for membership checks.
func walkedByKey(specs []routeSpec) map[string]routeSpec {
	out := make(map[string]routeSpec, len(specs))
	for _, s := range specs {
		out[s.key()] = s
	}
	return out
}

// adminSpecSide reports whether a docs/api/openapi.yaml operation belongs
// to the admin control plane: the path carries admin path-level servers
// (admin.yabanin.io / localhost:9091). Everything else rides the file's
// root /v1 servers or gateway path-level servers and is served by the
// gateway process — its membership against the walked gateway router is
// gateway allowlist is needed here.
func adminSpecSide(spec routeSpec) bool {
	for _, server := range spec.PathServers {
		if strings.Contains(server, "admin.yabanin.io") || strings.Contains(server, "localhost:9091") {
			return true
		}
	}
	return false
}

// dbGatedRoutes are documented admin routes whose group mounts only with a
// live Postgres pool and therefore cannot appear in the walked no-DB
// inventory: the reseller credits endpoints (PR1) require credits.Store.
// Their behavior is covered by the credits integration tests; the golden
var dbGatedRoutes = map[string]bool{
	"GET /api/orgs/{id}/credits/balance": true,
	"POST /api/orgs/{id}/credits/topup":  true,
}

// TestGatewayOpenAPIRoutesExist cross-checks the gateway contract file
// (docs/api/openapi.yaml): admin-side operations it documents must exist on
// the admin router, and gateway-side ones must stay gateway-served — a
// renamed, removed or re-homed route turns this test (or the pkg/gateway
// drift gate) red.
func TestGatewayOpenAPIRoutesExist(t *testing.T) {
	walked := walkedByKey(inventoryRoutes(t))
	documented := parseOpenAPIRoutes(t, gatewayOpenAPISpec)

	if len(documented) == 0 {
		t.Fatalf("no operations parsed from %s — spec parse is broken", gatewayOpenAPISpec)
	}
	gatewayOps := 0
	for key, spec := range documented {
		if !adminSpecSide(spec) {
			gatewayOps++
			continue
		}
		if dbGatedRoutes[key] {
			continue
		}
		if _, ok := walked[key]; !ok {
			t.Errorf("stale admin route %s in %s — not registered by the admin router",
				key, gatewayOpenAPISpec)
		}
	}
	// Floor guard: the classification must not silently swallow the whole
	// file. The spec currently documents 20+ gateway operations.
	if gatewayOps < 15 {
		t.Fatalf("classified only %d gateway ops in %s — the server-side classification is broken",
			gatewayOps, gatewayOpenAPISpec)
	}
}

// TestRoutesInventoryGenerate prints yaml stub entries (path, method,
// summary placeholder, permission class) for every walked route — the
// generator for new admin.openapi.yaml sections. Opt-in via envGenerate;
// without it the test skips.
func TestRoutesInventoryGenerate(t *testing.T) {
	if os.Getenv(envGenerate) == "" {
		t.Skipf("set %s=1 to print the route stubs", envGenerate)
	}
	specs := inventoryRoutes(t)
	fmt.Printf("# %d routes walked from SetupRouter\n", len(specs))
	for _, spec := range specs {
		fmt.Printf("  %s:\n    %s:\n      summary: TODO\n      x-permission: %s\n",
			spec.Pattern, strings.ToLower(spec.Method), spec.Permission)
	}
}

// sweepPlaceholder rewrites chi URL parameters into a probe segment so a
// walked template becomes a concrete request path.
var sweepPlaceholder = regexp.MustCompile(`\{[^}]*\}`)

// TestPrivilegedRoutes_DenyWithoutRights sweeps every middleware-gated
// privileged route (class root = MustBeRoot, global = RequireGlobalAuditRead
// matrix cares about: an anonymous request is 401 behind the session boundary,
// and an authenticated NON-root admin with no org memberships gets exactly
// 403 on root and global routes and 403 or 404 on org routes (plain
// RequireOrgPermission 403s a non-member; the resourceHidden variants —
// keys.manage, policies.manage, credits reads — 404 so a foreign org is
// indistinguishable from a missing one). Nothing may leak 2xx/3xx/5xx: the
// gates run before the handlers, so an unwired store cannot turn a denial
// into a 503.
//
// The sweep runs on the FULLY-WIRED golden router (routes_golden_test.go),
// so DB-gated groups (credits, resale pricing, sovereign, regions,
// templates, feedback export, retrain) are swept too. Handler-gated org
// surfaces (routing map, caps, settings, budgets) classify "session" in the
// walk and keep their dedicated RightsMatrix tests; the per-permission role
// matrix itself is TestRoleHas_Matrix in pkg/adminstore. The security-auditor
// ALLOW side of the global class is pinned by TestOrgRoutes_RoleMatrixSweep
// and TestGlobalAudit_RoleGate (role_matrix_sweep_test.go).
func TestPrivilegedRoutes_DenyWithoutRights(t *testing.T) {
	router := goldenHandlers(t).SetupRouter()
	specs, err := walkRoutes(router)
	if err != nil {
		t.Fatalf("walk routes: %v", err)
	}
	// makeSessionCookie resolves the cookie's user through the store (TP-02
	// session revalidation); newMockStore seeds admin-1 as active, non-root,
	// and member of no organization.
	memberlessCookie := makeSessionCookie(false, "test-session-key")
	const csrf = "sweep-csrf-token"

	probe := func(spec routeSpec, cookie *http.Cookie) int {
		path := sweepPlaceholder.ReplaceAllString(spec.Pattern, "sweep-target")
		req := httptest.NewRequestWithContext(t.Context(), spec.Method, path, nil)
		req.Host = "sweep.test"
		// The ambient scope hint targetOrgID falls back to; the org-gated
		// paths carry the target in the path itself, the rest resolve the
		// header so the gate sees a concrete (foreign) org instead of a 400.
		req.Header.Set(OrgHeader, "sweep-target")
		if cookie != nil {
			req.AddCookie(cookie)
			if spec.Method != http.MethodGet && spec.Method != http.MethodHead && spec.Method != http.MethodOptions {
				// CSRFValidation is a plain double-submit check.
				req.AddCookie(&http.Cookie{Name: "yabanin_csrf_token", Value: csrf,
					Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
				req.Header.Set("X-CSRF-Token", csrf)
			}
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code
	}

	var failures []string
	swept := 0
	for _, spec := range specs {
		if spec.Permission != "root" && spec.Permission != "global" && spec.Permission != "org" {
			continue
		}
		swept++
		if code := probe(spec, nil); code != http.StatusUnauthorized {
			failures = append(failures, fmt.Sprintf("%s %s: anon = %d, want 401", spec.Method, spec.Pattern, code))
		}
		code := probe(spec, memberlessCookie)
		denied := code == http.StatusForbidden || (spec.Permission == "org" && code == http.StatusNotFound)
		if !denied {
			want := "403"
			if spec.Permission == "org" {
				want = "403/404"
			}
			failures = append(failures, fmt.Sprintf("%s %s: memberless admin = %d, want %s", spec.Method, spec.Pattern, code, want))
		}
	}
	// Floor guard: a walk or class-filter regression must not silently empty
	// the sweep. The wired router currently walks 200+ privileged routes.
	if swept < 100 {
		t.Fatalf("sweep covered only %d privileged routes — the walk or the class filter is broken", swept)
	}
	if len(failures) > 0 {
		t.Errorf("%d privileged routes deny incorrectly:\n%s", len(failures), strings.Join(failures, "\n"))
	}
}
