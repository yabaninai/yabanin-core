package cli

// REVOCATION-PROPAGATION REPRODUCER — frozen before implementation (task
// task/auth-policy-revocation-repro, base 786885f).
//
// FROZEN INVARIANT: after an admin deny edit for (org, tool) commits, every
// live gateway surface that consults the org tool-policy engine must refuse
// that tool within BOUND = 5s engine TTL + 2s in-flight grace (= 7s), keep
// refusing it on every later attempt, produce ZERO new protected effects
// (upstream sink hits) after the bound, leave other orgs untouched, and the
// admin surface must reflect the deny immediately. The deny must precede
// egress. Effect oracles are INDEPENDENT: atomic hit counters on real
// httptest upstreams, never self-computed policy results.
//
// Wiring under test is the production shape: buildGateway with a real
// Postgres pool + real Redis wires gw.toolPolicies (gateway.go:476,
// 5*time.Second TTL), mcpProxy, toolExec and the /mcp streamable server; the
// admin CRUD handlers run over the same database with their OWN engine
// instance exactly as services/run/admin.go:391-392 wires them (the two
// engines are separate — admin Invalidate cannot reach the gateway engine).
// Authorization is real end-to-end: real agent keys (yag_) resolved by the
// real middleware over the real database. No mocked stores, no memLoader.
//
// Builtin tools are addressed under BOTH policy keys — the bare effective
// name ("web_fetch") and the qualified name ("yabanin:web_fetch") — on every
// builtin surface (invoke pre-check, executor, catalog). A deny row in
// EITHER form refuses and hides the tool; an allow row in one form never
// un-denies the other; within ONE form the engine ranking (specificity,
// priority) is unchanged.
//
// FROZEN CASES (IDs referenced from assertions; none may be re-scoped after
// results are observed):
//
//	RP0-HARNESS  production wiring: buildGateway(pool,rdb) + real admin handlers
//	RP1-PRE      allow phase: all surfaces succeed WITH real upstream effects
//	             (sink hits increase); includes RP1-N1 negative control: an
//	             unrelated deny row (other_*) must not block the target tool
//	RP2-FLIP     real admin PATCH action=deny for echo + web_fetch (org A)
//	RP3-VIS      admin GET reflects deny immediately after RP2-FLIP
//	RP4-BOUND    first refusal on each gateway surface <= commit + 7s
//	RP5-FOREVER  >= 10s of continued refusals; ZERO new sink hits on denied
//	             surfaces after each surface's first refusal
//	RP6-CROSSORG org B (same tool name, own server+policy) unaffected
//	RP7-VISIBILITY builtin catalog (/api/mcp/yabanin/tools) hides web_fetch
//	             for org A once RP4-BOUND holds
//	RP6B-BARE-INVOKE fresh org, bare "web_fetch" deny row from cold: invoke
//	             refused <= 7s, catalog hides web_fetch <= 7s, ZERO builtin
//	             sink hits ever
//	RP9-PREFIXED fresh org, "yabanin:web_fetch" deny row from cold: invoke
//	             refused <= 7s, ZERO builtin sink hits ever
//	RP9-MIX-BA   bare deny (p50) + prefixed ALLOW (p10): refused — a
//	             cross-form allow never un-denies
//	RP9-MIX-AB   prefixed deny (p50) + bare ALLOW (p10): refused
//	RP9-MIX-DD   bare deny + prefixed deny: refused
//	RP9-PRIORITY prefixed ALLOW (p10) + prefixed deny (p50) — one form:
//	             ALLOWED (within-form ranking preserved by the dual merge)
//
// OUTCOMES (owner contract): fail here => bounded fix, then broken-variant
// red, then fixed green. All pass => verified-negative: record + STOP.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/reireirei/yabanin/pkg/mcpagg"
	"github.com/reireirei/yabanin/pkg/ssrf"
	"github.com/reireirei/yabanin/pkg/toolexec"

	adminhandlers "github.com/reireirei/yabanin/services/admin/handlers"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/auth"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

// revocationBound is the frozen propagation budget: the engine TTL (5s, the
// documented staleness bound at gateway.go:476) plus in-flight grace.
const (
	revocationBound     = 7 * time.Second
	revocationForever   = 10 * time.Second
	revocationPollEvery = 250 * time.Millisecond
)

// revocationSink is an MCP upstream (JSON-RPC tools/call responder) with an
// independent hit counter — the protected-effect oracle for external egress.
type revocationSink struct {
	server *httptest.Server
	hits   atomic.Int64
}

func newRevocationSink(t *testing.T) *revocationSink {
	t.Helper()
	s := &revocationSink{}
	// TLS: the mcp_servers.url CHECK requires https:// (migration 0001),
	// so live upstreams must be TLS httptest servers.
	s.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rpc struct {
			ID     *json.Number `json:"id"`
			Method string       `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&rpc)
		id := "0"
		if rpc.ID != nil {
			id = rpc.ID.String()
		}
		var reply string
		switch rpc.Method {
		case "tools/list":
			// Discovery: a real MCP tools array (the gateway aggregates
			// this into /mcp tools/list). NOT a protected effect.
			reply = `{"jsonrpc":"2.0","id":` + id + `,"result":{"tools":[{"name":"echo","description":"revocation sink echo"}]}}`
		default:
			// tools/call and friends: the protected effect oracle.
			s.hits.Add(1)
			reply = `{"jsonrpc":"2.0","id":` + id + `,"result":{"content":[{"type":"text","text":"sink-ok"}],"isError":false}}`
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, reply)
	}))
	t.Cleanup(s.server.Close)
	return s
}

// revocationHarness carries the real production-shaped stack under test.
type revocationHarness struct {
	server  *httptest.Server
	client  *http.Client
	sinkA   *revocationSink
	sinkB   *revocationSink
	builtin *httptest.Server
	orgA    revocationOrg
	orgB    revocationOrg
	// streamSession is the /mcp session id captured at initialize.
	streamSession string
	// admin drives the REAL admin handlers (RP2-FLIP / RP3-VIS).
	admin *adminhandlers.AdminHandlers
	// builtinHits counts hits on the builtin web_fetch sink.
	builtinHits *atomic.Int64
	// commit / firstRefusal carry the RP2 flip instant and the per-surface
	// first-refusal instants between the phase methods. firstRefusalSink
	// records, AT each surface's OWN observed first refusal, the baseline of
	// that surface's protected sink (extA/streamA -> sinkA, builtinA ->
	// builtinHits), so RP5-FOREVER can require zero new effects per surface
	// since ITS OWN first refusal — an effect landing after an earlier
	// surface refused but before a later one did is still caught by the
	// earlier surface's baseline.
	commit           time.Time
	firstRefusal     map[string]time.Time
	firstRefusalSink map[string]int64
}

type revocationOrg struct {
	id, agentKey string
	serverName   string
}

// TestToolPolicyRevocationPropagation drives the full revocation scenario.
func TestToolPolicyRevocationPropagation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	pg := testdb.Postgres(t)
	rdb := testdb.Redis(t)
	log := slog.New(slog.DiscardHandler)

	// RP0-HARNESS: the production DB deployment wiring path.
	sinkA := newRevocationSink(t)
	sinkB := newRevocationSink(t)
	var builtinHits atomic.Int64
	builtin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		builtinHits.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("builtin-ok"))
	}))
	defer builtin.Close()

	gw, err := buildGateway(config.Gateway{
		ListenAddr:          ":0",
		AuthMode:            "header",
		Provider:            builtin.URL, // inference upstream; unused by MCP surfaces
		FallbackModel:       "repro-model",
		MCPGatewayEnabled:   true,
		MCPAllowedUpstreams: []string{"127.0.0.1"},
	}, rdb, pg, log, ctx, JWTWiring{}, CircuitScopeWiring{})
	if err != nil {
		t.Fatalf("RP0-HARNESS: buildGateway: %v", err)
	}
	if gw.toolPolicies == nil || gw.mcpProxy == nil || gw.toolExec == nil || gw.mcpStreamable == nil {
		t.Fatal("RP0-HARNESS: production egress wiring incomplete (toolPolicies/mcpProxy/toolExec/mcpStreamable)")
	}
	// Live-egress seam (repo precedent: mcpagg/toolgrant_store_int_test.go —
	// "the proxy wired exactly as the gateway builds it"): rebuild the proxy
	// and the executor with the gateway's own construction (gateway.go:512-515
	// and :570-576: same registry store, same guard chain, SAME shared engine
	// instance) with exactly two test-only deviations so loopback sinks are
	// reachable: (1) an injected Config.HTTP client trusting the TLS sinks,
	// (2) the D-4 exact-pins allow list (ssrf.NewAllowListTrustingExactPins —
	// the posture pkg/upstream/client.go uses for IP-literal pins). The
	// authorization under test — the tool-policy engine, its TTL refresh and
	// the guard chain — is the production path.
	sinkCertPool := x509.NewCertPool()
	sinkCertPool.AddCert(sinkA.server.Certificate())
	sinkCertPool.AddCert(sinkB.server.Certificate())
	pinsAllow, err := ssrf.NewAllowListTrustingExactPins([]string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("RP0-HARNESS: pins allow list: %v", err)
	}
	mcpSinkCfg := mcpagg.NewDefaultConfig()
	mcpSinkCfg.HTTP = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: sinkCertPool, MinVersion: tls.VersionTLS12},
		},
		Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	gw.mcpProxy = mcpagg.NewProxy(mcpagg.NewStore(pg), mcpSinkCfg, pinsAllow,
		&mcpParamGuard{gw: gw},
		&mcpAuditLogger{log: log}).
		WithToolGuard(gw.toolPolicies)
	gw.toolExec = toolexec.NewExecutor(toolexec.NewDefaultConfig(),
		func(urlStr string) error { return execURLGuard(urlStr, pinsAllow) },
		&mcpParamGuard{gw: gw}).
		WithToolGuard(gw.toolPolicies)
	router := chi.NewRouter()
	gw.routes(router)
	server := httptest.NewServer(router)
	defer server.Close()
	client := server.Client()
	client.Timeout = 15 * time.Second

	// RP0-HARNESS: admin side exactly as services/run/admin.go:391-392 — a
	// SEPARATE engine instance over the same database.
	admin := adminhandlers.New(nil, "", "", []string{})
	adminEngine := toolpolicy.NewEngine(toolpolicy.NewStore(pg), 5*time.Second)
	admin.SetToolPolicyStore(toolpolicy.NewStore(pg), adminEngine)

	store := adminstore.New(pg, log, nil)
	orgA := newRevocationOrg(t, ctx, pg, store, "a", sinkA)
	orgB := newRevocationOrg(t, ctx, pg, store, "b", sinkB)

	h := &revocationHarness{
		server: server, client: client,
		sinkA: sinkA, sinkB: sinkB, builtin: builtin,
		orgA: orgA, orgB: orgB,
		admin: admin, builtinHits: &builtinHits,
		firstRefusal:     map[string]time.Time{},
		firstRefusalSink: map[string]int64{},
	}

	// Policy rows via the REAL admin handlers (root context). The builtin
	// row uses the BARE tool name — the legacy address existing orgs already
	// have on disk; both keys must be enforced (see the RP6B/RP9 phases).
	mustPolicy(ctx, t, admin, orgA.id, "repro-a-echo", `{"subject":"*","server":"*","tool":"echo","action":"allow","priority":50,"enabled":true}`)
	mustPolicy(ctx, t, admin, orgA.id, "repro-a-webfetch", `{"subject":"*","server":"*","tool":"web_fetch","action":"allow","priority":50,"enabled":true}`)
	// RP1-N1: unrelated deny must not block echo/web_fetch pre-flip.
	mustPolicy(ctx, t, admin, orgA.id, "repro-a-unrelated", `{"subject":"*","server":"*","tool":"other_*","action":"deny","priority":40,"enabled":true}`)
	mustPolicy(ctx, t, admin, orgB.id, "repro-b-echo", `{"subject":"*","server":"*","tool":"echo","action":"allow","priority":50,"enabled":true}`)

	streamTool := h.allowPhase(ctx, t)
	h.flipPhase(ctx, t)
	h.boundPhase(ctx, t)
	h.foreverPhase(ctx, t)
	h.crossOrgPhase(ctx, t)
	h.catalogPhase(ctx, t)
	h.dualFormPhase(t, ctx, pg, store)

	t.Logf("REVOCATION REPRODUCER: verified-negative candidate — all frozen cases passed (stream tool %q; delays extA=%v builtinA=%v streamA=%v)",
		streamTool,
		h.firstRefusal["extA"].Sub(h.commit).Round(time.Millisecond),
		h.firstRefusal["builtinA"].Sub(h.commit).Round(time.Millisecond),
		h.firstRefusal["streamA"].Sub(h.commit).Round(time.Millisecond))
}

// allowPhase is RP1-PRE (+ the org B pre-effect check): both orgs produce
// real protected effects before the flip.
func (h *revocationHarness) allowPhase(ctx context.Context, t *testing.T) string {
	t.Helper()
	extA0 := h.sinkA.hits.Load()
	built0 := h.builtinHits.Load()
	extB0 := h.sinkB.hits.Load()
	for i := 0; i < 2; i++ {
		invokeOK(ctx, t, h.client, h.server, h.orgA.agentKey, `{"server":"`+h.orgA.serverName+`","tool":"echo","params":{}}`)
		invokeOK(ctx, t, h.client, h.server, h.orgA.agentKey, `{"server":"yabanin","tool":"web_fetch","params":{"url":`+quoteJSONRepro(h.builtin.URL)+`}}`)
	}
	streamTool := h.streamCallOK(ctx, t, "echo") // parse advertised name from the wire
	if got := h.sinkA.hits.Load() - extA0; got < 2 {
		t.Fatalf("RP1-PRE: external sink effects missing: want >=2 hits, got %d", got)
	}
	if got := h.builtinHits.Load() - built0; got < 2 {
		t.Fatalf("RP1-PRE: builtin sink effects missing: want >=2 hits, got %d", got)
	}
	invokeOK(ctx, t, h.client, h.server, h.orgB.agentKey, `{"server":"`+h.orgB.serverName+`","tool":"echo","params":{}}`)
	if got := h.sinkB.hits.Load() - extB0; got < 1 {
		t.Fatalf("RP6-CROSSORG pre: org B effects missing")
	}
	return streamTool
}

// flipPhase is RP2-FLIP + RP3-VIS: the real admin PATCH flips both rows to
// deny and the admin GET reflects it immediately.
func (h *revocationHarness) flipPhase(ctx context.Context, t *testing.T) {
	t.Helper()
	patchPolicy(ctx, t, h.admin, h.orgA.id, "repro-a-echo", `{"action":"deny"}`)
	patchPolicy(ctx, t, h.admin, h.orgA.id, "repro-a-webfetch", `{"action":"deny"}`)
	h.commit = time.Now()
	if action := getPolicyAction(ctx, t, h.admin, h.orgA.id, "repro-a-echo"); action != "deny" {
		t.Fatalf("RP3-VIS: admin GET shows action=%q immediately after PATCH, want deny", action)
	}
}

// refusalSinkFor maps each surface to the protected sink its effects land
// on: extA (external MCP echo) and streamA (stream surface echo) both hit
// sinkA; builtinA hits the builtin web_fetch sink.
func (h *revocationHarness) refusalSinkFor(surface string) *atomic.Int64 {
	switch surface {
	case "builtinA":
		return h.builtinHits
	default:
		return &h.sinkA.hits
	}
}

// boundPhase is RP4-BOUND: every surface must refuse within the bound. At
// each surface's OWN observed first refusal its sink baseline is recorded,
// so later phases can attribute any new effect to the surface whose
// first-refusal window it landed after.
func (h *revocationHarness) boundPhase(ctx context.Context, t *testing.T) {
	t.Helper()
	deadline := h.commit.Add(revocationBound)
	for _, surface := range []string{"extA", "builtinA", "streamA"} {
		ft := h.pollUntilRefused(ctx, t, surface, deadline)
		if ft.IsZero() {
			t.Fatalf("RP4-BOUND: surface %s still allowed at bound (commit+7s)", surface)
		}
		h.firstRefusal[surface] = ft
		h.firstRefusalSink[surface] = h.refusalSinkFor(surface).Load()
		t.Logf("RP4-BOUND: %s first refused %v after commit", surface, ft.Sub(h.commit).Round(time.Millisecond))
	}
}

// foreverPhase is RP5-FOREVER: refusals hold and no new protected effect
// leaks through any surface. Each surface is checked against ITS OWN
// first-refusal sink baseline, with the surface named in the assertion — a
// shared after-all-three snapshot would miss effects landing after an
// earlier surface's first refusal but before the last one's.
func (h *revocationHarness) foreverPhase(ctx context.Context, t *testing.T) {
	t.Helper()
	refusalStart := time.Now()
	for time.Since(refusalStart) < revocationForever {
		for _, surface := range []string{"extA", "builtinA", "streamA"} {
			if !h.surfaceRefused(ctx, t, surface) {
				t.Fatalf("RP5-FOREVER: surface %s allowed again after propagation", surface)
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	for _, surface := range []string{"extA", "builtinA", "streamA"} {
		if got := h.refusalSinkFor(surface).Load() - h.firstRefusalSink[surface]; got != 0 {
			t.Fatalf("RP5-FOREVER: surface %s: %d forbidden protected-sink hits since its own first refusal", surface, got)
		}
	}
}

// crossOrgPhase is RP6-CROSSORG: org B keeps its live egress end-to-end.
func (h *revocationHarness) crossOrgPhase(ctx context.Context, t *testing.T) {
	t.Helper()
	before := h.sinkB.hits.Load()
	invokeOK(ctx, t, h.client, h.server, h.orgB.agentKey, `{"server":"`+h.orgB.serverName+`","tool":"echo","params":{}}`)
	if got := h.sinkB.hits.Load() - before; got != 1 {
		t.Fatalf("RP6-CROSSORG: org B egress missing after org A revocation (hits=%d)", got)
	}
}

// catalogPhase is RP7-VISIBILITY: the builtin catalog hides the denied
// builtin within the bound.
func (h *revocationHarness) catalogPhase(ctx context.Context, t *testing.T) {
	t.Helper()
	for start := time.Now(); time.Since(start) < revocationBound; time.Sleep(revocationPollEvery) {
		catalog := catalogNames(ctx, t, h.client, h.server, h.orgA.agentKey)
		if _, hasWebFetch := catalog["web_fetch"]; !hasWebFetch {
			return
		}
	}
	t.Fatal("RP7-VISIBILITY: web_fetch still advertised after propagation")
}

// dualFormPhase covers RP6B-BARE-INVOKE and the RP9 deny family on fresh
// orgs (cold engine caches): each deny form alone must refuse from cold,
// and mixed cross-form allow/deny conflicts resolve to DENY.
func (h *revocationHarness) dualFormPhase(t *testing.T, ctx context.Context, pool *pgxpool.Pool, store *adminstore.Store) {
	t.Helper()
	cases := []struct {
		label string
		rows  [][2]string // {policy name, tool key}; "allow" in the name marks an allow row at p10
	}{
		{"RP6B-BARE-INVOKE", [][2]string{{"d-bare", "web_fetch"}}},
		{"RP9-PREFIXED", [][2]string{{"d-prefixed", "yabanin:web_fetch"}}},
		{"RP9-MIX-BA", [][2]string{{"d-mix-ba-bare", "web_fetch"}, {"d-mix-ba-allow", "yabanin:web_fetch"}}},
		{"RP9-MIX-AB", [][2]string{{"d-mix-ab-prefixed", "yabanin:web_fetch"}, {"d-mix-ab-allow", "web_fetch"}}},
		{"RP9-MIX-DD", [][2]string{{"d-mix-dd-bare", "web_fetch"}, {"d-mix-dd-prefixed", "yabanin:web_fetch"}}},
	}
	for i, tc := range cases {
		org := newRevocationOrg(t, ctx, pool, store, fmt.Sprintf("d%d", i), h.sinkB)
		h.seedDualRows(ctx, t, org, tc.rows)
		h.dualDenyCase(ctx, t, tc.label, org)
	}

	// RP9-PRIORITY: within ONE form the ranking is untouched — prefixed
	// allow p10 beats prefixed deny p50, so the call runs exactly once.
	org := newRevocationOrg(t, ctx, pool, store, "dp", h.sinkB)
	mustPolicy(ctx, t, h.admin, org.id, "d-pr-allow", `{"subject":"*","server":"*","tool":"yabanin:web_fetch","action":"allow","priority":10,"enabled":true}`)
	mustPolicy(ctx, t, h.admin, org.id, "d-pr-deny", `{"subject":"*","server":"*","tool":"yabanin:web_fetch","action":"deny","priority":50,"enabled":true}`)
	before := h.builtinHits.Load()
	invokeOK(ctx, t, h.client, h.server, org.agentKey, `{"server":"yabanin","tool":"web_fetch","params":{"url":`+quoteJSONRepro(h.builtin.URL)+`}}`)
	if got := h.builtinHits.Load() - before; got != 1 {
		t.Fatalf("RP9-PRIORITY: allowed call must produce exactly 1 builtin hit, got %d", got)
	}
}

// seedDualRows writes the case's rows via the REAL admin handlers: "allow"
// in a row name marks an allow row at priority 10, everything else denies
// at priority 50.
func (h *revocationHarness) seedDualRows(ctx context.Context, t *testing.T, org revocationOrg, rows [][2]string) {
	t.Helper()
	for _, row := range rows {
		action, priority := "deny", 50
		if strings.Contains(row[0], "allow") {
			action, priority = "allow", 10
		}
		mustPolicy(ctx, t, h.admin, org.id, row[0],
			`{"subject":"*","server":"*","tool":`+quoteJSONRepro(row[1])+`,"action":"`+action+`","priority":`+fmt.Sprint(priority)+`,"enabled":true}`)
	}
}

// dualDenyCase asserts one deny-family case: the invoke is refused within
// the bound, ZERO builtin egress ever happens, and (RP6B) the catalog hides
// the tool within the bound too.
func (h *revocationHarness) dualDenyCase(ctx context.Context, t *testing.T, label string, org revocationOrg) {
	t.Helper()
	before := h.builtinHits.Load()
	if !h.pollOrgInvokeRefused(ctx, t, org, time.Now().Add(revocationBound)) {
		t.Fatalf("%s: builtin invoke still allowed at bound (commit+7s)", label)
	}
	if got := h.builtinHits.Load() - before; got != 0 {
		t.Fatalf("%s: %d forbidden builtin egress hits", label, got)
	}
	if label != "RP6B-BARE-INVOKE" {
		return
	}
	for start := time.Now(); ; time.Sleep(revocationPollEvery) {
		if _, has := catalogNames(ctx, t, h.client, h.server, org.agentKey)["web_fetch"]; !has {
			return
		}
		if time.Since(start) >= revocationBound {
			t.Fatal("RP6B-BARE-INVOKE: web_fetch still advertised under a bare-key deny")
		}
	}
}

// pollOrgInvokeRefused polls a fresh org's builtin web_fetch invoke until the
// policy refuses it or the deadline passes.
func (h *revocationHarness) pollOrgInvokeRefused(ctx context.Context, t *testing.T, org revocationOrg, deadline time.Time) bool {
	t.Helper()
	for {
		if h.orgBuiltinRefused(ctx, t, org) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(revocationPollEvery)
	}
}

// orgBuiltinRefused reports whether the given org's builtin web_fetch invoke
// is refused with a policy error (never a bare 200).
func (h *revocationHarness) orgBuiltinRefused(ctx context.Context, t *testing.T, org revocationOrg) bool {
	t.Helper()
	status, body, err := postInvoke(ctx, h.client, h.server, org.agentKey,
		`{"server":"yabanin","tool":"web_fetch","params":{"url":`+quoteJSONRepro(h.builtin.URL)+`}}`)
	if err != nil {
		t.Fatalf("dual-form invoke transport: %v", err)
	}
	switch status {
	case http.StatusOK:
		return false
	case http.StatusForbidden, http.StatusBadRequest:
		if !strings.Contains(body, "policy_denied") && !strings.Contains(body, "mcp_tool_blocked") && !strings.Contains(body, "tool_blocked") {
			t.Fatalf("dual-form invoke unexpected %d body=%s", status, body)
		}
		return true
	}
	t.Fatalf("dual-form invoke unexpected status %d body=%s", status, body)
	return false
}

// ---- helpers ----------------------------------------------------------------

// newRevocationOrg creates a real org, a real yag_ agent key (real sha256 in
// agent_keys), a real registered MCP server row pointing at the sink, and the
// agent grant — all through the real database.
func newRevocationOrg(t *testing.T, ctx context.Context, pool *pgxpool.Pool, store *adminstore.Store, suffix string, sink *revocationSink) revocationOrg {
	t.Helper()
	org, err := store.CreateOrganization(ctx, "revocation-repro-"+suffix, "repro-revocation-"+suffix+"-"+fmt.Sprint(time.Now().UnixNano()))
	if err != nil {
		t.Fatalf("create org %s: %v", suffix, err)
	}
	plaintext, err := auth.GenerateAgentKey()
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	var agentID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO agent_keys (org_id, name, key_hash) VALUES ($1::uuid, $2, $3) RETURNING id::text`,
		org.ID, "repro-agent-"+suffix, auth.HashKey(plaintext)).Scan(&agentID); err != nil {
		t.Fatalf("seed agent key %s: %v", suffix, err)
	}
	serverName := "repro-sink-" + suffix
	if _, err := pool.Exec(ctx,
		`INSERT INTO mcp_servers (org_id, name, url, enabled) VALUES ($1::uuid, $2, $3, true)`,
		org.ID, serverName, sink.server.URL); err != nil {
		t.Fatalf("seed mcp server %s: %v", suffix, err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO mcp_server_grants (org_id, agent_id, server_name, enabled) VALUES ($1::uuid, $2::uuid, $3, true)`,
		org.ID, agentID, serverName); err != nil {
		t.Fatalf("seed agent grant %s: %v", suffix, err)
	}
	cleanupCtx := ctx
	t.Cleanup(func() {
		_, _ = pool.Exec(cleanupCtx, `DELETE FROM mcp_server_grants WHERE org_id::text = $1`, org.ID)
		_, _ = pool.Exec(cleanupCtx, `DELETE FROM mcp_servers WHERE org_id::text = $1`, org.ID)
		_, _ = pool.Exec(cleanupCtx, `DELETE FROM agent_keys WHERE org_id::text = $1`, org.ID)
		_, _ = pool.Exec(cleanupCtx, `DELETE FROM tool_policies WHERE org_id::text = $1`, org.ID)
		_, _ = pool.Exec(cleanupCtx, `DELETE FROM organizations WHERE id::text = $1`, org.ID)
	})
	return revocationOrg{id: org.ID, agentKey: plaintext, serverName: serverName}
}

// streamPost sends one JSON-RPC message over the real /mcp streamable route
// (real agent auth via the gateway middleware) and returns status, session id
// and body.
func (h *revocationHarness) streamPost(ctx context.Context, org revocationOrg, body string) (int, string, string) {
	req, _ := http.NewRequestWithContext(ctx, "POST", h.server.URL+"/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+org.agentKey)
	if h.streamSession != "" {
		req.Header.Set("Mcp-Session-Id", h.streamSession)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return 0, "", err.Error()
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", err.Error()
	}
	return resp.StatusCode, resp.Header.Get("Mcp-Session-Id"), string(raw)
}

// streamEnsureSession runs initialize once and keeps the issued session id.
func (h *revocationHarness) streamEnsureSession(ctx context.Context, t *testing.T, org revocationOrg) {
	t.Helper()
	if h.streamSession != "" {
		return
	}
	status, sid, body := h.streamPost(ctx, org, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`)
	if status != http.StatusOK {
		t.Fatalf("stream initialize: %d %s", status, body)
	}
	if sid != "" {
		h.streamSession = sid
	}
}

// streamAdvertised finds the advertised tool name on the wire (tools/list)
// matching the bare tool name (single-server shape: "echo"; composed shape:
// "server:echo"). Fails the test when the tool is not advertised.
func (h *revocationHarness) streamAdvertised(ctx context.Context, t *testing.T, org revocationOrg, tool string) string {
	t.Helper()
	status, _, body := h.streamPost(ctx, org, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if status != http.StatusOK {
		t.Fatalf("stream tools/list: %d %s", status, body)
	}
	var list struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(body), &list); err != nil {
		t.Fatalf("stream tools/list decode: %v body=%s", err, body)
	}
	for _, tl := range list.Result.Tools {
		if tl.Name == tool || strings.HasSuffix(tl.Name, ":"+tool) {
			return tl.Name
		}
	}
	t.Fatalf("stream tools/list did not advertise %q: body=%s", tool, body)
	return ""
}

// streamAdvertisedSoft is the non-fatal lookup used by refusal probing.
func (h *revocationHarness) streamAdvertisedSoft(ctx context.Context, org revocationOrg, tool string) (string, bool) {
	status, _, body := h.streamPost(ctx, org, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if status != http.StatusOK {
		return "", false
	}
	var list struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(body), &list); err != nil {
		return "", false
	}
	for _, tl := range list.Result.Tools {
		if tl.Name == tool || strings.HasSuffix(tl.Name, ":"+tool) {
			return tl.Name, true
		}
	}
	return "", false
}

// streamCallOK proves the pre-revocation effect through the streamable
// surface: initialize → tools/list → tools/call with the advertised name.
func (h *revocationHarness) streamCallOK(ctx context.Context, t *testing.T, tool string) string {
	t.Helper()
	h.streamEnsureSession(ctx, t, h.orgA)
	name := h.streamAdvertised(ctx, t, h.orgA, tool)
	before := h.sinkA.hits.Load()
	status, _, body := h.streamPost(ctx, h.orgA, fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":%q,"arguments":{}}}`, name))
	if status != http.StatusOK {
		t.Fatalf("RP1-PRE stream tools/call %q: %d %s", name, status, body)
	}
	var call struct {
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &call); err != nil || call.Error != nil {
		t.Fatalf("RP1-PRE stream tools/call %q error: %v body=%s", name, err, body)
	}
	if h.sinkA.hits.Load()-before != 1 {
		t.Fatalf("RP1-PRE stream call produced no upstream effect (name %q)", name)
	}
	return name
}

// surfaceRefused dispatches to the per-surface refusal predicate.
func (h *revocationHarness) surfaceRefused(ctx context.Context, t *testing.T, surface string) bool {
	t.Helper()
	switch surface {
	case "extA":
		return h.extRefused(ctx, t)
	case "builtinA":
		return h.builtinRefused(ctx, t)
	case "streamA":
		return h.streamRefused(ctx, t)
	}
	t.Fatalf("unknown surface %q", surface)
	return false
}

// extRefused: external MCP echo invoke of org A is refused with a policy
// error (never a bare 200).
func (h *revocationHarness) extRefused(ctx context.Context, t *testing.T) bool {
	t.Helper()
	status, body, err := postInvoke(ctx, h.client, h.server, h.orgA.agentKey,
		`{"server":"`+h.orgA.serverName+`","tool":"echo","params":{}}`)
	if err != nil {
		t.Fatalf("extA transport: %v", err)
	}
	switch status {
	case http.StatusOK:
		return false
	case http.StatusForbidden, http.StatusBadRequest:
		if !strings.Contains(body, "policy_denied") && !strings.Contains(body, "mcp_tool_blocked") {
			t.Fatalf("extA unexpected %d body=%s", status, body)
		}
		return true
	}
	t.Fatalf("extA unexpected status %d body=%s", status, body)
	return false
}

// builtinRefused: builtin web_fetch invoke of org A is refused with a policy
// error (never a bare 200).
func (h *revocationHarness) builtinRefused(ctx context.Context, t *testing.T) bool {
	t.Helper()
	status, body, err := postInvoke(ctx, h.client, h.server, h.orgA.agentKey,
		`{"server":"yabanin","tool":"web_fetch","params":{"url":`+quoteJSONRepro(h.builtin.URL)+`}}`)
	if err != nil {
		t.Fatalf("builtinA transport: %v", err)
	}
	switch status {
	case http.StatusOK:
		return false
	case http.StatusForbidden, http.StatusBadRequest:
		if !strings.Contains(body, "policy_denied") && !strings.Contains(body, "mcp_tool_blocked") && !strings.Contains(body, "tool_blocked") {
			t.Fatalf("builtinA unexpected %d body=%s", status, body)
		}
		return true
	}
	t.Fatalf("builtinA unexpected status %d body=%s", status, body)
	return false
}

// streamRefused: the streamable /mcp tools/call of org A answers with a
// JSON-RPC error, or the tool is no longer advertised at all.
func (h *revocationHarness) streamRefused(ctx context.Context, t *testing.T) bool {
	t.Helper()
	name, ok := h.streamAdvertisedSoft(ctx, h.orgA, "echo")
	if !ok {
		// Hidden from discovery after revocation: that IS refusal here.
		return true
	}
	status, _, body := h.streamPost(ctx, h.orgA, fmt.Sprintf(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":%q,"arguments":{}}}`, name))
	if status != http.StatusOK {
		t.Fatalf("streamA unexpected status %d body=%s", status, body)
	}
	var call struct {
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &call); err != nil {
		t.Fatalf("streamA decode: %v body=%s", err, body)
	}
	return call.Error != nil
}

// pollUntilRefused polls a surface until it is refused or the RP4-BOUND
// deadline passes (returns the zero time then).
func (h *revocationHarness) pollUntilRefused(ctx context.Context, t *testing.T, surface string, deadline time.Time) time.Time {
	t.Helper()
	for {
		if h.surfaceRefused(ctx, t, surface) {
			return time.Now()
		}
		if time.Now().After(deadline) {
			return time.Time{}
		}
		time.Sleep(revocationPollEvery)
	}
}

func mustPolicy(ctx context.Context, t *testing.T, h *adminhandlers.AdminHandlers, orgID, name, body string) {
	t.Helper()
	// CreateToolPolicy resolves the org from the JSON body (requireOrgScope),
	// so merge org_id into the payload.
	var payload map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("create policy %s/%s: bad body: %v", orgID, name, err)
	}
	orgRaw, _ := json.Marshal(orgID)
	payload["org_id"] = orgRaw
	nameRaw, _ := json.Marshal(name)
	payload["name"] = nameRaw
	merged, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("create policy %s/%s: merge: %v", orgID, name, err)
	}
	req := revocationRootReq(ctx, "POST", "/api/organizations/"+orgID+"/tool-policies", string(merged))
	w := httptest.NewRecorder()
	h.CreateToolPolicy()(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create policy %s/%s: %d %s", orgID, name, w.Code, w.Body.String())
	}
}

func patchPolicy(ctx context.Context, t *testing.T, h *adminhandlers.AdminHandlers, orgID, name, body string) {
	t.Helper()
	req := revocationRootReq(ctx, "PATCH", "/api/organizations/"+orgID+"/tool-policies/"+name, body)
	req.SetPathValue("id", orgID)
	req.SetPathValue("name", name)
	w := httptest.NewRecorder()
	h.UpdateToolPolicy()(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("patch policy %s/%s: %d %s", orgID, name, w.Code, w.Body.String())
	}
}

func getPolicyAction(ctx context.Context, t *testing.T, h *adminhandlers.AdminHandlers, orgID, name string) string {
	t.Helper()
	req := revocationRootReq(ctx, "GET", "/api/organizations/"+orgID+"/tool-policies/"+name, "")
	req.SetPathValue("id", orgID)
	req.SetPathValue("name", name)
	w := httptest.NewRecorder()
	h.GetToolPolicy()(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("get policy %s/%s: %d %s", orgID, name, w.Code, w.Body.String())
	}
	var p toolpolicy.Policy
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode policy: %v", err)
	}
	return p.Action
}

// revocationRootReq mirrors the handlers package rootRequest helper: a root
// operator context (any org in scope).
func revocationRootReq(ctx context.Context, method, target, body string) *http.Request {
	ctx = context.WithValue(ctx, adminauth.ContextKeyIsRoot{}, true)
	r, _ := http.NewRequestWithContext(ctx, method, target, strings.NewReader(body))
	return r
}

func invokeOK(ctx context.Context, t *testing.T, client *http.Client, server *httptest.Server, key, body string) {
	t.Helper()
	status, respBody, err := postInvoke(ctx, client, server, key, body)
	if err != nil || status != http.StatusOK {
		t.Fatalf("invoke expected 200, got %d err=%v body=%s", status, err, respBody)
	}
}

func postInvoke(ctx context.Context, client *http.Client, server *httptest.Server, key, body string) (int, string, error) {
	req, _ := http.NewRequestWithContext(ctx, "POST", server.URL+"/api/mcp/invoke", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(raw), nil
}

func quoteJSONRepro(s string) string { return "\"" + s + "\"" }

func catalogNames(ctx context.Context, t *testing.T, client *http.Client, server *httptest.Server, key string) map[string]bool {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, "GET", server.URL+"/api/mcp/yabanin/tools", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	// builtinToolCatalog (toolgate.go) writes a bare JSON array of tool
	// descriptors, filtered per-agent by the org deny policy.
	var payload []struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("catalog decode: %v", err)
	}
	out := map[string]bool{}
	for _, tool := range payload {
		out[tool.Name] = true
	}
	return out
}
