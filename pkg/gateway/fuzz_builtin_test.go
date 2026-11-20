package cli

// Fuzz seeds for the built-in executor surface (task gateway-fuzz-seeds).
// Case IDs and expected outcomes are frozen in FROZEN-CASE-TABLE.md
// (BT-*). Upstreams are loopback httptest servers reached through the
// pinned 127.0.0.1 allow-list; the executor's validate closure is the same
// execURLGuard the production wiring uses.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/mcpagg"
	"github.com/reireirei/yabanin/pkg/toolexec"
)

// fuzzBuiltinGateway wires a gateway around one executor configuration.
func fuzzBuiltinGateway(t *testing.T, cfg toolexec.Config, hook toolexec.Hook, guardOn, engineOn bool) *gateway {
	t.Helper()
	allow := fuzzLoopbackPinnedList(t)
	exec := toolexec.NewExecutor(cfg, func(u string) error { return execURLGuard(u, allow) }, hook)
	if guardOn {
		exec = exec.WithToolGuard(fuzzToolEngine())
	}
	gw := &gateway{log: fuzzDiscardLogger()}
	if engineOn {
		gw.toolPolicies = fuzzToolEngine()
	}
	gw.toolExec = exec
	return gw
}

func fuzzBuiltinCall(t *testing.T, gw *gateway, org, tool, params string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), "POST", "/api/mcp/yabanin/invoke", strings.NewReader("{}"))
	r.Header.Set("X-Org-Id", org)
	r.Header.Set("X-Agent-Id", "yag_1")
	r.Header.Set("X-Session-Id", "s1")
	w := httptest.NewRecorder()
	gw.builtinToolInvoke(w, r, org, mcpagg.Identity{AgentID: "yag_1", RequestID: "r1"},
		mcpagg.InvokeRequest{Tool: tool, Params: json.RawMessage(params)})
	return w
}

func FuzzBuiltinTools(f *testing.F) {
	for id := 1; id <= 19; id++ {
		f.Add([]byte{byte(id)}) // frozen regression corpus
	}
	// Generated-invoke seeds: SSRF-rejected host and a policy-denied fetch.
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0x40, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 0 && data[0] >= 1 && data[0] <= 19 {
			fuzzBTCases[int(data[0])](t)
			return
		}
		btGenerated(t, data)
	})
}

// btGenCase derives an invoke from fuzzed bytes: tool, org, URL host and
// args payload. Hosts: the pinned loopback counting server (allowed dial),
// a public hostname (SSRF-rejected before any dial) and a dead loopback
// port (allowed by the allowlist, upstream fails).
type btGenCase struct {
	tool, org, params string
	dialPinned        bool
	wantPolicyDeny    bool
	wantForbiddenArgs bool
}

func btGenCaseFor(p []byte, srvURL string) btGenCase {
	c := btGenCase{tool: "web_fetch", org: "org1"}
	tools := []string{"web_fetch", "web_fetch", "redis_get"}
	orgs := []string{"org1", "org-builtin", "org-fetch"}
	c.tool = tools[int(p[0])%len(tools)]
	c.org = orgs[int(p[1])%len(orgs)]
	switch p[2] % 3 {
	case 0:
		c.params = fmt.Sprintf(`{"url":%q}`, srvURL+"/fuzz")
		c.dialPinned = c.tool == "web_fetch" && c.org != "org-builtin"
	case 1:
		c.params = `{"url":"http://not-allowed.example.net/fuzz"}`
	default:
		c.params = fmt.Sprintf(`{"url":"http://127.0.0.1:1/fuzz","q":%q}`, string(p))
	}
	if c.org == "org-builtin" && c.tool == "web_fetch" {
		c.wantPolicyDeny = true
	}
	if c.org == "org-fetch" && strings.Contains(c.params, "forbidden") {
		c.wantForbiddenArgs = true
	}
	return c
}

// fuzzBuiltinGenerated drives the real builtinToolInvoke against a live
// counting upstream with generated tool/org/URL/args and asserts the
// authorization and SSRF invariants independently of the response prose:
// policy-denied and SSRF-rejected invokes must never dial, an allowed
// invoke dials the pinned server exactly once.
func btGenerated(t *testing.T, data []byte) {
	t.Helper()
	p := data
	if len(p) > 0 && p[0] < 20 {
		p = p[1:]
	}
	if len(p) < 3 {
		p = append(p, 0, 1, 2)
	}
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "text/plain")
		if _, err := io.WriteString(w, "fuzz-ok"); err != nil {
			http.Error(w, "probe write failed", http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)

	gw := fuzzBuiltinGateway(t, toolexec.NewDefaultConfig(), nil, false, true)
	before := atomic.LoadInt32(&hits)
	c := btGenCaseFor(p, srv.URL)
	w := fuzzBuiltinCall(t, gw, c.org, c.tool, c.params)
	after := atomic.LoadInt32(&hits)
	btGenAssert(t, c, w, before, after)
	if w.Body.Len() > 0 && !json.Valid(w.Body.Bytes()) {
		t.Fatalf("bt gen: non-JSON envelope: %q", w.Body.String())
	}
	// Critical-go contract pins for the event media-hygiene funnel (this
	// driver wires no publisher, so auditBuiltin's hygiene call is
	// unreachable here; the contract is pinned directly instead).
	if mediaHygienicEvent(nil) != nil {
		t.Fatal("bt gen: nil event must stay nil")
	}
	media := &eventpub.Event{Payload: `{"img":"data:image/png;base64,` + strings.Repeat("QUJD", 64) + `"}`}
	sanitized := mediaHygienicEvent(media)
	if sanitized == nil || sanitized == media || sanitized.Payload == media.Payload ||
		strings.Contains(sanitized.Payload, "QUJDQUJDQUJD") {
		t.Fatalf("bt gen: inline media not stripped: %q", sanitized.Payload)
	}
	plain := &eventpub.Event{Payload: `{"ok":true}`}
	if got := mediaHygienicEvent(plain); got != plain {
		t.Fatal("bt gen: media-free event must return the same pointer")
	}
}

// btGenAssert checks the generated invoke against the authorization and
// dial invariants: policy/args denials must answer 403, and an allowed
// invoke dials the pinned upstream exactly once while a non-allowlisted
// URL never dials at all.
func btGenAssert(t *testing.T, c btGenCase, w *httptest.ResponseRecorder, before, after int32) {
	t.Helper()
	switch {
	case c.wantPolicyDeny || c.wantForbiddenArgs:
		if w.Code != http.StatusForbidden {
			t.Fatalf("bt gen: policy denial expected: org=%s tool=%s params=%s -> %d %s",
				c.org, c.tool, c.params, w.Code, w.Body.String())
		}
	case c.tool != "web_fetch":
		// non-fetch tools resolve without the pinned HTTP dial
	default:
		if !c.dialPinned && after != before {
			t.Fatalf("bt gen: unexpected upstream hit without an allowlisted URL: params=%s hits %d->%d",
				c.params, before, after)
		}
		if c.dialPinned && after != before+1 {
			t.Fatalf("bt gen: allowed invoke must dial exactly once: params=%s hits %d->%d (%d %s)",
				c.params, before, after, w.Code, w.Body.String())
		}
	}
}

var fuzzBTCases = map[int]func(*testing.T){
	1:  fuzzBT01,
	2:  fuzzBT02,
	3:  fuzzBT03,
	4:  fuzzBT04,
	5:  fuzzBT05,
	6:  fuzzBT06,
	7:  fuzzBT07,
	8:  fuzzBT08,
	9:  fuzzBT09,
	10: fuzzBT10,
	11: fuzzBT11,
	12: fuzzBT12,
	13: fuzzBT13,
	14: fuzzBT14,
	15: fuzzBT15,
	16: fuzzBT16,
	17: fuzzBT17,
	18: fuzzBT18,
	19: fuzzBT19,
}

// // BT-01 executor not configured → 503
func fuzzBT01(t *testing.T) {
	t.Helper()

	gw := &gateway{log: fuzzDiscardLogger()}
	w := fuzzBuiltinCall(t, gw, "org1", "time_now", `{}`)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "unavailable") {
		t.Fatalf("BT-01: %d %s", w.Code, w.Body.String())
	}
}

// // BT-02 policy denies yabanin:web_fetch → 403 policy_denied
func fuzzBT02(t *testing.T) {
	t.Helper()

	gw := fuzzBuiltinGateway(t, toolexec.NewDefaultConfig(), nil, false, true)
	w := fuzzBuiltinCall(t, gw, "org-builtin", "web_fetch", `{"url":"https://127.0.0.1:1/"}`)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "policy_denied") {
		t.Fatalf("BT-02: %d %s", w.Code, w.Body.String())
	}
}

// // BT-03 unknown tool → 404 not_found
func fuzzBT03(t *testing.T) {
	t.Helper()

	gw := fuzzBuiltinGateway(t, toolexec.NewDefaultConfig(), nil, false, false)
	w := fuzzBuiltinCall(t, gw, "org1", "nope", `{}`)
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), toolexec.ErrCodeNotFound) {
		t.Fatalf("BT-03: %d %s", w.Code, w.Body.String())
	}
}

// // BT-04 missing url → 400 bad_request
func fuzzBT04(t *testing.T) {
	t.Helper()

	gw := fuzzBuiltinGateway(t, toolexec.NewDefaultConfig(), nil, false, false)
	w := fuzzBuiltinCall(t, gw, "org1", "web_fetch", `{}`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), toolexec.ErrCodeBadReq) {
		t.Fatalf("BT-04: %d %s", w.Code, w.Body.String())
	}
}

// // BT-05 host outside the allow-list → 400 ssrf_blocked
func fuzzBT05(t *testing.T) {
	t.Helper()

	gw := fuzzBuiltinGateway(t, toolexec.NewDefaultConfig(), nil, false, false)
	w := fuzzBuiltinCall(t, gw, "org1", "web_fetch", `{"url":"http://not-allowed.example.net/x"}`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), toolexec.ErrCodeSSRF) {
		t.Fatalf("BT-05: %d %s", w.Code, w.Body.String())
	}
}

// // BT-06 guard hook deny → 409 denied
func fuzzBT06(t *testing.T) {
	t.Helper()

	gw := fuzzBuiltinGateway(t, toolexec.NewDefaultConfig(),
		fuzzA2AHook{deny: "url targets a secret"}, false, false)
	w := fuzzBuiltinCall(t, gw, "org1", "web_fetch", `{"url":"http://127.0.0.1:1/x"}`)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), toolexec.ErrCodeDenied) {
		t.Fatalf("BT-06: %d %s", w.Code, w.Body.String())
	}
}

// // BT-07 pinned loopback port closed → 502 upstream
func fuzzBT07(t *testing.T) {
	t.Helper()

	gw := fuzzBuiltinGateway(t, toolexec.NewDefaultConfig(), nil, false, false)
	w := fuzzBuiltinCall(t, gw, "org1", "web_fetch", `{"url":"http://127.0.0.1:1/x"}`)
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), toolexec.ErrCodeUpstream) {
		t.Fatalf("BT-07: %d %s", w.Code, w.Body.String())
	}
}

// // BT-08 upstream 500 → 502 upstream
func fuzzBT08(t *testing.T) {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	gw := fuzzBuiltinGateway(t, toolexec.NewDefaultConfig(), nil, false, false)
	w := fuzzBuiltinCall(t, gw, "org1", "web_fetch", `{"url":"`+srv.URL+`"}`)
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), toolexec.ErrCodeUpstream) {
		t.Fatalf("BT-08: %d %s", w.Code, w.Body.String())
	}
}

// // BT-09 binary content type → 502 upstream
func fuzzBT09(t *testing.T) {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("\x00\x01"))
	}))
	t.Cleanup(srv.Close)
	gw := fuzzBuiltinGateway(t, toolexec.NewDefaultConfig(), nil, false, false)
	w := fuzzBuiltinCall(t, gw, "org1", "web_fetch", `{"url":"`+srv.URL+`"}`)
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), toolexec.ErrCodeUpstream) {
		t.Fatalf("BT-09: %d %s", w.Code, w.Body.String())
	}
}

// // BT-10 slow upstream, ReadTimeout 30ms → 504 timeout
func fuzzBT10(t *testing.T) {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte("late"))
	}))
	t.Cleanup(srv.Close)
	cfg := toolexec.NewDefaultConfig()
	cfg.ReadTimeout = 30 * time.Millisecond
	gw := fuzzBuiltinGateway(t, cfg, nil, false, false)
	w := fuzzBuiltinCall(t, gw, "org1", "web_fetch", `{"url":"`+srv.URL+`"}`)
	if w.Code != http.StatusGatewayTimeout || !strings.Contains(w.Body.String(), toolexec.ErrCodeTimeout) {
		t.Fatalf("BT-10: %d %s", w.Code, w.Body.String())
	}
}

// // BT-11 args guard blocks before dispatch → 400 mcp_tool_blocked
func fuzzBT11(t *testing.T) {
	t.Helper()

	gw := fuzzBuiltinGateway(t, toolexec.NewDefaultConfig(), nil, true, false)
	w := fuzzBuiltinCall(t, gw, "org-fetch", "web_fetch", `{"url":"http://127.0.0.1:1/forbidden"}`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), mcpagg.ErrCodeToolBlocked) {
		t.Fatalf("BT-11: %d %s", w.Code, w.Body.String())
	}
}

// // BT-12 text/plain fetch → 200 envelope, not truncated
func fuzzBT12(t *testing.T) {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("hello"))
	}))
	t.Cleanup(srv.Close)
	gw := fuzzBuiltinGateway(t, toolexec.NewDefaultConfig(), nil, false, false)
	w := fuzzBuiltinCall(t, gw, "org1", "web_fetch", `{"url":"`+srv.URL+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("BT-12: %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"truncated":false`) || !strings.Contains(w.Body.String(), "hello") {
		t.Fatalf("BT-12: envelope wrong: %s", w.Body.String())
	}
}

// // BT-13 response cap → truncated=true
func fuzzBT13(t *testing.T) {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("0123456789abcdefghij"))
	}))
	t.Cleanup(srv.Close)
	cfg := toolexec.NewDefaultConfig()
	cfg.MaxResponseBytes = 8
	gw := fuzzBuiltinGateway(t, cfg, nil, false, false)
	w := fuzzBuiltinCall(t, gw, "org1", "web_fetch", `{"url":"`+srv.URL+`"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"truncated":true`) {
		t.Fatalf("BT-13: %d %s", w.Code, w.Body.String())
	}
}

// // BT-14 time_now → 200, no network
func fuzzBT14(t *testing.T) {
	t.Helper()

	gw := fuzzBuiltinGateway(t, toolexec.NewDefaultConfig(), nil, false, false)
	w := fuzzBuiltinCall(t, gw, "org1", "time_now", `{}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "rfc3339") {
		t.Fatalf("BT-14: %d %s", w.Code, w.Body.String())
	}
}

// // BT-15 success against failing writer → warn, no panic
func fuzzBT15(t *testing.T) {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("hello"))
	}))
	t.Cleanup(srv.Close)
	gw := fuzzBuiltinGateway(t, toolexec.NewDefaultConfig(), nil, false, false)
	fw := &fuzzRecorder{ResponseRecorder: httptest.NewRecorder(), failWrite: true}
	r := httptest.NewRequestWithContext(context.Background(), "POST", "/api/mcp/yabanin/invoke", nil)
	r.Header.Set("X-Org-Id", "org1")
	r.Header.Set("X-Agent-Id", "yag_1")
	gw.builtinToolInvoke(fw, r, "org1", mcpagg.Identity{AgentID: "yag_1", RequestID: "r1"},
		mcpagg.InvokeRequest{Tool: "time_now", Params: json.RawMessage(`{}`)})
	if fw.Code != http.StatusOK {
		t.Fatalf("BT-15: status %d", fw.Code)
	}
}

// // BT-16 catalog: nil exec, no org, no agent, deny-hides, full list
func fuzzBT16(t *testing.T) {
	t.Helper()

	nilGW := &gateway{log: fuzzDiscardLogger()}
	w := httptest.NewRecorder()
	nilGW.builtinToolCatalog(w, httptest.NewRequestWithContext(context.Background(), "GET", "/api/mcp/yabanin", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("BT-16: nil exec %d", w.Code)
	}
	gw := fuzzBuiltinGateway(t, toolexec.NewDefaultConfig(), nil, false, true)
	w = httptest.NewRecorder()
	gw.builtinToolCatalog(w, httptest.NewRequestWithContext(context.Background(), "GET", "/api/mcp/yabanin", nil)) // no org
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("BT-16: no org %d", w.Code)
	}
	r := httptest.NewRequestWithContext(context.Background(), "GET", "/api/mcp/yabanin", nil)
	r.Header.Set("X-Org-Id", "org1") // no agent
	w = httptest.NewRecorder()
	gw.builtinToolCatalog(w, r)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "agent_only") {
		t.Fatalf("BT-16: no agent %d %s", w.Code, w.Body.String())
	}
	r = httptest.NewRequestWithContext(context.Background(), "GET", "/api/mcp/yabanin", nil)
	r.Header.Set("X-Org-Id", "org-builtin")
	r.Header.Set("X-Agent-Id", "yag_1")
	w = httptest.NewRecorder()
	gw.builtinToolCatalog(w, r) // web_fetch hidden by policy
	if strings.Contains(w.Body.String(), `"web_fetch"`) {
		t.Fatalf("BT-16: denied tool must be hidden: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "time_now") {
		t.Fatalf("BT-16: time_now must remain: %s", w.Body.String())
	}
	r = httptest.NewRequestWithContext(context.Background(), "GET", "/api/mcp/yabanin", nil)
	r.Header.Set("X-Org-Id", "org1")
	r.Header.Set("X-Agent-Id", "yag_1")
	w = httptest.NewRecorder()
	gw.builtinToolCatalog(w, r) // unrestricted org: full flat list
	if !strings.Contains(w.Body.String(), `"web_fetch"`) {
		t.Fatalf("BT-16: full list must include web_fetch: %s", w.Body.String())
	}
}

// // BT-17 auditBuiltin: nil publisher no-op, OK path builds and publishes
func fuzzBT17(t *testing.T) {
	t.Helper()

	silent := &gateway{log: fuzzDiscardLogger()}
	silent.auditBuiltin(context.Background(), "org1", mcpagg.Identity{RequestID: "r1"}, "web_fetch",
		nil, mcpagg.OutcomeOK, 0, 0, "")
	live := &gateway{log: fuzzDiscardLogger(), publisher: fuzzDeadRedis(t)}
	live.auditBuiltin(context.Background(), "org1", mcpagg.Identity{RequestID: "r2", AgentID: "yag_1"}, "web_fetch",
		json.RawMessage(`{"url":"http://127.0.0.1/x"}`), mcpagg.OutcomeOK, 200, 3, "http://127.0.0.1/x")
}

// // BT-18 REAL error-path audit: a failing web_fetch (loopback port closed)
// // with a live publisher attached — line 610 audits (code, status=0): the
// // captured event must be request.failed with mcp:<code> and no upstream
// // status (ExecuteGuarded discards the result on error paths; finding F3).
func fuzzBT18(t *testing.T) {
	t.Helper()

	var got *eventpub.Event
	restore := observeEvent(func(ev *eventpub.Event) { got = ev })
	defer restore()

	gw := fuzzBuiltinGateway(t, toolexec.NewDefaultConfig(), nil, false, false)
	gw.publisher = fuzzDeadRedis(t)
	w := fuzzBuiltinCall(t, gw, "org-builtin", "web_fetch", `{"url":"http://127.0.0.1:1/x"}`)
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), toolexec.ErrCodeUpstream) {
		t.Fatalf("BT-18: %d %s", w.Code, w.Body.String())
	}
	if got == nil || got.EventType != "request.failed" || got.Error != "mcp:"+toolexec.ErrCodeUpstream {
		t.Fatalf("BT-18: audit event %+v", got)
	}
	if got.StatusCode != 0 {
		t.Fatalf("BT-18: error-path audit must carry status 0, got %d", got.StatusCode)
	}
}

// // BT-19 auditBuiltin direct entry, (non-OK, status>0) shape: no
// // production caller pair yields it (line 610 audits status=0, line 637
// // audits outcome=OK) — the guard arm must still format the upstream
// // status into the error string and stamp StatusCode (finding F3).
func fuzzBT19(t *testing.T) {
	t.Helper()

	var got *eventpub.Event
	restore := observeEvent(func(ev *eventpub.Event) { got = ev })
	defer restore()

	live := &gateway{log: fuzzDiscardLogger(), publisher: fuzzDeadRedis(t)}
	live.auditBuiltin(context.Background(), "org-builtin",
		mcpagg.Identity{RequestID: "fuzz-bt-19", AgentID: "ag1"}, "web_fetch", nil,
		toolexec.ErrCodeUpstream, http.StatusBadGateway, 3, "http://127.0.0.1:1/x")
	if got == nil {
		t.Fatal("BT-19: audit event not observed")
	}
	if want := "mcp:" + toolexec.ErrCodeUpstream + " (upstream 502)"; got.Error != want {
		t.Fatalf("BT-19: error %q, want %q", got.Error, want)
	}
	if got.StatusCode != http.StatusBadGateway || got.EventType != "request.failed" {
		t.Fatalf("BT-19: %+v", got)
	}
}
