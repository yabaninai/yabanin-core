package cli

// DUALFORM-ORACLE-01 (auth/SSE correction packet, case 10): the two forms
// of tool-policy refusal for built-in tools are SEPARATE surfaces with
// their own exact documented status and structured type, asserted by
// JSON-decoding the envelope — never by substring. The gateway pre-check
// (policyDeniesTool → Decide) refuses with 403 / "policy_denied"; the
// executor refusal (toolexec.ExecuteGuarded → GuardArgs) surfaces after
// the pre-check PASSED, as 400 / "mcp_tool_blocked" in the mounted
// route's invoke vocabulary. Within-form allow requires a successful
// payload from a counting sink; the mask-only positive control actually
// masks. Expected addresses are literal constants below.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/toolexec"
	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

// Dualform org addresses — literal, per the packet: no helper computes
// or shares these strings.
const (
	dualformOrgPre      = "org-dualform-pre"      // pre-check deny form
	dualformOrgExec     = "org-dualform-exec"     // executor args-deny form
	dualformOrgAllow    = "org-dualform-allow"    // within-form allow
	dualformOrgMask     = "org-dualform-mask"     // mask-only control
	dualformOrgDegraded = "org-dualform-degraded" // degraded policy store (typed 503 leg)
)

// dualformLoader serves the literal org rows AND keeps the consulted-
// address ledger: the oracle asserts which literal org addresses the
// policy engine actually consulted, not just what it answered.
type dualformLoader struct {
	mu       sync.Mutex
	consults map[string]int
}

func newDualformLoader() *dualformLoader {
	return &dualformLoader{consults: make(map[string]int)}
}

// consulted counts store consultations for one literal org address.
func (l *dualformLoader) consulted(org string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.consults[org]
}

// consultedAddrs returns the sorted literal set of consulted addresses.
func (l *dualformLoader) consultedAddrs() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, 0, len(l.consults))
	for k := range l.consults {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (l *dualformLoader) ListEnabled(_ context.Context, orgID string) ([]toolpolicy.Policy, error) {
	l.mu.Lock()
	l.consults[orgID]++
	l.mu.Unlock()
	switch orgID {
	case dualformOrgPre:
		return []toolpolicy.Policy{{
			ID: "df-pre", OrgID: orgID, Name: "deny-fetch", Subject: "*", Server: "*",
			Tool: toolexec.ToolWebFetch, Action: toolpolicy.ActionDeny, Enabled: true,
		}}, nil
	case dualformOrgExec:
		return []toolpolicy.Policy{{
			ID: "df-exec", OrgID: orgID, Name: "guard-fetch", Subject: "*", Server: "*",
			Tool: toolexec.ToolWebFetch, Action: toolpolicy.ActionAllow, Enabled: true,
			Rules: json.RawMessage(`{"args":{"deny_regex":["forbidden-"]}}`),
		}}, nil
	case dualformOrgAllow:
		return []toolpolicy.Policy{{
			ID: "df-allow", OrgID: orgID, Name: "allow-fetch", Subject: "*", Server: "*",
			Tool: toolexec.ToolWebFetch, Action: toolpolicy.ActionAllow, Enabled: true,
		}}, nil
	case dualformOrgMask:
		return []toolpolicy.Policy{{
			ID: "df-mask", OrgID: orgID, Name: "mask-fetch", Subject: "*", Server: "*",
			Tool: toolexec.ToolWebFetch, Action: toolpolicy.ActionAllow, Enabled: true,
			Rules: json.RawMessage(`{"result":{"mode":"mask","deny_regex":["MARKER-X"]}}`),
		}}, nil
	case dualformOrgDegraded:
		return nil, errors.New("dualform: policy store degraded for " + orgID)
	}
	return nil, nil
}

// dualformSink is the countable side effect: a loopback HTTP server whose
// body carries the mask marker.
type dualformSink struct {
	srv  *httptest.Server
	hits atomic.Int32
	body string
}

func newDualformSink(t *testing.T) *dualformSink {
	t.Helper()
	s := &dualformSink{body: `{"text":"payload MARKER-X end"}`}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, s.body)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func dualformGateway(t *testing.T) (*gateway, *dualformLoader) {
	t.Helper()
	l := newDualformLoader()
	eng := toolpolicy.NewEngine(l, time.Minute)
	allow := fuzzLoopbackPinnedList(t)
	exec := toolexec.NewExecutor(toolexec.NewDefaultConfig(),
		func(u string) error { return execURLGuard(u, allow) }, nil).WithToolGuard(eng)
	// A non-nil publisher is required for the audit path (auditBuiltin
	// returns early otherwise); the dead instance only drops the XADDs —
	// the oracle observes events before publish.
	return &gateway{log: fuzzDiscardLogger(), publisher: fuzzDeadRedis(t), toolPolicies: eng, toolExec: exec}, l
}

// dualformType JSON-decodes the OpenAI envelope and returns its exact
// structured type — substring matching cannot substitute.
func dualformType(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var env struct {
		Error struct {
			Type string `json:"type"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("dualform: response is not the JSON envelope: %v (%s)", err, w.Body.String())
	}
	if env.Error.Type == "" {
		t.Fatalf("dualform: envelope carries no structured type: %s", w.Body.String())
	}
	return env.Error.Type
}

func dualformError(t *testing.T, w *httptest.ResponseRecorder, label string, status int, wantType string) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("%s: status %d, body %s", label, w.Code, w.Body.String())
	}
	if typ := dualformType(t, w); typ != wantType {
		t.Fatalf("%s: structured type %q, want %s", label, typ, wantType)
	}
}

func dualformPayload(t *testing.T, w *httptest.ResponseRecorder, label, sinkBody string) {
	t.Helper()
	var env struct {
		Status    int    `json:"status"`
		Content   string `json:"content"`
		Truncated bool   `json:"truncated"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("%s: not the web_fetch envelope: %v (%s)", label, err, w.Body.String())
	}
	if env.Status != 200 || env.Content != sinkBody || env.Truncated {
		t.Fatalf("%s: envelope status=%d content=%q truncated=%v, want the sink body verbatim",
			label, env.Status, env.Content, env.Truncated)
	}
}

type dualformFetch func(org, path string) *httptest.ResponseRecorder

func assertDualformPreCheck(t *testing.T, fetch dualformFetch, sink *dualformSink) {
	t.Helper()
	dualformError(t, fetch(dualformOrgPre, "/doc"), "pre-check form", http.StatusForbidden, "policy_denied")
	if n := sink.hits.Load(); n != 0 {
		t.Fatalf("pre-check form: denied call egressed %d times", n)
	}
}

func assertDualformExecutorGuard(t *testing.T, fetch dualformFetch, sink *dualformSink) {
	t.Helper()
	dualformError(t, fetch(dualformOrgExec, "/forbidden-path"), "executor form", http.StatusBadRequest, "mcp_tool_blocked")
	if n := sink.hits.Load(); n != 0 {
		t.Fatalf("executor form: args-denied call egressed %d times", n)
	}
}

func assertDualformBenign(t *testing.T, fetch dualformFetch, sink *dualformSink) {
	t.Helper()
	before := sink.hits.Load()
	w := fetch(dualformOrgExec, "/benign-doc")
	if w.Code != http.StatusOK {
		t.Fatalf("benign args form: status %d, body %s", w.Code, w.Body.String())
	}
	dualformPayload(t, w, "benign args form", sink.body)
	if n := sink.hits.Load(); n != before+1 {
		t.Fatalf("benign args form: expected exactly one sink hit, got %d→%d", before, n)
	}
}

func assertDualformAllow(t *testing.T, fetch dualformFetch, sink *dualformSink) {
	t.Helper()
	before := sink.hits.Load()
	w := fetch(dualformOrgAllow, "/doc")
	if w.Code != http.StatusOK {
		t.Fatalf("allow form: status %d, body %s", w.Code, w.Body.String())
	}
	dualformPayload(t, w, "allow form", sink.body)
	if n := sink.hits.Load(); n != before+1 {
		t.Fatalf("allow form: expected exactly one sink hit, got %d→%d", before, n)
	}
}

func assertDualformMask(t *testing.T, fetch dualformFetch, sink *dualformSink) {
	t.Helper()
	before := sink.hits.Load()
	w := fetch(dualformOrgMask, "/doc")
	if w.Code != http.StatusOK {
		t.Fatalf("mask form: status %d, body %s", w.Code, w.Body.String())
	}
	if got := w.Body.String(); !strings.Contains(got, "[REDACTED]") || strings.Contains(got, "MARKER-X") {
		t.Fatalf("mask form: body must carry the redaction token, not the marker: %s", got)
	}
	if n := sink.hits.Load(); n != before+1 {
		t.Fatalf("mask form: expected exactly one more sink hit, got %d→%d", before, n)
	}
}

func assertDualformDegraded(t *testing.T, fetch dualformFetch, sink *dualformSink) {
	t.Helper()
	var degradedEvents []*eventpublisher.Event
	restore := observeEvent(func(ev *eventpublisher.Event) {
		if ev.OrgID == dualformOrgDegraded {
			degradedEvents = append(degradedEvents, ev)
		}
	})
	hitsBefore := sink.hits.Load()
	w := fetch(dualformOrgDegraded, "/doc")
	restore()
	dualformError(t, w, "degraded form", http.StatusServiceUnavailable, "policy_unavailable")
	if n := sink.hits.Load(); n != hitsBefore {
		t.Fatalf("degraded form: refused call egressed %d times", n-hitsBefore)
	}
	if len(degradedEvents) != 1 {
		t.Fatalf("degraded form: observed %d degraded audit records, want exactly 1", len(degradedEvents))
	}
	if ev := degradedEvents[0]; ev.EventType != "request.failed" || ev.Error != "mcp:policy_unavailable" ||
		ev.UpstreamURL != "" || ev.ModelUsed != "mcp:yabanin:"+toolexec.ToolWebFetch {
		t.Fatalf("degraded form: audit record event_type=%q error=%q upstream=%q model=%q, want request.failed / mcp:policy_unavailable / empty / web_fetch",
			ev.EventType, ev.Error, ev.UpstreamURL, ev.ModelUsed)
	}
}

func assertDualformConsulted(t *testing.T, loader *dualformLoader) {
	t.Helper()
	wantAddrs := []string{dualformOrgAllow, dualformOrgDegraded, dualformOrgExec, dualformOrgMask, dualformOrgPre}
	if got := loader.consultedAddrs(); !reflect.DeepEqual(got, wantAddrs) {
		t.Fatalf("consulted addresses %v, want exactly %v", got, wantAddrs)
	}
	for _, org := range wantAddrs {
		if loader.consulted(org) < 1 {
			t.Fatalf("literal org address %q was never consulted by the policy engine", org)
		}
	}
}

func TestDualformOracle_01_GatewayAndExecutorForms(t *testing.T) {
	gw, loader := dualformGateway(t)
	sink := newDualformSink(t)
	fetch := func(org, path string) *httptest.ResponseRecorder {
		return fuzzBuiltinCall(t, gw, org, toolexec.ToolWebFetch,
			`{"url":"`+sink.srv.URL+path+`"}`)
	}
	t.Run("gateway_pre_check", func(t *testing.T) { assertDualformPreCheck(t, fetch, sink) })
	t.Run("executor_args_guard", func(t *testing.T) { assertDualformExecutorGuard(t, fetch, sink) })
	t.Run("executor_benign_args", func(t *testing.T) { assertDualformBenign(t, fetch, sink) })
	t.Run("within_form_allow", func(t *testing.T) { assertDualformAllow(t, fetch, sink) })
	t.Run("mask_only_control", func(t *testing.T) { assertDualformMask(t, fetch, sink) })
	t.Run("degraded_policy_store", func(t *testing.T) { assertDualformDegraded(t, fetch, sink) })
	t.Run("literal_consulted_addresses", func(t *testing.T) { assertDualformConsulted(t, loader) })
}
