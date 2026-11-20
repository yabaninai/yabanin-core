package cli

// Fuzz seeds for the TOOL-02/03 surface (fuzz-seed infrastructure, task
// gateway-fuzz-seeds). Case IDs and expected outcomes are frozen in
// FROZEN-CASE-TABLE.md (TG-*); each seed asserts its documented outcome so
// the gate's seed-mode run fails loudly on any drift.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/toolexec"
	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

// fuzzPolicyLoader serves static policy sets per org: org-deny denies
// "secret_tool", org-args denies "forbidden" arguments on "safe_tool",
// org-a2a denies "a2a:alpha", org-builtin denies "yabanin:web_fetch",
// org-fetch keys the forbidden-argument guard to the builtin executor's
// web_fetch, and org-name01 adds a weak allowed first name (shim_tool,
// no argument rules) beside that strict executable web_fetch for the
// SSE-NAME-01 conflicting-declaration legs. Every other org resolves to
// no rows (implicit allow-all).
type fuzzPolicyLoader struct{}

func (fuzzPolicyLoader) ListEnabled(_ context.Context, orgID string) ([]toolpolicy.Policy, error) {
	switch orgID {
	case "org-deny":
		return []toolpolicy.Policy{{
			ID: "d1", OrgID: orgID, Name: "deny-secret", Subject: "*", Server: "*",
			Tool: "secret_tool", Action: toolpolicy.ActionDeny, Enabled: true,
		}}, nil
	case "org-args":
		// The chat-path gates engage only when the org has at least one deny
		// row, so org-args pairs a marker deny with the args-guard allow.
		return []toolpolicy.Policy{
			{ID: "a0", OrgID: orgID, Name: "deny-never", Subject: "*", Server: "*",
				Tool: "never_tool", Action: toolpolicy.ActionDeny, Enabled: true},
			{ID: "a1", OrgID: orgID, Name: "args-guard", Subject: "*", Server: "*",
				Tool: "safe_tool", Action: toolpolicy.ActionAllow, Enabled: true,
				Rules: json.RawMessage(`{"args":{"deny_regex":["forbidden"]}}`)},
		}, nil
	case "org-a2a":
		return []toolpolicy.Policy{{
			ID: "a9", OrgID: orgID, Name: "deny-a2a-alpha", Subject: "*", Server: "*",
			Tool: "a2a:alpha", Action: toolpolicy.ActionDeny, Enabled: true,
		}}, nil
	case "org-builtin":
		return []toolpolicy.Policy{{
			ID: "b1", OrgID: orgID, Name: "deny-webfetch", Subject: "*", Server: "*",
			Tool: "yabanin:web_fetch", Action: toolpolicy.ActionDeny, Enabled: true,
		}}, nil
	case "org-fetch":
		// Same shape as org-args, keyed to the builtin executor's tool
		// name (server "yabanin", tool "web_fetch").
		return []toolpolicy.Policy{
			{ID: "f0", OrgID: orgID, Name: "deny-never", Subject: "*", Server: "*",
				Tool: "never_tool", Action: toolpolicy.ActionDeny, Enabled: true},
			{ID: "f1", OrgID: orgID, Name: "fetch-args", Subject: "*", Server: "*",
				Tool: "web_fetch", Action: toolpolicy.ActionAllow, Enabled: true,
				Rules: json.RawMessage(`{"args":{"deny_regex":["forbidden"]}}`)},
		}, nil
	case "org-name01":
		// SSE-NAME-01: secret_tool denied (also the gate-activating marker),
		// shim_tool allowed with no argument rules (weak first name), and
		// web_fetch allowed with the forbidden-argument deny_regex (strict
		// executable final name).
		return []toolpolicy.Policy{
			{ID: "m0", OrgID: orgID, Name: "deny-secret", Subject: "*", Server: "*",
				Tool: "secret_tool", Action: toolpolicy.ActionDeny, Enabled: true},
			{ID: "m1", OrgID: orgID, Name: "shim-allow", Subject: "*", Server: "*",
				Tool: "shim_tool", Action: toolpolicy.ActionAllow, Enabled: true},
			{ID: "m2", OrgID: orgID, Name: "fetch-args", Subject: "*", Server: "*",
				Tool: "web_fetch", Action: toolpolicy.ActionAllow, Enabled: true,
				Rules: json.RawMessage(`{"args":{"deny_regex":["forbidden"]}}`)},
		}, nil
	}
	return nil, nil
}

func fuzzToolEngine() *toolpolicy.Engine {
	return toolpolicy.NewEngine(fuzzPolicyLoader{}, time.Minute)
}

// fuzzRecorder is an http.ResponseWriter whose Write can be made to fail,
// for the write-error branches.
type fuzzRecorder struct {
	*httptest.ResponseRecorder
	failWrite bool
}

func (r *fuzzRecorder) Write(p []byte) (int, error) {
	if r.failWrite {
		return 0, fmt.Errorf("write failed")
	}
	return r.ResponseRecorder.Write(p)
}

func FuzzToolGateJSON(f *testing.F) {
	for id := 1; id <= 18; id++ {
		f.Add([]byte{byte(id)}) // frozen regression corpus
	}
	// Generated-body seeds: mixed allowed/denied calls, and a raw-bytes body.
	f.Add([]byte{0x00, 0x01, 0x00, 0x01})
	f.Add([]byte{0x55, 0x01, 0x02})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 0 && data[0] >= 1 && data[0] <= 18 {
			fuzzTGCases[int(data[0])](t)
			return
		}
		tgGenerated(t, data)
	})
}

// tgGenBody builds a completion body from fuzzed bytes: zero or more
// tool_calls with generated names/indices/args inside generated choices.
// Names cycle through the policy-denied name, an allowed name and a
// generated (unknown ⇒ implicitly allowed) name.
func tgGenBody(p []byte) []byte {
	names := []string{"secret_tool", "safe_tool"}
	choices := make([]any, 0, 2)
	for i := 0; i+1 < len(p); i += 2 {
		c := p[i : i+2]
		var name string
		switch c[0] & 3 {
		case 0:
			name = names[0]
		case 1:
			name = names[1]
		default:
			name = fmt.Sprintf("gen_tool_%02x", c[0])
		}
		call := map[string]any{
			"id":    fmt.Sprintf("call_%02x", c[1]),
			"type":  "function",
			"index": c[1] % 3,
			"function": map[string]any{
				"name":      name,
				"arguments": fmt.Sprintf(`{"k":%q}`, string(c)),
			},
		}
		msg := map[string]any{"role": "assistant", "content": "ok"}
		if c[0]&4 != 0 {
			msg["tool_calls"] = []any{call}
		} else {
			msg["content"] = fmt.Sprintf(`uses %q`, name) // name echoes outside calls: must survive
		}
		choices = append(choices, map[string]any{"index": len(choices), "message": msg})
	}
	body, _ := json.Marshal(map[string]any{"id": "cmpl_fuzz", "object": "chat.completion", "choices": choices})
	return body
}

// tgGenOracle holds the independent response-surface invariants for
// generated bodies: valid JSON in ⇒ valid JSON out, no denied NAME survives
// as a tool call (the same name echoed as plain content must survive), and
// allowed calls are never dropped or reordered away.
func tgGenOracle(t *testing.T, in, out []byte, denied []string, rawMode bool) {
	t.Helper()
	if !rawMode && !json.Valid(out) {
		t.Fatalf("tg gen: gate made the body unparseable: %q", out)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		if rawMode {
			return // passthrough of arbitrary bytes is asserted byte-identical below
		}
		t.Fatalf("tg gen: output not JSON: %v (%q)", err, out)
	}
	kept, deniedSeen := tgGenCountCalls(doc)
	if deniedSeen > 0 {
		t.Fatalf("tg gen: denied tool call survived the gate: %q", out)
	}
	for _, n := range denied {
		if !bytes.Contains(in, []byte(n)) {
			t.Fatalf("tg gen: fabricated denial of %q not present in input", n)
		}
	}
	if kept != bytes.Count(in, []byte(`"name":"safe_tool"`)) {
		t.Fatalf("tg gen: allowed calls lost: kept %d in output, input had %d (%q)", kept,
			bytes.Count(in, []byte(`"name":"safe_tool"`)), out)
	}
}

// tgGenCountCalls counts surviving tool calls by name class: kept allowed
// calls and any denied-name survivors (which must be zero after the gate).
func tgGenCountCalls(doc map[string]any) (kept, deniedSeen int) {
	choices, _ := doc["choices"].([]any)
	for _, c := range choices {
		choice, _ := c.(map[string]any)
		if choice == nil {
			continue
		}
		msg, _ := choice["message"].(map[string]any)
		calls, _ := msg["tool_calls"].([]any)
		for _, cl := range calls {
			fn, _ := cl.(map[string]any)["function"].(map[string]any)
			name, _ := fn["name"].(string)
			if name == "safe_tool" {
				kept++
			}
			if name == "secret_tool" {
				deniedSeen++
			}
		}
	}
	return kept, deniedSeen
}

// tgGenerated drives the real gateToolCallsJSON with either a generated
// completion body or the raw fuzzed bytes (passthrough surface).
func tgGenerated(t *testing.T, data []byte) {
	t.Helper()
	p := data
	if len(p) > 0 && p[0] < 19 {
		p = p[1:]
	}
	gw := &gateway{log: fuzzDiscardLogger(), toolPolicies: fuzzToolEngine()}
	var body []byte
	rawMode := len(p) > 0 && p[0]&0x80 != 0
	if rawMode {
		body = p // arbitrary bytes: unparseable bodies pass through untouched
	} else {
		body = tgGenBody(p)
	}
	out, denied := gw.gateToolCallsJSON(context.Background(), "org-deny", "*", body)
	// Unparseable raw bytes must pass through untouched; parseable raw
	// bodies are filtered like generated ones and share the oracle.
	if rawMode && !json.Valid(body) && !bytes.Equal(out, body) {
		t.Fatalf("tg gen: passthrough altered raw body: %q -> %q", body, out)
	}
	tgGenOracle(t, body, out, denied, rawMode && !json.Valid(body))
}

var fuzzTGCases = map[int]func(*testing.T){
	1:  fuzzTG01,
	2:  fuzzTG02,
	3:  fuzzTG03,
	4:  fuzzTG04,
	5:  fuzzTG05,
	6:  fuzzTG06,
	7:  fuzzTG07,
	8:  fuzzTG08,
	9:  fuzzTG09,
	10: fuzzTG10,
	11: fuzzTG11,
	12: fuzzTG12,
	13: fuzzTG13,
	14: fuzzTG14,
	15: fuzzTG15,
	16: fuzzTG16,
	17: fuzzTG17,
	18: fuzzTG18,
}

// // TG-01 engine nil → byte-identical passthrough
func fuzzTG01(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	gw := &gateway{log: fuzzDiscardLogger(), toolPolicies: fuzzToolEngine()}
	gw.toolPolicies = nil
	resp := `{"choices":[{"message":{"tool_calls":[{"function":{"name":"secret_tool"}}]}}]}`
	out, denied := gw.gateToolCallsJSON(ctx, "org-deny", "*", []byte(resp))
	if string(out) != resp || denied != nil {
		t.Fatalf("TG-01: passthrough broken: %q %v", out, denied)
	}
}

// // TG-02 org without deny rows → passthrough
func fuzzTG02(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	gw := &gateway{log: fuzzDiscardLogger(), toolPolicies: fuzzToolEngine()}
	resp := `{"choices":[{"message":{"tool_calls":[{"function":{"name":"secret_tool"}}]}}]}`
	out, denied := gw.gateToolCallsJSON(ctx, "org-clean", "*", []byte(resp))
	if string(out) != resp || denied != nil {
		t.Fatalf("TG-02: no-deny org passthrough broken: %q %v", out, denied)
	}
}

// // TG-03 unparseable body → untouched
func fuzzTG03(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	gw := &gateway{log: fuzzDiscardLogger(), toolPolicies: fuzzToolEngine()}
	out, denied := gw.gateToolCallsJSON(ctx, "org-deny", "*", []byte("not json"))
	if string(out) != "not json" || denied != nil {
		t.Fatalf("TG-03: invalid json must pass through: %q %v", out, denied)
	}
}

// // TG-04 no tool_calls → untouched
func fuzzTG04(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	gw := &gateway{log: fuzzDiscardLogger(), toolPolicies: fuzzToolEngine()}
	resp := `{"choices":[{"message":{"content":"hi"}}],"object":"chat.completion"}`
	out, denied := gw.gateToolCallsJSON(ctx, "org-deny", "*", []byte(resp))
	if string(out) != resp || denied != nil {
		t.Fatalf("TG-04: no-calls passthrough broken: %q %v", out, denied)
	}
}

// // TG-05 denied call, none kept → tool_calls removed, finish rewritten
func fuzzTG05(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	gw := &gateway{log: fuzzDiscardLogger(), toolPolicies: fuzzToolEngine()}
	resp := `{"choices":[{"message":{"tool_calls":[{"function":{"name":"secret_tool","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}`
	out, denied := gw.gateToolCallsJSON(ctx, "org-deny", "*", []byte(resp))
	if len(denied) != 1 || denied[0] != "secret_tool" {
		t.Fatalf("TG-05: denied list wrong: %v", denied)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("TG-05: output not json: %v", err)
	}
	choice := doc["choices"].([]any)[0].(map[string]any)
	msg := choice["message"].(map[string]any)
	if _, has := msg["tool_calls"]; has {
		t.Fatal("TG-05: tool_calls must be deleted when none kept")
	}
	if choice["finish_reason"] != "stop" {
		t.Fatalf("TG-05: finish_reason must normalize to stop, got %v", choice["finish_reason"])
	}
}

// // TG-06 mixed calls → denied stripped, allowed kept
func fuzzTG06(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	gw := &gateway{log: fuzzDiscardLogger(), toolPolicies: fuzzToolEngine()}
	resp := `{"choices":[{"message":{"tool_calls":[{"function":{"name":"secret_tool"}},{"function":{"name":"safe_tool"}}]}}]}`
	out, denied := gw.gateToolCallsJSON(ctx, "org-deny", "*", []byte(resp))
	if len(denied) != 1 || denied[0] != "secret_tool" {
		t.Fatalf("TG-06: denied wrong: %v", denied)
	}
	var doc map[string]any
	_ = json.Unmarshal(out, &doc)
	calls := doc["choices"].([]any)[0].(map[string]any)["message"].(map[string]any)["tool_calls"].([]any)
	if len(calls) != 1 || calls[0].(map[string]any)["function"].(map[string]any)["name"] != "safe_tool" {
		t.Fatalf("TG-06: kept calls wrong: %v", calls)
	}
}

// // TG-07 args rule denies an allowed-name call
func fuzzTG07(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	gw := &gateway{log: fuzzDiscardLogger(), toolPolicies: fuzzToolEngine()}
	resp := `{"choices":[{"message":{"tool_calls":[{"function":{"name":"safe_tool","arguments":"{\"q\":\"forbidden thing\"}"}}]}}]}`
	out, denied := gw.gateToolCallsJSON(ctx, "org-args", "*", []byte(resp))
	if len(denied) != 1 || denied[0] != "safe_tool" {
		t.Fatalf("TG-07: args-denied wrong: %v", denied)
	}
	if strings.Contains(string(out), "safe_tool") {
		t.Fatalf("TG-07: denied call must be stripped: %s", out)
	}
}

// // TG-08 nameless call kept
func fuzzTG08(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	gw := &gateway{log: fuzzDiscardLogger(), toolPolicies: fuzzToolEngine()}
	resp := `{"choices":[{"message":{"tool_calls":[{"function":{"arguments":"{}"}}]}}]}`
	out, denied := gw.gateToolCallsJSON(ctx, "org-deny", "*", []byte(resp))
	if denied != nil || !strings.Contains(string(out), "tool_calls") {
		t.Fatalf("TG-08: nameless call must be kept: %q %v", out, denied)
	}
}

// // TG-09 declaredArgs four arms
func fuzzTG09(t *testing.T) {
	t.Helper()

	if got := string(declaredArgs(map[string]any{"arguments": ""})); got != "{}" {
		t.Fatalf("TG-09: empty string → %q", got)
	}
	if got := string(declaredArgs(map[string]any{"arguments": "  \t "})); got != "{}" {
		t.Fatalf("TG-09: blank string → %q", got)
	}
	if got := string(declaredArgs(map[string]any{"arguments": `{"a":1}`})); got != `{"a":1}` {
		t.Fatalf("TG-09: string passthrough → %q", got)
	}
	if got := string(declaredArgs(map[string]any{"arguments": map[string]any{"b": 2.0}})); got != `{"b":2}` {
		t.Fatalf("TG-09: map normalize → %q", got)
	}
	// TG-09 (SSE-DECL-01 correction of the former "{}" pin): any other
	// JSON value serializes as the consumer receives it.
	if got := string(declaredArgs(map[string]any{"arguments": 3.5})); got != "3.5" {
		t.Fatalf("TG-09: other type → %q", got)
	}
	if got := string(declaredArgs(map[string]any{"arguments": []any{"a"}})); got != `["a"]` {
		t.Fatalf("TG-09: array form → %q", got)
	}
}

// // TG-10 agentSubject both arms
func fuzzTG10(t *testing.T) {
	t.Helper()

	r := httptest.NewRequestWithContext(context.Background(), "POST", "/", nil)
	if agentSubject(r) != "*" {
		t.Fatal("TG-10: missing header must map to *")
	}
	r.Header.Set("X-Agent-Id", "yag_1")
	if agentSubject(r) != "yag_1" {
		t.Fatal("TG-10: header must map to agent id")
	}
}

// // TG-11 policyDeniesTool: nil engine, allow, deny
func fuzzTG11(t *testing.T) {
	t.Helper()

	gw := &gateway{log: fuzzDiscardLogger(), toolPolicies: fuzzToolEngine()}
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), "POST", "/", nil)
	gwNil := &gateway{}
	if gwNil.policyDeniesTool(w, r, "org-deny", "yag_1", "secret_tool") {
		t.Fatal("TG-11: nil engine must not deny")
	}
	if gw.policyDeniesTool(w, r, "org-deny", "yag_1", "safe_tool") {
		t.Fatal("TG-11: allowed tool must not deny")
	}
	if !gw.policyDeniesTool(w, r, "org-deny", "yag_1", "secret_tool") {
		t.Fatal("TG-11: denied tool must return true")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("TG-11: want 403, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "policy_denied") {
		t.Fatalf("TG-11: body must carry policy_denied: %s", w.Body.String())
	}
}

// // TG-12 publishToolPolicyDenial with logger set, nil publisher
func fuzzTG12(t *testing.T) {
	t.Helper()

	gw := &gateway{log: fuzzDiscardLogger(), toolPolicies: fuzzToolEngine()}
	r := httptest.NewRequestWithContext(context.Background(), "POST", "/", nil)
	r.Header.Set("X-Session-Id", "s1")
	gw.publishToolPolicyDenial(r, "org-deny", "yag_1", "secret_tool",
		toolpolicy.Decision{Action: toolpolicy.ActionDeny,
			Policy: &toolpolicy.Policy{ID: "d1", Name: "deny-secret"}})
}

// // TG-13 execURLGuard parse error
func fuzzTG13(t *testing.T) {
	t.Helper()

	if err := execURLGuard("http://exa\x7fmple.com/", fuzzLoopbackPinnedList(t)); err == nil ||
		!strings.Contains(err.Error(), "invalid url") {
		t.Fatalf("TG-13: want parse error, got %v", err)
	}
}

// // TG-14 scheme / host / credentials errors
func fuzzTG14(t *testing.T) {
	t.Helper()

	allow := fuzzLoopbackPinnedList(t)
	if err := execURLGuard("ftp://example.com/", allow); err == nil ||
		!strings.Contains(err.Error(), "scheme must be http or https") {
		t.Fatalf("TG-14: scheme: %v", err)
	}
	if err := execURLGuard("http:///path", allow); err == nil ||
		!strings.Contains(err.Error(), "no host") {
		t.Fatalf("TG-14: host: %v", err)
	}
	if err := execURLGuard("http://u:p@127.0.0.1:1/", allow); err == nil ||
		!strings.Contains(err.Error(), "credentials") {
		t.Fatalf("TG-14: credentials: %v", err)
	}
}

// // TG-15 allow-list outcomes (hermetic resolver)
func fuzzTG15(t *testing.T) {
	t.Helper()

	allow := fuzzPublicAllowList(t)
	if err := execURLGuard("https://api.example.com/v1", allow); err != nil {
		t.Fatalf("TG-15: allowed host rejected: %v", err)
	}
	if err := execURLGuard("https://other.example.net/", allow); err == nil {
		t.Fatal("TG-15: unlisted host must be rejected")
	}
	if err := execURLGuard("https://api.example.com/", fuzzResolverErrList(t)); err == nil {
		t.Fatal("TG-15: resolver error must reject")
	}
	res := fuzzReservedList(t)
	if err := execURLGuard("https://api.example.com/", res); err == nil ||
		!strings.Contains(err.Error(), "reserved") {
		t.Fatalf("TG-15: reserved IP must be rejected: %v", err)
	}
	empty := fuzzEmptyAnswerList(t)
	if err := execURLGuard("https://api.example.com/", empty); err == nil ||
		!strings.Contains(err.Error(), "no IPs") {
		t.Fatalf("TG-15: empty answer must be rejected: %v", err)
	}
}

// // TG-16 errorsAs, toolNamesFromDenied, ptrBool
func fuzzTG16(t *testing.T) {
	t.Helper()

	e := &toolexec.ExecError{Code: "upstream", Message: "x"}
	var target *toolexec.ExecError
	if !errorsAs(e, &target) || target != e {
		t.Fatal("TG-16: ExecError must match")
	}
	if errorsAs(fmt.Errorf("plain"), &target) {
		t.Fatal("TG-16: plain error must not match")
	}
	if toolNamesFromDenied([]string{"a", "b"}) != "a,b" {
		t.Fatal("TG-16: join wrong")
	}
	if v := ptrBool(true); v == nil || !*v {
		t.Fatal("TG-16: ptrBool(true) wrong")
	}
}

// // TG-17 malformed choices entries: nil choice and nil message survive
func fuzzTG17(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	gw := &gateway{log: fuzzDiscardLogger(), toolPolicies: fuzzToolEngine()}
	out, denied := gw.gateToolCallsJSON(ctx, "org-deny", "*", []byte(
		`{"choices":[null,"bogus",{"no_message":true},{"message":{"tool_calls":[{"function":{"name":"secret_tool"}}]}}]}`))
	if len(denied) != 1 || denied[0] != "secret_tool" {
		t.Fatalf("TG-17: deny must survive malformed siblings: %q %v", out, denied)
	}
	if strings.Contains(string(out), "secret_tool") {
		t.Fatalf("TG-17: denied call must drop: %q", out)
	}
}

// // TG-18 declaredArgs marshal guard: a map carrying a non-JSON-native
// // value (NaN cannot arrive through json.Unmarshal) must fall back to the
// // empty-object bytes instead of failing — the deny path then evaluates an
// // empty arg set. Production callers only pass Unmarshal-derived maps; this
// // seed pins the guard's fallback contract at the function's own entry.
func fuzzTG18(t *testing.T) {
	t.Helper()

	got := declaredArgs(map[string]any{"arguments": map[string]any{"n": math.NaN()}})
	if string(got) != "{}" {
		t.Fatalf("TG-18: unmarshalable arguments must fall back to {}: %s", got)
	}
}
