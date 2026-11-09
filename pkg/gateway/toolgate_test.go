package cli

// TOOL-02 tests: the JSON-surface gate and the SSE frame filter, over a
// real toolpolicy engine with an in-memory loader.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/mcpagg"
	"github.com/reireirei/yabanin/pkg/toolexec"
	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

func mustWrite(t *testing.T, g *sseToolGateWriter, p []byte) {
	t.Helper()
	if _, err := g.Write(p); err != nil {
		t.Fatalf("write: %v", err)
	}
}

type memLoader struct{ policies []toolpolicy.Policy }

func (m *memLoader) ListEnabled(context.Context, string) ([]toolpolicy.Policy, error) {
	return m.policies, nil
}

func denyTool(name string) toolpolicy.Policy {
	return toolpolicy.Policy{OrgID: "org-1", Name: "deny-" + name, Subject: "*", Tool: name, Action: toolpolicy.ActionDeny, Enabled: true}
}

func gateWith(policies ...toolpolicy.Policy) *gateway {
	gw := &gateway{}
	gw.toolPolicies = toolpolicy.NewEngine(&memLoader{policies: policies}, time.Minute)
	return gw
}

func TestGateToolCallsJSON(t *testing.T) {
	resp := []byte(`{"id":"1","choices":[{"index":0,"message":{"role":"assistant","tool_calls":[` +
		`{"id":"c1","type":"function","function":{"name":"web_fetch","arguments":"{}"}},` +
		`{"id":"c2","type":"function","function":{"name":"calculator","arguments":"{}"}}]},` +
		`"finish_reason":"tool_calls"}],"usage":{"total_tokens":5}}`)

	t.Run("no policies = byte identity", func(t *testing.T) {
		got, denied := gateWith().gateToolCallsJSON(context.Background(), "org-1", "a", resp)
		if !bytes.Equal(got, resp) || denied != nil {
			t.Fatalf("must be a no-op without policies")
		}
	})
	t.Run("allowed only = byte identity", func(t *testing.T) {
		got, denied := gateWith(denyTool("shell")).gateToolCallsJSON(context.Background(), "org-1", "a", resp)
		if !bytes.Equal(got, resp) || len(denied) != 0 {
			t.Fatalf("unrelated deny must not touch the body")
		}
	})
	t.Run("partial deny strips one call, keeps finish_reason", func(t *testing.T) {
		got, denied := gateWith(denyTool("web_fetch")).gateToolCallsJSON(context.Background(), "org-1", "a", resp)
		if len(denied) != 1 || denied[0] != "web_fetch" {
			t.Fatalf("denied list: %v", denied)
		}
		var doc struct {
			Choices []struct {
				Message struct {
					ToolCalls []map[string]any `json:"tool_calls"`
				} `json:"message"`
				FinishReason string `json:"finish_reason"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(got, &doc); err != nil {
			t.Fatalf("filtered body must be valid JSON: %v", err)
		}
		calls := doc.Choices[0].Message.ToolCalls
		if len(calls) != 1 || calls[0]["id"] != "c2" {
			t.Fatalf("kept calls: %+v", calls)
		}
		// calculator survives → the tool loop must continue.
		if doc.Choices[0].FinishReason != "tool_calls" {
			t.Fatalf("finish_reason must stay tool_calls while a call remains, got %q", doc.Choices[0].FinishReason)
		}
	})
	t.Run("all denied strips tool_calls and normalizes finish_reason", func(t *testing.T) {
		got, denied := gateWith(denyTool("*")).gateToolCallsJSON(context.Background(), "org-1", "a", resp)
		if len(denied) != 2 {
			t.Fatalf("denied list: %v", denied)
		}
		var doc struct {
			Choices []struct {
				Message      map[string]any `json:"message"`
				FinishReason string         `json:"finish_reason"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(got, &doc); err != nil {
			t.Fatalf("filtered body must be valid JSON: %v", err)
		}
		if _, has := doc.Choices[0].Message["tool_calls"]; has {
			t.Fatal("tool_calls must be removed entirely")
		}
		if doc.Choices[0].FinishReason != "stop" {
			t.Fatalf("finish_reason must normalize to stop, got %q", doc.Choices[0].FinishReason)
		}
	})
	t.Run("partial deny keeps finish_reason tool_calls", func(t *testing.T) {
		got, _ := gateWith(denyTool("web_fetch")).gateToolCallsJSON(context.Background(), "org-1", "a", resp)
		var doc struct {
			Choices []struct {
				FinishReason string `json:"finish_reason"`
			} `json:"choices"`
		}
		_ = json.Unmarshal(got, &doc)
		// calculator survives → tool loop continues
		if len(doc.Choices) > 0 && doc.Choices[0].FinishReason != "tool_calls" {
			// (with a kept call the reason must remain tool_calls)
			t.Fatalf("finish_reason must stay tool_calls while calls remain, got %q", doc.Choices[0].FinishReason)
		}
	})
	t.Run("garbage body passes through", func(t *testing.T) {
		bad := []byte("not json")
		got, denied := gateWith(denyTool("*")).gateToolCallsJSON(context.Background(), "org-1", "a", bad)
		if !bytes.Equal(got, bad) || denied != nil {
			t.Fatal("non-JSON body must pass through")
		}
	})
}

func TestSSEToolGateWriter(t *testing.T) {
	engine := toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{denyTool("web_fetch")}}, time.Minute)
	rec := httptest.NewRecorder()
	g := newSSEToolGateWriter(context.Background(), rec, engine, "org-1", "agent-1", true)

	// First fragment carries the name (denied): must be suppressed entirely.
	mustWrite(t, g, []byte(`data: {"id":1,"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":"web_fetch","arguments":""}}]}}]}`+"\n\n"))
	// Argument continuation for index 0 (denied): suppressed.
	mustWrite(t, g, []byte(`data: {"id":1,"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"u\""}}]}}]}`+"\n\n"))
	// An allowed call's fragments must pass.
	mustWrite(t, g, []byte(`data: {"id":1,"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"name":"calc","arguments":""}}]}}]}`+"\n\n"))
	// Split-frame: one frame across two writes (buffering must hold).
	mustWrite(t, g, []byte("data: {\"id\":1,\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hel"))
	mustWrite(t, g, []byte("lo\"}}]}\n\n"))
	// Terminal.
	mustWrite(t, g, []byte("data: [DONE]\n\n"))
	g.Flush()

	body := rec.Body.String()
	if bytes.Contains([]byte(body), []byte("web_fetch")) {
		t.Fatalf("denied tool name leaked:\n%s", body)
	}
	if !bytes.Contains([]byte(body), []byte("calc")) {
		t.Fatalf("allowed tool suppressed:\n%s", body)
	}
	if !bytes.Contains([]byte(body), []byte("hello")) {
		t.Fatalf("content frame lost or corrupted:\n%s", body)
	}
	if !bytes.Contains([]byte(body), []byte("[DONE]")) {
		t.Fatalf("terminal lost")
	}
	if g.DeniedCount() != 1 {
		t.Fatalf("denied count: %d", g.DeniedCount())
	}
}

func TestSSEToolGateWriter_FinishReasonRewrite(t *testing.T) {
	engine := toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{denyTool("web_fetch")}}, time.Minute)
	rec := httptest.NewRecorder()
	g := newSSEToolGateWriter(context.Background(), rec, engine, "org-1", "agent-1", true)

	mustWrite(t, g, []byte(`data: {"id":1,"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":"web_fetch"}}]}}]}`+"\n\n"))
	// Terminal chunk with finish_reason tool_calls → must become stop.
	mustWrite(t, g, []byte(`data: {"id":1,"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`+"\n\n"))
	mustWrite(t, g, []byte("data: [DONE]\n\n"))
	g.Flush()

	body := rec.Body.String()
	if bytes.Contains([]byte(body), []byte(`"finish_reason":"tool_calls"`)) {
		t.Fatalf("stranded tool_calls finish leaked:\n%s", body)
	}
	if !bytes.Contains([]byte(body), []byte(`"finish_reason":"stop"`)) {
		t.Fatalf("normalized stop missing:\n%s", body)
	}
}

func TestSSEToolGateWriter_AllowedCallKeepsEventBoundaries(t *testing.T) {
	engine := toolpolicy.NewEngine(&memLoader{policies: []toolpolicy.Policy{denyTool("http_delete")}}, time.Minute)
	rec := httptest.NewRecorder()
	gate := newSSEToolGateWriter(context.Background(), rec, engine, "org-1", "*", true)
	frames := []string{
		`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"bash","arguments":"{\"command\":\"echo ok\"}"}}]}}]}`,
		`data: {"choices":[{"index":0,"finish_reason":"tool_calls","delta":{"role":"assistant","content":""}}]}`,
		`data: [DONE]`,
	}
	for _, frame := range frames {
		// The provider writes each line and each newline separately, flushing
		// after every line. Keep this pattern in the regression test.
		mustWrite(t, gate, []byte(frame))
		mustWrite(t, gate, []byte("\n"))
		gate.Flush()
		mustWrite(t, gate, []byte("\n"))
		gate.Flush()
	}
	got := rec.Body.String()
	if strings.Count(got, "\n\n") != len(frames) {
		t.Fatalf("SSE frame separators lost: %q", got)
	}
	for _, frame := range strings.Split(strings.TrimSpace(got), "\n\n") {
		if frame == "data: [DONE]" {
			continue
		}
		if !strings.HasPrefix(frame, "data: ") || !json.Valid([]byte(strings.TrimPrefix(frame, "data: "))) {
			t.Fatalf("malformed SSE event: %q", frame)
		}
	}
}

// errLoader always fails with the configured error — simulates an
// unreachable policy store (e.g. a cancelled request context).
type errLoader struct{ err error }

func (l errLoader) ListEnabled(context.Context, string) ([]toolpolicy.Policy, error) {
	return nil, l.err
}

// TestToolPolicyFailsOpenOnCancelledContext pins the tool-policy failure
// mode (D-15): when the policy store is unreachable — including through a
// cancelled request context — Decide fails OPEN. A client hanging up
// mid-stream must never start denying tool calls.
func TestToolPolicyFailsOpenOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	engine := toolpolicy.NewEngine(errLoader{err: context.Canceled}, time.Minute)
	if d := engine.Decide(ctx, "org-1", "agent-1", "web_fetch"); d.Action != toolpolicy.ActionAllow {
		t.Fatalf("cancelled context must fail open, got action %q", d.Action)
	}
}

// blockingCtxLoader blocks until its context is done — simulates a slow
// policy store so the gate's context handling is observable.
type blockingCtxLoader struct{}

func (blockingCtxLoader) ListEnabled(ctx context.Context, _ string) ([]toolpolicy.Policy, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestSSEToolGateWriteStopsWhenClientContextCancelled: while a stream is
// gated, a client disconnect must stop the wait for Decide — a frame write
// must not block on the policy store once the request context is cancelled
// (D-15). The failure mode stays fail-open: the frame passes unmodified.
func TestSSEToolGateWriteStopsWhenClientContextCancelled(t *testing.T) {
	engine := toolpolicy.NewEngine(blockingCtxLoader{}, time.Minute)
	rec := httptest.NewRecorder()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancel() // the client went away mid-stream
	g := newSSEToolGateWriter(ctx, rec, engine, "org-1", "agent-1", true)
	frame := []byte(`data: {"id":1,"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":"web_fetch"}}]}}]}` + "\n\n")

	done := make(chan struct{})
	go func() {
		_, _ = g.Write(frame)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("frame Write blocked waiting for Decide after client cancellation")
	}
	if rec.Body.String() != string(frame) {
		t.Fatalf("cancelled context must fail open (frame unmodified), got %q", rec.Body.String())
	}
}

func TestAgentSubject(t *testing.T) {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", nil)
	if got := agentSubject(r); got != "*" {
		t.Fatalf("no header: %q", got)
	}
	r.Header.Set("X-Agent-Id", "agent-7")
	if got := agentSubject(r); got != "agent-7" {
		t.Fatalf("with header: %q", got)
	}
}

func TestBuiltinToolInvoke_EffectiveNamePolicy(t *testing.T) {
	// A policy denying yabanin:http_post must block http_request with
	// method=post but not method=get.
	gw := gateWith(func() toolpolicy.Policy {
		p := denyTool("yabanin:http_post")
		return p
	}())
	gw.toolExec = toolexec.NewExecutor(toolexec.NewDefaultConfig(), nil, nil)

	mkReq := func() *http.Request {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/mcp/invoke", nil)
		r.Header.Set("X-Org-Id", "org-1")
		r.Header.Set("X-Agent-Id", "agent-1")
		return r
	}

	// POST through http_request → denied by the composed name yabanin:http_post.
	w := httptest.NewRecorder()
	gw.builtinToolInvoke(w, mkReq(), "org-1", mcpagg.Identity{AgentID: "agent-1"},
		mcpagg.InvokeRequest{Server: "yabanin", Tool: "http_request",
			Params: json.RawMessage(`{"url":"https://x.test","method":"post"}`)})
	if w.Code != http.StatusForbidden {
		t.Fatalf("http_request post: got %d, want 403 (body %s)", w.Code, w.Body.String())
	}
}

// TestBuiltinToolInvoke_DenyPublishesDecisionRecord: CORE-TRACE-05 — the
// invoke-path deny publishes the unified decision envelope
// (rule_namespace=tool-policy, trace_completeness=absent: this decision type
// carries no step instrumentation and must never read as "no steps ran").
// Version stays 0 (tool policies have no version column — unknown stays
// unknown) and effective_hash stays empty (no compiled-policy hashing for
// tool policies). The response-surface gates (JSON/SSE stripping) are
// separate remaining TRACE work, asserted absent here only in the sense
// that this test pins the invoke path's contract.
func TestBuiltinToolInvoke_DenyPublishesDecisionRecord(t *testing.T) {
	p := denyTool("yabanin:web_fetch")
	p.ID = "tp-1"
	gw := gateWith(p)
	gw.toolExec = toolexec.NewExecutor(toolexec.NewDefaultConfig(), nil, nil)
	events := captureEvents(t)

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/mcp/invoke", nil)
	r.Header.Set("X-Org-Id", "org-1")
	w := httptest.NewRecorder()
	gw.builtinToolInvoke(w, r, "org-1", mcpagg.Identity{AgentID: "agent-1"},
		mcpagg.InvokeRequest{Server: "yabanin", Tool: "web_fetch",
			Params: json.RawMessage(`{"url":"https://x.test"}`)})
	if w.Code != http.StatusForbidden {
		t.Fatalf("invoke deny: got %d, want 403 (body %s)", w.Code, w.Body.String())
	}

	var denial *eventpub.Event
	for _, ev := range events() {
		if ev.EventType == "request.invalid" {
			denial = ev
		}
	}
	if denial == nil {
		t.Fatal("no tool-policy denial event published")
	}
	if denial.OrgID != "org-1" {
		t.Errorf("denial org = %q, want org-1", denial.OrgID)
	}
	decisions := parseDecisions(t, denial.Policy)
	if len(decisions) != 1 {
		t.Fatalf("decisions = %+v, want exactly one tool-policy record", decisions)
	}
	d := decisions[0]
	if d.PolicyID != "tp-1" || d.Name != "deny-yabanin:web_fetch" {
		t.Errorf("policy identity = %s/%s, want tp-1/deny-yabanin:web_fetch", d.PolicyID, d.Name)
	}
	if d.RuleNamespace != "tool-policy" || d.Hook != "tool_pre" {
		t.Errorf("namespace/hook = %s/%s, want tool-policy/tool_pre", d.RuleNamespace, d.Hook)
	}
	if d.Mode != "enforce" {
		t.Errorf("mode = %q, want enforce (tool policies are enforce-only today)", d.Mode)
	}
	if d.Verdict != "deny" || d.EffectiveAction != "deny" || d.AppliedAction != "deny" {
		t.Errorf("verdict/effective/applied = %s/%s/%s, want deny/deny/deny", d.Verdict, d.EffectiveAction, d.AppliedAction)
	}
	if d.Matched == nil || !*d.Matched {
		t.Errorf("matched = %+v, want true", d.Matched)
	}
	if d.TraceCompleteness != "absent" {
		t.Errorf("trace_completeness = %q, want absent", d.TraceCompleteness)
	}
	if d.Version != 0 || d.EffectiveHash != "" {
		t.Errorf("version/effective_hash = %d/%q, want 0/\"\" (unknown stays unknown)", d.Version, d.EffectiveHash)
	}
	if len(d.Steps) != 0 || len(d.Findings) != 0 {
		t.Errorf("steps/findings = %+v/%+v, want none (args findings are the guard's own surface)", d.Steps, d.Findings)
	}
}
