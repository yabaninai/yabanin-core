package builtins

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// testEngine wires every builtin factory into a fresh engine.
func testEngine(t *testing.T) *pipeline.Engine {
	t.Helper()
	eng := pipeline.NewEngine()
	for name, f := range Registry() {
		if err := eng.Steps().Register(name, f); err != nil {
			t.Fatalf("register %s: %v", name, err)
		}
	}
	return eng
}

// runOne compiles a one-step enforce policy (step id "s1") for the named
// builtin and runs it against in.
func runOne(t *testing.T, name string, params map[string]any, in *pipeline.Payload, opts ...func(*pipeline.Policy)) *pipeline.Result {
	t.Helper()
	eng := testEngine(t)
	pol := pipeline.Policy{
		APIVersion: pipeline.APIVersionYPP,
		Kind:       pipeline.KindPolicy,
		Name:       "test-policy",
		Mode:       pipeline.ModeEnforce,
		Hooks:      []pipeline.Hook{pipeline.HookPreUpstream},
		Steps:      []pipeline.StepSpec{{ID: "s1", Detector: name, Params: params}},
	}
	for _, o := range opts {
		o(&pol)
	}
	c, err := eng.CompilePolicy(pol)
	if err != nil {
		t.Fatalf("compile %s: %v", name, err)
	}
	return eng.Run(context.Background(), []pipeline.Compiled{c}, in)
}

// mustCompileErr asserts the policy fails at LOAD time.
func mustCompileErr(t *testing.T, name string, params map[string]any) {
	t.Helper()
	eng := testEngine(t)
	pol := pipeline.Policy{
		APIVersion: pipeline.APIVersionYPP,
		Kind:       pipeline.KindPolicy,
		Name:       "test-policy",
		Mode:       pipeline.ModeEnforce,
		Hooks:      []pipeline.Hook{pipeline.HookPreUpstream},
		Steps:      []pipeline.StepSpec{{ID: "s1", Detector: name, Params: params}},
	}
	if _, err := eng.CompilePolicy(pol); err == nil {
		t.Fatalf("compile %s with params %v: want load error", name, params)
	}
}

// findingsOf returns findings of the given step ids (all findings when no
// id is passed).
func findingsOf(res *pipeline.Result, stepIDs ...string) []pipeline.Finding {
	want := map[string]bool{}
	for _, id := range stepIDs {
		want[id] = true
	}
	var out []pipeline.Finding
	for _, f := range res.Findings {
		if len(want) == 0 || want[f.Step] {
			out = append(out, f)
		}
	}
	return out
}

// assertRan asserts the single step ran without error.
func assertRan(t *testing.T, res *pipeline.Result) {
	t.Helper()
	if len(res.Trace) != 1 {
		t.Fatalf("trace = %+v, want exactly one entry", res.Trace)
	}
	tr := res.Trace[0]
	if tr.Outcome != pipeline.StepRan {
		t.Fatalf("outcome = %q error %q, want ran", tr.Outcome, tr.Error)
	}
}

// reqPayload builds a request payload carrying one user message.
func reqPayload(text string) *pipeline.Payload {
	return &pipeline.Payload{
		Kind:     pipeline.KindRequest,
		Endpoint: "chat",
		Messages: []pipeline.Message{{Role: "user", Content: text}},
		Meta:     &pipeline.RequestMeta{Org: "org-a", Key: "key-1", Model: "gpt-4o", Provider: "openai"},
	}
}

// respPayload builds a response payload carrying one assistant message.
func respPayload(text string) *pipeline.Payload {
	return &pipeline.Payload{
		Kind:     pipeline.KindResponse,
		Endpoint: "chat",
		Messages: []pipeline.Message{{Role: "assistant", Content: text}},
		Meta:     &pipeline.RequestMeta{Org: "org-a", Key: "key-1", Model: "gpt-4o", Provider: "openai"},
	}
}

func TestPayloadText_Precedence(t *testing.T) {
	p := &pipeline.Payload{
		Kind:        pipeline.KindRequest,
		Messages:    []pipeline.Message{{Role: "user", Content: "a"}, {Role: "assistant", Content: "b"}},
		Body:        []byte(`{"body":true}`),
		StreamChunk: "chunk",
	}
	if got := payloadText(p); got != "a\nb" {
		t.Errorf("payloadText = %q, want messages joined", got)
	}
	p.Messages = nil
	if got := payloadText(p); got != `{"body":true}` {
		t.Errorf("payloadText = %q, want body", got)
	}
	p.Body = nil
	if got := payloadText(p); got != "chunk" {
		t.Errorf("payloadText = %q, want stream chunk", got)
	}
	p.StreamChunk = ""
	if got := payloadText(p); got != "" {
		t.Errorf("payloadText = %q, want empty", got)
	}
}

func TestJSONText_BodyOverMessages(t *testing.T) {
	p := &pipeline.Payload{
		Kind:     pipeline.KindResponse,
		Messages: []pipeline.Message{{Role: "assistant", Content: `{"from":"message"}`}},
		Body:     []byte(`{"from":"body"}`),
	}
	if got := jsonText(p); got != `{"from":"body"}` {
		t.Errorf("jsonText = %q, want body", got)
	}
	p.Body = nil
	if got := jsonText(p); got != `{"from":"message"}` {
		t.Errorf("jsonText = %q, want message", got)
	}
}

func TestParseKinds_Validation(t *testing.T) {
	// Absent param defaults to ALL kinds (a step must not be silently inert).
	set, err := parseKinds(map[string]any{})
	if err != nil {
		t.Fatalf("parseKinds default: %v", err)
	}
	for _, k := range allKindsList() {
		if !set[k] {
			t.Errorf("default kinds missing %q", k)
		}
	}
	if _, err = parseKinds(map[string]any{"kinds": []any{"request", "bogus"}}); err == nil {
		t.Error("unknown kind: want error")
	}
	if _, err = parseKinds(map[string]any{"kinds": []any{}}); err == nil {
		t.Error("empty kinds list: want error")
	}
	set, err = parseKinds(map[string]any{"kinds": "response"})
	if err != nil || !set[pipeline.KindResponse] || len(set) != 1 {
		t.Errorf("single-string kinds = %v, %v", set, err)
	}
}

func TestParseAction_Validation(t *testing.T) {
	if a, err := parseAction(map[string]any{}); err != nil || a != pipeline.ActionFlag {
		t.Errorf("default action = %q, %v", a, err)
	}
	for _, bad := range []string{"allow", "DENY", "destroy", ""} {
		if _, err := parseAction(map[string]any{"action": bad}); err == nil {
			t.Errorf("action %q: want error", bad)
		}
	}
	for _, good := range []string{"flag", "mask", "deny"} {
		if _, err := parseAction(map[string]any{"action": good}); err != nil {
			t.Errorf("action %q: %v", good, err)
		}
	}
}

func TestClipEvidence(t *testing.T) {
	if got := clipEvidence("short", maxEvidence); got != "short" {
		t.Errorf("clipEvidence short = %q", got)
	}
	long := strings.Repeat("ё", 100) // multi-byte runes
	got := clipEvidence(long, maxEvidence)
	if len(got) >= maxEvidence+10 {
		t.Errorf("clipEvidence did not bound the excerpt (%d bytes)", len(got))
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("clipEvidence truncated excerpt = %q, want … suffix", got)
	}
	if !strings.HasPrefix(long, strings.TrimSuffix(got, "…")) {
		t.Errorf("clipEvidence prefix mismatch: %q", got)
	}
}

func TestParamHelpers(t *testing.T) {
	params := map[string]any{"s": "x", "list": []any{"a", "b"}, "n": 3, "f": 2.5, "b": true, "bs": "off"}
	if v, err := paramInt(params, "n", 0); err != nil || v != 3 {
		t.Errorf("paramInt int = %d, %v", v, err)
	}
	if v, err := paramInt(params, "missing", 7); err != nil || v != 7 {
		t.Errorf("paramInt default = %d, %v", v, err)
	}
	if _, err := paramInt(params, "f", 0); err == nil {
		t.Error("paramInt float fraction: want error")
	}
	if v, err := paramBool(params, "bs", true); err != nil || v != false {
		t.Errorf("paramBool string = %v, %v", v, err)
	}
	if v, err := paramBool(params, "missing", true); err != nil || !v {
		t.Errorf("paramBool default = %v, %v", v, err)
	}
	if v, err := paramStrings(params, "list"); err != nil || fmt.Sprint(v) != "[a b]" {
		t.Errorf("paramStrings = %v, %v", v, err)
	}
	if _, err := paramStrings(params, "missing"); err == nil {
		t.Error("paramStrings missing: want error")
	}
	if _, err := paramStrings(map[string]any{"list": []any{"a", ""}}, "list"); err == nil {
		t.Error("paramStrings empty entry: want error")
	}
}
