package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/reireirei/yabanin/pkg/toolexec"
)

// SSE-DECL-01: nameless calls and object-valued argument forms must be
// normalized exactly as the consumer receives them or refused fail-closed.
// The guard must not inspect "{}" while the consumer receives an object.
//
// The counting consumer below is what an OpenAI chat client does with the
// released stream: it reassembles tool_calls by call index and dispatches
// every named assembly through the real builtin executor (unguarded — the
// client trusts what the response surface handed it). Zero forbidden
// dispatch is therefore asserted behaviorally, not just recorder
// visibility. All frames are rendered programmatically: a hand-written
// literal that fails to parse would silently exercise the malformed-frame
// path instead of the declaration path under test.

type declSink struct {
	mu    sync.Mutex
	paths []string
}

func declSinkServer(t *testing.T) (*declSink, *httptest.Server) {
	t.Helper()
	s := &declSink{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.paths = append(s.paths, r.URL.Path)
		s.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	return s, srv
}

// declCall is one consumer-side assembled tool call.
type declCall struct {
	idx        int
	name       string
	named      bool
	objectForm bool
	args       string
}

type declToolFragment struct {
	Index    *int `json:"index"`
	Function struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"function"`
}

type declChoice struct {
	Delta struct {
		ToolCalls []declToolFragment `json:"tool_calls"`
	} `json:"delta"`
}

type declDocument struct {
	Choices []declChoice `json:"choices"`
}

type declNameMerge func(call *declCall, name string)

func declFirstName(call *declCall, name string) {
	if name != "" && !call.named {
		call.name = name
		call.named = true
	}
}

func declLastName(call *declCall, name string) {
	if name != "" {
		call.name = name
		call.named = true
	}
}

func declApplyFragment(calls map[int]*declCall, fragment declToolFragment, merge declNameMerge) {
	idx := 0
	if fragment.Index != nil {
		idx = *fragment.Index
	}
	call := calls[idx]
	if call == nil {
		call = &declCall{idx: idx}
		calls[idx] = call
	}
	merge(call, fragment.Function.Name)
	raw := fragment.Function.Arguments
	if len(raw) == 0 || string(raw) == "null" {
		return
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		call.args += text
		return
	}
	call.objectForm = true
	call.args = string(raw)
}

func declApplyDocument(calls map[int]*declCall, doc declDocument, merge declNameMerge) {
	for _, choice := range doc.Choices {
		for _, fragment := range choice.Delta.ToolCalls {
			declApplyFragment(calls, fragment, merge)
		}
	}
}

func declAssemble(stream string, merge declNameMerge) map[int]*declCall {
	calls := map[int]*declCall{}
	for _, line := range strings.Split(stream, "\n") {
		data, ok := strings.CutPrefix(line, "data: ")
		if !ok || data == "" || data == "[DONE]" {
			continue
		}
		var doc declDocument
		if err := json.Unmarshal([]byte(data), &doc); err != nil {
			continue // Malformed lines are not consumer calls.
		}
		declApplyDocument(calls, doc, merge)
	}
	return calls
}

func declOrderedCalls(calls map[int]*declCall) []declCall {
	indexes := make([]int, 0, len(calls))
	for idx := range calls {
		indexes = append(indexes, idx)
	}
	sort.Ints(indexes)
	out := make([]declCall, 0, len(indexes))
	for _, idx := range indexes {
		out = append(out, *calls[idx])
	}
	return out
}

func declExecute(t *testing.T, exec *toolexec.Executor, call declCall, tool, label string) bool {
	t.Helper()
	if _, err := exec.Execute(context.Background(), tool, json.RawMessage(call.args)); err != nil {
		t.Logf("%s: dispatch %s: %v", label, call.name, err)
		return false
	}
	return true
}

func declDispatchWebFetch(t *testing.T, calls []declCall, exec *toolexec.Executor, label string) {
	t.Helper()
	for _, call := range calls {
		if !call.named {
			continue
		}
		declExecute(t, exec, call, toolexec.ToolWebFetch, label)
	}
}

func declDispatchNamed(t *testing.T, calls []declCall, exec *toolexec.Executor, label string) int {
	t.Helper()
	ok := 0
	for _, call := range calls {
		if !call.named {
			continue
		}
		if declExecute(t, exec, call, call.name, label) {
			ok++
		}
	}
	return ok
}

// declConsume keeps the first declared name, as this consumer contract requires.
func declConsume(t *testing.T, stream string, exec *toolexec.Executor) []declCall {
	t.Helper()
	calls := declOrderedCalls(declAssemble(stream, declFirstName))
	declDispatchWebFetch(t, calls, exec, "declConsume")
	return calls
}

// declFrame renders one SSE data frame for choice 0 carrying an optional
// tool-call fragment (a map with name and/or arguments keys) and an
// optional finish_reason. Every rendered frame must parse.
func declFrame(t *testing.T, call map[string]any, finish string) string {
	t.Helper()
	delta := map[string]any{}
	if call != nil {
		delta["tool_calls"] = []any{call}
	}
	choice := map[string]any{"index": 0, "delta": delta}
	if finish != "" {
		choice["finish_reason"] = finish
	}
	b, err := json.Marshal(map[string]any{"choices": []any{choice}})
	if err != nil {
		t.Fatalf("declFrame: %v", err)
	}
	return string(b)
}

// declMessageResp renders one non-streaming response for choice 0 whose
// message carries the given tool_calls.
func declMessageResp(t *testing.T, calls []any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"choices": []any{map[string]any{
		"index": 0, "finish_reason": "tool_calls",
		"message": map[string]any{"tool_calls": calls},
	}}})
	if err != nil {
		t.Fatalf("declMessageResp: %v", err)
	}
	return string(b)
}

func declDrive(t *testing.T, frames []string) string {
	t.Helper()
	for _, f := range frames {
		var probe any
		if err := json.Unmarshal([]byte(f), &probe); err != nil {
			t.Fatalf("declDrive: test bug: frame does not parse: %q: %v", f, err)
		}
	}
	w := httptest.NewRecorder()
	g := newSSEToolGateWriter(context.Background(), w, fuzzToolEngine(), "org-fetch", "*", true)
	var b strings.Builder
	for _, f := range frames {
		b.WriteString("data: " + f + "\n\n")
	}
	b.WriteString("data: [DONE]\n\n")
	if _, err := g.Write([]byte(b.String())); err != nil {
		t.Fatalf("declDrive: write: %v", err)
	}
	g.Flush()
	return w.Body.String()
}

func declSinkPaths(s *declSink) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.paths...)
}

// SSE-DECL-01a: object-valued arguments on a held call must be refused
// fail-closed. On the unfixed surface the gate would inspect "{}" while the
// consumer receives the object, and a forbidden URL in object form becomes
// a real client-side dispatch.
func TestSSEDecl_ObjectFormArgsRefused(t *testing.T) {
	sink, srv := declSinkServer(t)
	exec := toolexec.NewExecutor(toolexec.NewDefaultConfig(), nil, nil)
	out := declDrive(t, []string{
		declFrame(t, map[string]any{"index": 0, "function": map[string]any{"name": "web_fetch"}}, ""),
		declFrame(t, map[string]any{"index": 0, "function": map[string]any{
			"arguments": map[string]any{"url": srv.URL + "/leak-forbidden-object"}}}, ""),
		declFrame(t, nil, "tool_calls"),
	})
	assembled := declConsume(t, out, exec)
	for _, c := range assembled {
		if c.named && c.objectForm {
			t.Fatalf("DECL-01a: consumer received an object-form call: %+v", c)
		}
	}
	if strings.Contains(out, "forbidden") {
		t.Fatalf("DECL-01a: object-form args bytes leaked: %s", out)
	}
	if paths := declSinkPaths(sink); len(paths) != 0 {
		t.Fatalf("DECL-01a: forbidden dispatch observed: %v", paths)
	}
}

// SSE-DECL-01b: a nameless call carrying argument content is an ambiguous
// executable declaration and must not reach the consumer unguarded.
func TestSSEDecl_NamelessContentRefused(t *testing.T) {
	sink, srv := declSinkServer(t)
	exec := toolexec.NewExecutor(toolexec.NewDefaultConfig(), nil, nil)
	chunk1 := `{"url":"` + srv.URL + `/leak-`
	chunk2 := `forbidden-nameless"}`
	out := declDrive(t, []string{
		declFrame(t, map[string]any{"index": 0, "function": map[string]any{"arguments": chunk1}}, ""),
		declFrame(t, map[string]any{"index": 0, "function": map[string]any{"arguments": chunk2}}, ""),
		declFrame(t, nil, "tool_calls"),
	})
	assembled := declConsume(t, out, exec)
	for _, c := range assembled {
		if strings.Contains(c.args, "forbidden") {
			t.Fatalf("DECL-01b: nameless args reached the consumer: %+v", c)
		}
	}
	if strings.Contains(out, "forbidden") {
		t.Fatalf("DECL-01b: nameless args bytes leaked: %s", out)
	}
	if paths := declSinkPaths(sink); len(paths) != 0 {
		t.Fatalf("DECL-01b: unexpected dispatch: %v", paths)
	}
}

// SSE-DECL-01c (control): an allowed call with benign string arguments
// passes the gate and the consumer dispatches exactly once — proving the
// counting consumer executes, so the refusal legs are not permissive
// probes.
func TestSSEDecl_AllowedCallDispatches(t *testing.T) {
	sink, srv := declSinkServer(t)
	exec := toolexec.NewExecutor(toolexec.NewDefaultConfig(), nil, nil)
	out := declDrive(t, []string{
		declFrame(t, map[string]any{"index": 0, "function": map[string]any{"name": "web_fetch"}}, ""),
		declFrame(t, map[string]any{"index": 0, "function": map[string]any{
			"arguments": `{"url":"` + srv.URL + `/benign-page"}`}}, ""),
		declFrame(t, nil, "tool_calls"),
	})
	assembled := declConsume(t, out, exec)
	named := 0
	for _, c := range assembled {
		if c.named && c.name == "web_fetch" && strings.Contains(c.args, "/benign-page") {
			named++
		}
	}
	if named != 1 {
		t.Fatalf("DECL-01c: consumer must assemble the allowed call once, got %d (%+v)", named, assembled)
	}
	paths := declSinkPaths(sink)
	if len(paths) != 1 || paths[0] != "/benign-page" {
		t.Fatalf("DECL-01c: consumer must dispatch exactly once, got %v", paths)
	}
	if !strings.Contains(out, "/benign-page") {
		t.Fatalf("DECL-01c: allowed call must remain in the stream: %s", out)
	}
}

// JSON-surface DECL-01d: a nameless call carrying argument content is
// refused (dropped, finish normalized); the refusal is a form refusal, not
// a policy verdict, so `denied` stays empty.
func TestGateToolCallsJSON_NamelessContentRefused(t *testing.T) {
	gw := &gateway{log: fuzzDiscardLogger(), toolPolicies: fuzzToolEngine()}
	resp := declMessageResp(t, []any{map[string]any{
		"function": map[string]any{"arguments": `{"url":"http://example.test/forbidden-page"}`}}})
	out, denied := gw.gateToolCallsJSON(context.Background(), "org-fetch", "*", []byte(resp))
	if strings.Contains(string(out), "forbidden") {
		t.Fatalf("DECL-01d: nameless args leaked: %s", out)
	}
	if len(denied) != 0 {
		t.Fatalf("DECL-01d: form refusal is not a policy denial: %v", denied)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("DECL-01d: out not JSON: %v", err)
	}
	choice, _ := doc["choices"].([]any)[0].(map[string]any)
	msg, _ := choice["message"].(map[string]any)
	if _, still := msg["tool_calls"]; still {
		t.Fatalf("DECL-01d: nameless content call must be refused: %s", out)
	}
	if fr := choice["finish_reason"]; fr != "stop" {
		t.Fatalf("DECL-01d: finish must normalize to stop, got %v", fr)
	}
}

// JSON-surface DECL-01e: non-object argument forms (arrays here) are
// normalized to what the consumer receives before the args guard runs, so
// deny_regex sees the array text instead of "{}".
func TestGateToolCallsJSON_ArrayFormArgsGuarded(t *testing.T) {
	gw := &gateway{log: fuzzDiscardLogger(), toolPolicies: fuzzToolEngine()}
	resp := declMessageResp(t, []any{map[string]any{
		"function": map[string]any{"name": "web_fetch",
			"arguments": []any{"http://example.test/forbidden-array"}}}})
	out, denied := gw.gateToolCallsJSON(context.Background(), "org-fetch", "*", []byte(resp))
	if len(denied) != 1 || denied[0] != "web_fetch" {
		t.Fatalf("DECL-01e: array-form args must be args-denied, got %v", denied)
	}
	if strings.Contains(string(out), "forbidden") {
		t.Fatalf("DECL-01e: array-form args leaked: %s", out)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("DECL-01e: out not JSON: %v", err)
	}
	choice, _ := doc["choices"].([]any)[0].(map[string]any)
	if fr := choice["finish_reason"]; fr != "stop" {
		t.Fatalf("DECL-01e: finish must normalize to stop, got %v", fr)
	}
}
