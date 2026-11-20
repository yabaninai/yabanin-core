package cli

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/toolexec"
)

// SSE-NAME-01 (packet case 4): successive name-bearing fragments may not
// retain a weaker first allowed name for the argument guard while the
// consumer executes a later name. The frozen reproducer below drives a
// first allowed name with NO argument rules (org-name01's shim_tool) and
// a later allowed EXECUTABLE name whose rules would deny the accumulated
// arguments (web_fetch). On the unfixed surface the release guard
// evaluates the arguments under the first name while the counting
// consumer — modeling the OpenAI client's last-name-wins reassembly —
// really fetches the forbidden URL. The fix rejects conflicting
// declarations fail-closed and sticky; both deny directions and the
// idempotent rename stay live.

// nameConsume uses the consumer's last-name-wins assembly contract.
func nameConsume(t *testing.T, stream string, exec *toolexec.Executor) []declCall {
	t.Helper()
	calls := declOrderedCalls(declAssemble(stream, declLastName))
	declDispatchWebFetch(t, calls, exec, "nameConsume")
	return calls
}

// nameDrive streams the frames through the org-name01 gate and returns
// the released bytes. Every frame must parse (see the DECL lesson).
func nameDrive(t *testing.T, frames []string) string {
	t.Helper()
	for _, f := range frames {
		var probe any
		if err := json.Unmarshal([]byte(f), &probe); err != nil {
			t.Fatalf("nameDrive: test bug: frame does not parse: %q: %v", f, err)
		}
	}
	w := httptest.NewRecorder()
	g := newSSEToolGateWriter(context.Background(), w, fuzzToolEngine(), "org-name01", "*", true)
	var b strings.Builder
	for _, f := range frames {
		b.WriteString("data: " + f + "\n\n")
	}
	b.WriteString("data: [DONE]\n\n")
	if _, err := g.Write([]byte(b.String())); err != nil {
		t.Fatalf("nameDrive: write: %v", err)
	}
	g.Flush()
	return w.Body.String()
}

// nameFrameN renders one SSE data frame for choice 0 carrying several
// tool-call fragments at once.
func nameFrameN(t *testing.T, calls []any, finish string) string {
	t.Helper()
	delta := map[string]any{}
	if len(calls) > 0 {
		delta["tool_calls"] = calls
	}
	choice := map[string]any{"index": 0, "delta": delta}
	if finish != "" {
		choice["finish_reason"] = finish
	}
	b, err := json.Marshal(map[string]any{"choices": []any{choice}})
	if err != nil {
		t.Fatalf("nameFrameN: %v", err)
	}
	return string(b)
}

// SSE-NAME-01a: the frozen reproducer. A first allowed name without
// argument rules must not permit the consumer's later executable name:
// on the unfixed surface the counting consumer fetches the forbidden URL.
func TestSSEName_ConflictingNameRefused(t *testing.T) {
	sink, srv := declSinkServer(t)
	exec := toolexec.NewExecutor(toolexec.NewDefaultConfig(), nil, nil)
	stream := nameDrive(t, []string{
		declFrame(t, map[string]any{"index": 0, "function": map[string]any{"name": "shim_tool"}}, ""),
		declFrame(t, map[string]any{"index": 0, "function": map[string]any{"arguments": `{"url":"` + srv.URL + `/leak-`}}, ""),
		declFrame(t, map[string]any{"index": 0, "function": map[string]any{"arguments": `forbidden-nameconflict"}`}}, ""),
		declFrame(t, map[string]any{"index": 0, "function": map[string]any{"name": "web_fetch"}}, ""),
		declFrame(t, nil, "tool_calls"),
	})
	if strings.Contains(stream, "forbidden") {
		t.Fatalf("SSE-NAME-01a: forbidden argument bytes released: %q", stream)
	}
	calls := nameConsume(t, stream, exec)
	for _, c := range calls {
		if c.named && strings.Contains(c.args, "forbidden") {
			t.Fatalf("SSE-NAME-01a: consumer assembled forbidden args under %q: %+v", c.name, c)
		}
	}
	if paths := declSinkPaths(sink); len(paths) != 0 {
		t.Fatalf("SSE-NAME-01a: sink hits = %d, want 0 (paths %v)", len(paths), paths)
	}
}

// SSE-NAME-01b (regression, deny direction): an allowed first name
// renamed to a DENIED tool still drops the whole held call (SSE-16 /
// SSEG-F5A pins preserved).
func TestSSEName_AllowedThenDeniedRenameDrops(t *testing.T) {
	sink, srv := declSinkServer(t)
	exec := toolexec.NewExecutor(toolexec.NewDefaultConfig(), nil, nil)
	stream := nameDrive(t, []string{
		declFrame(t, map[string]any{"index": 0, "function": map[string]any{"name": "web_fetch"}}, ""),
		declFrame(t, map[string]any{"index": 0, "function": map[string]any{"arguments": `{"url":"` + srv.URL + `/ok"}`}}, ""),
		declFrame(t, map[string]any{"index": 0, "function": map[string]any{"name": "secret_tool"}}, ""),
		declFrame(t, nil, "tool_calls"),
	})
	if strings.Contains(stream, "secret_tool") {
		t.Fatalf("SSE-NAME-01b: denied rename released: %q", stream)
	}
	if calls := nameConsume(t, stream, exec); len(calls) != 0 {
		t.Fatalf("SSE-NAME-01b: consumer assembled a refused call: %+v", calls)
	}
	if paths := declSinkPaths(sink); len(paths) != 0 {
		t.Fatalf("SSE-NAME-01b: sink hits = %d, want 0", len(paths))
	}
}

// SSE-NAME-01c (regression, deny-first direction): a denied first name
// stays denied; a later rename to an allowed name must not un-deny it.
func TestSSEName_DeniedFirstStaysDenied(t *testing.T) {
	sink, srv := declSinkServer(t)
	exec := toolexec.NewExecutor(toolexec.NewDefaultConfig(), nil, nil)
	stream := nameDrive(t, []string{
		declFrame(t, map[string]any{"index": 0, "function": map[string]any{"name": "secret_tool"}}, ""),
		declFrame(t, map[string]any{"index": 0, "function": map[string]any{"name": "web_fetch"}}, ""),
		declFrame(t, map[string]any{"index": 0, "function": map[string]any{"arguments": `{"url":"` + srv.URL + `/ok"}`}}, ""),
		declFrame(t, nil, "tool_calls"),
	})
	if strings.Contains(stream, "secret_tool") || strings.Contains(stream, "web_fetch") {
		t.Fatalf("SSE-NAME-01c: sticky-denied call released: %q", stream)
	}
	if calls := nameConsume(t, stream, exec); len(calls) != 0 {
		t.Fatalf("SSE-NAME-01c: consumer assembled a refused call: %+v", calls)
	}
	if paths := declSinkPaths(sink); len(paths) != 0 {
		t.Fatalf("SSE-NAME-01c: sink hits = %d, want 0", len(paths))
	}
}

// SSE-NAME-01d (regression, idempotent rename): repeating the SAME name
// is not a conflicting declaration — the allowed call still dispatches.
func TestSSEName_IdempotentRenameAllowed(t *testing.T) {
	sink, srv := declSinkServer(t)
	exec := toolexec.NewExecutor(toolexec.NewDefaultConfig(), nil, nil)
	stream := nameDrive(t, []string{
		declFrame(t, map[string]any{"index": 0, "function": map[string]any{"name": "web_fetch"}}, ""),
		declFrame(t, map[string]any{"index": 0, "function": map[string]any{"name": "web_fetch"}}, ""),
		declFrame(t, map[string]any{"index": 0, "function": map[string]any{"arguments": `{"url":"` + srv.URL + `/benign-repeat"}`}}, ""),
		declFrame(t, nil, "tool_calls"),
	})
	calls := nameConsume(t, stream, exec)
	if len(calls) != 1 || !calls[0].named || calls[0].name != "web_fetch" {
		t.Fatalf("SSE-NAME-01d: consumer assemblies = %+v, want one web_fetch", calls)
	}
	if paths := declSinkPaths(sink); len(paths) != 1 || paths[0] != "/benign-repeat" {
		t.Fatalf("SSE-NAME-01d: sink paths = %v, want [/benign-repeat]", paths)
	}
}

func assertNameSiblingCalls(t *testing.T, calls []declCall) {
	t.Helper()
	var dispatched []string
	for _, call := range calls {
		if call.named && strings.Contains(call.args, "forbidden") {
			t.Fatalf("SSE-NAME-01e: consumer assembled forbidden args under %q", call.name)
		}
		if call.named {
			dispatched = append(dispatched, call.name)
		}
	}
	if len(dispatched) != 1 || dispatched[0] != "web_fetch" {
		t.Fatalf("SSE-NAME-01e: dispatched = %v, want [web_fetch]", dispatched)
	}
}

// SSE-NAME-01e: the refusal is scoped per identity — a valid allowed
// sibling call in the same choice survives the conflicting sibling and
// still dispatches, and the tool loop's finish_reason stays tool_calls.
func TestSSEName_SiblingSurvivesScopedRefusal(t *testing.T) {
	sink, srv := declSinkServer(t)
	exec := toolexec.NewExecutor(toolexec.NewDefaultConfig(), nil, nil)
	stream := nameDrive(t, []string{
		nameFrameN(t, []any{
			map[string]any{"index": 0, "function": map[string]any{"name": "shim_tool"}},
			map[string]any{"index": 1, "function": map[string]any{"name": "web_fetch"}},
		}, ""),
		declFrame(t, map[string]any{"index": 0, "function": map[string]any{"arguments": `{"url":"` + srv.URL + `/leak-`}}, ""),
		declFrame(t, map[string]any{"index": 1, "function": map[string]any{"arguments": `{"url":"` + srv.URL + `/sibling-ok"}`}}, ""),
		declFrame(t, map[string]any{"index": 0, "function": map[string]any{"arguments": `forbidden-nameconflict"}`}}, ""),
		declFrame(t, map[string]any{"index": 0, "function": map[string]any{"name": "web_fetch"}}, ""),
		declFrame(t, nil, "tool_calls"),
	})
	if strings.Contains(stream, "forbidden") {
		t.Fatalf("SSE-NAME-01e: forbidden argument bytes released: %q", stream)
	}
	assertNameSiblingCalls(t, nameConsume(t, stream, exec))
	if paths := declSinkPaths(sink); len(paths) != 1 || paths[0] != "/sibling-ok" {
		t.Fatalf("SSE-NAME-01e: sink paths = %v, want [/sibling-ok]", paths)
	}
	if !strings.Contains(stream, `/sibling-ok`) {
		t.Fatalf("SSE-NAME-01e: sibling args absent from the released stream")
	}
	if !strings.Contains(stream, `"finish_reason":"tool_calls"`) {
		t.Fatalf("SSE-NAME-01e: sibling tool loop finish stranded: %q", stream)
	}
}
