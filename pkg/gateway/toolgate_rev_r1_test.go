package cli

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/toolexec"
	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

// SSE-REV-01 (packet case 5): a stream opened before a deny is installed
// must not pass a newly denied tool declaration after the revocation
// bound. The stream stage resolves HasDenyPolicies once at open: an org
// without deny rows at open ran the whole in-flight response unfiltered,
// so a deny installed mid-stream never gated it. The fix refreshes
// applicability on live tool-bearing output — the first tool-bearing
// frame of an inactive gate re-consults the engine (whose org cache the
// admin edit invalidates) and activates one-way.
//
// The revocation bound is modeled exactly as the admin path performs it:
// the row becomes visible in the loader AND the engine's org cache is
// invalidated. The engine TTL is one minute, so no natural expiry can
// explain the fixed behavior. The legs drive a genuinely in-flight
// response — writes span the bound with real delay — and assert through
// the counting consumer (consumer-readable SSE framing), never by
// regexing the source.

// revLoader is a mutable policy loader: rows change after the stream
// opens, modeling the admin CRUD bound.
type revLoader struct {
	mu   sync.Mutex
	rows []toolpolicy.Policy
}

func (l *revLoader) ListEnabled(_ context.Context, _ string) ([]toolpolicy.Policy, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]toolpolicy.Policy(nil), l.rows...), nil
}

// revoke installs the admin bound: the deny row plus cache invalidation.
func (l *revLoader) revoke(engine *toolpolicy.Engine, org string, p toolpolicy.Policy) {
	l.mu.Lock()
	l.rows = append(l.rows, p)
	l.mu.Unlock()
	engine.Invalidate(org)
}

// newRevEngine starts the org WITHOUT deny rows: the gate opens inactive.
// web_fetch is allowed with the forbidden-argument guard; time_now is
// allowed plainly and stays allowed after the bound (the sibling).
func newRevEngine(t *testing.T) (*toolpolicy.Engine, *revLoader) {
	t.Helper()
	l := &revLoader{rows: []toolpolicy.Policy{
		{ID: "r1", OrgID: "org-rev", Name: "fetch-args", Subject: "*", Server: "*",
			Tool: toolexec.ToolWebFetch, Action: toolpolicy.ActionAllow, Enabled: true,
			Rules: json.RawMessage(`{"args":{"deny_regex":["forbidden"]}}`)},
		{ID: "r2", OrgID: "org-rev", Name: "time-allow", Subject: "*", Server: "*",
			Tool: toolexec.ToolTimeNow, Action: toolpolicy.ActionAllow, Enabled: true},
	}}
	return toolpolicy.NewEngine(l, time.Minute), l
}

func revDenyWebFetch() toolpolicy.Policy {
	// Priority -1 makes the revocation dominate the base allow row (same
	// tool specificity, both subject '*'): the lowest priority number
	// wins, so the deny cannot lose the tie to name order.
	return toolpolicy.Policy{ID: "r9", OrgID: "org-rev", Name: "revoke-fetch", Subject: "*", Server: "*",
		Tool: toolexec.ToolWebFetch, Action: toolpolicy.ActionDeny, Enabled: true, Priority: -1}
}

// revWriter models stream.go's construction: the open-time
// HasDenyPolicies snapshot decides the gate's initial state.
func revWriter(t *testing.T, e *toolpolicy.Engine) (*sseToolGateWriter, *httptest.ResponseRecorder) {
	t.Helper()
	w := httptest.NewRecorder()
	g := newSSEToolGateWriter(context.Background(), w, e, "org-rev", "alice",
		e.HasDenyPolicies(context.Background(), "org-rev"))
	return g, w
}

// revWrite streams frames through the in-flight gate. Every frame must
// parse (see the DECL lesson).
func revWrite(t *testing.T, g *sseToolGateWriter, frames ...string) {
	t.Helper()
	for _, f := range frames {
		var probe any
		if err := json.Unmarshal([]byte(f), &probe); err != nil {
			t.Fatalf("revWrite: test bug: frame does not parse: %q: %v", f, err)
		}
		if _, err := g.Write([]byte("data: " + f + "\n\n")); err != nil {
			t.Fatalf("revWrite: write: %v", err)
		}
	}
}

func revDone(t *testing.T, g *sseToolGateWriter) {
	t.Helper()
	if _, err := g.Write([]byte("data: [DONE]\n\n")); err != nil {
		t.Fatalf("revDone: write: %v", err)
	}
	g.Flush()
}

// revConsume dispatches each last-name-wins assembly by its declared name.
func revConsume(t *testing.T, stream string, exec *toolexec.Executor) (calls []declCall, ok int) {
	t.Helper()
	calls = declOrderedCalls(declAssemble(stream, declLastName))
	ok = declDispatchNamed(t, calls, exec, "revConsume")
	return calls, ok
}

// SSE-REV-01a: the pure post-bound declaration — the stream opens before
// the deny exists, the whole tool declaration arrives after the bound.
// On the unfixed surface the open-time snapshot runs the response
// unfiltered and the counting consumer fetches the revoked tool's URL.
func TestSSERev_PostBoundDeclarationRefused(t *testing.T) {
	e, l := newRevEngine(t)
	g, w := revWriter(t, e)
	sink, srv := declSinkServer(t)
	exec := toolexec.NewExecutor(toolexec.NewDefaultConfig(), nil, nil)
	revWrite(t, g, declFrame(t, nil, "")) // content-only frame, pre-bound
	l.revoke(e, "org-rev", revDenyWebFetch())
	time.Sleep(20 * time.Millisecond) // the response is genuinely in flight
	revWrite(t, g,
		declFrame(t, map[string]any{"index": 0, "function": map[string]any{"name": toolexec.ToolWebFetch}}, ""),
		declFrame(t, map[string]any{"index": 0, "function": map[string]any{"arguments": `{"url":"` + srv.URL + `/revoked-leak"}`}}, ""),
		declFrame(t, nil, "tool_calls"),
	)
	revDone(t, g)
	stream := w.Body.String()
	if strings.Contains(stream, "web_fetch") {
		t.Fatalf("SSE-REV-01a: revoked tool released: %q", stream)
	}
	calls, ok := revConsume(t, stream, exec)
	if len(calls) != 0 || ok != 0 {
		t.Fatalf("SSE-REV-01a: consumer assembled/dispatched a revoked call: %+v ok=%d", calls, ok)
	}
	if paths := declSinkPaths(sink); len(paths) != 0 {
		t.Fatalf("SSE-REV-01a: sink hits = %v, want none", paths)
	}
}

// SSE-REV-01b: the name fragment was already flushed before the bound
// (nothing can recall flushed SSE bytes); the argument fragments arrive
// after it. Activation on the live tool-bearing output holds and drops
// them fail-closed — the consumer is left a name without arguments and
// cannot dispatch. On the unfixed surface the arguments flow too and the
// revoked tool executes.
func TestSSERev_PreBoundNamePostBoundArgsRefused(t *testing.T) {
	e, l := newRevEngine(t)
	g, w := revWriter(t, e)
	sink, srv := declSinkServer(t)
	exec := toolexec.NewExecutor(toolexec.NewDefaultConfig(), nil, nil)
	revWrite(t, g,
		declFrame(t, nil, ""),
		declFrame(t, map[string]any{"index": 0, "function": map[string]any{"name": toolexec.ToolWebFetch}}, ""),
	)
	l.revoke(e, "org-rev", revDenyWebFetch())
	time.Sleep(20 * time.Millisecond)
	revWrite(t, g,
		declFrame(t, map[string]any{"index": 0, "function": map[string]any{"arguments": `{"url":"` + srv.URL + `/revoked-`}}, ""),
		declFrame(t, map[string]any{"index": 0, "function": map[string]any{"arguments": `forbidden-args"}`}}, ""),
		declFrame(t, nil, "tool_calls"),
	)
	revDone(t, g)
	stream := w.Body.String()
	if strings.Contains(stream, "forbidden") {
		t.Fatalf("SSE-REV-01b: revoked tool's arguments released: %q", stream)
	}
	calls, ok := revConsume(t, stream, exec)
	if ok != 0 {
		t.Fatalf("SSE-REV-01b: a revoked tool dispatched: ok=%d calls=%+v", ok, calls)
	}
	if paths := declSinkPaths(sink); len(paths) != 0 {
		t.Fatalf("SSE-REV-01b: sink hits = %v, want none", paths)
	}
}

// SSE-REV-01c: the delayed in-flight response with a valid allowed
// sibling — the refusal is scoped to the revoked tool. time_now stays
// allowed across the bound, assembles, dispatches successfully, and
// keeps the choice's tool loop finish_reason tool_calls.
func TestSSERev_SiblingSurvivesRevocation(t *testing.T) {
	e, l := newRevEngine(t)
	g, w := revWriter(t, e)
	sink, srv := declSinkServer(t)
	exec := toolexec.NewExecutor(toolexec.NewDefaultConfig(), nil, nil)
	revWrite(t, g, declFrame(t, nil, ""))
	l.revoke(e, "org-rev", revDenyWebFetch())
	time.Sleep(20 * time.Millisecond)
	revWrite(t, g,
		nameFrameN(t, []any{
			map[string]any{"index": 0, "function": map[string]any{"name": toolexec.ToolWebFetch}},
			map[string]any{"index": 1, "function": map[string]any{"name": toolexec.ToolTimeNow}},
		}, ""),
		declFrame(t, map[string]any{"index": 0, "function": map[string]any{"arguments": `{"url":"` + srv.URL + `/revoked-sibling-leak"}`}}, ""),
		declFrame(t, map[string]any{"index": 1, "function": map[string]any{"arguments": `{}`}}, ""),
		declFrame(t, nil, "tool_calls"),
	)
	revDone(t, g)
	stream := w.Body.String()
	if strings.Contains(stream, "web_fetch") {
		t.Fatalf("SSE-REV-01c: revoked tool released: %q", stream)
	}
	if !strings.Contains(stream, "time_now") {
		t.Fatalf("SSE-REV-01c: allowed sibling absent: %q", stream)
	}
	calls, ok := revConsume(t, stream, exec)
	if len(calls) != 1 || calls[0].name != toolexec.ToolTimeNow {
		t.Fatalf("SSE-REV-01c: assemblies = %+v, want one time_now", calls)
	}
	if ok != 1 {
		t.Fatalf("SSE-REV-01c: successful dispatches = %d, want 1", ok)
	}
	if paths := declSinkPaths(sink); len(paths) != 0 {
		t.Fatalf("SSE-REV-01c: sink hits = %v, want none", paths)
	}
	if !strings.Contains(stream, `"finish_reason":"tool_calls"`) {
		t.Fatalf("SSE-REV-01c: sibling tool loop finish stranded: %q", stream)
	}
}

// SSE-REV-01d (control): no bound ever lands — the org never gains deny
// rows, the gate stays inactive, and both tools dispatch. Activation must
// not over-refuse streams whose org simply has no denies.
func TestSSERev_NoBoundNoRefusal(t *testing.T) {
	e, _ := newRevEngine(t)
	g, w := revWriter(t, e)
	sink, srv := declSinkServer(t)
	exec := toolexec.NewExecutor(toolexec.NewDefaultConfig(), nil, nil)
	revWrite(t, g,
		declFrame(t, nil, ""),
		nameFrameN(t, []any{
			map[string]any{"index": 0, "function": map[string]any{"name": toolexec.ToolWebFetch}},
			map[string]any{"index": 1, "function": map[string]any{"name": toolexec.ToolTimeNow}},
		}, ""),
		declFrame(t, map[string]any{"index": 0, "function": map[string]any{"arguments": `{"url":"` + srv.URL + `/benign-no-bound"}`}}, ""),
		declFrame(t, map[string]any{"index": 1, "function": map[string]any{"arguments": `{}`}}, ""),
		declFrame(t, nil, "tool_calls"),
	)
	revDone(t, g)
	stream := w.Body.String()
	calls, ok := revConsume(t, stream, exec)
	if ok != 2 {
		t.Fatalf("SSE-REV-01d: successful dispatches = %d, want 2 (calls %+v)", ok, calls)
	}
	if paths := declSinkPaths(sink); len(paths) != 1 || paths[0] != "/benign-no-bound" {
		t.Fatalf("SSE-REV-01d: sink paths = %v, want [/benign-no-bound]", paths)
	}
}
