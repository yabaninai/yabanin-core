package cli

// SSE-IDX-01 R2 (Astra review sha 4842bf56..., REQUEST_CHANGES): identity
// ambiguity must not borrow a sibling permit. A frame that omits
// choice.index after the stream has carried explicit indexes, a
// fractional choice.index, or two occurrences resolving to the same
// choice index within one frame cannot identify WHICH call a fragment
// belongs to - such fragments must never accumulate under, nor be
// released through, a sibling's allowed verdict: they fail closed, while
// consistently unindexed (positional) streams keep their legacy behavior
// and valid sparse/reordered indexed streams keep theirs. Frozen legs:
//
//	SSE-IDX-01R2a  denied wire-1 continuation omitting choice.index at
//	               stable position 0 - borrows allowed (0,0) and leaks
//	SSE-IDX-01R2b  fractional index 0.5 - int() truncation borrows (0,0)
//	SSE-IDX-01R2c  duplicate index 0 twice in one frame - shared key
//	               merges the denied continuation into the allowed call
//	SSE-IDX-01R2d  argument-dependent verdict (org-args deny_regex): the
//	               borrowed key MERGES arguments, so the forbidden chunk
//	               suppresses the allowed wire-0 call - accumulation, not
//	               output filtering
//	SSE-IDX-01R2e  consistently unindexed dense stream (control): legacy
//	               positional gating still holds (passes before and after)
//
// Under position-fallback identity the leak legs fail with denied bytes
// (a, b, c) or a suppressed allowed call (d) on the wire.

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
)

// r2Drive runs one stream through the real writer under the named org
// and returns the decoded fragments, the finish map (wire index ->
// finish_reason) and the raw output.
func r2Drive(t *testing.T, name, org, stream string) (frags []idxFragment, fin map[int]string, out string) {
	t.Helper()
	engine := fuzzToolEngine()
	w := httptest.NewRecorder()
	g := newSSEToolGateWriter(context.Background(), w, engine, org, "*", true)
	if _, err := g.Write([]byte(stream)); err != nil {
		t.Fatalf("%s: write: %v", name, err)
	}
	g.Flush() // force final release of anything still held
	out = w.Body.String()
	return idxDecode(t, out), finishByChoice(t, out), out
}

func r2SafeScan(fragments []idxFragment) (safeName, safeArgs bool, leaked []idxFragment) {
	for _, fragment := range fragments {
		if strings.Contains(fragment.name, "secret") || strings.Contains(fragment.args, "secret") {
			leaked = append(leaked, fragment)
			continue
		}
		if fragment.choice == 0 && fragment.name == "safe_tool" {
			safeName = true
		}
		if fragment.choice == 0 && strings.Contains(fragment.args, "safe-payload") {
			safeArgs = true
		}
	}
	return safeName, safeArgs, leaked
}

func r2UnindexedContinuation(t *testing.T) {
	frags, fin, out := r2Drive(t, "SSE-IDX-01R2a", "org-deny", strings.Join([]string{
		`data: {"choices":[{"index":1,"delta":{"tool_calls":[{"index":0,"function":{"name":"secret_tool","arguments":""}}]}}]}`,
		`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":"safe_tool","arguments":"safe-payload"}}]}}]}`,
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"secret-payload"}}]}}]}`,
		`data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"},{"index":1,"delta":{},"finish_reason":"tool_calls"}]}`,
		`data: [DONE]`,
		"",
	}, "\n\n"))
	safeName, safeArgs, leaked := r2SafeScan(frags)
	if len(leaked) != 0 {
		t.Fatalf("SSE-IDX-01R2a: ambiguous continuation borrowed the allowed verdict and leaked: %+v (out %q)", leaked[0], out)
	}
	if !safeName || !safeArgs {
		t.Fatalf("SSE-IDX-01R2a: allowed wire-0 call must survive complete on wire 0 (name=%v args=%v), out %q", safeName, safeArgs, out)
	}
	if fin[1] != "stop" || fin[0] != "tool_calls" {
		t.Fatalf("SSE-IDX-01R2a: finishes must pin to their wire indices (wire1=%q wire0=%q), out %q", fin[1], fin[0], out)
	}
}

func r2FractionalIdentity(t *testing.T) {
	frags, fin, out := r2Drive(t, "SSE-IDX-01R2b", "org-deny", strings.Join([]string{
		`data: {"choices":[{"index":1,"delta":{"tool_calls":[{"index":0,"function":{"name":"secret_tool","arguments":""}}]}}]}`,
		`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":"safe_tool","arguments":"safe-payload"}}]}}]}`,
		`data: {"choices":[{"index":0.5,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"secret-payload"}}]}}]}`,
		`data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"},{"index":1,"delta":{},"finish_reason":"tool_calls"}]}`,
		`data: [DONE]`,
		"",
	}, "\n\n"))
	safeName, safeArgs, leaked := r2SafeScan(frags)
	if len(leaked) != 0 {
		t.Fatalf("SSE-IDX-01R2b: fractional identity borrowed the allowed verdict and leaked: %+v (out %q)", leaked[0], out)
	}
	if !safeName || !safeArgs || fin[1] != "stop" || fin[0] != "tool_calls" {
		t.Fatalf("SSE-IDX-01R2b: allowed wire-0 call must survive with pinned finishes (name=%v args=%v wire1=%q wire0=%q), out %q", safeName, safeArgs, fin[1], fin[0], out)
	}
}

func r2DuplicateIdentity(t *testing.T) {
	frags, _, out := r2Drive(t, "SSE-IDX-01R2c", "org-deny", strings.Join([]string{
		`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":"safe_tool","arguments":"safe-payload"}}]}},{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"secret-payload"}}]}}]}`,
		`data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
		`data: [DONE]`,
		"",
	}, "\n\n"))
	for _, fragment := range frags {
		if strings.Contains(fragment.name, "secret") || strings.Contains(fragment.args, "secret") {
			t.Fatalf("SSE-IDX-01R2c: duplicate identity merged into the allowed verdict and leaked: %+v (out %q)", fragment, out)
		}
	}
	if len(frags) != 0 {
		t.Fatalf("SSE-IDX-01R2c: a frame with duplicate choice identity is ambiguous - both occurrences fail closed, got %+v (out %q)", frags, out)
	}
	if !strings.Contains(out, "data: [DONE]") {
		t.Fatalf("SSE-IDX-01R2c: [DONE] must survive, out %q", out)
	}
}

func r2BorrowedAccumulation(t *testing.T) {
	frags, fin, out := r2Drive(t, "SSE-IDX-01R2d", "org-args", strings.Join([]string{
		`data: {"choices":[{"index":1,"delta":{"tool_calls":[{"index":0,"function":{"name":"safe_tool","arguments":""}}]}}]}`,
		`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":"safe_tool","arguments":"{\"x\":123ok456}"}}]}}]}`,
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"y\":123forbidden456}"}}]}}]}`,
		`data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"},{"index":1,"delta":{},"finish_reason":"tool_calls"}]}`,
		`data: [DONE]`,
		"",
	}, "\n\n"))
	var okArgs bool
	for _, fragment := range frags {
		if strings.Contains(fragment.args, "forbidden") {
			t.Fatalf("SSE-IDX-01R2d: ambiguous continuation must not be released: %+v (out %q)", fragment, out)
		}
		if fragment.choice == 0 && fragment.args == `{"x":123ok456}` {
			okArgs = true
		}
	}
	if !okArgs {
		t.Fatalf("SSE-IDX-01R2d: allowed wire-0 call must keep its OWN accumulated arguments, out %q", out)
	}
	if fin[0] != "tool_calls" || fin[1] != "tool_calls" {
		t.Fatalf("SSE-IDX-01R2d: both surviving choices finish tool_calls (wire0=%q wire1=%q), out %q", fin[0], fin[1], out)
	}
}

func r2PositionalCompatibility(t *testing.T) {
	frags, _, out := r2Drive(t, "SSE-IDX-01R2e", "org-deny", strings.Join([]string{
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"name":"safe_tool","arguments":""}}]}},{"delta":{"tool_calls":[{"index":0,"function":{"name":"secret_tool","arguments":""}}]}}]}`,
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"safe-payload"}}]}},{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"secret-payload"}}]}}]}`,
		`data: {"choices":[{"delta":{},"finish_reason":"tool_calls"},{"delta":{},"finish_reason":"tool_calls"}]}`,
		`data: [DONE]`,
		"",
	}, "\n\n"))
	safeName, safeArgs, leaked := r2SafeScan(frags)
	if len(leaked) != 0 {
		t.Fatalf("SSE-IDX-01R2e: denied positional call fragments released: %+v (out %q)", leaked[0], out)
	}
	if !safeName || !safeArgs {
		t.Fatalf("SSE-IDX-01R2e: allowed positional call must survive complete, out %q", out)
	}
}

func TestSSEChoiceIdx_AmbiguousIdentityFailsClosed(t *testing.T) {
	t.Run("unindexed-continuation", r2UnindexedContinuation)
	t.Run("fractional-identity", r2FractionalIdentity)
	t.Run("duplicate-identity", r2DuplicateIdentity)
	t.Run("borrowed-accumulation", r2BorrowedAccumulation)
	t.Run("positional-compatibility", r2PositionalCompatibility)
}
