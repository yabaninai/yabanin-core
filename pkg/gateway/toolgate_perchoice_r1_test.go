package cli

// SSE-REL-01 (auth/SSE/tool-policy correction, pinned contract): release
// is scoped per choice. A finish_reason on one
// choice must not evaluate and release ANOTHER choice's still-streaming
// tool call: the args guard must see the call's COMPLETE accumulated
// arguments, so a call denied only by its final chunks is dropped whole
// instead of leaking its early fragments when a sibling choice finishes
// first. Frozen legs:
//
//	SSE-REL-01a  choice 0 finishes early while choice 1's call is still
//	             streaming - the denied choice-1 call must be absent
//	             WHOLE (name and every fragment), the choice-0 finish
//	             frame and [DONE] must survive
//	SSE-REL-01b  solo baseline (no sibling finish) - same denied call is
//	             dropped whole already (negative control: the interleave
//	             is the only cause)
//	SSE-REL-01c  interleave with ALLOWED args - the complete safe_tool
//	             call must survive the sibling finish (no
//	             over-suppression)
//	SSE-REL-01d  mirror of a with the denied call on choice 0 and the
//	             early finish on choice 1 - scoping keys on the WIRE
//	             index, not the array position
//	SSE-REL-01e  a malformed termination discards still-unresolved
//	             executable calls (partial arguments never stream
//	             unchecked); the malformed frame itself passes through
//	SSE-REL-01f  argument denial is sticky for the response lifetime: a
//	             late continuation after the call's own finish never
//	             re-opens a call whose accumulated arguments were denied
//
// Under any-choice global release legs a and d fail: the early sibling
// finish releases the denied choice's partial arguments before the deny
// materializes.

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// relDrive runs one stream through the real writer under org-args
// (deny_regex "forbidden" on safe_tool) and returns the decoded state:
// tool-call fragments grouped by wire index (idxDecode), whether the
// choice-0 stop frame survived, and whether [DONE] survived.
func relDrive(t *testing.T, name, stream string) (frags []idxFragment, choice0Stop, done bool, out string) {
	t.Helper()
	engine := fuzzToolEngine()
	w := httptest.NewRecorder()
	g := newSSEToolGateWriter(context.Background(), w, engine, "org-args", "*", true)
	if _, err := g.Write([]byte(stream)); err != nil {
		t.Fatalf("%s: write: %v", name, err)
	}
	g.Flush() // force final release of anything still held
	out = w.Body.String()
	frags = relDecode(t, out)
	for _, line := range strings.Split(out, "\n") {
		if line == "data: [DONE]" {
			done = true
		}
		if d, ok := strings.CutPrefix(line, "data: "); ok && d != "" && d != "[DONE]" && strings.Contains(d, "\"finish_reason\":\"stop\"") && strings.Contains(d, "\"index\":0") {
			choice0Stop = true
		}
	}
	return frags, choice0Stop, done, out
}

// relDecode decodes tool-call fragments from the released stream,
// skipping the malformed passthrough frame (SSE-REL-01e expects it in the
// raw output); every deny leg also scans the raw output bytes directly.
func relDecode(t *testing.T, out string) []idxFragment {
	t.Helper()
	var got []idxFragment
	for _, line := range strings.Split(out, "\n") {
		d, ok := strings.CutPrefix(line, "data: ")
		if !ok || d == "" || d == "[DONE]" {
			continue
		}
		var doc struct {
			Choices []struct {
				Delta struct {
					ToolCalls []struct {
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(d), &doc); err != nil {
			continue // the malformed passthrough frame
		}
		for _, ch := range doc.Choices {
			for _, tc := range ch.Delta.ToolCalls {
				got = append(got, idxFragment{name: tc.Function.Name, args: tc.Function.Arguments})
			}
		}
	}
	return got
}

func relDeniedFragments(fragments []idxFragment) []idxFragment {
	var leaked []idxFragment
	for _, fragment := range fragments {
		if fragment.name == "safe_tool" || strings.Contains(fragment.args, "forbi") || strings.Contains(fragment.args, "dden") {
			leaked = append(leaked, fragment)
		}
	}
	return leaked
}

func relAssertDenied(t *testing.T, label string, fragments []idxFragment, out string) {
	t.Helper()
	if leaked := relDeniedFragments(fragments); len(leaked) != 0 {
		t.Fatalf("%s: denied call fragments released: %+v (out %q)", label, leaked, out)
	}
	if strings.Contains(out, "forbi") || strings.Contains(out, "dden456") {
		t.Fatalf("%s: denied bytes in raw output: %q", label, out)
	}
}

func relRequireDone(t *testing.T, label string, done bool, out string) {
	t.Helper()
	if !done {
		t.Fatalf("%s: [DONE] must survive, out %q", label, out)
	}
}

func relInterleavedFinish(t *testing.T) {
	frags, choice0Stop, done, out := relDrive(t, "SSE-REL-01a", strings.Join([]string{
		`data: {"choices":[{"index":1,"delta":{"tool_calls":[{"index":0,"function":{"name":"safe_tool","arguments":""}}]}}]}`,
		`data: {"choices":[{"index":1,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"x\":123forbi"}}]}}]}`,
		`data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`,
		`data: {"choices":[{"index":1,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"dden456}"}}]}}]}`,
		`data: {"choices":[{"index":1,"delta":{},"finish_reason":"tool_calls"}]}`,
		`data: [DONE]`,
		"",
	}, "\n\n"))
	relAssertDenied(t, "SSE-REL-01a", frags, out)
	if !choice0Stop {
		t.Fatalf("SSE-REL-01a: choice-0 finish frame must survive, out %q", out)
	}
	relRequireDone(t, "SSE-REL-01a", done, out)
}

func relSoloBaseline(t *testing.T) {
	frags, _, done, out := relDrive(t, "SSE-REL-01b", strings.Join([]string{
		`data: {"choices":[{"index":1,"delta":{"tool_calls":[{"index":0,"function":{"name":"safe_tool","arguments":""}}]}}]}`,
		`data: {"choices":[{"index":1,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"x\":123forbi"}}]}}]}`,
		`data: {"choices":[{"index":1,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"dden456}"}}]}}]}`,
		`data: {"choices":[{"index":1,"delta":{},"finish_reason":"tool_calls"}]}`,
		`data: [DONE]`,
		"",
	}, "\n\n"))
	relAssertDenied(t, "SSE-REL-01b", frags, out)
	relRequireDone(t, "SSE-REL-01b", done, out)
}

func relAllowedSurvives(t *testing.T) {
	frags, choice0Stop, done, out := relDrive(t, "SSE-REL-01c", strings.Join([]string{
		`data: {"choices":[{"index":1,"delta":{"tool_calls":[{"index":0,"function":{"name":"safe_tool","arguments":""}}]}}]}`,
		`data: {"choices":[{"index":1,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"x\":123ok456}"}}]}}]}`,
		`data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`,
		`data: {"choices":[{"index":1,"delta":{},"finish_reason":"tool_calls"}]}`,
		`data: [DONE]`,
		"",
	}, "\n\n"))
	var nameSeen, argsSeen bool
	for _, fragment := range frags {
		if fragment.name == "safe_tool" {
			nameSeen = true
		}
		if fragment.args == `{"x":123ok456}` {
			argsSeen = true
		}
	}
	if !nameSeen || !argsSeen || !choice0Stop || !done {
		t.Fatalf("SSE-REL-01c: allowed call must survive complete (name=%v args=%v stop=%v done=%v), out %q", nameSeen, argsSeen, choice0Stop, done, out)
	}
}

func relMirrorDeniedChoice0(t *testing.T) {
	frags, _, done, out := relDrive(t, "SSE-REL-01d", strings.Join([]string{
		`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":"safe_tool","arguments":""}}]}}]}`,
		`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"x\":123forbi"}}]}}]}`,
		`data: {"choices":[{"index":1,"delta":{},"finish_reason":"stop"}]}`,
		`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"dden456}"}}]}}]}`,
		`data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
		`data: [DONE]`,
		"",
	}, "\n\n"))
	choice1Stop := false
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, `"finish_reason":"stop"`) && strings.Contains(line, `"index":1`) {
			choice1Stop = true
		}
	}
	relAssertDenied(t, "SSE-REL-01d", frags, out)
	if !choice1Stop {
		t.Fatalf("SSE-REL-01d: choice-1 finish frame must survive, out %q", out)
	}
	relRequireDone(t, "SSE-REL-01d", done, out)
}

func relMalformedDiscardsUnresolved(t *testing.T) {
	_, _, done, out := relDrive(t, "SSE-REL-01e", strings.Join([]string{
		`data: {"choices":[{"index":1,"delta":{"tool_calls":[{"index":0,"function":{"name":"safe_tool","arguments":""}}]}}]}`,
		`data: {"choices":[{"index":1,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"x\":123forbi"}}]}}]}`,
		`data: {oops-not-json`,
		`data: [DONE]`,
		"",
	}, "\n\n"))
	if leaked := relDecode(t, out); len(leaked) != 0 {
		t.Fatalf("SSE-REL-01e: unresolved call fragments released at a malformed termination: %+v (out %q)", leaked, out)
	}
	if strings.Contains(out, "forbi") {
		t.Fatalf("SSE-REL-01e: denied bytes in raw output: %q", out)
	}
	if !strings.Contains(out, "oops-not-json") {
		t.Fatalf("SSE-REL-01e: the malformed frame itself must pass through, out %q", out)
	}
	relRequireDone(t, "SSE-REL-01e", done, out)
}

func relArgsDenySticky(t *testing.T) {
	frags, _, done, out := relDrive(t, "SSE-REL-01f", strings.Join([]string{
		`data: {"choices":[{"index":1,"delta":{"tool_calls":[{"index":0,"function":{"name":"safe_tool","arguments":""}}]}}]}`,
		`data: {"choices":[{"index":1,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"x\":123forbidden456}"}}]}}]}`,
		`data: {"choices":[{"index":1,"delta":{},"finish_reason":"tool_calls"}]}`,
		`data: {"choices":[{"index":1,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"junk-after-deny"}}]}}]}`,
		`data: [DONE]`,
		"",
	}, "\n\n"))
	for _, fragment := range frags {
		if fragment.name == "safe_tool" || strings.Contains(fragment.args, "forbidden") || strings.Contains(fragment.args, "junk-after-deny") {
			t.Fatalf("SSE-REL-01f: denied call re-opened by a late continuation: %+v (out %q)", fragment, out)
		}
	}
	if strings.Contains(out, "forbidden456") || strings.Contains(out, "junk-after-deny") {
		t.Fatalf("SSE-REL-01f: denied bytes in raw output: %q", out)
	}
	relRequireDone(t, "SSE-REL-01f", done, out)
}

func TestSSEPerChoiceRelease_ScopedEvaluation(t *testing.T) {
	t.Run("interleaved-finish", relInterleavedFinish)
	t.Run("solo-baseline", relSoloBaseline)
	t.Run("interleave-allowed-survives", relAllowedSurvives)
	t.Run("mirror-denied-choice0", relMirrorDeniedChoice0)
	t.Run("malformed-discards-unresolved", relMalformedDiscardsUnresolved)
	t.Run("args-deny-sticky-on-late-continuation", relArgsDenySticky)
}
