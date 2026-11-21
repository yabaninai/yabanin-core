package cli

// SSE-IDX-01 (auth/SSE/tool-policy correction R1, original behavioral
// reproducer): streaming choices are identified by their WIRE
// choice.index, never by array position - providers emit sparse choices
// arrays (index 1 alone) and reorder choices between frames. The oracle
// decodes the released stream and groups every tool-call fragment by wire
// index: the denied wire choice's call must be absent WHOLE (name and
// arguments), the allowed wire choice's call must survive complete.
// Frozen legs:
//
//	SSE-IDX-01a  choices reordered between held frames (positions swap)
//	SSE-IDX-01b  sparse wire-1 choice later joined by wire 0
//
// Under array-position keying both legs fail with the verdict inverted
// across the two choices: the denied call's argument fragment is released
// to the client while the allowed call's fragment is dropped.

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// idxFragment is one tool-call fragment the client received, grouped by
// the WIRE choice index it was emitted under.
type idxFragment struct {
	choice int
	name   string
	args   string
}

// idxDecode walks the released stream and returns every tool-call
// fragment keyed by wire index (never by array position).
func idxDecode(t *testing.T, out string) []idxFragment {
	t.Helper()
	var got []idxFragment
	for _, line := range strings.Split(out, "\n") {
		d, ok := strings.CutPrefix(line, "data: ")
		if !ok || d == "" || d == "[DONE]" {
			continue
		}
		var doc struct {
			Choices []struct {
				Index float64 `json:"index"` // fractional members survive on stripped frames
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
			t.Fatalf("SSE-IDX-01: released data line is not valid JSON: %q (out %q)", d, out)
		}
		for _, ch := range doc.Choices {
			for _, tc := range ch.Delta.ToolCalls {
				got = append(got, idxFragment{choice: int(ch.Index), name: tc.Function.Name, args: tc.Function.Arguments})
			}
		}
	}
	return got
}

type idxSafety struct {
	safeName bool
	safeArgs bool
	leaked   []idxFragment
}

func idxScanReleased(fragments []idxFragment) idxSafety {
	var state idxSafety
	for _, fragment := range fragments {
		if strings.Contains(fragment.name, "secret") || strings.Contains(fragment.args, "secret") || fragment.choice != 0 {
			state.leaked = append(state.leaked, fragment)
			continue
		}
		if fragment.name == "safe_tool" {
			state.safeName = true
		}
		if strings.Contains(fragment.args, "safe-payload") {
			state.safeArgs = true
		}
	}
	return state
}

// idxAssert drives one stream through the real writer (org-deny denies
// secret_tool; safe_tool is implicitly allowed) and applies the
// wire-index oracle.
func idxAssert(t *testing.T, name, stream string) {
	t.Helper()
	engine := fuzzToolEngine()
	w := httptest.NewRecorder()
	g := newSSEToolGateWriter(context.Background(), w, engine, "org-deny", "*", true)
	if _, err := g.Write([]byte(stream)); err != nil {
		t.Fatalf("%s: write: %v", name, err)
	}
	g.Flush() // force final release of anything still held
	out := w.Body.String()
	state := idxScanReleased(idxDecode(t, out))
	if len(state.leaked) != 0 {
		t.Fatalf("%s: denied wire-choice call fragments released to the client: %+v (out %q)", name, state.leaked, out)
	}
	if !state.safeName || !state.safeArgs {
		t.Fatalf("%s: allowed call must survive complete ON WIRE 0 (name=%v args=%v), out %q", name, state.safeName, state.safeArgs, out)
	}
	fin := finishByChoice(t, out)
	if fin[1] != "stop" {
		t.Fatalf("%s: denied wire-1 choice must finish stop (its call was dropped whole), got %q, out %q", name, fin[1], out)
	}
	if fin[0] != "tool_calls" {
		t.Fatalf("%s: allowed wire-0 choice must finish tool_calls (its call survived), got %q, out %q", name, fin[0], out)
	}
}

// finishByChoice pins each choice's finish_reason to its WIRE index: the
// denied wire-1 call normalizes to stop, the surviving wire-0 call keeps
// tool_calls - a swap of the two must fail the oracle.
func finishByChoice(t *testing.T, out string) map[int]string {
	t.Helper()
	fin := map[int]string{}
	for _, line := range strings.Split(out, "\n") {
		d, ok := strings.CutPrefix(line, "data: ")
		if !ok || d == "" || d == "[DONE]" {
			continue
		}
		var doc struct {
			Choices []struct {
				Index  float64 `json:"index"` // fractional members survive on stripped frames
				Finish string  `json:"finish_reason"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(d), &doc); err != nil {
			t.Fatalf("finishByChoice: released data line is not valid JSON: %q (out %q)", d, out)
		}
		for _, ch := range doc.Choices {
			if ch.Finish != "" {
				fin[int(ch.Index)] = ch.Finish
			}
		}
	}
	return fin
}

func TestSSEChoiceIdx_WireIndexKeysToolCallVerdicts(t *testing.T) {
	// SSE-IDX-01a: frame 1 declares both calls at their wire positions;
	// frame 2 REORDERS the choices array - position 0 now carries wire 1's
	// denied argument fragment, position 1 carries wire 0's allowed one.
	t.Run("reordered-frames", func(t *testing.T) {
		idxAssert(t, "SSE-IDX-01a", strings.Join([]string{
			`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":"safe_tool","arguments":""}}]}},{"index":1,"delta":{"tool_calls":[{"index":0,"function":{"name":"secret_tool","arguments":""}}]}}]}`,
			`data: {"choices":[{"index":1,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"secret-payload"}}]}},{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"safe-payload"}}]}}]}`,
			`data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"},{"index":1,"delta":{},"finish_reason":"tool_calls"}]}`,
			`data: [DONE]`,
			"",
		}, "\n\n"))
	})

	// SSE-IDX-01b: a sparse frame carries wire 1 ALONE (array position 0);
	// the next frame joins wire 0 ahead of it, so wire 1 sits at position 1.
	t.Run("sparse-then-alongside", func(t *testing.T) {
		idxAssert(t, "SSE-IDX-01b", strings.Join([]string{
			`data: {"choices":[{"index":1,"delta":{"tool_calls":[{"index":0,"function":{"name":"secret_tool","arguments":""}}]}}]}`,
			`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":"safe_tool","arguments":"safe-payload"}}]}},{"index":1,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"secret-payload2"}}]}}]}`,
			`data: {"choices":[{"index":1,"delta":{},"finish_reason":"tool_calls"},{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
			`data: [DONE]`,
			"",
		}, "\n\n"))
	})
}
