package cli

// SSE tool-gate hold/release regressions, written against the original
// defects: (1) the release-time drop decision must honor the per-call-index
// name verdicts — a name-denied call sharing its first frame with an allowed
// call opened the hold but was never dropped at release; (2) a frame that
// carries both a denied call and finish_reason "tool_calls" deleted the call
// and stranded the consumer's tool loop. Deterministic scripted streams over
// a real toolpolicy engine with an in-memory loader — no live dependencies.

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

// sseGateFor builds an active gate writer over a recorder with the given
// policy rows (org-1, subject "*", the production wiring shape).
func sseGateFor(policies ...toolpolicy.Policy) (*sseToolGateWriter, *httptest.ResponseRecorder) {
	engine := toolpolicy.NewEngine(&memLoader{policies: policies}, time.Minute)
	rec := httptest.NewRecorder()
	return newSSEToolGateWriter(context.Background(), rec, engine, "org-1", "*", true), rec
}

// sseArgsDenyRow returns an allow row carrying an args deny_regex rule, the
// chat-path args-guard shape.
func sseArgsDenyRow(name, marker string) toolpolicy.Policy {
	return toolpolicy.Policy{
		OrgID: "org-1", Name: "args-" + name, Subject: "*", Server: "*",
		Tool: name, Action: toolpolicy.ActionAllow, Enabled: true,
		Rules: json.RawMessage(`{"args":{"deny_regex":["` + marker + `"]}}`),
	}
}

// sseDataFrames decodes every data frame of an SSE body except [DONE].
func sseDataFrames(t *testing.T, body string) []map[string]any {
	t.Helper()
	var docs []map[string]any
	for _, frame := range strings.Split(strings.TrimSpace(body), "\n\n") {
		payload := strings.TrimSpace(strings.TrimPrefix(frame, "data: "))
		if payload == "[DONE]" {
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(payload), &doc); err != nil {
			t.Fatalf("released frame is not valid JSON (%q): %v", payload, err)
		}
		docs = append(docs, doc)
	}
	return docs
}

// sseFirstChoice returns the first choice object of a parsed frame.
func sseFirstChoice(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	choices, _ := doc["choices"].([]any)
	if len(choices) == 0 {
		t.Fatalf("frame carries no choices: %v", doc)
	}
	choice, _ := choices[0].(map[string]any)
	if choice == nil {
		t.Fatalf("first choice is not an object: %v", doc)
	}
	return choice
}

// sseFinishReason returns the first choice's finish_reason ("" when absent).
func sseFinishReason(t *testing.T, doc map[string]any) string {
	t.Helper()
	fr, _ := sseFirstChoice(t, doc)["finish_reason"].(string)
	return fr
}

// sseChoiceByIndex returns the choice object whose "index" field matches
// (falling back to array position when the field is absent).
func sseChoiceByIndex(t *testing.T, doc map[string]any, want int) map[string]any {
	t.Helper()
	choices, _ := doc["choices"].([]any)
	for pos, c := range choices {
		choice, _ := c.(map[string]any)
		var idx int
		if v, ok := choice["index"].(float64); ok {
			idx = int(v)
		} else {
			idx = pos
		}
		if idx == want && choice != nil {
			return choice
		}
	}
	t.Fatalf("frame carries no choice index %d: %v", want, doc)
	return nil
}

// sseChoiceFinish returns one choice's finish_reason ("" when absent).
func sseChoiceFinish(t *testing.T, doc map[string]any, ci int) string {
	t.Helper()
	fr, _ := sseChoiceByIndex(t, doc, ci)["finish_reason"].(string)
	return fr
}

// sseHasToolCalls reports whether the choice's delta still carries calls.
func sseHasToolCalls(choice map[string]any) bool {
	delta, _ := choice["delta"].(map[string]any)
	if delta == nil {
		return false
	}
	_, has := delta["tool_calls"]
	return has
}

// sseCallIndexes lists the call indexes of the choice's delta.
func sseCallIndexes(t *testing.T, choice map[string]any) []int {
	t.Helper()
	delta, _ := choice["delta"].(map[string]any)
	calls, _ := delta["tool_calls"].([]any)
	idxs := make([]int, 0, len(calls))
	for _, cl := range calls {
		call, _ := cl.(map[string]any)
		if v, ok := call["index"].(float64); ok {
			idxs = append(idxs, int(v))
		}
	}
	return idxs
}

func sseMustNotContain(t *testing.T, body string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if strings.Contains(body, n) {
			t.Errorf("released stream must not contain %q:\n%s", n, body)
		}
	}
}

func sseMustContain(t *testing.T, body string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if !strings.Contains(body, n) {
			t.Errorf("released stream must contain %q:\n%s", n, body)
		}
	}
}

// sseAssertNoFragmentOfIndex fails when any released frame still carries a
// fragment of the denied call index: the sticky deny must have removed
// every fragment of that identity from the whole released stream.
func sseAssertNoFragmentOfIndex(t *testing.T, docs []map[string]any, denied int, body string) {
	t.Helper()
	for i, doc := range docs {
		delta, _ := sseFirstChoice(t, doc)["delta"].(map[string]any)
		if delta == nil {
			continue
		}
		calls, _ := delta["tool_calls"].([]any)
		for _, cl := range calls {
			call, _ := cl.(map[string]any)
			if v, _ := call["index"].(float64); int(v) == denied {
				t.Errorf("frame %d released a fragment of the denied identity (index %d):\n%s", i, denied, body)
			}
		}
	}
}

// SSEG-F1-MIXED-FIRST-FRAME: a name-denied call sharing its first frame
// with an allowed call opens the hold (the allowed call declares arguments);
// the release-time drop decision must honor the per-index name verdicts —
// the denied call's output never reaches the client stream, the allowed
// call survives, and the released indexes stay consistent.
func TestSSEToolGateRegression_MixedFirstFrameDeniedCallHeld(t *testing.T) {
	g, rec := sseGateFor(denyTool("secret_tool"))
	mustWrite(t, g, []byte(`data: {"choices":[{"index":0,"delta":{"tool_calls":[`+
		`{"index":0,"function":{"name":"safe_tool","arguments":"{\"q\":\"ok\"}"}},`+
		`{"index":1,"function":{"name":"secret_tool","arguments":"{\"secret\":\"leak\"}"}}]}}]}`+"\n\n"))
	mustWrite(t, g, []byte(`data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`+"\n\n"))
	mustWrite(t, g, []byte("data: [DONE]\n\n"))

	body := rec.Body.String()
	sseMustNotContain(t, body, "secret_tool", "leak")
	sseMustContain(t, body, "safe_tool", "ok")

	docs := sseDataFrames(t, body)
	if len(docs) != 2 {
		t.Fatalf("released data frames = %d, want 2 (fragment + terminal):\n%s", len(docs), body)
	}
	if got := sseCallIndexes(t, sseFirstChoice(t, docs[0])); len(got) != 1 || got[0] != 0 {
		t.Errorf("released call indexes = %v, want exactly [0] (per-index drop)", got)
	}
	if fr := sseFinishReason(t, docs[1]); fr != "tool_calls" {
		t.Errorf("terminal finish_reason = %q, want tool_calls (a call survived)", fr)
	}
	if g.DeniedCount() != 1 {
		t.Errorf("denied count = %d, want 1", g.DeniedCount())
	}
}

// SSEG-F2-COMBINED-ARGS-FINISH: a single frame carrying an args-denied call
// fragment together with finish_reason "tool_calls" must not strand the
// consumer: the call is deleted and the finish reason rewrites to "stop" in
// the SAME emitted frame — the split-frame sequence and the JSON surface
// (gateToolCallsJSON) pin the same no-strand contract.
func TestSSEToolGateRegression_CombinedArgsDeniedFragmentFinishFrame(t *testing.T) {
	g, rec := sseGateFor(denyTool("never_tool"), sseArgsDenyRow("safe_tool", "forbidden"))
	mustWrite(t, g, []byte(`data: {"choices":[{"index":0,"delta":{"tool_calls":[`+
		`{"index":0,"function":{"name":"safe_tool","arguments":"forbidden"}}]},`+
		`"finish_reason":"tool_calls"}]}`+"\n\n"))
	mustWrite(t, g, []byte("data: [DONE]\n\n"))

	body := rec.Body.String()
	sseMustNotContain(t, body, "forbidden", "safe_tool")

	docs := sseDataFrames(t, body)
	if len(docs) != 1 {
		t.Fatalf("released data frames = %d, want 1 (the rewritten frame):\n%s", len(docs), body)
	}
	if sseHasToolCalls(sseFirstChoice(t, docs[0])) {
		t.Errorf("args-denied call must be deleted from the released frame:\n%s", body)
	}
	if fr := sseFinishReason(t, docs[0]); fr != "stop" {
		t.Errorf("finish_reason = %q, want stop (no stranded tool loop)", fr)
	}
	if g.DeniedCount() != 1 {
		t.Errorf("denied count = %d, want 1", g.DeniedCount())
	}
}

// SSEG-F2N-COMBINED-NAME-FINISH: the same no-strand contract on the
// immediate (non-hold) path — a name-denied call alone never opens the
// hold, so the combined fragment+finish frame is filtered directly.
func TestSSEToolGateRegression_CombinedNameDeniedFragmentFinishFrame(t *testing.T) {
	g, rec := sseGateFor(denyTool("secret_tool"))
	mustWrite(t, g, []byte(`data: {"choices":[{"index":0,"delta":{"tool_calls":[`+
		`{"index":0,"function":{"name":"secret_tool","arguments":"x"}}]},`+
		`"finish_reason":"tool_calls"}]}`+"\n\n"))
	mustWrite(t, g, []byte("data: [DONE]\n\n"))

	body := rec.Body.String()
	sseMustNotContain(t, body, "secret_tool")

	docs := sseDataFrames(t, body)
	if len(docs) != 1 {
		t.Fatalf("released data frames = %d, want 1 (the rewritten frame):\n%s", len(docs), body)
	}
	if sseHasToolCalls(sseFirstChoice(t, docs[0])) {
		t.Errorf("name-denied call must be deleted from the emitted frame:\n%s", body)
	}
	if fr := sseFinishReason(t, docs[0]); fr != "stop" {
		t.Errorf("finish_reason = %q, want stop (no stranded tool loop)", fr)
	}
	if g.DeniedCount() != 1 {
		t.Errorf("denied count = %d, want 1", g.DeniedCount())
	}
}

// SSEG-F4-CHOICE-COLLISION (both orders): OpenAI streaming call indexes are
// unique only within a choice — two choices may validly declare index 0. Verdicts,
// argument tracking and release drops keyed by call index alone let one
// choice's decision overwrite the other's. For BOTH orders: no denied byte may
// reach the stream, the allowed call survives its own choice, exactly one
// denial is counted, and each choice's finish reason reflects its own calls
// (denied choice "stop", allowed choice "tool_calls").
func TestSSEG4ChoiceCollisionDeniedFirst(t *testing.T) {
	g, rec := sseGateFor(denyTool("secret_tool"))
	mustWrite(t, g, []byte(`data: {"choices":[{"index":0,"delta":{"tool_calls":[`+
		`{"index":0,"function":{"name":"secret_tool","arguments":"{\"secret\":\"forbidden-marker\"}"}}]}},`+
		`{"index":1,"delta":{"tool_calls":[{"index":0,"function":{"name":"safe_tool","arguments":"{}"}}]}}]}`+"\n\n"))
	mustWrite(t, g, []byte(`data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"},`+
		`{"index":1,"delta":{},"finish_reason":"tool_calls"}]}`+"\n\n"))
	mustWrite(t, g, []byte("data: [DONE]\n\n"))

	body := rec.Body.String()
	sseMustNotContain(t, body, "secret_tool", "forbidden-marker")
	sseMustContain(t, body, "safe_tool")

	docs := sseDataFrames(t, body)
	if len(docs) != 2 {
		t.Fatalf("released data frames = %d, want 2 (calls + terminal):\n%s", len(docs), body)
	}
	if got := sseCallIndexes(t, sseChoiceByIndex(t, docs[0], 1)); len(got) != 1 || got[0] != 0 {
		t.Errorf("allowed choice must keep its own index-0 call, got %v:\n%s", got, body)
	}
	if sseHasToolCalls(sseChoiceByIndex(t, docs[0], 0)) {
		t.Errorf("denied choice must lose its call in the same frame:\n%s", body)
	}
	if fr := sseChoiceFinish(t, docs[1], 0); fr != "stop" {
		t.Errorf("denied choice finish_reason = %q, want stop", fr)
	}
	if fr := sseChoiceFinish(t, docs[1], 1); fr != "tool_calls" {
		t.Errorf("allowed choice finish_reason = %q, want tool_calls", fr)
	}
	if g.DeniedCount() != 1 {
		t.Errorf("denied count = %d, want 1", g.DeniedCount())
	}
}

func TestSSEG4ChoiceCollisionAllowedFirst(t *testing.T) {
	g, rec := sseGateFor(denyTool("secret_tool"))
	mustWrite(t, g, []byte(`data: {"choices":[{"index":0,"delta":{"tool_calls":[`+
		`{"index":0,"function":{"name":"safe_tool","arguments":"{}"}}]}},`+
		`{"index":1,"delta":{"tool_calls":[{"index":0,"function":{"name":"secret_tool","arguments":"{\"secret\":\"forbidden-marker\"}"}}]}}]}`+"\n\n"))
	mustWrite(t, g, []byte(`data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"},`+
		`{"index":1,"delta":{},"finish_reason":"tool_calls"}]}`+"\n\n"))
	mustWrite(t, g, []byte("data: [DONE]\n\n"))

	body := rec.Body.String()
	sseMustNotContain(t, body, "secret_tool", "forbidden-marker")
	sseMustContain(t, body, "safe_tool")

	docs := sseDataFrames(t, body)
	if len(docs) != 2 {
		t.Fatalf("released data frames = %d, want 2 (calls + terminal):\n%s", len(docs), body)
	}
	if got := sseCallIndexes(t, sseChoiceByIndex(t, docs[0], 0)); len(got) != 1 || got[0] != 0 {
		t.Errorf("allowed choice must keep its own index-0 call, got %v:\n%s", got, body)
	}
	if sseHasToolCalls(sseChoiceByIndex(t, docs[0], 1)) {
		t.Errorf("denied choice must lose its call in the same frame:\n%s", body)
	}
	if fr := sseChoiceFinish(t, docs[1], 0); fr != "tool_calls" {
		t.Errorf("allowed choice finish_reason = %q, want tool_calls", fr)
	}
	if fr := sseChoiceFinish(t, docs[1], 1); fr != "stop" {
		t.Errorf("denied choice finish_reason = %q, want stop", fr)
	}
	if g.DeniedCount() != 1 {
		t.Errorf("denied count = %d, want 1", g.DeniedCount())
	}
}

// SSEG-F3-SPLIT-SURVIVOR: an allowed call in an earlier frame of a choice
// keeps that choice's tool loop alive even when a LATER frame carries only a
// denied call: the denied fragment is dropped but the terminal finish_reason
// must REMAIN "tool_calls" — the finish rewrite must consider every call of
// the choice across the response, not just the frame in hand.
func TestSSEG3SplitSurvivorKeepsToolFinish(t *testing.T) {
	g, rec := sseGateFor(denyTool("secret_tool"))
	mustWrite(t, g, []byte(`data: {"choices":[{"index":0,"delta":{"tool_calls":[`+
		`{"index":0,"function":{"name":"safe_tool","arguments":"{}"}}]}}]}`+"\n\n"))
	mustWrite(t, g, []byte(`data: {"choices":[{"index":0,"delta":{"tool_calls":[`+
		`{"index":1,"function":{"name":"secret_tool","arguments":"{}"}}]}}]}`+"\n\n"))
	mustWrite(t, g, []byte(`data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`+"\n\n"))
	mustWrite(t, g, []byte("data: [DONE]\n\n"))

	body := rec.Body.String()
	sseMustNotContain(t, body, "secret_tool")
	sseMustContain(t, body, "safe_tool")

	docs := sseDataFrames(t, body)
	if len(docs) != 3 {
		t.Fatalf("released data frames = %d, want 3 (allowed, denied-emptied, terminal):\n%s", len(docs), body)
	}
	if got := sseCallIndexes(t, sseFirstChoice(t, docs[0])); len(got) != 1 || got[0] != 0 {
		t.Errorf("allowed call lost from its frame, got %v:\n%s", got, body)
	}
	if sseHasToolCalls(sseFirstChoice(t, docs[1])) {
		t.Errorf("denied call must be dropped from its frame:\n%s", body)
	}
	if fr := sseFinishReason(t, docs[2]); fr != "tool_calls" {
		t.Errorf("surviving safe_tool requires tool_calls finish, got %q:\n%s", fr, body)
	}
	if g.DeniedCount() != 1 {
		t.Errorf("denied count = %d, want exactly 1", g.DeniedCount())
	}
}

// SSEG-F3B-ALL-DENIED-SPLIT-STOPS: the no-strand contract still holds when
// every call of a choice is denied across SEPARATE frames — the finish
// normalizes to "stop" and no fragment of any denied call is released.
func TestSSEG3AllDeniedAcrossFramesStops(t *testing.T) {
	g, rec := sseGateFor(denyTool("secret_tool"), sseArgsDenyRow("safe_tool", "forbidden"))
	mustWrite(t, g, []byte(`data: {"choices":[{"index":0,"delta":{"tool_calls":[`+
		`{"index":0,"function":{"name":"safe_tool","arguments":"for"}}]}}]}`+"\n\n"))
	mustWrite(t, g, []byte(`data: {"choices":[{"index":0,"delta":{"tool_calls":[`+
		`{"index":0,"function":{"arguments":"bidden"}},`+
		`{"index":1,"function":{"name":"secret_tool","arguments":"{}"}}]}}]}`+"\n\n"))
	mustWrite(t, g, []byte(`data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`+"\n\n"))
	mustWrite(t, g, []byte("data: [DONE]\n\n"))

	body := rec.Body.String()
	sseMustNotContain(t, body, "safe_tool", "forbidden", "secret_tool")

	docs := sseDataFrames(t, body)
	if len(docs) != 3 {
		t.Fatalf("released data frames = %d, want 3 (two emptied fragments + terminal):\n%s", len(docs), body)
	}
	for i := 0; i < 2; i++ {
		if sseHasToolCalls(sseFirstChoice(t, docs[i])) {
			t.Errorf("frame %d must carry no tool_calls after all calls were denied:\n%s", i, body)
		}
	}
	if fr := sseFinishReason(t, docs[2]); fr != "stop" {
		t.Errorf("all-denied choice finish_reason = %q, want stop", fr)
	}
	if g.DeniedCount() != 2 {
		t.Errorf("denied count = %d, want 2 (name deny + args deny)", g.DeniedCount())
	}
}

// SSEG-FD-DUAL-FORM-IDENTITY: the policy key of a model-declared call is its
// declared name verbatim — a bare deny row must not match the prefixed form
// and vice versa — and that verbatim dual-form key space must survive under
// per-(choice, index) identity: the prefixed call of one choice neither
// borrows nor pollutes the bare call's verdict of the other.
func TestSSEGDualFormKeysUnderChoiceIdentity(t *testing.T) {
	g, rec := sseGateFor(denyTool("web_fetch"), denyTool("yabanin:http_post"))
	mustWrite(t, g, []byte(`data: {"choices":[{"index":0,"delta":{"tool_calls":[`+
		`{"index":0,"function":{"name":"yabanin:web_fetch","arguments":"{}"}}]}},`+
		`{"index":1,"delta":{"tool_calls":[{"index":0,"function":{"name":"web_fetch","arguments":"{}"}}]}}]}`+"\n\n"))
	mustWrite(t, g, []byte(`data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"},`+
		`{"index":1,"delta":{},"finish_reason":"tool_calls"}]}`+"\n\n"))
	mustWrite(t, g, []byte("data: [DONE]\n\n"))

	body := rec.Body.String()
	sseMustContain(t, body, "yabanin:web_fetch")

	docs := sseDataFrames(t, body)
	if len(docs) != 2 {
		t.Fatalf("released data frames = %d, want 2 (calls + terminal):\n%s", len(docs), body)
	}
	if got := sseCallIndexes(t, sseChoiceByIndex(t, docs[0], 0)); len(got) != 1 || got[0] != 0 {
		t.Errorf("prefixed-name call must survive the bare deny row, got %v:\n%s", got, body)
	}
	if sseHasToolCalls(sseChoiceByIndex(t, docs[0], 1)) {
		t.Errorf("bare-name call must be denied by the bare row:\n%s", body)
	}
	if fr := sseChoiceFinish(t, docs[1], 0); fr != "tool_calls" {
		t.Errorf("allowed prefixed choice finish_reason = %q, want tool_calls", fr)
	}
	if fr := sseChoiceFinish(t, docs[1], 1); fr != "stop" {
		t.Errorf("denied bare choice finish_reason = %q, want stop", fr)
	}
	if g.DeniedCount() != 1 {
		t.Errorf("denied count = %d, want 1", g.DeniedCount())
	}
}

// SSEG-F5-DENIED-RENAME-STICKY: a deny decided on a call's first name
// fragment is sticky for the call's whole identity — a later fragment
// renaming the call to an allowed name must not let any fragment of that
// call survive (deny-wins per identity), while an independent allowed call
// of the same choice keeps streaming and keeps the tool loop alive.
func TestSSEG5DeniedToAllowedRenameStickyDeny(t *testing.T) {
	g, rec := sseGateFor(denyTool("secret_tool"))
	mustWrite(t, g, []byte(`data: {"choices":[{"index":0,"delta":{"tool_calls":[`+
		`{"index":0,"function":{"name":"safe_tool","arguments":"{}"}}]}}]}`+"\n\n"))
	mustWrite(t, g, []byte(`data: {"choices":[{"index":0,"delta":{"tool_calls":[`+
		`{"index":1,"function":{"name":"secret_tool","arguments":"{\"secret\":\"first-part\"}"}}]}}]}`+"\n\n"))
	mustWrite(t, g, []byte(`data: {"choices":[{"index":0,"delta":{"tool_calls":[`+
		`{"index":1,"function":{"name":"safe_tool","arguments":", \"more\":\"second-part\"}"}}]}}]}`+"\n\n"))
	mustWrite(t, g, []byte(`data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`+"\n\n"))
	mustWrite(t, g, []byte("data: [DONE]\n\n"))

	body := rec.Body.String()
	sseMustNotContain(t, body, "secret_tool", "first-part", "second-part")
	sseMustContain(t, body, "safe_tool")

	// The gate filters each input frame in place and preserves event
	// boundaries: one released frame per input frame. The two input frames
	// carrying fragments of the denied identity stay in the stream as
	// empty-delta events (they are not coalesced away), so the exact
	// expected sequence is 4 frames — allowed call, two emptied frames,
	// terminal — never an arbitrary count.
	docs := sseDataFrames(t, body)
	if len(docs) != 4 {
		t.Fatalf("released data frames = %d, want 4 (allowed call, two emptied denied-fragment frames, terminal):\n%s", len(docs), body)
	}
	kept, _ := sseFirstChoice(t, docs[0])["delta"].(map[string]any)["tool_calls"].([]any)
	if len(kept) != 1 {
		t.Fatalf("first frame must carry exactly the allowed call:\n%s", body)
	}
	call, _ := kept[0].(map[string]any)
	fn, _ := call["function"].(map[string]any)
	if fn["name"] != "safe_tool" {
		t.Errorf("first frame must keep the allowed safe_tool call:\n%s", body)
	}
	for i := 1; i <= 2; i++ {
		delta, _ := sseFirstChoice(t, docs[i])["delta"].(map[string]any)
		if calls, _ := delta["tool_calls"].([]any); len(calls) != 0 {
			t.Errorf("emptied frame %d must carry no tool_calls after the sticky deny:\n%s", i, body)
		}
	}
	sseAssertNoFragmentOfIndex(t, docs, 1, body)
	if fr := sseFinishReason(t, docs[3]); fr != "tool_calls" {
		t.Errorf("surviving safe_tool requires tool_calls finish, got %q:\n%s", fr, body)
	}
	if g.DeniedCount() != 1 {
		t.Errorf("denied count = %d, want exactly 1 (sticky deny counts once)", g.DeniedCount())
	}
}

// SSEG-F5N-DENIED-RENAME-STICKY-IMMEDIATE: the same sticky contract on the
// immediate (non-hold) path — the denied call's rename fragment is dropped
// like every other fragment of that identity, and the all-denied choice
// normalizes to "stop".
func TestSSEG5DeniedRenameStickyImmediate(t *testing.T) {
	g, rec := sseGateFor(denyTool("secret_tool"))
	mustWrite(t, g, []byte(`data: {"choices":[{"index":0,"delta":{"tool_calls":[`+
		`{"index":0,"function":{"name":"secret_tool","arguments":"a1"}}]}}]}`+"\n\n"))
	mustWrite(t, g, []byte(`data: {"choices":[{"index":0,"delta":{"tool_calls":[`+
		`{"index":0,"function":{"name":"safe_tool","arguments":"a2"}}]}}]}`+"\n\n"))
	mustWrite(t, g, []byte(`data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`+"\n\n"))
	mustWrite(t, g, []byte("data: [DONE]\n\n"))

	body := rec.Body.String()
	sseMustNotContain(t, body, "secret_tool", "safe_tool", "a1", "a2")

	docs := sseDataFrames(t, body)
	if len(docs) != 3 {
		t.Fatalf("released data frames = %d, want 3 (two emptied fragments + terminal):\n%s", len(docs), body)
	}
	for i := 0; i < 2; i++ {
		if sseHasToolCalls(sseFirstChoice(t, docs[i])) {
			t.Errorf("frame %d must carry no tool_calls after the sticky deny:\n%s", i, body)
		}
	}
	if fr := sseFinishReason(t, docs[2]); fr != "stop" {
		t.Errorf("all-denied choice finish_reason = %q, want stop", fr)
	}
	if g.DeniedCount() != 1 {
		t.Errorf("denied count = %d, want exactly 1", g.DeniedCount())
	}
}

// SSEG-F5A-ALLOWED-THEN-DENIED-RENAME: the opposite rename direction stays
// live — a call first allowed and later renamed to a denied name drops
// whole (its earlier allowed-name fragments too) and the choice
// normalizes to "stop".
func TestSSEG5AllowedThenDeniedRenameDropsWholeCall(t *testing.T) {
	g, rec := sseGateFor(denyTool("secret_tool"))
	mustWrite(t, g, []byte(`data: {"choices":[{"index":0,"delta":{"tool_calls":[`+
		`{"index":0,"function":{"name":"safe_tool"}}]}}]}`+"\n\n"))
	mustWrite(t, g, []byte(`data: {"choices":[{"index":0,"delta":{"tool_calls":[`+
		`{"index":0,"function":{"name":"secret_tool","arguments":"x"}}]}}]}`+"\n\n"))
	mustWrite(t, g, []byte(`data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`+"\n\n"))
	mustWrite(t, g, []byte("data: [DONE]\n\n"))

	body := rec.Body.String()
	sseMustNotContain(t, body, "safe_tool", "secret_tool")

	docs := sseDataFrames(t, body)
	if len(docs) != 3 {
		t.Fatalf("released data frames = %d, want 3 (two emptied fragments + terminal):\n%s", len(docs), body)
	}
	if fr := sseFinishReason(t, docs[2]); fr != "stop" {
		t.Errorf("renamed-denied choice finish_reason = %q, want stop", fr)
	}
	if g.DeniedCount() != 1 {
		t.Errorf("denied count = %d, want 1", g.DeniedCount())
	}
}
