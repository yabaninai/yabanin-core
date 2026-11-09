package consumer

import (
	"strings"
	"testing"
)

func TestExtractToolCallInvocations_CompletionDoc(t *testing.T) {
	sample := `{"choices":[{"message":{"tool_calls":[
		{"id":"c1","type":"function","function":{"name":"bash","arguments":"{\"cmd\":\"ls\"}"}},
		{"id":"c2","type":"function","function":{"name":"read","arguments":"{\"path\":\"a\"}"}}
	]}}]}`
	got := extractToolCallInvocations(sample)
	if len(got) != 2 {
		t.Fatalf("want 2 invocations, got %d: %+v", len(got), got)
	}
	if got[0].Name != "bash" || got[0].CallID != "c1" || got[0].Args != `{"cmd":"ls"}` {
		t.Errorf("inv0 = %+v", got[0])
	}
	if got[1].Seq != 1 || got[1].Name != "read" {
		t.Errorf("inv1 = %+v", got[1])
	}
}

func TestExtractToolCallInvocations_SSEFragmentsReassemble(t *testing.T) {
	sample := strings.Join([]string{
		`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_b1","type":"function","function":{"name":"bash","arguments":"{\"cmd\":\"git"}}]}}]}`,
		`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":" status\"}"}}]}}]}`,
		`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"call_r1","type":"function","function":{"name":"read","arguments":"{\"path\":"}}]}}]}`,
		`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"\"Makefile\"}"}}]}}]}`,
		`data: [DONE]`,
	}, "\n\n")
	got := extractToolCallInvocations(sample)
	if len(got) != 2 {
		t.Fatalf("want 2 invocations, got %d: %+v", len(got), got)
	}
	if got[0].Args != `{"cmd":"git status"}` {
		t.Errorf("reassembled args = %q, want %q", got[0].Args, `{"cmd":"git status"}`)
	}
	if got[1].CallID != "call_r1" || got[1].Args != `{"path":"Makefile"}` {
		t.Errorf("inv1 = %+v", got[1])
	}
	if got[1].Seq != 1 {
		t.Errorf("seq = %d, want 1 (first-appearance order)", got[1].Seq)
	}
}

func TestExtractToolCallInvocations_TruncatedMidArgs(t *testing.T) {
	// The sample cut mid-fragment: arguments survive only partially — honest.
	sample := strings.Join([]string{
		`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c","type":"function","function":{"name":"edit","arguments":"{\"new\":\"aaaaaaaa"}}]}}]}`,
		`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"argum`, // cut mid-JSON
	}, "\n")
	got := extractToolCallInvocations(sample)
	if len(got) != 1 {
		t.Fatalf("want 1 invocation, got %d: %+v", len(got), got)
	}
	if got[0].Name != "edit" || got[0].Args != `{"new":"aaaaaaaa` {
		t.Errorf("inv0 = %+v", got[0])
	}
}

func TestExtractToolCallInvocations_NamelessFragmentAnchoredByIndex(t *testing.T) {
	// First fragment carries id+name; a later same-index fragment without a
	// name still extends the args (never starts a phantom invocation).
	sample := strings.Join([]string{
		`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":2,"id":"x","type":"function","function":{"name":"grep","arguments":"{\"q\":\"a"}}]}}]}`,
		`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":2,"function":{"arguments":"b\"}"}}]}}]}`,
	}, "\n")
	got := extractToolCallInvocations(sample)
	if len(got) != 1 {
		t.Fatalf("want 1 invocation, got %d: %+v", len(got), got)
	}
	if got[0].Args != `{"q":"ab"}` {
		t.Errorf("args = %q", got[0].Args)
	}
}

func TestExtractToolCallInvocations_EmptyAndNone(t *testing.T) {
	if got := extractToolCallInvocations(""); got != nil {
		t.Errorf("empty sample: got %+v", got)
	}
	if got := extractToolCallInvocations(`{"choices":[{"message":{"content":"hi"}}]}`); got != nil {
		t.Errorf("no tool calls: got %+v", got)
	}
	if got := extractToolCallInvocations("data: not-json\ndata: [DONE]"); got != nil {
		t.Errorf("unparseable frames: got %+v", got)
	}
}
