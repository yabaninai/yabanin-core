package streaming

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// chunkFrame renders one chat.completion.chunk SSE event with the given
// delta content.
func chunkFrame(t *testing.T, id, content string) []byte {
	t.Helper()
	ch := map[string]any{
		"id":      id,
		"object":  "chat.completion.chunk",
		"created": int64(1),
		"model":   "test-model",
		"choices": []any{map[string]any{
			"index":         0,
			"delta":         map[string]any{"content": content},
			"finish_reason": nil,
		}},
	}
	b, err := json.Marshal(ch)
	if err != nil {
		t.Fatalf("marshal chunk: %v", err)
	}
	return append(append([]byte("data: "), b...), '\n', '\n')
}

// parseContent extracts choices[0].delta.content of a data frame.
func parseContent(t *testing.T, frame []byte) (string, bool) {
	t.Helper()
	_, payload, _, ok, done := splitSSEData(frame)
	if !ok || done {
		return "", false
	}
	var top struct {
		Choices []struct {
			Delta struct {
				Content *string `json:"content"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(payload, &top); err != nil {
		t.Fatalf("frame is not valid JSON: %v (%q)", err, frame)
	}
	if len(top.Choices) == 0 || top.Choices[0].Delta.Content == nil {
		return "", false
	}
	return *top.Choices[0].Delta.Content, true
}

func TestFrameProcessor_PreservesSSEStructure(t *testing.T) {
	cp, err := NewChunkProcessor(map[string]string{testSecretTrigger: testSecretMask})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	fp := NewFrameProcessor(cp)

	out := fp.ProcessFrame(chunkFrame(t, "c1", "value is "+testSecretTrigger+" end"))
	if got, _ := parseContent(t, out); got != "value is "+testSecretMask+" end" {
		t.Fatalf("mutated content = %q", got)
	}
	if !bytes.HasSuffix(out, []byte("\n\n")) {
		t.Fatalf("event boundary broken: %q", out)
	}
	if !bytes.HasPrefix(out, []byte("data: ")) {
		t.Fatalf("data line prefix broken: %q", out)
	}

	// A longer replacement changes the frame length: the boundary must be
	// rebuilt around it, not broken.
	long := chunkFrame(t, "c2", testSecretTrigger)
	if got, _ := parseContent(t, fp.ProcessFrame(long)); got != testSecretMask {
		t.Fatalf("shrunk content = %q", got)
	}
}

func TestFrameProcessor_TerminatorPassthrough(t *testing.T) {
	cp, _ := NewChunkProcessor(map[string]string{"DONE": "X"})
	fp := NewFrameProcessor(cp)
	done := []byte("data: [DONE]\n\n")
	if got := fp.ProcessFrame(done); !bytes.Equal(got, done) {
		t.Fatalf("[DONE] rewritten: %q", got)
	}
	if got := fp.ProcessFrame([]byte(": keep-alive comment\n\n")); !bytes.Equal(got, []byte(": keep-alive comment\n\n")) {
		t.Fatalf("comment line rewritten: %q", got)
	}
}

func TestFrameProcessor_NonContentFramesPassthrough(t *testing.T) {
	cp, _ := NewChunkProcessor(map[string]string{"assistant": "X", "stop": "Y"})
	fp := NewFrameProcessor(cp)

	tests := [][]byte{
		[]byte(`data: {"id":"c1","choices":[{"index":0,"delta":{"role":"assistant"}}]}` + "\n\n"),
		[]byte(`data: {"id":"c1","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}` + "\n\n"),
		[]byte(`data: {"id":"c1","choices":[{"index":0,"delta":{"content":null}}]}` + "\n\n"),
		[]byte(`data: {"usage":{"total_tokens":5}}` + "\n\n"),
		[]byte("data: not-json\n\n"),
	}
	for i, frame := range tests {
		if got := fp.ProcessFrame(frame); !bytes.Equal(got, frame) {
			t.Fatalf("frame %d rewritten: %q", i, got)
		}
	}
}

func TestFrameProcessor_UnknownFieldsSurvive(t *testing.T) {
	cp, _ := NewChunkProcessor(map[string]string{"b": "X"})
	fp := NewFrameProcessor(cp)
	frame := []byte(`data: {"id":"c1","custom":{"nested":[1,2,"b"]},"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"a b c"},"logprobs":null}]}` + "\n\n")
	out := fp.ProcessFrame(frame)
	var top map[string]json.RawMessage
	_, payload, _, ok, _ := splitSSEData(out)
	if !ok {
		t.Fatal("no data line in output")
	}
	if err := json.Unmarshal(payload, &top); err != nil {
		t.Fatalf("output not JSON: %v", err)
	}
	if string(top["custom"]) != `{"nested":[1,2,"b"]}` {
		t.Fatalf("custom field lost: %s", top["custom"])
	}
	if got, _ := parseContent(t, out); got != "a X c" {
		t.Fatalf("content = %q", got)
	}
}

func TestFrameProcessor_FullStreamNoLeak(t *testing.T) {
	cp, err := NewChunkProcessor(map[string]string{testSecretTrigger: testSecretMask})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	fp := NewFrameProcessor(cp)

	// The alias is split across three frames.
	frames := [][]byte{
		chunkFrame(t, "c1", "the value is super-"),
		chunkFrame(t, "c1", "secret-"),
		chunkFrame(t, "c1", "value, done"),
		[]byte("data: [DONE]\n\n"),
	}
	var wire bytes.Buffer
	for _, f := range frames {
		wire.Write(fp.ProcessFrame(f))
	}
	if tail := fp.FlushFrame("c1", "test-model"); tail != nil {
		t.Fatalf("nothing should be held after a complete match: %q", tail)
	}
	full := wire.String()
	if strings.Contains(full, testSecretTrigger) {
		t.Fatalf("original leaked across frame boundaries: %q", full)
	}
	if !strings.Contains(full, "data: [DONE]\n\n") {
		t.Fatal("terminator lost")
	}
	// Every emitted frame must parse independently.
	for _, line := range strings.Split(full, "\n\n") {
		if line == "" {
			continue
		}
		var top map[string]any
		if after, ok := bytes.CutPrefix([]byte(line), []byte("data: ")); ok {
			if string(after) == "[DONE]" {
				continue
			}
			if err := json.Unmarshal(after, &top); err != nil {
				t.Fatalf("frame does not parse after mutation: %v (%q)", err, line)
			}
		}
	}
}

func TestFrameProcessor_FlushFrameCarriesTail(t *testing.T) {
	cp, err := NewChunkProcessor(map[string]string{testSecretTrigger: testSecretMask})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	fp := NewFrameProcessor(cp)
	out := fp.ProcessFrame(chunkFrame(t, "c1", "starts super-"))
	if got, _ := parseContent(t, out); got != "starts " {
		t.Fatalf("held frame content = %q, want the non-match prefix", got)
	}
	tail := fp.FlushFrame("c1", "test-model")
	if tail == nil {
		t.Fatal("held tail lost at end of stream")
	}
	if !bytes.HasPrefix(tail, []byte("data: ")) || !bytes.HasSuffix(tail, []byte("\n\n")) {
		t.Fatalf("flush frame is not a valid SSE event: %q", tail)
	}
	if got, ok := parseContent(t, tail); !ok || got != "super-" {
		t.Fatalf("flush content = %q ok=%v", got, ok)
	}
}

func TestFrameProcessor_SecondaryChoiceUntouched(t *testing.T) {
	cp, _ := NewChunkProcessor(map[string]string{"secret": "X"})
	fp := NewFrameProcessor(cp)
	frame := []byte(`data: {"id":"c1","choices":[{"index":0,"delta":{"content":"a secret"}},{"index":1,"delta":{"content":"b secret"}}]}` + "\n\n")
	out := fp.ProcessFrame(frame)
	var top struct {
		Choices []struct {
			Index int `json:"index"`
			Delta struct {
				Content *string `json:"content"`
			} `json:"delta"`
		} `json:"choices"`
	}
	_, payload, _, ok, _ := splitSSEData(out)
	if !ok {
		t.Fatal("no data line")
	}
	if err := json.Unmarshal(payload, &top); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if len(top.Choices) != 2 || top.Choices[0].Delta.Content == nil || top.Choices[1].Delta.Content == nil {
		t.Fatalf("choices lost: %+v", top)
	}
	if *top.Choices[0].Delta.Content != "a X" {
		t.Fatalf("primary choice = %q", *top.Choices[0].Delta.Content)
	}
	if *top.Choices[1].Delta.Content != "b secret" {
		t.Fatalf("secondary choice must pass through: %q", *top.Choices[1].Delta.Content)
	}
}

func TestSplitSSEData(t *testing.T) {
	head, payload, tail, ok, done := splitSSEData([]byte("event: x\ndata: hello\n\n"))
	if !ok || done || string(head) != "event: x\n" || string(payload) != "hello" || string(tail) != "\n\n" {
		t.Fatalf("split = (%q, %q, %q, %v, %v)", head, payload, tail, ok, done)
	}
	_, payload, _, ok, done = splitSSEData([]byte("data:no-space\n"))
	if !ok || done || string(payload) != "no-space" {
		t.Fatalf("no-space split = (%q, %v, %v)", payload, ok, done)
	}
	_, _, _, ok, done = splitSSEData([]byte("data: [DONE]\n\n"))
	if !ok || !done {
		t.Fatalf("[DONE] = (ok=%v, done=%v)", ok, done)
	}
	_, _, _, ok, _ = splitSSEData([]byte("event: only\n\n"))
	if ok {
		t.Fatal("event without a data line reported ok")
	}
}

// TestSplitSSEData_UnspacedDONE pins the compact terminator form
// (N03-P01-T03 boundary): producers emit "data: [DONE]", the compact
// "data:[DONE]" must be recognized as the same terminator.
func TestSplitSSEData_UnspacedDONE(t *testing.T) {
	_, _, _, ok, done := splitSSEData([]byte("data:[DONE]\n\n"))
	if !ok || !done {
		t.Fatalf("unspaced [DONE] = (ok=%v, done=%v)", ok, done)
	}
}

// TestFrameProcessor_ReasoningFramePassthrough pins the reasoning facet
// (N03-P01-T03): reasoning_content rides delta without content, so the frame
// passes through byte-identical even when the replacement map would match
// words inside the reasoning text — reasoning is mutated only via the same
// content contract, which it does not carry here.
func TestFrameProcessor_ReasoningFramePassthrough(t *testing.T) {
	cp, _ := NewChunkProcessor(map[string]string{"think": "X", "answer": "Y"})
	fp := NewFrameProcessor(cp)
	frame := []byte(`data: {"id":"c1","choices":[{"index":0,"delta":{"reasoning_content":"think hard"}}]}` + "\n\n")
	if got := fp.ProcessFrame(frame); !bytes.Equal(got, frame) {
		t.Fatalf("reasoning frame rewritten: %q", got)
	}
}

// TestFrameProcessor_MutationPreservesReasoning proves the re-encode path
// keeps reasoning_content intact: a frame carrying BOTH content and
// reasoning_content is rebuilt around the mutated content — the reasoning
// string (multi-byte) and unknown fields must survive byte-for-byte.
func TestFrameProcessor_MutationPreservesReasoning(t *testing.T) {
	cp, _ := NewChunkProcessor(map[string]string{"secret": "[X]"})
	fp := NewFrameProcessor(cp)
	frame := []byte(`data: {"id":"c1","custom":{"k":"secret"},"choices":[{"index":0,"delta":{"content":"a secret","reasoning_content":"думаю"},"logprobs":null}]}` + "\n\n")
	out := fp.ProcessFrame(frame)
	var top struct {
		Custom  map[string]any `json:"custom"`
		Choices []struct {
			Delta struct {
				Content   *string `json:"content"`
				Reasoning *string `json:"reasoning_content"`
			} `json:"delta"`
		} `json:"choices"`
	}
	_, payload, _, ok, _ := splitSSEData(out)
	if !ok {
		t.Fatal("no data line in output")
	}
	if err := json.Unmarshal(payload, &top); err != nil {
		t.Fatalf("output not JSON: %v (%q)", err, out)
	}
	if len(top.Choices) != 1 || top.Choices[0].Delta.Content == nil {
		t.Fatalf("choices lost: %+v", top)
	}
	if *top.Choices[0].Delta.Content != "a [X]" {
		t.Fatalf("content = %q", *top.Choices[0].Delta.Content)
	}
	if top.Choices[0].Delta.Reasoning == nil || *top.Choices[0].Delta.Reasoning != "думаю" {
		t.Fatalf("reasoning_content = %v", top.Choices[0].Delta.Reasoning)
	}
	if len(top.Custom) != 1 || top.Custom["k"] != "secret" {
		t.Fatalf("custom = %+v", top.Custom)
	}
}

// TestFrameProcessor_ToolCallFragmentsPassthrough pins the tools + partial
// JSON facet (N03-P01-T03): tool-call fragments carrying partial-JSON
// arguments have no delta.content — they must pass through byte-identical
// so the client can assemble the arguments itself.
func TestFrameProcessor_ToolCallFragmentsPassthrough(t *testing.T) {
	cp, _ := NewChunkProcessor(map[string]string{"city": "X", "Moscow": "Y"})
	fp := NewFrameProcessor(cp)
	frames := [][]byte{
		[]byte(`data: {"id":"c1","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":""}}]}}]}` + "\n\n"),
		[]byte(`data: {"id":"c1","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"city\":"}}]}}]}` + "\n\n"),
		[]byte(`data: {"id":"c1","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"Moscow\"}"}}]}}]}` + "\n\n"),
		[]byte(`data: {"id":"c1","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}` + "\n\n"),
	}
	for i, frame := range frames {
		if got := fp.ProcessFrame(frame); !bytes.Equal(got, frame) {
			t.Fatalf("fragment %d rewritten: %q", i, got)
		}
	}
}

// TestFrameProcessor_UnspacedDONEPassthrough pins the compact terminator
// against the mutation path: "data:[DONE]" must never be rewritten, same as
// the spaced canonical form.
func TestFrameProcessor_UnspacedDONEPassthrough(t *testing.T) {
	cp, _ := NewChunkProcessor(map[string]string{"DONE": "X"})
	fp := NewFrameProcessor(cp)
	done := []byte("data:[DONE]\n\n")
	if got := fp.ProcessFrame(done); !bytes.Equal(got, done) {
		t.Fatalf("unspaced [DONE] rewritten: %q", got)
	}
}

// TestFrameProcessor_UTF8ContentReframed pins the UTF-8 facet on the
// mutation path: multi-byte content that triggers a replacement (the censored
// term itself is Cyrillic) re-encodes the frame without tearing any rune —
// the output must still be a valid SSE event whose content decodes exactly.
func TestFrameProcessor_UTF8ContentReframed(t *testing.T) {
	const censoredTerm = "суперсекрет"
	const censoredValue = "[УДАЛЕНО]"
	cp, err := NewChunkProcessor(map[string]string{censoredTerm: censoredValue})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	fp := NewFrameProcessor(cp)

	// The term is split across two frames mid-word (both halves are
	// complete runes; the wire-level byte split is proven at the parser).
	out1 := fp.ProcessFrame(chunkFrame(t, "c1", "пароль: супер"))
	if got, _ := parseContent(t, out1); got != "пароль: " {
		t.Fatalf("frame 1 content = %q", got)
	}
	out2 := fp.ProcessFrame(chunkFrame(t, "c1", "секрет!"))
	if got, _ := parseContent(t, out2); got != censoredValue+"!" {
		t.Fatalf("frame 2 content = %q", got)
	}
	if tail := fp.FlushFrame("c1", "m"); tail != nil {
		t.Fatalf("nothing held after complete match: %q", tail)
	}
}
