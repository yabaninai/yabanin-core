package apiformat

import "testing"

func anth(event, data string) SSEEvent { return SSEEvent{Event: event, Data: data} }

func TestValidateAnthropicStream_Valid(t *testing.T) {
	events := []SSEEvent{
		anth("ping", `{"type":"ping"}`),
		anth("message_start", `{"type":"message_start"}`),
		anth("content_block_start", `{"index":0,"content_block":{"type":"text"}}`),
		anth("content_block_delta", `{"index":0,"delta":{"type":"text_delta","text":"hi"}}`),
		anth("content_block_stop", `{"index":0}`),
		anth("content_block_start", `{"index":1,"content_block":{"type":"tool_use"}}`),
		anth("content_block_delta", `{"index":1,"delta":{"type":"input_json_delta","partial_json":"{\"a\":"}}`),
		anth("content_block_delta", `{"index":1,"delta":{"type":"input_json_delta","partial_json":"1}"}}`),
		anth("content_block_stop", `{"index":1}`),
		anth("message_delta", `{"delta":{"stop_reason":"tool_use"}}`),
		anth("message_stop", `{"type":"message_stop"}`),
	}
	if err := ValidateAnthropicStream(events); err != nil {
		t.Fatal(err)
	}
}

func TestValidateAnthropicStream_DeltaWithoutStart(t *testing.T) {
	events := []SSEEvent{
		anth("message_start", `{}`),
		anth("content_block_delta", `{"index":0,"delta":{"type":"text_delta","text":"x"}}`),
		anth("message_delta", `{"delta":{"stop_reason":"end_turn"}}`),
		anth("message_stop", `{}`),
	}
	if err := ValidateAnthropicStream(events); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateAnthropicStream_DoubleStop(t *testing.T) {
	events := []SSEEvent{
		anth("message_start", `{}`),
		anth("content_block_start", `{"index":0,"content_block":{"type":"text"}}`),
		anth("content_block_stop", `{"index":0}`),
		anth("content_block_stop", `{"index":0}`),
		anth("message_delta", `{"delta":{"stop_reason":"end_turn"}}`),
		anth("message_stop", `{}`),
	}
	if err := ValidateAnthropicStream(events); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateAnthropicStream_SkippedIndex(t *testing.T) {
	events := []SSEEvent{
		anth("message_start", `{}`),
		anth("content_block_start", `{"index":1,"content_block":{"type":"text"}}`),
		anth("content_block_stop", `{"index":1}`),
		anth("message_delta", `{"delta":{"stop_reason":"end_turn"}}`),
		anth("message_stop", `{}`),
	}
	if err := ValidateAnthropicStream(events); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateAnthropicStream_MissingMessageStop(t *testing.T) {
	events := []SSEEvent{
		anth("message_start", `{}`),
		anth("content_block_start", `{"index":0,"content_block":{"type":"text"}}`),
		anth("content_block_delta", `{"index":0,"delta":{"type":"text_delta","text":"x"}}`),
		anth("content_block_stop", `{"index":0}`),
		anth("message_delta", `{"delta":{"stop_reason":"end_turn"}}`),
	}
	if err := ValidateAnthropicStream(events); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateAnthropicStream_ErrorEndsStream(t *testing.T) {
	events := []SSEEvent{
		anth("message_start", `{}`),
		anth("error", `{"type":"error"}`),
	}
	if err := ValidateAnthropicStream(events); err != nil {
		t.Fatal(err)
	}
}

func TestValidateAnthropicStream_BadPartialJSON(t *testing.T) {
	events := []SSEEvent{
		anth("message_start", `{}`),
		anth("content_block_start", `{"index":0,"content_block":{"type":"tool_use"}}`),
		anth("content_block_delta", `{"index":0,"delta":{"type":"input_json_delta","partial_json":"["}}`),
		anth("content_block_stop", `{"index":0}`),
		anth("message_delta", `{"delta":{"stop_reason":"tool_use"}}`),
		anth("message_stop", `{}`),
	}
	if err := ValidateAnthropicStream(events); err == nil {
		t.Fatal("expected error")
	}
}

func respEv(event string, seq int, extra string) SSEEvent {
	data := `{"type":"` + event + `","sequence_number":` + itoa(seq)
	if extra != "" {
		data += "," + extra
	}
	data += `}`
	return SSEEvent{Event: event, Data: data}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func TestValidateResponsesStream_Valid(t *testing.T) {
	events := []SSEEvent{
		respEv("response.created", 0, ""),
		respEv("response.in_progress", 1, ""),
		respEv("response.output_item.added", 2, `"output_index":0,"item":{"id":"msg_1","type":"message"}`),
		respEv("response.output_text.delta", 3, `"output_index":0,"delta":"hi"`),
		respEv("response.output_item.done", 4, `"output_index":0,"item":{"id":"msg_1","type":"message"}`),
		respEv("response.completed", 5, `"response":{"output":[{"id":"msg_1","type":"message"}]}`),
	}
	if err := ValidateResponsesStream(events); err != nil {
		t.Fatal(err)
	}
}

func TestValidateResponsesStream_DeltaWithoutItem(t *testing.T) {
	events := []SSEEvent{
		respEv("response.created", 0, ""),
		respEv("response.in_progress", 1, ""),
		respEv("response.output_text.delta", 2, `"output_index":0`),
		respEv("response.completed", 3, `"response":{"output":[]}`),
	}
	if err := ValidateResponsesStream(events); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateResponsesStream_DoubleDone(t *testing.T) {
	events := []SSEEvent{
		respEv("response.created", 0, ""),
		respEv("response.in_progress", 1, ""),
		respEv("response.output_item.added", 2, `"output_index":0,"item":{"id":"msg_1","type":"message"}`),
		respEv("response.output_item.done", 3, `"output_index":0,"item":{"id":"msg_1","type":"message"}`),
		respEv("response.output_item.done", 4, `"output_index":0,"item":{"id":"msg_1","type":"message"}`),
		respEv("response.completed", 5, `"response":{"output":[{"id":"msg_1","type":"message"}]}`),
	}
	if err := ValidateResponsesStream(events); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateResponsesStream_SkippedIndex(t *testing.T) {
	events := []SSEEvent{
		respEv("response.created", 0, ""),
		respEv("response.in_progress", 1, ""),
		respEv("response.output_item.added", 2, `"output_index":1,"item":{"id":"msg_1","type":"message"}`),
		respEv("response.output_item.done", 3, `"output_index":1,"item":{"id":"msg_1","type":"message"}`),
		respEv("response.completed", 4, `"response":{"output":[{"id":"msg_1","type":"message"}]}`),
	}
	if err := ValidateResponsesStream(events); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateResponsesStream_MissingTerminal(t *testing.T) {
	events := []SSEEvent{
		respEv("response.created", 0, ""),
		respEv("response.in_progress", 1, ""),
		respEv("response.output_item.added", 2, `"output_index":0,"item":{"id":"msg_1","type":"message"}`),
		respEv("response.output_item.done", 3, `"output_index":0,"item":{"id":"msg_1","type":"message"}`),
	}
	if err := ValidateResponsesStream(events); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateResponsesStream_Incomplete(t *testing.T) {
	events := []SSEEvent{
		respEv("response.created", 0, ""),
		respEv("response.in_progress", 1, ""),
		respEv("response.incomplete", 2, ""),
	}
	if err := ValidateResponsesStream(events); err != nil {
		t.Fatal(err)
	}
}

func TestValidateAnthropicStream_NameFromJSONType(t *testing.T) {
	events := []SSEEvent{
		{Data: `{"type":"message_start"}`},
		{Data: `{"type":"content_block_start","index":0,"content_block":{"type":"text"}}`},
		{Data: `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{}"}}`},
		{Data: `{"type":"message_stop"}`},
	}
	if err := ValidateAnthropicStream(events); err == nil {
		t.Fatal("expected delta type mismatch")
	}
	open := []SSEEvent{
		anth("message_start", `{}`),
		anth("content_block_start", `{"index":0,"content_block":{"type":"text"}}`),
		anth("message_delta", `{"delta":{"stop_reason":"end_turn"}}`),
		anth("message_stop", `{}`),
	}
	if err := ValidateAnthropicStream(open); err == nil {
		t.Fatal("expected message_delta while block is open")
	}
	if err := ValidateAnthropicStream([]SSEEvent{anth("content_block_start", `{"index":0}`)}); err == nil {
		t.Fatal("expected first-event error")
	}
}

func TestValidateResponsesStream_SequenceAndOutput(t *testing.T) {
	gap := []SSEEvent{
		respEv("response.created", 0, ""),
		respEv("response.in_progress", 2, ""),
	}
	if err := ValidateResponsesStream(gap); err == nil {
		t.Fatal("expected sequence error")
	}
	mismatch := []SSEEvent{
		respEv("response.created", 0, ""),
		respEv("response.in_progress", 1, ""),
		respEv("response.output_item.added", 2, `"output_index":0,"item":{"id":"msg_1","type":"message"}`),
		respEv("response.function_call_arguments.delta", 3, `"output_index":0`),
		respEv("response.output_item.done", 4, `"output_index":0,"item":{"id":"msg_1","type":"message"}`),
		respEv("response.completed", 5, `"response":{"output":[{"id":"other","type":"message"}]}`),
	}
	if err := ValidateResponsesStream(mismatch); err == nil {
		t.Fatal("expected output mismatch")
	}
	if err := ValidateResponsesStream(nil); err == nil {
		t.Fatal("expected short stream error")
	}
}

func TestValidateChatStream_ToolIndexes(t *testing.T) {
	lines := []string{
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0}]}}]}`,
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0},{"index":1}]}}]}`,
		"data: [DONE]",
	}
	if err := ValidateChatStream(lines); err != nil {
		t.Fatal(err)
	}
	bad := []string{
		`data: {"choices":[{"delta":{"tool_calls":[{"index":1}]}}]}`,
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0}]}}]}`,
		"data: [DONE]",
	}
	if err := ValidateChatStream(bad); err == nil {
		t.Fatal("expected decreasing index to fail")
	}
	if err := ValidateChatStream([]string{`data: {`, "data: [DONE]"}); err == nil {
		t.Fatal("expected invalid json to fail")
	}
	if err := ValidateChatStream([]string{`data: {"choices":[]}`}); err == nil {
		t.Fatal("expected missing DONE to fail")
	}
	if err := ValidateChatStream([]string{"data: [DONE]", `data: {"choices":[]}`}); err == nil {
		t.Fatal("expected data after DONE to fail")
	}
	if err := ValidateChatStream([]string{"data: 1", "data: [DONE]"}); err != nil {
		t.Fatal(err)
	}
}

// TestValidateChatStream_DONEForms pins the terminator boundary: producers
// emit the spaced canonical form; the compact form without the separating
// space is tolerated by the oracle (both must count as the one [DONE]).
func TestValidateChatStream_DONEForms(t *testing.T) {
	spaced := []string{`data: {"choices":[]}`, "data: [DONE]"}
	if err := ValidateChatStream(spaced); err != nil {
		t.Fatalf("spaced producer form: %v", err)
	}
	unspaced := []string{`data: {"choices":[]}`, "data:[DONE]"}
	if err := ValidateChatStream(unspaced); err != nil {
		t.Fatalf("unspaced compact form: %v", err)
	}
	mixed := []string{`data: {"choices":[]}`, "data:[DONE]", "data: [DONE]"}
	if err := ValidateChatStream(mixed); err == nil {
		t.Fatal("expected duplicate [DONE] across forms to fail")
	}
}

// TestValidateChatStream_UTF8 pins the encoding boundary (N03-P01-T03):
// json.Valid alone does not reject raw invalid bytes inside strings, so a
// stream whose multi-byte runes were torn apart by a mid-chunk re-split must
// be caught by the encoding check, while real multi-byte content passes.
func TestValidateChatStream_UTF8(t *testing.T) {
	rawInvalid := "data: {\"choices\":[{\"delta\":{\"content\":\"\xff\"}}]}"
	if err := ValidateChatStream([]string{rawInvalid, "data: [DONE]"}); err == nil {
		t.Fatal("expected invalid UTF-8 payload to fail")
	}
	// Torn 3-byte rune: 0xD1 is a leading byte, 'b' is not a continuation.
	torn := "data: {\"choices\":[{\"delta\":{\"content\":\"a\xd1b\"}}]}"
	if err := ValidateChatStream([]string{torn, "data: [DONE]"}); err == nil {
		t.Fatal("expected torn multi-byte sequence to fail")
	}
}

// TestValidateChatStream_MultiByteContentAccepted proves the oracle accepts
// valid multi-byte content — rejecting broken UTF-8 must not reject CJK,
// Cyrillic or emoji.
func TestValidateChatStream_MultiByteContentAccepted(t *testing.T) {
	lines := []string{
		`data: {"choices":[{"index":0,"delta":{"content":"привет 🚀 日本語"}}]}`,
		"data: [DONE]",
	}
	if err := ValidateChatStream(lines); err != nil {
		t.Fatal(err)
	}
}

// TestValidateChatStream_ReasoningDeltasAccepted pins reasoning deltas
// (delta.reasoning_content) as first-class stream members: they are valid
// chat frames and must not trip any framing rule.
func TestValidateChatStream_ReasoningDeltasAccepted(t *testing.T) {
	lines := []string{
		`data: {"choices":[{"index":0,"delta":{"role":"assistant","reasoning_content":""}}]}`,
		`data: {"choices":[{"index":0,"delta":{"reasoning_content":"шаг 1…"}}]}`,
		`data: {"choices":[{"index":0,"delta":{"reasoning_content":"готово"}}]}`,
		`data: {"choices":[{"index":0,"delta":{"content":"ответ"}}]}`,
		`data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`,
		"data: [DONE]",
	}
	if err := ValidateChatStream(lines); err != nil {
		t.Fatal(err)
	}
}

// TestValidateChatStream_ToolFragmentsNotJudgedAsJSON pins the partial-JSON
// boundary (N03-P01-T03): argument fragments of one call split across frames
// and two calls interleaved by index are well-formed. The oracle judges
// framing and index order only — it does NOT require fragments to assemble
// into valid JSON (live passthrough contract, D2).
func TestValidateChatStream_ToolFragmentsNotJudgedAsJSON(t *testing.T) {
	lines := []string{
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_a","type":"function","function":{"name":"f","arguments":""}}]}}]}`,
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"a\":"}}]}}]}`,
		`data: {"choices":[{"delta":{"tool_calls":[{"index":1,"id":"call_b","type":"function","function":{"name":"g","arguments":"{\"b\":"}}]}}]}`,
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"1}"}}]}}]}`,
		`data: {"choices":[{"delta":{"tool_calls":[{"index":1,"function":{"arguments":"2}"}}]}}]}`,
		"data: [DONE]",
	}
	if err := ValidateChatStream(lines); err != nil {
		t.Fatal(err)
	}
}
