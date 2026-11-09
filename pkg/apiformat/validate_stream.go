package apiformat

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

type anthBlock struct {
	kind    string
	open    bool
	stopped bool
	partial strings.Builder
}

type respItem struct {
	id   string
	kind string
	done bool
}

// ValidateAnthropicStream checks an Anthropic Messages SSE sequence (A1 §11).
// ping events are ignored. An error event ends the stream and does not require
// message_delta or message_stop.
func ValidateAnthropicStream(events []SSEEvent) error {
	var (
		seenStart   bool
		startCount  int
		nextIndex   int
		stopReasons int
		stops       int
		sawError    bool
		last        string
	)
	blocks := map[int]*anthBlock{}
	for _, ev := range events {
		name := eventName(ev)
		if name == "ping" {
			continue
		}
		last = name
		if !seenStart && name != "message_start" {
			return fmt.Errorf("anthropic stream: first event %q, want message_start", name)
		}
		seenStart = true
		switch name {
		case "message_start":
			startCount++
			if startCount > 1 {
				return fmt.Errorf("anthropic stream: duplicate message_start")
			}
		case "content_block_start":
			idx, kind, err := anthropicBlockStart(ev.Data)
			if err != nil {
				return err
			}
			if idx != nextIndex {
				return fmt.Errorf("anthropic stream: content_block_start index %d, want %d", idx, nextIndex)
			}
			nextIndex++
			blocks[idx] = &anthBlock{kind: kind, open: true}
		case "content_block_delta":
			idx, deltaType, partial, err := anthropicBlockDelta(ev.Data)
			if err != nil {
				return err
			}
			b := blocks[idx]
			if b == nil || !b.open || b.stopped {
				return fmt.Errorf("anthropic stream: delta for unopened index %d", idx)
			}
			if !anthropicDeltaMatches(b.kind, deltaType) {
				return fmt.Errorf("anthropic stream: delta %q does not match block %q", deltaType, b.kind)
			}
			if deltaType == "input_json_delta" {
				b.partial.WriteString(partial)
			}
		case "content_block_stop":
			idx, err := anthropicIndex(ev.Data)
			if err != nil {
				return err
			}
			b := blocks[idx]
			if b == nil || b.stopped {
				return fmt.Errorf("anthropic stream: duplicate or missing stop for index %d", idx)
			}
			b.open = false
			b.stopped = true
		case "message_delta":
			if anthropicStopReason(ev.Data) == "" {
				continue
			}
			if anyBlockOpen(blocks) {
				return fmt.Errorf("anthropic stream: message_delta while a block is open")
			}
			stopReasons++
			if stopReasons > 1 {
				return fmt.Errorf("anthropic stream: duplicate message_delta stop_reason")
			}
		case "message_stop":
			stops++
			if stops > 1 {
				return fmt.Errorf("anthropic stream: duplicate message_stop")
			}
		case "error":
			sawError = true
		default:
			return fmt.Errorf("anthropic stream: unknown event %q", name)
		}
	}
	if startCount != 1 {
		return fmt.Errorf("anthropic stream: want exactly one message_start")
	}
	if sawError {
		if last != "error" {
			return fmt.Errorf("anthropic stream: error must be the last event")
		}
		return nil
	}
	if last != "message_stop" {
		return fmt.Errorf("anthropic stream: missing message_stop")
	}
	if stopReasons != 1 {
		return fmt.Errorf("anthropic stream: want exactly one message_delta with stop_reason")
	}
	for i := 0; i < nextIndex; i++ {
		b := blocks[i]
		if b == nil || !b.stopped {
			return fmt.Errorf("anthropic stream: index %d was not stopped", i)
		}
		if b.kind != "tool_use" {
			continue
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal([]byte(b.partial.String()), &obj); err != nil {
			return fmt.Errorf("anthropic stream: tool_use index %d partial_json is not an object", i)
		}
	}
	return nil
}

// ValidateResponsesStream checks a Responses API SSE sequence (A1 §11).
func ValidateResponsesStream(events []SSEEvent) error {
	if len(events) < 2 {
		return fmt.Errorf("responses stream: need response.created and response.in_progress")
	}
	names := make([]string, len(events))
	for i, ev := range events {
		names[i] = eventName(ev)
		seq, ok := jsonIntField(ev.Data, "sequence_number")
		if !ok {
			return fmt.Errorf("responses stream: event %d missing sequence_number", i)
		}
		if seq != i {
			return fmt.Errorf("responses stream: sequence_number %d, want %d", seq, i)
		}
	}
	if names[0] != "response.created" || names[1] != "response.in_progress" {
		return fmt.Errorf("responses stream: first events %q %q", names[0], names[1])
	}
	items := map[int]*respItem{}
	nextIndex := 0
	terminals := 0
	var terminal string
	for i, ev := range events {
		switch names[i] {
		case "response.created", "response.in_progress":
			continue
		case "response.output_item.added":
			idx, ok := jsonIntField(ev.Data, "output_index")
			if !ok || idx != nextIndex {
				return fmt.Errorf("responses stream: output_item.added index")
			}
			id, kind := jsonItem(ev.Data)
			items[idx] = &respItem{id: id, kind: kind}
			nextIndex++
		case "response.output_item.done":
			idx, ok := jsonIntField(ev.Data, "output_index")
			it := items[idx]
			if !ok || it == nil || it.done {
				return fmt.Errorf("responses stream: output_item.done index %d", idx)
			}
			id, kind := jsonItem(ev.Data)
			if id != it.id || kind != it.kind {
				return fmt.Errorf("responses stream: done item does not match added item")
			}
			it.done = true
		case "response.output_text.delta", "response.output_text.done",
			"response.content_part.added", "response.content_part.done",
			"response.function_call_arguments.delta", "response.function_call_arguments.done",
			"response.custom_tool_call_input.delta", "response.custom_tool_call_input.done":
			idx, ok := jsonIntField(ev.Data, "output_index")
			it := items[idx]
			if !ok || it == nil || it.done {
				return fmt.Errorf("responses stream: delta outside an open item")
			}
		case "response.completed", "response.incomplete", "response.failed":
			terminals++
			terminal = names[i]
			if i != len(events)-1 {
				return fmt.Errorf("responses stream: terminal event is not last")
			}
		default:
			return fmt.Errorf("responses stream: unknown event %q", names[i])
		}
	}
	if terminals != 1 {
		return fmt.Errorf("responses stream: want exactly one terminal event")
	}
	for i := 0; i < nextIndex; i++ {
		if items[i] == nil || !items[i].done {
			return fmt.Errorf("responses stream: output_index %d missing done", i)
		}
	}
	if terminal != "response.completed" {
		return nil
	}
	out := jsonOutput(events[len(events)-1].Data)
	if len(out) != nextIndex {
		return fmt.Errorf("responses stream: completed output length %d, want %d", len(out), nextIndex)
	}
	for i := 0; i < nextIndex; i++ {
		if out[i].id != items[i].id || out[i].kind != items[i].kind {
			return fmt.Errorf("responses stream: completed output[%d] does not match done item", i)
		}
	}
	return nil
}

// ValidateChatStream checks OpenAI chat SSE lines. Every data payload except
// [DONE] must be JSON, [DONE] must be the last data line, and the first time
// a tool-call index appears it must not be lower than an index already seen.
// Payloads must also be valid UTF-8 (RFC 8259 §8.1): the JSON scanner alone
// does not check encoding, so a multi-byte rune torn apart by a mid-chunk
// re-split would otherwise pass. The [DONE] payload is recognized with or
// without the separating space after "data:" — producers emit the spaced
// form, the compact form is tolerated. Tool-call argument fragments are NOT
// judged as JSON: the wire contract is fail-open passthrough (D2), fragments
// may or may not assemble into one JSON value.
func ValidateChatStream(lines []string) error {
	seenDone := false
	dataLines := 0
	highest := -1
	seen := map[int]struct{}{}
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimPrefix(line, "data:")
		payload = strings.TrimPrefix(payload, " ")
		dataLines++
		if payload == "[DONE]" {
			if seenDone {
				return fmt.Errorf("chat stream: duplicate [DONE]")
			}
			seenDone = true
			continue
		}
		if seenDone {
			return fmt.Errorf("chat stream: data after [DONE]")
		}
		if !utf8.ValidString(payload) {
			return fmt.Errorf("chat stream: data is not valid UTF-8")
		}
		if !json.Valid([]byte(payload)) {
			return fmt.Errorf("chat stream: data is not JSON")
		}
		var chunk struct {
			Choices []struct {
				Delta struct {
					ToolCalls []struct {
						Index int `json:"index"`
					} `json:"tool_calls"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			// Valid JSON that is not a chat chunk has no tool-call indexes.
			continue
		}
		for _, choice := range chunk.Choices {
			for _, call := range choice.Delta.ToolCalls {
				if _, ok := seen[call.Index]; ok {
					continue
				}
				if call.Index < highest {
					return fmt.Errorf("chat stream: tool index %d follows %d", call.Index, highest)
				}
				seen[call.Index] = struct{}{}
				highest = call.Index
			}
		}
	}
	if dataLines == 0 || !seenDone {
		return fmt.Errorf("chat stream: missing [DONE]")
	}
	return nil
}

func eventName(ev SSEEvent) string {
	if ev.Event != "" {
		return ev.Event
	}
	return jsonType(ev.Data)
}

func jsonType(data string) string {
	var wrap struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal([]byte(data), &wrap); err != nil {
		return ""
	}
	return wrap.Type
}

func anthropicBlockStart(data string) (int, string, error) {
	var ev struct {
		Index        *int `json:"index"`
		ContentBlock struct {
			Type string `json:"type"`
		} `json:"content_block"`
	}
	if err := json.Unmarshal([]byte(data), &ev); err != nil || ev.Index == nil {
		return 0, "", fmt.Errorf("anthropic stream: bad content_block_start")
	}
	return *ev.Index, ev.ContentBlock.Type, nil
}

func anthropicBlockDelta(data string) (int, string, string, error) {
	var ev struct {
		Index *int `json:"index"`
		Delta struct {
			Type        string `json:"type"`
			PartialJSON string `json:"partial_json"`
		} `json:"delta"`
	}
	if err := json.Unmarshal([]byte(data), &ev); err != nil || ev.Index == nil {
		return 0, "", "", fmt.Errorf("anthropic stream: bad content_block_delta")
	}
	return *ev.Index, ev.Delta.Type, ev.Delta.PartialJSON, nil
}

func anthropicIndex(data string) (int, error) {
	var ev struct {
		Index *int `json:"index"`
	}
	if err := json.Unmarshal([]byte(data), &ev); err != nil || ev.Index == nil {
		return 0, fmt.Errorf("anthropic stream: bad index")
	}
	return *ev.Index, nil
}

func anthropicStopReason(data string) string {
	var ev struct {
		Delta struct {
			StopReason string `json:"stop_reason"`
		} `json:"delta"`
	}
	if err := json.Unmarshal([]byte(data), &ev); err != nil {
		return ""
	}
	return ev.Delta.StopReason
}

func anthropicDeltaMatches(blockKind, deltaType string) bool {
	switch blockKind {
	case "text":
		return deltaType == "text_delta"
	case "tool_use":
		return deltaType == "input_json_delta"
	default:
		return false
	}
}

func anyBlockOpen(blocks map[int]*anthBlock) bool {
	for _, b := range blocks {
		if b.open {
			return true
		}
	}
	return false
}

func jsonIntField(data, field string) (int, bool) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(data), &raw); err != nil {
		return 0, false
	}
	v, ok := raw[field]
	if !ok {
		return 0, false
	}
	var n int
	if err := json.Unmarshal(v, &n); err != nil {
		return 0, false
	}
	return n, true
}

func jsonItem(data string) (string, string) {
	var ev struct {
		Item struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		} `json:"item"`
	}
	_ = json.Unmarshal([]byte(data), &ev)
	return ev.Item.ID, ev.Item.Type
}

type outputRef struct {
	id   string
	kind string
}

func jsonOutput(data string) []outputRef {
	var ev struct {
		Response struct {
			Output []struct {
				ID   string `json:"id"`
				Type string `json:"type"`
			} `json:"output"`
		} `json:"response"`
	}
	if err := json.Unmarshal([]byte(data), &ev); err != nil {
		return nil
	}
	out := make([]outputRef, len(ev.Response.Output))
	for i, item := range ev.Response.Output {
		out[i] = outputRef{id: item.ID, kind: item.Type}
	}
	return out
}
