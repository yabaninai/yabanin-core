package provider

import (
	"encoding/json"
	"fmt"
)

// AnthropicEventType is the event-type label in Anthropic SSE.
type AnthropicEventType string

const (
	anthropicEventMessageStart      AnthropicEventType = "message_start"
	anthropicEventContentBlockStart AnthropicEventType = "content_block_start"
	anthropicEventContentBlockDelta AnthropicEventType = "content_block_delta"
	anthropicEventContentBlockStop  AnthropicEventType = "content_block_stop"
	anthropicEventMessageDelta      AnthropicEventType = "message_delta"
	anthropicEventMessageStop       AnthropicEventType = "message_stop"
	anthropicEventError             AnthropicEventType = "error"
	anthropicEventPing              AnthropicEventType = "ping"
)

// AnthropicStreamTranslator converts Anthropic SSE events into OpenAI
// chat.completion.chunk payloads. It keeps per-stream state: message id,
// tool-call indexes, and usage for the optional trailing usage chunk.
type AnthropicStreamTranslator struct {
	model        string
	msgID        string
	toolIdx      int
	blockTool    map[int]int
	inputTokens  int64
	outputTokens int64
	cacheRead    int64
	cacheCreate  int64
	emitUsage    bool
}

// NewAnthropicStreamTranslator returns a translator bound to the given model
// name (emitted in every OpenAI chunk). Tool indexes start at -1 so the first
// tool_use block becomes OpenAI index 0.
func NewAnthropicStreamTranslator(model string) *AnthropicStreamTranslator {
	return &AnthropicStreamTranslator{model: model, toolIdx: -1, blockTool: map[int]int{}}
}

// SetEmitUsage controls whether message_stop emits a choices:[] usage chunk.
func (t *AnthropicStreamTranslator) SetEmitUsage(v bool) { t.emitUsage = v }

// Translate converts one Anthropic event payload into zero or one OpenAI
// chunk. done is true on message_stop; the caller emits [DONE] after the chunk.
func (t *AnthropicStreamTranslator) Translate(eventType, data string) (chunk string, done bool, err error) {
	switch AnthropicEventType(eventType) {
	case anthropicEventPing, anthropicEventContentBlockStop:
		return "", false, nil
	case anthropicEventMessageStart:
		return t.onMessageStart(data)
	case anthropicEventContentBlockStart:
		return t.onBlockStart(data)
	case anthropicEventContentBlockDelta:
		return t.onBlockDelta(data)
	case anthropicEventMessageDelta:
		return t.onMessageDelta(data)
	case anthropicEventMessageStop:
		if t.emitUsage {
			return t.usageChunk(), true, nil
		}
		return "", true, nil
	case anthropicEventError:
		return "", false, fmt.Errorf("anthropic stream error: %s", data)
	}
	return "", false, nil
}

func (t *AnthropicStreamTranslator) onMessageStart(data string) (string, bool, error) {
	var ms struct {
		Message struct {
			ID    string `json:"id"`
			Usage struct {
				InputTokens              int64 `json:"input_tokens"`
				OutputTokens             int64 `json:"output_tokens"`
				CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
				CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
			} `json:"usage"`
		} `json:"message"`
	}
	if err := json.Unmarshal([]byte(data), &ms); err != nil {
		return "", false, fmt.Errorf("decode message_start: %w", err)
	}
	t.msgID = ms.Message.ID
	t.inputTokens = ms.Message.Usage.InputTokens
	t.outputTokens = ms.Message.Usage.OutputTokens
	t.cacheRead = ms.Message.Usage.CacheReadInputTokens
	t.cacheCreate = ms.Message.Usage.CacheCreationInputTokens
	return t.deltaChunk(map[string]any{"role": "assistant"}, nil), false, nil
}

func (t *AnthropicStreamTranslator) onBlockStart(data string) (string, bool, error) {
	var ev struct {
		Index        int `json:"index"`
		ContentBlock struct {
			Type string `json:"type"`
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"content_block"`
	}
	if err := json.Unmarshal([]byte(data), &ev); err != nil {
		return "", false, fmt.Errorf("decode content_block_start: %w", err)
	}
	if ev.ContentBlock.Type != "tool_use" {
		return "", false, nil
	}
	t.toolIdx++
	t.blockTool[ev.Index] = t.toolIdx
	delta := map[string]any{
		"tool_calls": []any{map[string]any{
			"index": t.toolIdx,
			"id":    ev.ContentBlock.ID,
			"type":  "function",
			"function": map[string]any{
				"name":      ev.ContentBlock.Name,
				"arguments": "",
			},
		}},
	}
	return t.deltaChunk(delta, nil), false, nil
}

func (t *AnthropicStreamTranslator) onBlockDelta(data string) (string, bool, error) {
	var d struct {
		Index int `json:"index"`
		Delta struct {
			Type        string `json:"type"`
			Text        string `json:"text"`
			PartialJSON string `json:"partial_json"`
		} `json:"delta"`
	}
	if err := json.Unmarshal([]byte(data), &d); err != nil {
		return "", false, fmt.Errorf("decode content_block_delta: %w", err)
	}
	switch d.Delta.Type {
	case "text_delta":
		if d.Delta.Text == "" {
			return "", false, nil
		}
		return t.deltaChunk(map[string]any{"content": d.Delta.Text}, nil), false, nil
	case "input_json_delta":
		idx, ok := t.blockTool[d.Index]
		if !ok {
			return "", false, nil
		}
		delta := map[string]any{
			"tool_calls": []any{map[string]any{
				"index": idx,
				"function": map[string]any{
					"arguments": d.Delta.PartialJSON,
				},
			}},
		}
		return t.deltaChunk(delta, nil), false, nil
	default:
		// thinking_delta and signature_delta have no OpenAI chunk.
		return "", false, nil
	}
}

func (t *AnthropicStreamTranslator) onMessageDelta(data string) (string, bool, error) {
	var md struct {
		Delta struct {
			StopReason string `json:"stop_reason"`
		} `json:"delta"`
		Usage struct {
			InputTokens              int64 `json:"input_tokens"`
			OutputTokens             int64 `json:"output_tokens"`
			CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
			CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal([]byte(data), &md); err != nil {
		return "", false, fmt.Errorf("decode message_delta: %w", err)
	}
	if md.Usage.InputTokens != 0 {
		t.inputTokens = md.Usage.InputTokens
	}
	if md.Usage.OutputTokens != 0 {
		t.outputTokens = md.Usage.OutputTokens
	}
	if md.Usage.CacheReadInputTokens != 0 {
		t.cacheRead = md.Usage.CacheReadInputTokens
	}
	if md.Usage.CacheCreationInputTokens != 0 {
		t.cacheCreate = md.Usage.CacheCreationInputTokens
	}
	if md.Delta.StopReason == "" {
		return "", false, nil
	}
	reason := mapAnthropicStop(md.Delta.StopReason)
	return t.deltaChunk(map[string]any{}, &reason), false, nil
}

func (t *AnthropicStreamTranslator) usageChunk() string {
	prompt := t.inputTokens + t.cacheRead + t.cacheCreate
	usage := map[string]any{
		"prompt_tokens":     prompt,
		"completion_tokens": t.outputTokens,
		"total_tokens":      prompt + t.outputTokens,
	}
	if t.cacheRead > 0 {
		usage["prompt_tokens_details"] = map[string]any{"cached_tokens": t.cacheRead}
	}
	chunk := map[string]any{
		"id":      t.chunkID(),
		"object":  "chat.completion.chunk",
		"model":   t.model,
		"choices": []any{},
		"usage":   usage,
	}
	b, _ := json.Marshal(chunk)
	return string(b)
}

func (t *AnthropicStreamTranslator) deltaChunk(delta map[string]any, finishReason *string) string {
	choice := map[string]any{
		"index":         0,
		"delta":         delta,
		"finish_reason": nil,
	}
	if finishReason != nil {
		choice["finish_reason"] = *finishReason
	}
	chunk := map[string]any{
		"id":      t.chunkID(),
		"object":  "chat.completion.chunk",
		"model":   t.model,
		"choices": []any{choice},
	}
	b, _ := json.Marshal(chunk)
	return string(b)
}

func (t *AnthropicStreamTranslator) chunkID() string {
	return "chatcmpl-" + t.msgID
}
