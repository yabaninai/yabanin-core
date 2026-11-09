package apiformat

import (
	"encoding/json"
	"log/slog"
	"strings"
)

// ChatToAnthropic translates a non-streaming chat completion into an Anthropic
// Messages response. Only choices[0] is used. Gateway error envelopes stay in
// ToAnthropicError.
func ChatToAnthropic(chatResp []byte, meta AnthropicMeta, opts AnthropicOptions) ([]byte, error) {
	_ = opts.Now
	_ = opts.KeepAlive
	idGen := opts.IDGen
	if idGen == nil {
		idGen = NewID
	}
	var chat ChatResponse
	if err := json.Unmarshal(chatResp, &chat); err != nil {
		return nil, err
	}
	if len(chat.Choices) == 0 {
		return nil, ErrNoChoices
	}
	msg := chat.Choices[0].Message
	content := make([]AnthropicBlock, 0)
	if text := ContentText(msg.Content); text != "" {
		content = append(content, AnthropicBlock{Type: "text", Text: text})
	}
	for _, call := range msg.ToolCalls {
		id := call.ID
		if id == "" {
			id = idGen("toolu_")
		}
		content = append(content, AnthropicBlock{
			Type:  "tool_use",
			ID:    id,
			Name:  call.Function.Name,
			Input: anthropicToolInput(call.Function.Arguments),
		})
	}
	resp := AnthropicResponse{
		ID:         idGen("msg_"),
		Type:       "message",
		Role:       "assistant",
		Model:      meta.RequestedModel,
		Content:    content,
		StopReason: chatFinishToAnthropicStop(chat.Choices[0].FinishReason, len(msg.ToolCalls) > 0),
		Usage:      anthropicUsage(chat.Usage),
	}
	return json.Marshal(resp)
}

func chatFinishToAnthropicStop(finish string, hasTools bool) string {
	if hasTools {
		return "tool_use"
	}
	switch finish {
	case "length":
		return "max_tokens"
	case "content_filter":
		return "refusal"
	default:
		return "end_turn"
	}
}

func anthropicUsage(usage *ChatUsage) AnthropicUsage {
	if usage == nil {
		return AnthropicUsage{}
	}
	var cached int64
	if usage.PromptTokensDetails != nil {
		cached = usage.PromptTokensDetails.CachedTokens
	}
	input := usage.PromptTokens - cached
	if input < 0 {
		input = 0
	}
	return AnthropicUsage{
		InputTokens:              input,
		OutputTokens:             usage.CompletionTokens,
		CacheCreationInputTokens: 0,
		CacheReadInputTokens:     cached,
	}
}

func anthropicToolInput(arguments string) json.RawMessage {
	trimmed := strings.TrimSpace(arguments)
	if trimmed == "" {
		return json.RawMessage(`{}`)
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(trimmed), &obj); err != nil || obj == nil {
		slog.Warn("anthropic tool arguments are not a JSON object; using empty input")
		return json.RawMessage(`{}`)
	}
	encoded, err := json.Marshal(obj)
	if err != nil {
		slog.Warn("anthropic tool arguments are not a JSON object; using empty input")
		return json.RawMessage(`{}`)
	}
	return encoded
}
