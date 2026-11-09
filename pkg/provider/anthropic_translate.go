package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/reireirei/yabanin/pkg/apiformat"
)

// anthropicNow is the clock for translated chat responses. Tests replace it
// so golden files stay deterministic.
var anthropicNow = time.Now

const defaultAnthropicMaxTokens = 4096

// anthropicToChatResponse converts a non-streaming Anthropic Messages response
// into an OpenAI chat completion (A1 §10).
func anthropicToChatResponse(body []byte) ([]byte, error) {
	var resp struct {
		ID         string `json:"id"`
		Model      string `json:"model"`
		StopReason string `json:"stop_reason"`
		Content    []struct {
			Type  string          `json:"type"`
			Text  string          `json:"text"`
			ID    string          `json:"id"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		} `json:"content"`
		Usage struct {
			InputTokens              int64 `json:"input_tokens"`
			OutputTokens             int64 `json:"output_tokens"`
			CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
			CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode anthropic response: %w", err)
	}

	var text strings.Builder
	var refusal strings.Builder
	var calls []any
	for _, block := range resp.Content {
		switch block.Type {
		case "text":
			if resp.StopReason == "refusal" {
				// OpenAI refusal shape: the refusal wording lives in
				// message.refusal, not content (go-openai Message.Refusal);
				// pinned SDK clients branch on it to detect refusals.
				refusal.WriteString(block.Text)
			} else {
				text.WriteString(block.Text)
			}
		case "tool_use":
			calls = append(calls, map[string]any{
				"id":   block.ID,
				"type": "function",
				"function": map[string]any{
					"name":      block.Name,
					"arguments": toolArguments(block.Input),
				},
			})
		default:
			// thinking and unknown blocks are not part of the chat message.
		}
	}
	var content any
	switch {
	case text.Len() > 0:
		content = text.String()
	case len(calls) > 0:
		content = nil
	case refusal.Len() > 0:
		content = nil
	default:
		content = ""
	}
	message := map[string]any{
		"role":    "assistant",
		"content": content,
	}
	if len(calls) > 0 {
		message["tool_calls"] = calls
	}
	if refusal.Len() > 0 {
		message["refusal"] = refusal.String()
	}
	prompt := resp.Usage.InputTokens + resp.Usage.CacheReadInputTokens + resp.Usage.CacheCreationInputTokens
	usage := map[string]any{
		"prompt_tokens":     prompt,
		"completion_tokens": resp.Usage.OutputTokens,
		"total_tokens":      prompt + resp.Usage.OutputTokens,
	}
	if resp.Usage.CacheReadInputTokens > 0 || resp.Usage.CacheCreationInputTokens > 0 {
		// round-trip — they bill at their own rates (CacheReadPerM /
		// CacheWritePerM) and feed the x-yabanin-prompt-cache header. The
		// detail fields are additive: OpenAI clients ignore unknown
		// prompt_tokens_details members.
		details := map[string]any{}
		if resp.Usage.CacheReadInputTokens > 0 {
			details["cached_tokens"] = resp.Usage.CacheReadInputTokens
		}
		if resp.Usage.CacheCreationInputTokens > 0 {
			details["cache_creation_input_tokens"] = resp.Usage.CacheCreationInputTokens
		}
		usage["prompt_tokens_details"] = details
	}
	out := map[string]any{
		"id":      resp.ID,
		"object":  "chat.completion",
		"created": anthropicNow().Unix(),
		"model":   resp.Model,
		"choices": []any{map[string]any{
			"index":         0,
			"message":       message,
			"finish_reason": mapAnthropicStop(resp.StopReason),
		}},
		"usage": usage,
	}
	return json.Marshal(out)
}

func toolArguments(input json.RawMessage) string {
	if len(input) == 0 || string(input) == "null" {
		return "{}"
	}
	var v any
	if err := json.Unmarshal(input, &v); err != nil || v == nil {
		return "{}"
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(raw)
}

// chatToAnthropicRequest converts an OpenAI chat request into an Anthropic
// Messages request (A1 §9). Fields Anthropic rejects are omitted.
// Media-bearing parts the mapping cannot represent (unknown content-part
// types, nil/empty or unmappable image URLs, non-base64 data URLs) are
// explicit typed rejections — never a silent drop answered as a text-only
// success (N07-P05-T05, same fail-closed convention as bedrock/vertex).
func chatToAnthropicRequest(body []byte) ([]byte, error) {
	body = coerceStopToArray(body)
	var req struct {
		apiformat.ChatRequest
		MaxCompletionTokens *int `json:"max_completion_tokens,omitempty"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("decode openai request: %w", err)
	}
	if err := rejectUnmappedResponseFormat("anthropic", req.ResponseFormat); err != nil {
		return nil, err
	}
	// N07-P01-T05 (I51): reasoning_effort is a modeled request field with no
	// Anthropic Messages equivalent — extended thinking uses a different
	// request shape and no effort control is mapped yet. A client that asked
	// for a reasoning level must not receive a default-effort answer, so
	// reject instead of silently dropping the field.
	if req.ReasoningEffort != "" {
		return nil, fmt.Errorf("anthropic: reasoning_effort %q is not mapped (Anthropic thinking uses a different request shape); rejecting instead of silently dropping (I51)", req.ReasoningEffort)
	}

	var systemParts []string
	var msgs []builtMsg
	for _, msg := range req.Messages {
		switch msg.Role {
		case "system":
			systemParts = append(systemParts, systemText(msg.Content))
		case "user":
			m, err := userMessage(msg.Content)
			if err != nil {
				return nil, err
			}
			msgs = appendMsg(msgs, m)
		case "assistant":
			m, err := assistantMessage(msg)
			if err != nil {
				return nil, err
			}
			msgs = appendMsg(msgs, m)
		case "tool":
			msgs = appendMsg(msgs, builtMsg{
				role:   "user",
				blocks: []any{toolResultBlock(msg)},
			})
		default:
			// Anthropic has no other roles; dropping avoids a 400.
		}
	}

	out := map[string]any{
		"model":      req.Model,
		"max_tokens": anthropicMaxTokens(req.MaxTokens, req.MaxCompletionTokens),
		"messages":   renderMessages(msgs),
	}
	if len(systemParts) > 0 {
		out["system"] = strings.Join(systemParts, "\n\n")
	}
	if req.Temperature != nil {
		temp := *req.Temperature
		if temp > 1 {
			temp = 1
		}
		out["temperature"] = temp
	}
	if req.TopP != nil {
		out["top_p"] = *req.TopP
	}
	if req.Stream {
		out["stream"] = true
	}
	if len(req.Stop) > 0 {
		out["stop_sequences"] = req.Stop
	}
	if tools := anthropicTools(req.Tools); len(tools) > 0 {
		out["tools"] = tools
	}
	// N07-P01-T07 (I51): an unmapped or malformed tool_choice is a modeled
	// field value the target route cannot express — it must reject with the
	// exact reason, never silently reshape into "no choice" (the vertex
	// adapter's precedent).
	choice, present, err := anthropicToolChoice(req.ToolChoice, req.ParallelToolCalls)
	if err != nil {
		return nil, err
	}
	if present {
		out["tool_choice"] = choice
	}
	if req.User != "" {
		out["metadata"] = map[string]any{"user_id": req.User}
	}
	return json.Marshal(out)
}

type builtMsg struct {
	role   string
	text   string
	blocks []any
	isText bool
}

func appendMsg(msgs []builtMsg, next builtMsg) []builtMsg {
	if len(msgs) == 0 || msgs[len(msgs)-1].role != next.role {
		return append(msgs, next)
	}
	last := &msgs[len(msgs)-1]
	if next.isText {
		last.addBlocks([]any{textBlock(next.text, nil)})
		return msgs
	}
	last.addBlocks(next.blocks)
	return msgs
}

func (m *builtMsg) addBlocks(blocks []any) {
	if m.isText {
		var prior []any
		if m.text != "" {
			prior = []any{textBlock(m.text, nil)}
		}
		m.blocks = append(prior, blocks...)
		m.isText = false
		m.text = ""
		return
	}
	m.blocks = append(m.blocks, blocks...)
}

func (m builtMsg) content() any {
	if m.isText {
		return m.text
	}
	if m.blocks == nil {
		return []any{}
	}
	return m.blocks
}

func renderMessages(msgs []builtMsg) []any {
	out := make([]any, 0, len(msgs))
	for _, msg := range msgs {
		out = append(out, map[string]any{
			"role":    msg.role,
			"content": msg.content(),
		})
	}
	return out
}

func systemText(raw json.RawMessage) string {
	if s, ok := rawJSONString(raw); ok {
		return s
	}
	return string(raw)
}

func userMessage(raw json.RawMessage) (builtMsg, error) {
	if s, ok := rawJSONString(raw); ok {
		return builtMsg{role: "user", text: s, isText: true}, nil
	}
	blocks, err := contentBlocks(raw)
	if err != nil {
		return builtMsg{}, err
	}
	return builtMsg{role: "user", blocks: blocks}, nil
}

func assistantMessage(msg apiformat.ChatMessage) (builtMsg, error) {
	var blocks []any
	if s, ok := rawJSONString(msg.Content); ok {
		if s != "" {
			blocks = append(blocks, textBlock(s, nil))
		}
	} else {
		content, err := contentBlocks(msg.Content)
		if err != nil {
			return builtMsg{}, err
		}
		blocks = append(blocks, content...)
	}
	for _, call := range msg.ToolCalls {
		blocks = append(blocks, toolUseBlock(call))
	}
	if len(msg.ToolCalls) == 0 {
		if s, ok := rawJSONString(msg.Content); ok {
			return builtMsg{role: "assistant", text: s, isText: true}, nil
		}
	}
	return builtMsg{role: "assistant", blocks: blocks}, nil
}

type oaiPart struct {
	Type         string          `json:"type"`
	Text         string          `json:"text"`
	ImageURL     *oaiImage       `json:"image_url"`
	CacheControl json.RawMessage `json:"cache_control"`
}

type oaiImage struct {
	URL string `json:"url"`
}

// contentBlocks maps OpenAI content parts to Anthropic blocks. Parts the
// mapping cannot represent fail closed with a typed UnsupportedFeatureError
// — a silent drop would answer an image/audio request with a text-only
// completion pretending the part never existed (false success on a
// negative scenario; N07-P05-T05).
func contentBlocks(raw json.RawMessage) ([]any, error) {
	// Absent or unparsable content degrades to zero parts (pre-existing
	// passthrough semantic: the raw payload is upstream-owned elsewhere);
	// parsed-but-unrepresentable parts fail closed below.
	var parts []oaiPart
	if len(raw) != 0 && string(raw) != "null" && json.Unmarshal(raw, &parts) != nil {
		parts = nil
	}
	var blocks []any
	for _, part := range parts {
		switch part.Type {
		case "text":
			blocks = append(blocks, textBlock(part.Text, part.CacheControl))
		case "image_url":
			if part.ImageURL == nil {
				return nil, &UnsupportedFeatureError{
					Provider: "anthropic",
					Reason:   "image_url part has no url object; rejecting instead of silently dropping the part",
				}
			}
			b, err := imageBlock(part.ImageURL.URL, part.CacheControl)
			if err != nil {
				return nil, err
			}
			blocks = append(blocks, b)
		default:
			// Same convention text as the bedrock/vertex adapters (F1).
			return nil, &UnsupportedFeatureError{
				Provider: "anthropic",
				Reason:   fmt.Sprintf("content part type %q is not mapped; rejecting instead of silently dropping the part", part.Type),
			}
		}
	}
	return blocks, nil
}

func textBlock(text string, cache json.RawMessage) map[string]any {
	b := map[string]any{"type": "text", "text": text}
	if cacheRaw(cache) != nil {
		b["cache_control"] = cacheRaw(cache)
	}
	return b
}

// imageBlock maps an OpenAI image URL to an Anthropic image source block.
// Only base64 data URLs and http(s) references are representable; anything
// else fails closed with a typed rejection (the reason never embeds the URL
// itself — references may carry credentials and the answer must stay
// deterministic and small).
func imageBlock(url string, cache json.RawMessage) (map[string]any, error) {
	var source map[string]any
	switch {
	case strings.HasPrefix(url, "data:"):
		media, data, ok := splitDataURL(url)
		if !ok {
			return nil, &UnsupportedFeatureError{
				Provider: "anthropic",
				Reason:   "data URL is not a base64 image payload; rejecting instead of silently dropping the image part",
			}
		}
		source = map[string]any{"type": "base64", "media_type": media, "data": data}
	case strings.HasPrefix(url, "https://"), strings.HasPrefix(url, "http://"):
		source = map[string]any{"type": "url", "url": url}
	default:
		return nil, &UnsupportedFeatureError{
			Provider: "anthropic",
			Reason:   "image URL scheme is not mapped (only data:, https:// and http:// are accepted); rejecting instead of silently dropping the image part",
		}
	}
	b := map[string]any{"type": "image", "source": source}
	if cacheRaw(cache) != nil {
		b["cache_control"] = cacheRaw(cache)
	}
	return b, nil
}

func splitDataURL(url string) (media, data string, ok bool) {
	rest, found := strings.CutPrefix(url, "data:")
	if !found {
		return "", "", false
	}
	media, data, ok = strings.Cut(rest, ";base64,")
	if !ok || media == "" {
		return "", "", false
	}
	return media, data, true
}

func toolUseBlock(call apiformat.ToolCall) map[string]any {
	input := map[string]any{}
	args := call.Function.Arguments
	if args != "" {
		if err := json.Unmarshal([]byte(args), &input); err != nil || input == nil {
			input = map[string]any{}
			slog.Warn("anthropic tool_use arguments are not a json object", "tool", call.Function.Name)
		}
	}
	return map[string]any{
		"type":  "tool_use",
		"id":    call.ID,
		"name":  call.Function.Name,
		"input": input,
	}
}

func toolResultBlock(msg apiformat.ChatMessage) map[string]any {
	text, _ := rawJSONString(msg.Content)
	if text == "" && len(msg.Content) > 0 && string(msg.Content) != "null" && !jsonStringish(msg.Content) {
		text = apiformat.ContentText(msg.Content)
	}
	return map[string]any{
		"type":        "tool_result",
		"tool_use_id": msg.ToolCallID,
		"content":     text,
	}
}

func anthropicTools(tools []apiformat.ChatTool) []any {
	if len(tools) == 0 {
		return nil
	}
	out := make([]any, 0, len(tools))
	for _, tool := range tools {
		schema := json.RawMessage(tool.Function.Parameters)
		var input any
		if len(schema) == 0 || string(schema) == "null" {
			input = map[string]any{"type": "object", "properties": map[string]any{}}
		} else {
			input = schema
		}
		item := map[string]any{
			"name":         tool.Function.Name,
			"input_schema": input,
		}
		if tool.Function.Description != "" {
			item["description"] = tool.Function.Description
		}
		out = append(out, item)
	}
	return out
}

// anthropicToolChoice translates the OpenAI tool_choice value space to the
// Anthropic native shape. N07-P01-T07 (I51): values outside the mapped space
// return a typed rejection naming the field — the same boundary the vertex
// adapter enforces — instead of silently dropping the client's instruction.
// The present flag reports whether a tool_choice must be sent at all
// (absent client field → false); with no choice given but parallel calls
// disabled, the Anthropic-equivalent default (auto + disable flag) is
// still synthesized.
func anthropicToolChoice(raw json.RawMessage, parallel *bool) (map[string]any, bool, error) {
	var choice map[string]any
	if s, ok := rawJSONString(raw); ok {
		switch s {
		case "auto":
			choice = map[string]any{"type": "auto"}
		case "required":
			choice = map[string]any{"type": "any"}
		case "none":
			choice = map[string]any{"type": "none"}
		default:
			return nil, false, fmt.Errorf("anthropic: unsupported tool_choice %q; rejecting instead of silently dropping (I51)", s)
		}
	} else if len(raw) > 0 && string(raw) != "null" {
		var obj struct {
			Function struct {
				Name string `json:"name"`
			} `json:"function"`
		}
		if err := json.Unmarshal(raw, &obj); err != nil || obj.Function.Name == "" {
			return nil, false, errors.New(`anthropic: tool_choice must be "auto"|"none"|"required" or {"type":"function","function":{"name":…}}; rejecting instead of silently dropping (I51)`)
		}
		choice = map[string]any{"type": "tool", "name": obj.Function.Name}
	}
	if choice == nil {
		if parallel != nil && !*parallel {
			return map[string]any{"type": "auto", "disable_parallel_tool_use": true}, true, nil
		}
		// No client tool_choice and nothing default-derived: send nothing.
		return nil, false, nil
	}
	if parallel != nil && !*parallel {
		choice["disable_parallel_tool_use"] = true
	}
	return choice, true, nil
}

func anthropicMaxTokens(maxTokens, maxCompletion *int) int {
	if maxTokens != nil {
		return *maxTokens
	}
	if maxCompletion != nil {
		return *maxCompletion
	}
	return defaultAnthropicMaxTokens
}

func rawJSONString(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", false
	}
	if raw[0] != '"' {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

func jsonStringish(raw json.RawMessage) bool {
	return len(raw) > 0 && raw[0] == '"'
}

func cacheRaw(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	return raw
}

// coerceStopToArray rewrites a JSON string `stop` into a one-element array so
// apiformat.ChatRequest (stop is []string) can decode it. Other shapes are left
// untouched.
func coerceStopToArray(body []byte) []byte {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return body
	}
	raw, ok := doc["stop"]
	if !ok || len(raw) == 0 || raw[0] != '"' {
		return body
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return body
	}
	arr, err := json.Marshal([]string{s})
	if err != nil {
		return body
	}
	doc["stop"] = arr
	out, err := json.Marshal(doc)
	if err != nil {
		return body
	}
	return out
}
