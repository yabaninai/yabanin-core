package apiformat

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
)

// AnthropicToChat translates an Anthropic Messages request into canonical chat JSON.
// System messages that are not a leading prefix become user messages prefixed
// with "[system]" (A1 §0.4a).
func AnthropicToChat(body []byte) ([]byte, AnthropicMeta, *FormatError) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(body, &root); err != nil || root == nil {
		return nil, AnthropicMeta{}, &FormatError{Status: 400, Type: "invalid_request_error", Code: "invalid_json", Message: "request body must be a JSON object"}
	}
	var meta AnthropicMeta
	model, ferr := requiredAnthropicString(root, "model", "model: Field required")
	if ferr != nil {
		return nil, meta, ferr
	}
	meta.RequestedModel = model
	maxTokens, ferr := requiredAnthropicInt(root, "max_tokens", "max_tokens: Field required")
	if ferr != nil {
		return nil, meta, ferr
	}
	rawMessages, ok := root["messages"]
	if !ok || string(bytes.TrimSpace(rawMessages)) == "null" {
		return nil, meta, &FormatError{Status: 400, Type: "invalid_request_error", Message: "messages: at least one message is required"}
	}
	var incoming []AnthropicMessage
	if err := json.Unmarshal(rawMessages, &incoming); err != nil || len(incoming) == 0 {
		return nil, meta, &FormatError{Status: 400, Type: "invalid_request_error", Message: "messages: at least one message is required"}
	}

	var messages []ChatMessage
	if raw, ok := root["system"]; ok && string(bytes.TrimSpace(raw)) != "null" {
		if msg, ok := systemFromField(raw, &meta); ok {
			messages = append(messages, msg)
		}
	}
	for _, msg := range incoming {
		messages = append(messages, convertAnthropicMessage(msg, &meta)...)
	}
	messages = normalizeSystems(messages)

	req := ChatRequest{Model: model, MaxTokens: &maxTokens, Messages: messages}
	if raw, ok := root["stop_sequences"]; ok {
		var stops []string
		if json.Unmarshal(raw, &stops) == nil {
			if len(stops) > 4 {
				addAnthropicDrop(&meta, "stop_sequences_over_4")
				stops = stops[:4]
			}
			req.Stop = stops
		}
	}
	if raw, ok := root["temperature"]; ok {
		var n float64
		if json.Unmarshal(raw, &n) == nil {
			req.Temperature = &n
		}
	}
	if raw, ok := root["top_p"]; ok {
		var n float64
		if json.Unmarshal(raw, &n) == nil {
			req.TopP = &n
		}
	}
	if raw, ok := root["top_k"]; ok && string(bytes.TrimSpace(raw)) != "null" {
		addAnthropicDrop(&meta, "top_k")
	}
	if raw, ok := root["stream"]; ok {
		_ = json.Unmarshal(raw, &req.Stream)
		meta.Stream = req.Stream
		if req.Stream {
			req.StreamOptions = &StreamOptions{IncludeUsage: true}
		}
	}
	req.Tools = convertAnthropicTools(root["tools"], &meta)
	if raw, ok := root["tool_choice"]; ok && string(bytes.TrimSpace(raw)) != "null" {
		applyAnthropicToolChoice(&req, raw, &meta)
	}
	if raw, ok := root["metadata"]; ok {
		var md AnthropicMetadata
		if json.Unmarshal(raw, &md) == nil {
			req.User = md.UserID
		}
	}
	noteAnthropicThinking(root["thinking"], &meta)
	noteUnknownAnthropic(root, &meta)

	out, err := json.Marshal(req)
	if err != nil {
		return nil, meta, &FormatError{Status: 500, Type: "api_error", Message: "failed to encode chat request"}
	}
	return out, meta, nil
}

func requiredAnthropicString(root map[string]json.RawMessage, key, message string) (string, *FormatError) {
	raw, ok := root[key]
	if !ok || string(bytes.TrimSpace(raw)) == "null" {
		return "", &FormatError{Status: 400, Type: "invalid_request_error", Message: message}
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || value == "" {
		return "", &FormatError{Status: 400, Type: "invalid_request_error", Message: message}
	}
	return value, nil
}

func requiredAnthropicInt(root map[string]json.RawMessage, key, message string) (int, *FormatError) {
	raw, ok := root[key]
	if !ok || string(bytes.TrimSpace(raw)) == "null" {
		return 0, &FormatError{Status: 400, Type: "invalid_request_error", Message: message}
	}
	var value int
	if err := json.Unmarshal(raw, &value); err != nil {
		return 0, &FormatError{Status: 400, Type: "invalid_request_error", Message: message}
	}
	return value, nil
}

func systemFromField(raw json.RawMessage, meta *AnthropicMeta) (ChatMessage, bool) {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return systemMessage(text), true
	}
	var blocks []AnthropicBlock
	if err := json.Unmarshal(raw, &blocks); err != nil {
		addAnthropicDrop(meta, "system")
		return ChatMessage{}, false
	}
	var parts []string
	for _, block := range blocks {
		if block.Type == "text" {
			parts = append(parts, block.Text)
		}
	}
	return systemMessage(strings.Join(parts, "\n\n")), true
}

func convertAnthropicMessage(msg AnthropicMessage, meta *AnthropicMeta) []ChatMessage {
	switch msg.Role {
	case "user":
		return convertUser(msg.Content, meta)
	case "assistant":
		return []ChatMessage{convertAssistant(msg.Content, meta)}
	case "system":
		return []ChatMessage{systemMessage(anthropicText(msg.Content))}
	default:
		addAnthropicDrop(meta, "role:"+msg.Role)
		return nil
	}
}

func convertUser(raw json.RawMessage, meta *AnthropicMeta) []ChatMessage {
	if text, ok := rawStringContent(raw); ok {
		return []ChatMessage{userMessage(text)}
	}
	var blocks []AnthropicBlock
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return []ChatMessage{userMessage(anthropicText(raw))}
	}
	var toolMsgs []ChatMessage
	var parts []ContentPart
	for _, block := range blocks {
		switch block.Type {
		case "text":
			parts = append(parts, ContentPart{Type: "text", Text: block.Text})
		case "image":
			parts = append(parts, imagePart(block.Source, meta))
		case "document":
			parts = append(parts, documentPart(block.Source, meta))
		case "tool_result":
			text := toolResultText(block.Content)
			if block.IsError {
				text = "ERROR: " + text
			}
			toolMsgs = append(toolMsgs, ChatMessage{Role: "tool", Content: mustRaw(text), ToolCallID: block.ToolUseID})
		default:
			addAnthropicDrop(meta, "block:"+block.Type)
		}
	}
	if len(parts) == 0 {
		return toolMsgs
	}
	return append(toolMsgs, userFromParts(parts))
}

func imagePart(src *AnthropicSource, meta *AnthropicMeta) ContentPart {
	if src != nil && src.Type == "base64" {
		return ContentPart{Type: "image_url", ImageURL: &ImageURL{URL: "data:" + src.MediaType + ";base64," + src.Data}}
	}
	if src != nil && src.Type == "url" {
		return ContentPart{Type: "image_url", ImageURL: &ImageURL{URL: src.URL}}
	}
	addAnthropicDrop(meta, "image_source")
	return ContentPart{Type: "text", Text: "[image omitted]"}
}

func documentPart(src *AnthropicSource, meta *AnthropicMeta) ContentPart {
	if src != nil && src.Type == "text" {
		return ContentPart{Type: "text", Text: src.Data}
	}
	addAnthropicDrop(meta, "document")
	return ContentPart{Type: "text", Text: "[document omitted: not supported on this route]"}
}

func toolResultText(raw json.RawMessage) string {
	if text, ok := rawStringContent(raw); ok {
		return text
	}
	var blocks []AnthropicBlock
	if len(raw) == 0 || string(bytes.TrimSpace(raw)) == "null" || json.Unmarshal(raw, &blocks) != nil {
		return ""
	}
	var parts []string
	for _, block := range blocks {
		switch block.Type {
		case "text":
			parts = append(parts, block.Text)
		case "image":
			parts = append(parts, "[image omitted]")
		}
	}
	return strings.Join(parts, "\n")
}

func userFromParts(parts []ContentPart) ChatMessage {
	allText := true
	var texts []string
	for _, part := range parts {
		if part.Type != "text" {
			allText = false
			break
		}
		texts = append(texts, part.Text)
	}
	if allText {
		return userMessage(strings.Join(texts, "\n\n"))
	}
	encoded, err := json.Marshal(parts)
	if err != nil {
		return userMessage("")
	}
	return ChatMessage{Role: "user", Content: encoded}
}

func convertAssistant(raw json.RawMessage, meta *AnthropicMeta) ChatMessage {
	msg := ChatMessage{Role: "assistant", Content: json.RawMessage("null")}
	if text, ok := rawStringContent(raw); ok {
		msg.Content = mustRaw(text)
		return msg
	}
	var blocks []AnthropicBlock
	if err := json.Unmarshal(raw, &blocks); err != nil {
		msg.Content = mustRaw(anthropicText(raw))
		return msg
	}
	var text strings.Builder
	var sawText bool
	for _, block := range blocks {
		switch block.Type {
		case "text":
			sawText = true
			text.WriteString(block.Text)
		case "tool_use":
			msg.ToolCalls = append(msg.ToolCalls, ToolCall{
				ID:   block.ID,
				Type: "function",
				Function: ToolCallFunction{
					Name:      block.Name,
					Arguments: compactInput(block.Input),
				},
			})
		case "thinking", "redacted_thinking":
		default:
			addAnthropicDrop(meta, "block:"+block.Type)
		}
	}
	if sawText {
		msg.Content = mustRaw(text.String())
	}
	return msg
}

func compactInput(raw json.RawMessage) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return "{}"
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, trimmed); err != nil {
		return "{}"
	}
	return buf.String()
}

func anthropicText(raw json.RawMessage) string {
	if text, ok := rawStringContent(raw); ok {
		return text
	}
	var blocks []AnthropicBlock
	if json.Unmarshal(raw, &blocks) != nil {
		return ""
	}
	var parts []string
	for _, block := range blocks {
		if block.Type == "text" {
			parts = append(parts, block.Text)
		}
	}
	return strings.Join(parts, "\n\n")
}

func rawStringContent(raw json.RawMessage) (string, bool) {
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return "", false
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return "", false
	}
	return text, true
}

func convertAnthropicTools(raw json.RawMessage, meta *AnthropicMeta) []ChatTool {
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return nil
	}
	var tools []struct {
		Type        string          `json:"type"`
		Name        string          `json:"name"`
		Description string          `json:"description"`
		InputSchema json.RawMessage `json:"input_schema"`
		Strict      *bool           `json:"strict"`
	}
	if err := json.Unmarshal(raw, &tools); err != nil {
		addAnthropicDrop(meta, "tools")
		return nil
	}
	var out []ChatTool
	for _, tool := range tools {
		if tool.Type != "" && tool.Type != "custom" {
			addAnthropicDrop(meta, "tool:"+tool.Type)
			continue
		}
		params := bytes.TrimSpace(tool.InputSchema)
		if len(params) == 0 || string(params) == "null" {
			params = []byte(`{"type":"object","properties":{}}`)
		}
		out = append(out, ChatTool{
			Type: "function",
			Function: ChatFunction{
				Name:        tool.Name,
				Description: tool.Description,
				Parameters:  append(json.RawMessage(nil), params...),
				Strict:      tool.Strict,
			},
		})
	}
	return out
}

func applyAnthropicToolChoice(req *ChatRequest, raw json.RawMessage, meta *AnthropicMeta) {
	var choice AnthropicToolChoice
	if err := json.Unmarshal(raw, &choice); err != nil {
		addAnthropicDrop(meta, "tool_choice")
		req.ToolChoice = json.RawMessage(`"auto"`)
		return
	}
	switch choice.Type {
	case "auto":
		req.ToolChoice = json.RawMessage(`"auto"`)
	case "any":
		req.ToolChoice = json.RawMessage(`"required"`)
	case "none":
		req.ToolChoice = json.RawMessage(`"none"`)
	case "tool":
		encoded, err := json.Marshal(struct {
			Type     string `json:"type"`
			Function struct {
				Name string `json:"name"`
			} `json:"function"`
		}{Type: "function", Function: struct {
			Name string `json:"name"`
		}{Name: choice.Name}})
		if err != nil {
			req.ToolChoice = json.RawMessage(`"auto"`)
			return
		}
		req.ToolChoice = encoded
	default:
		addAnthropicDrop(meta, "tool_choice")
		req.ToolChoice = json.RawMessage(`"auto"`)
	}
	if choice.DisableParallelToolUse {
		off := false
		req.ParallelToolCalls = &off
	}
}

func noteAnthropicThinking(raw json.RawMessage, meta *AnthropicMeta) {
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return
	}
	var thinking struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &thinking) != nil {
		addAnthropicDrop(meta, "thinking")
		return
	}
	switch thinking.Type {
	case "adaptive", "disabled":
	default:
		addAnthropicDrop(meta, "thinking")
	}
}

func noteUnknownAnthropic(root map[string]json.RawMessage, meta *AnthropicMeta) {
	known := map[string]bool{
		"model": true, "max_tokens": true, "system": true, "messages": true,
		"stop_sequences": true, "temperature": true, "top_p": true, "top_k": true,
		"stream": true, "tools": true, "tool_choice": true, "metadata": true, "thinking": true,
	}
	var extra []string
	for key := range root {
		if !known[key] {
			extra = append(extra, key)
		}
	}
	sort.Strings(extra)
	for _, key := range extra {
		addAnthropicDrop(meta, key)
	}
}

func addAnthropicDrop(meta *AnthropicMeta, name string) {
	if name == "" {
		return
	}
	for _, existing := range meta.Dropped {
		if existing == name {
			return
		}
	}
	meta.Dropped = append(meta.Dropped, name)
}
