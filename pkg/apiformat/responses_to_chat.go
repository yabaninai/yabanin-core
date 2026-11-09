package apiformat

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/reireirei/yabanin/pkg/metrics"
)

// ResponsesToChat translates a Responses API request into canonical chat JSON.
// Reasoning effort is not forwarded: ResponsesForwardReasoningEffort defaults
// to false, so reasoning.effort is dropped.
func ResponsesToChat(body []byte) ([]byte, ResponsesMeta, *FormatError) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(body, &root); err != nil || root == nil {
		return nil, ResponsesMeta{}, &FormatError{Status: 400, Type: "invalid_request_error", Code: "invalid_json", Message: "request body must be a JSON object"}
	}
	meta := ResponsesMeta{Echo: defaultEcho()}
	if ferr := rejectUnsupported(root); ferr != nil {
		return nil, meta, ferr
	}
	noteUnknown(root, &meta)

	model, ferr := requiredString(root, "model", "missing_model", "model is required")
	if ferr != nil {
		return nil, meta, ferr
	}
	meta.RequestedModel = model

	if raw, ok := root["instructions"]; ok {
		meta.Echo.Instructions = append(json.RawMessage(nil), raw...)
	}
	if raw, ok := root["tools"]; ok {
		meta.Echo.Tools = append(json.RawMessage(nil), raw...)
	}
	if raw, ok := root["tool_choice"]; ok {
		meta.Echo.ToolChoice = append(json.RawMessage(nil), raw...)
	}
	if raw, ok := root["text"]; ok {
		meta.Echo.Text = append(json.RawMessage(nil), raw...)
	}
	if raw, ok := root["reasoning"]; ok {
		meta.Echo.Reasoning = append(json.RawMessage(nil), raw...)
	}
	if raw, ok := root["metadata"]; ok {
		meta.Echo.Metadata = append(json.RawMessage(nil), raw...)
	}
	if raw, ok := root["prompt_cache_key"]; ok {
		if err := json.Unmarshal(raw, &meta.PromptCacheKey); err != nil {
			silentParseField("prompt_cache_key")
		}
	}

	messages, ferr := responsesMessages(root, &meta)
	if ferr != nil {
		return nil, meta, ferr
	}
	messages = normalizeSystems(messages)
	if len(messages) == 0 {
		return nil, meta, &FormatError{Status: 400, Type: "invalid_request_error", Code: "empty_input", Message: "input must contain at least one message"}
	}

	req := ChatRequest{Model: model, Messages: messages}
	if raw, ok := root["stream"]; ok {
		if err := json.Unmarshal(raw, &req.Stream); err != nil {
			silentParseField("stream")
		}
		meta.Stream = req.Stream
		if req.Stream {
			req.StreamOptions = &StreamOptions{IncludeUsage: true}
		}
	}
	if ferr := applyTools(&req, root, &meta); ferr != nil {
		return nil, meta, ferr
	}
	if raw, ok := root["tool_choice"]; ok {
		req.ToolChoice = mapToolChoice(raw, &meta)
	}
	if raw, ok := root["parallel_tool_calls"]; ok {
		var v bool
		if json.Unmarshal(raw, &v) == nil {
			req.ParallelToolCalls = &v
			meta.Echo.ParallelToolCalls = &v
		}
	}
	if raw, ok := root["max_output_tokens"]; ok {
		var n int
		if json.Unmarshal(raw, &n) == nil {
			req.MaxTokens = &n
			meta.Echo.MaxOutputTokens = &n
		}
	}
	if raw, ok := root["temperature"]; ok {
		var n float64
		if json.Unmarshal(raw, &n) == nil {
			req.Temperature = &n
			meta.Echo.Temperature = &n
		}
	}
	if raw, ok := root["top_p"]; ok {
		var n float64
		if json.Unmarshal(raw, &n) == nil {
			req.TopP = &n
			meta.Echo.TopP = &n
		}
	}
	applyTextFormat(&req, root, &meta)
	applyReasoning(root, &meta)
	applyUser(&req, root, &meta)

	out, err := json.Marshal(req)
	if err != nil {
		return nil, meta, &FormatError{Status: 500, Type: "api_error", Message: "failed to encode chat request"}
	}
	return out, meta, nil
}

// silentParseField counts an optional field whose malformed JSON was
// silently dropped (the translation keeps the zero value and proceeds) —
func silentParseField(field string) {
	metrics.SilentFailure("apiformat_request_parse", field)
}

func defaultEcho() ResponsesEcho {
	return ResponsesEcho{
		Instructions: json.RawMessage("null"),
		Tools:        json.RawMessage("[]"),
		ToolChoice:   json.RawMessage(`"auto"`),
		Text:         json.RawMessage(`{"format":{"type":"text"}}`),
		Reasoning:    json.RawMessage("null"),
		Metadata:     json.RawMessage("{}"),
	}
}

var silentResponsesKeys = map[string]struct{}{
	"model": {}, "instructions": {}, "input": {}, "tools": {}, "tool_choice": {},
	"parallel_tool_calls": {}, "max_output_tokens": {}, "temperature": {}, "top_p": {},
	"stream": {}, "text": {}, "reasoning": {}, "user": {}, "safety_identifier": {},
	"metadata": {}, "store": {}, "include": {}, "prompt_cache_key": {},
	"previous_response_id": {}, "conversation": {}, "background": {}, "prompt": {},
	"truncation": {}, "service_tier": {}, "max_tool_calls": {}, "top_logprobs": {},
	"stream_options": {},
}

func noteUnknown(root map[string]json.RawMessage, meta *ResponsesMeta) {
	for key := range root {
		if _, ok := silentResponsesKeys[key]; !ok {
			addDropped(meta, key)
		}
	}
}

// ErrPreviousResponseID is the uniform stateless-Responses rejection
// continuation id is refused with the same explicit 400 whether the request
// would ride the translated or the native passthrough route.
var ErrPreviousResponseID = &FormatError{
	Status: 400, Type: "invalid_request_error", Code: "previous_response_not_supported",
	Message: "previous_response_id is not supported by this gateway route; send the full conversation in input with store=false",
}

// RejectPreviousResponseID reports whether the raw Responses body asks for
// server-side continuation (previous_response_id set to a non-empty value).
// The value is probed as raw JSON so every non-empty shape — a string id, a
// number, a boolean, an object or an array (a client that misuses an
// approval-operation id as a continuation id, for example) — is refused,
// exactly matching the emptyJSON boundary of the translated route. The
// gateway native path uses it to enforce the same stateless contract the
// translation layer has (rejectUnsupported below returns the identical
// error value for the translated path); an unset field (absent, null,
// empty string, empty container) passes so clients echoing the field
// unset are not penalized.
func RejectPreviousResponseID(body []byte) *FormatError {
	var probe struct {
		PreviousResponseID json.RawMessage `json:"previous_response_id"`
	}
	if json.Unmarshal(body, &probe) != nil || len(probe.PreviousResponseID) == 0 || emptyJSON(probe.PreviousResponseID) {
		return nil
	}
	return ErrPreviousResponseID
}

func rejectUnsupported(root map[string]json.RawMessage) *FormatError {
	if raw, ok := root["previous_response_id"]; ok && !emptyJSON(raw) {
		return ErrPreviousResponseID
	}
	if raw, ok := root["conversation"]; ok && !emptyJSON(raw) {
		return &FormatError{Status: 400, Type: "invalid_request_error", Code: "conversation_not_supported", Message: "conversation is not supported"}
	}
	if raw, ok := root["background"]; ok {
		var on bool
		if json.Unmarshal(raw, &on) == nil && on {
			return &FormatError{Status: 400, Type: "invalid_request_error", Code: "background_not_supported", Message: "background is not supported"}
		}
	}
	if raw, ok := root["prompt"]; ok && !emptyJSON(raw) {
		return &FormatError{Status: 400, Type: "invalid_request_error", Code: "prompt_templates_not_supported", Message: "prompt templates are not supported"}
	}
	return nil
}

func emptyJSON(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s == "" || s == "null" || s == `""` || s == "{}" || s == "[]"
}

func requiredString(root map[string]json.RawMessage, key, code, message string) (string, *FormatError) {
	raw, ok := root[key]
	if !ok {
		return "", &FormatError{Status: 400, Type: "invalid_request_error", Code: code, Message: message}
	}
	var s string
	if json.Unmarshal(raw, &s) != nil || s == "" {
		return "", &FormatError{Status: 400, Type: "invalid_request_error", Code: code, Message: message}
	}
	return s, nil
}

func responsesMessages(root map[string]json.RawMessage, meta *ResponsesMeta) ([]ChatMessage, *FormatError) {
	var messages []ChatMessage
	if raw, ok := root["instructions"]; ok {
		var text string
		if json.Unmarshal(raw, &text) == nil && text != "" {
			messages = append(messages, systemMessage(text))
		}
	}
	raw, ok := root["input"]
	if !ok {
		return messages, nil
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return messages, nil
	}
	if trimmed[0] == '"' {
		var text string
		if err := json.Unmarshal(trimmed, &text); err != nil {
			return nil, &FormatError{Status: 400, Type: "invalid_request_error", Code: "invalid_input", Message: "input string is invalid"}
		}
		return append(messages, userMessage(text)), nil
	}
	if trimmed[0] != '[' {
		addDropped(meta, "input")
		return messages, nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(trimmed, &items); err != nil {
		return nil, &FormatError{Status: 400, Type: "invalid_request_error", Code: "invalid_input", Message: "input array is invalid"}
	}
	pending := -1
	for _, itemRaw := range items {
		msg, kind, ferr := translateInputItem(itemRaw, meta)
		if ferr != nil {
			return nil, ferr
		}
		switch kind {
		case itemSkip:
			continue
		case itemToolCall:
			if pending >= 0 {
				messages[pending].ToolCalls = append(messages[pending].ToolCalls, msg.ToolCalls...)
				continue
			}
			messages = append(messages, msg)
			pending = len(messages) - 1
		case itemAssistant:
			messages = append(messages, msg)
			pending = len(messages) - 1
		default:
			messages = append(messages, msg)
			pending = -1
		}
	}
	return messages, nil
}

const (
	itemMessage = iota
	itemAssistant
	itemToolCall
	itemSkip
)

func translateInputItem(raw json.RawMessage, meta *ResponsesMeta) (ChatMessage, int, *FormatError) {
	var head struct {
		Type string `json:"type"`
		Role string `json:"role"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return ChatMessage{}, itemSkip, &FormatError{Status: 400, Type: "invalid_request_error", Code: "invalid_input", Message: "input item is invalid"}
	}
	if head.Type == "" && head.Role != "" {
		head.Type = "message"
	}
	switch head.Type {
	case "message":
		msg, assistant, ferr := translateMessageItem(raw, head.Role, meta)
		if ferr != nil {
			return ChatMessage{}, itemSkip, ferr
		}
		if assistant {
			return msg, itemAssistant, nil
		}
		return msg, itemMessage, nil
	case "function_call":
		return functionCallMessage(raw, false), itemToolCall, nil
	case "custom_tool_call":
		return functionCallMessage(raw, true), itemToolCall, nil
	case "function_call_output", "custom_tool_call_output":
		msg := toolOutputMessage(raw, meta)
		return msg, itemMessage, nil
	case "reasoning":
		return ChatMessage{}, itemSkip, nil
	case "item_reference":
		return ChatMessage{}, itemSkip, &FormatError{Status: 400, Type: "invalid_request_error", Code: "item_reference_not_supported", Message: "item_reference is not supported"}
	default:
		if head.Type != "" {
			addDropped(meta, "input:"+head.Type)
		}
		return ChatMessage{}, itemSkip, nil
	}
}

func translateMessageItem(raw json.RawMessage, role string, meta *ResponsesMeta) (ChatMessage, bool, *FormatError) {
	var item struct {
		Content json.RawMessage `json:"content"`
	}
	if err := json.Unmarshal(raw, &item); err != nil {
		silentParseField("message_item")
	}
	switch role {
	case "system", "developer":
		return systemMessage(textOf(item.Content, "\n")), false, nil
	case "assistant":
		return ChatMessage{Role: "assistant", Content: mustRaw(assistantText(item.Content))}, true, nil
	default:
		content, ferr := userContent(item.Content, meta)
		if ferr != nil {
			return ChatMessage{}, false, ferr
		}
		return ChatMessage{Role: "user", Content: content}, false, nil
	}
}

func userContent(content json.RawMessage, meta *ResponsesMeta) (json.RawMessage, *FormatError) {
	trimmed := bytes.TrimSpace(content)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		var text string
		if json.Unmarshal(content, &text) == nil {
			return mustRaw(text), nil
		}
		return mustRaw(""), nil
	}
	var parts []map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &parts); err != nil {
		return nil, &FormatError{Status: 400, Type: "invalid_request_error", Code: "invalid_input", Message: "user content is invalid"}
	}
	allText := true
	var texts []string
	var out []ContentPart
	for _, part := range parts {
		kind := rawString(part["type"])
		switch kind {
		case "input_text", "text", "":
			texts = append(texts, rawString(part["text"]))
			out = append(out, ContentPart{Type: "text", Text: rawString(part["text"])})
		case "input_image":
			allText = false
			if _, hasURL := part["image_url"]; !hasURL {
				if _, hasFile := part["file_id"]; hasFile {
					return nil, &FormatError{Status: 400, Type: "invalid_request_error", Code: "input_image_file_id_not_supported", Message: "input_image file_id is not supported"}
				}
			}
			url, detail := imageURL(part)
			out = append(out, ContentPart{Type: "image_url", ImageURL: &ImageURL{URL: url, Detail: detail}})
		case "input_file":
			return nil, &FormatError{Status: 400, Type: "invalid_request_error", Code: "input_file_not_supported", Message: "input_file is not supported"}
		case "input_audio":
			return nil, &FormatError{Status: 400, Type: "invalid_request_error", Code: "input_audio_not_supported", Message: "input_audio is not supported"}
		default:
			allText = false
			addDropped(meta, "input:"+kind)
		}
	}
	if allText {
		return mustRaw(strings.Join(texts, "\n\n")), nil
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return nil, &FormatError{Status: 500, Type: "api_error", Message: "failed to encode content"}
	}
	return encoded, nil
}

func imageURL(part map[string]json.RawMessage) (string, string) {
	raw := part["image_url"]
	detail := rawString(part["detail"])
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) > 0 && trimmed[0] == '"' {
		return rawString(raw), detail
	}
	var obj struct {
		URL    string `json:"url"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		silentParseField("image_url")
	}
	if detail == "" {
		detail = obj.Detail
	}
	return obj.URL, detail
}

func assistantText(content json.RawMessage) string {
	trimmed := bytes.TrimSpace(content)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return ""
	}
	if trimmed[0] != '[' {
		var text string
		if json.Unmarshal(content, &text) == nil {
			return text
		}
		return ""
	}
	var parts []map[string]json.RawMessage
	if json.Unmarshal(trimmed, &parts) != nil {
		return ""
	}
	var b strings.Builder
	for _, part := range parts {
		kind := rawString(part["type"])
		switch kind {
		case "output_text", "text", "refusal", "":
			if t := rawString(part["text"]); t != "" {
				b.WriteString(t)
			} else if t := rawString(part["refusal"]); t != "" {
				b.WriteString(t)
			}
		}
	}
	return b.String()
}

func textOf(content json.RawMessage, sep string) string {
	trimmed := bytes.TrimSpace(content)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return ""
	}
	if trimmed[0] != '[' {
		var text string
		if json.Unmarshal(content, &text) == nil {
			return text
		}
		return ""
	}
	var parts []map[string]json.RawMessage
	if json.Unmarshal(trimmed, &parts) != nil {
		return ""
	}
	var texts []string
	for _, part := range parts {
		if t := rawString(part["text"]); t != "" {
			texts = append(texts, t)
		}
	}
	return strings.Join(texts, sep)
}

func functionCallMessage(raw json.RawMessage, custom bool) ChatMessage {
	var item struct {
		CallID    string          `json:"call_id"`
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
		Input     json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal(raw, &item); err != nil {
		silentParseField("function_call")
	}
	args := "{}"
	if custom {
		input := item.Input
		if len(bytes.TrimSpace(input)) == 0 {
			input = json.RawMessage("null")
		}
		encoded, err := json.Marshal(map[string]json.RawMessage{"input": input})
		if err == nil {
			args = string(encoded)
		}
	} else {
		args = argumentsString(item.Arguments)
	}
	return ChatMessage{
		Role:    "assistant",
		Content: json.RawMessage("null"),
		ToolCalls: []ToolCall{{
			ID:       item.CallID,
			Type:     "function",
			Function: ToolCallFunction{Name: item.Name, Arguments: args},
		}},
	}
}

func argumentsString(raw json.RawMessage) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" || string(trimmed) == `""` {
		return "{}"
	}
	var s string
	if json.Unmarshal(trimmed, &s) == nil {
		if s == "" {
			return "{}"
		}
		return s
	}
	return string(trimmed)
}

func toolOutputMessage(raw json.RawMessage, meta *ResponsesMeta) ChatMessage {
	var item struct {
		CallID string          `json:"call_id"`
		Output json.RawMessage `json:"output"`
	}
	if err := json.Unmarshal(raw, &item); err != nil {
		silentParseField("tool_output")
	}
	return ChatMessage{Role: "tool", ToolCallID: item.CallID, Content: mustRaw(toolOutputText(item.Output, meta))}
}

func toolOutputText(raw json.RawMessage, meta *ResponsesMeta) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return ""
	}
	if trimmed[0] == '"' {
		var s string
		if json.Unmarshal(trimmed, &s) == nil {
			return s
		}
	}
	if trimmed[0] == '[' {
		var parts []map[string]json.RawMessage
		if json.Unmarshal(trimmed, &parts) == nil {
			var texts []string
			for _, part := range parts {
				kind := rawString(part["type"])
				switch kind {
				case "input_text", "output_text", "text", "":
					texts = append(texts, rawString(part["text"]))
				default:
					texts = append(texts, "[non-text tool output omitted]")
					addDropped(meta, "tool_output_non_text")
				}
			}
			return strings.Join(texts, "\n")
		}
	}
	addDropped(meta, "tool_output_non_text")
	return string(trimmed)
}

func systemMessage(text string) ChatMessage {
	return ChatMessage{Role: "system", Content: mustRaw(text)}
}

func userMessage(text string) ChatMessage {
	return ChatMessage{Role: "user", Content: mustRaw(text)}
}

func mustRaw(text string) json.RawMessage {
	b, err := json.Marshal(text)
	if err != nil {
		return json.RawMessage(`""`)
	}
	return b
}

func normalizeSystems(messages []ChatMessage) []ChatMessage {
	if len(messages) == 0 {
		return messages
	}
	firstOther := 0
	for firstOther < len(messages) && messages[firstOther].Role == "system" {
		firstOther++
	}
	var out []ChatMessage
	if firstOther > 0 {
		var texts []string
		for _, msg := range messages[:firstOther] {
			var text string
			if err := json.Unmarshal(msg.Content, &text); err != nil {
				silentParseField("system_text")
			}
			texts = append(texts, text)
		}
		out = append(out, systemMessage(strings.Join(texts, "\n\n")))
	}
	for _, msg := range messages[firstOther:] {
		if msg.Role != "system" {
			out = append(out, msg)
			continue
		}
		var text string
		if err := json.Unmarshal(msg.Content, &text); err != nil {
			silentParseField("system_text")
		}
		out = append(out, userMessage("[system]\n"+text))
	}
	return out
}

func applyTools(req *ChatRequest, root map[string]json.RawMessage, meta *ResponsesMeta) *FormatError {
	raw, ok := root["tools"]
	if !ok || emptyJSON(raw) {
		return nil
	}
	var tools []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &tools); err != nil {
		return &FormatError{Status: 400, Type: "invalid_request_error", Code: "invalid_tools", Message: "tools must be an array"}
	}
	for _, tool := range tools {
		kind := rawString(tool["type"])
		switch kind {
		case "function":
			req.Tools = append(req.Tools, ChatTool{Type: "function", Function: functionSchema(tool)})
		case "custom":
			name := rawString(tool["name"])
			if meta.CustomToolNames == nil {
				meta.CustomToolNames = map[string]bool{}
			}
			meta.CustomToolNames[name] = true
			req.Tools = append(req.Tools, ChatTool{Type: "function", Function: customSchema(tool)})
		default:
			addDropped(meta, "tool:"+kind)
		}
	}
	return nil
}

func functionSchema(tool map[string]json.RawMessage) ChatFunction {
	fn := ChatFunction{
		Name:        rawString(tool["name"]),
		Description: rawString(tool["description"]),
		Parameters:  tool["parameters"],
	}
	if len(bytes.TrimSpace(fn.Parameters)) == 0 || string(bytes.TrimSpace(fn.Parameters)) == "null" {
		fn.Parameters = json.RawMessage(`{"type":"object","properties":{}}`)
	}
	if raw, ok := tool["strict"]; ok {
		var strict bool
		if json.Unmarshal(raw, &strict) == nil {
			fn.Strict = &strict
		}
	}
	return fn
}

func customSchema(tool map[string]json.RawMessage) ChatFunction {
	desc := "Raw input for this tool."
	var format struct {
		Type       string `json:"type"`
		Syntax     string `json:"syntax"`
		Definition string `json:"definition"`
	}
	if raw, ok := tool["format"]; ok {
		if err := json.Unmarshal(raw, &format); err != nil {
			silentParseField("tool_format")
		}
	}
	if format.Type == "grammar" {
		def := format.Definition
		if len(def) > 8192 {
			def = def[:8192]
		}
		desc += "\n\nThe input MUST match this " + format.Syntax + " grammar:\n" + def
	}
	params, _ := json.Marshal(map[string]any{
		"type": "object",
		"properties": map[string]any{
			"input": map[string]any{"type": "string", "description": desc},
		},
		"required":             []string{"input"},
		"additionalProperties": false,
	})
	return ChatFunction{Name: rawString(tool["name"]), Description: rawString(tool["description"]), Parameters: params}
}

func mapToolChoice(raw json.RawMessage, meta *ResponsesMeta) json.RawMessage {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) > 0 && trimmed[0] == '"' {
		var s string
		if json.Unmarshal(trimmed, &s) == nil && (s == "auto" || s == "none" || s == "required") {
			return append(json.RawMessage(nil), trimmed...)
		}
	}
	var obj struct {
		Type string `json:"type"`
		Name string `json:"name"`
	}
	if json.Unmarshal(trimmed, &obj) == nil && (obj.Type == "function" || obj.Type == "custom") && obj.Name != "" {
		encoded, err := json.Marshal(map[string]any{
			"type":     "function",
			"function": map[string]string{"name": obj.Name},
		})
		if err == nil {
			return encoded
		}
	}
	addDropped(meta, "tool_choice")
	return json.RawMessage(`"auto"`)
}

func applyTextFormat(req *ChatRequest, root map[string]json.RawMessage, meta *ResponsesMeta) {
	raw, ok := root["text"]
	if !ok {
		return
	}
	var text struct {
		Format struct {
			Type        string          `json:"type"`
			Name        string          `json:"name"`
			Schema      json.RawMessage `json:"schema"`
			Strict      *bool           `json:"strict"`
			Description string          `json:"description"`
		} `json:"format"`
		Verbosity json.RawMessage `json:"verbosity"`
	}
	if json.Unmarshal(raw, &text) != nil {
		return
	}
	if len(bytes.TrimSpace(text.Verbosity)) > 0 && string(bytes.TrimSpace(text.Verbosity)) != "null" {
		addDropped(meta, "text.verbosity")
	}
	switch text.Format.Type {
	case "", "text":
		return
	case "json_object":
		req.ResponseFormat = json.RawMessage(`{"type":"json_object"}`)
	case "json_schema":
		schema := map[string]any{
			"type": "json_schema",
			"json_schema": map[string]any{
				"name":        text.Format.Name,
				"schema":      json.RawMessage(text.Format.Schema),
				"strict":      text.Format.Strict,
				"description": text.Format.Description,
			},
		}
		encoded, err := json.Marshal(schema)
		if err == nil {
			req.ResponseFormat = encoded
		}
	}
}

func applyReasoning(root map[string]json.RawMessage, meta *ResponsesMeta) {
	raw, ok := root["reasoning"]
	if !ok {
		return
	}
	var reasoning struct {
		Effort json.RawMessage `json:"effort"`
	}
	if err := json.Unmarshal(raw, &reasoning); err != nil {
		silentParseField("reasoning")
	}
	if len(bytes.TrimSpace(reasoning.Effort)) > 0 && string(bytes.TrimSpace(reasoning.Effort)) != "null" {
		addDropped(meta, "reasoning")
	}
}

func applyUser(req *ChatRequest, root map[string]json.RawMessage, meta *ResponsesMeta) {
	if raw, ok := root["user"]; ok {
		if err := json.Unmarshal(raw, &req.User); err != nil {
			silentParseField("user")
		}
	}
	if req.User == "" {
		if raw, ok := root["safety_identifier"]; ok {
			if err := json.Unmarshal(raw, &req.User); err != nil {
				silentParseField("user")
			}
		}
	}
	meta.Echo.User = req.User
}

func addDropped(meta *ResponsesMeta, name string) {
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

func rawString(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}
