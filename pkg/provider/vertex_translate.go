// Package provider — Vertex request/response translation: OpenAI
// ChatCompletion ⇄ Gemini generateContent JSON.
//
// The internal envelope {"model":…,"gemini":{…}} carries the model from
// TranslateRequest to PrepareRequest (the Gemini generateContent body has NO
// model field — the model lives only in the endpoint URL path — and the
// Gemini proto schema rejects unknown top-level fields, so the model must be
// stripped from the wire body). The envelope never reaches the wire:
// PrepareRequest parses it, runs the capability matrix on the model, and
// sends only the inner generateContent payload.
//
// The gateway's per-hop model rewrite (overrideModel) sets the envelope's
// "model" key directly, which is why the model stays a first-class envelope
// member instead of being re-derived from the messages.
package provider

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/reireirei/yabanin/pkg/apiformat"
)

// vertexEnvelope is the adapter-internal TranslateRequest → PrepareRequest
// carrier (bedrockEnvelope precedent).
type vertexEnvelope struct {
	Model  string          `json:"model"`
	Gemini json.RawMessage `json:"gemini"`
}

// parseVertexEnvelope decodes and validates the envelope. The model check is
// also the fail-closed guard against URL path injection: the model becomes a
// URL path segment in PrepareRequest, so separators and traversal sequences
// are rejected here.
func parseVertexEnvelope(body []byte) (vertexEnvelope, error) {
	var env vertexEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return vertexEnvelope{}, errors.New("vertex: request body is not a vertex envelope; TranslateRequest must run first")
	}
	model := strings.TrimSpace(env.Model)
	if model == "" {
		return vertexEnvelope{}, errors.New("vertex: request envelope has no model; cannot resolve the Gemini model")
	}
	if strings.ContainsAny(model, "/\\?#:") || strings.Contains(model, "..") {
		return vertexEnvelope{}, fmt.Errorf("vertex: model %q contains URL path separators; registry model_name must be a bare model id", model)
	}
	if len(env.Gemini) == 0 {
		return vertexEnvelope{}, errors.New("vertex: request envelope has no gemini payload")
	}
	env.Model = model
	return env, nil
}

// — Gemini generateContent request wire shapes (proto3 JSON, camelCase) —

type vertexGenerateRequest struct {
	Contents          []vertexContent         `json:"contents"`
	SystemInstruction *vertexContent          `json:"systemInstruction,omitempty"`
	Tools             []vertexTool            `json:"tools,omitempty"`
	ToolConfig        *vertexToolConfig       `json:"toolConfig,omitempty"`
	GenerationConfig  *vertexGenerationConfig `json:"generationConfig,omitempty"`
}

// vertexContent is one Gemini Content: a role plus an ordered part list.
// Roles on the wire are "user" and "model" only.
type vertexContent struct {
	Role  string          `json:"role,omitempty"`
	Parts []vertexReqPart `json:"parts"`
}

// vertexReqPart is the request-side part union; exactly one field is set.
// Media parts are never emitted — the translation rejects them upstream.
type vertexReqPart struct {
	Text             string                  `json:"text,omitempty"`
	FunctionCall     *vertexFunctionCall     `json:"functionCall,omitempty"`
	FunctionResponse *vertexFunctionResponse `json:"functionResponse,omitempty"`
}

// vertexFunctionCall mirrors a Gemini FunctionCall. Args is a JSON object
// (proto Struct); nil/absent means "no arguments".
type vertexFunctionCall struct {
	Name string          `json:"name"`
	Args json.RawMessage `json:"args,omitempty"`
}

// vertexFunctionResponse mirrors a Gemini FunctionResponse. Response must be
// a JSON object (proto Struct requirement).
type vertexFunctionResponse struct {
	Name     string          `json:"name"`
	Response json.RawMessage `json:"response"`
}

type vertexTool struct {
	FunctionDeclarations []vertexFunctionDeclaration `json:"functionDeclarations"`
}

type vertexFunctionDeclaration struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

type vertexToolConfig struct {
	FunctionCallingConfig vertexFunctionCallingConfig `json:"functionCallingConfig"`
}

type vertexFunctionCallingConfig struct {
	Mode                 string   `json:"mode"`
	AllowedFunctionNames []string `json:"allowedFunctionNames,omitempty"`
}

type vertexGenerationConfig struct {
	MaxOutputTokens  *int     `json:"maxOutputTokens,omitempty"`
	Temperature      *float64 `json:"temperature,omitempty"`
	TopP             *float64 `json:"topP,omitempty"`
	StopSequences    []string `json:"stopSequences,omitempty"`
	ResponseMimeType string   `json:"responseMimeType,omitempty"`
}

// — Gemini generateContent response wire shapes —

type vertexGenerateResponse struct {
	Candidates    []vertexCandidate    `json:"candidates"`
	UsageMetadata *vertexUsageMetadata `json:"usageMetadata"`
	ModelVersion  string               `json:"modelVersion"`
	// Error carries an in-band Google error object (same shape the stream
	// path's vertexStreamEvent already surfaces). Vertex normally reports
	// failures via HTTP status, but a refusal delivered inside a 200 body
	// must not be silently reclassified as "no candidates".
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Status  string `json:"status"`
	} `json:"error"`
	PromptFeedback *struct {
		BlockReason string `json:"blockReason"`
	} `json:"promptFeedback"`
}

type vertexCandidate struct {
	Content *struct {
		Parts []vertexRespPart `json:"parts"`
		Role  string           `json:"role"`
	} `json:"content"`
	FinishReason string `json:"finishReason"`
	Index        int32  `json:"index"`
}

// vertexRespPart is the response-side part union. Fields the adapter cannot
// map back to OpenAI are kept as raw messages ONLY so the kind detection can
// name them in a precise rejection; their payloads are never forwarded.
type vertexRespPart struct {
	Text         *string             `json:"text"`
	Thought      bool                `json:"thought"`
	FunctionCall *vertexFunctionCall `json:"functionCall"`

	InlineData          json.RawMessage `json:"inlineData"`
	FileData            json.RawMessage `json:"fileData"`
	FunctionResponse    json.RawMessage `json:"functionResponse"`
	ExecutableCode      json.RawMessage `json:"executableCode"`
	CodeExecutionResult json.RawMessage `json:"codeExecutionResult"`
	VideoMetadata       json.RawMessage `json:"videoMetadata"`
}

// kind reports which union member is set: "text", "functionCall", or the
// raw field name for unmappable kinds. Empty means "no recognized member".
func (p vertexRespPart) kind() string {
	switch {
	case p.FunctionCall != nil:
		return "functionCall"
	case p.Text != nil:
		return "text"
	case len(p.InlineData) > 0:
		return "inlineData"
	case len(p.FileData) > 0:
		return "fileData"
	case len(p.FunctionResponse) > 0:
		return "functionResponse"
	case len(p.ExecutableCode) > 0:
		return "executableCode"
	case len(p.CodeExecutionResult) > 0:
		return "codeExecutionResult"
	case len(p.VideoMetadata) > 0:
		return "videoMetadata"
	default:
		return ""
	}
}

// vertexUsageMetadata is the Gemini usage object, shared by the non-streaming
// response translation, the stream translator and ParseUsage.
type vertexUsageMetadata struct {
	PromptTokenCount        int64 `json:"promptTokenCount"`
	CandidatesTokenCount    int64 `json:"candidatesTokenCount"`
	TotalTokenCount         int64 `json:"totalTokenCount"`
	CachedContentTokenCount int64 `json:"cachedContentTokenCount"`
}

// toUsage applies the canonical fold: PromptTokens is promptTokenCount
// (Vertex reports it inclusive of cached content, matching the canonical
// Usage semantics), CacheReadTokens is cachedContentTokenCount,
// CompletionTokens is candidatesTokenCount.
func (m *vertexUsageMetadata) toUsage() Usage {
	u := Usage{
		PromptTokens:     m.PromptTokenCount,
		CompletionTokens: m.CandidatesTokenCount,
		TotalTokens:      m.TotalTokenCount,
		CacheReadTokens:  m.CachedContentTokenCount,
		Source:           UsageSourceProvider,
	}
	if u.TotalTokens == 0 {
		u.TotalTokens = u.PromptTokens + u.CompletionTokens
	}
	return u
}

// TranslateRequest converts an OpenAI ChatCompletionRequest into the
// adapter-internal vertex envelope. See chatToVertexGenerate.
func (*Vertex) TranslateRequest(openaiBody []byte) ([]byte, error) {
	gemini, model, err := chatToVertexGenerate(openaiBody)
	if err != nil {
		return nil, err
	}
	out, err := json.Marshal(vertexEnvelope{Model: model, Gemini: gemini})
	if err != nil {
		return nil, fmt.Errorf("vertex: encode envelope: %w", err)
	}
	return out, nil
}

// chatToVertexGenerate maps an OpenAI chat body to (geminiJSON, model).
// Supported: system/developer→systemInstruction, user/assistant text
// (string or text-part arrays), assistant tool_calls → functionCall parts,
// tool results → functionResponse parts, tools/tool_choice, max_tokens/
// max_completion_tokens, temperature, top_p, stop, response_format
// json_object. Media parts and unmappable features reject precisely (I51) —
// an OpenAI client expecting a tool call must never receive a text answer
// that pretends the request succeeded.
func chatToVertexGenerate(body []byte) ([]byte, string, error) {
	body = coerceStopToArray(body)
	var req struct {
		apiformat.ChatRequest
		MaxCompletionTokens *int `json:"max_completion_tokens,omitempty"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, "", fmt.Errorf("vertex: decode openai request: %w", err)
	}
	model := strings.TrimSpace(req.Model)
	if model == "" {
		return nil, "", errors.New("vertex: request body has no model field; cannot resolve the Gemini model")
	}
	// N07-P01-T05 (I51): reasoning_effort is modeled but has no mapped Gemini
	// equivalent yet (thinkingConfig mapping pending). Reject instead of
	// silently answering at a default reasoning level.
	if req.ReasoningEffort != "" {
		return nil, "", fmt.Errorf("vertex: reasoning_effort %q is not mapped yet (Gemini thinkingConfig mapping pending); rejecting instead of silently dropping (I51)", req.ReasoningEffort)
	}

	var (
		out      vertexGenerateRequest
		system   []vertexReqPart
		contents []vertexContent
		// toolNames resolves OpenAI tool_call_id → Gemini function name for
		// tool result messages (OpenAI addresses results by id, Gemini by
		// function name).
		toolNames = map[string]string{}
		frIdx     = -1 // index of the functionResponse content being merged
	)
	for _, msg := range req.Messages {
		switch msg.Role {
		case "system", "developer":
			text, err := vertexTextOf(msg.Content)
			if err != nil {
				return nil, "", err
			}
			if text != "" {
				system = append(system, vertexReqPart{Text: text})
			}
		case "user":
			text, err := vertexTextOf(msg.Content)
			if err != nil {
				return nil, "", err
			}
			if text == "" {
				return nil, "", errors.New("vertex: user message has no translatable content; rejecting instead of sending an empty Gemini content")
			}
			contents = append(contents, vertexContent{Role: "user", Parts: []vertexReqPart{{Text: text}}})
			frIdx = -1
		case "assistant":
			parts := make([]vertexReqPart, 0, 1+len(msg.ToolCalls))
			if text, err := vertexTextOf(msg.Content); err != nil {
				return nil, "", err
			} else if text != "" {
				parts = append(parts, vertexReqPart{Text: text})
			}
			for _, tc := range msg.ToolCalls {
				if tc.Type != "" && tc.Type != "function" {
					return nil, "", fmt.Errorf("vertex: unsupported tool call type %q; only function calls are mapped", tc.Type)
				}
				if tc.Function.Name == "" {
					return nil, "", errors.New("vertex: tool call without a function name; cannot map to a Gemini functionCall")
				}
				args, err := vertexArgsBytes(tc.Function.Arguments)
				if err != nil {
					return nil, "", err
				}
				toolNames[tc.ID] = tc.Function.Name
				parts = append(parts, vertexReqPart{FunctionCall: &vertexFunctionCall{Name: tc.Function.Name, Args: args}})
			}
			if len(parts) == 0 {
				// An assistant message with neither content nor tool calls
				// carries no semantics to translate; Gemini would reject the
				// empty content outright.
				continue
			}
			contents = append(contents, vertexContent{Role: "model", Parts: parts})
			frIdx = -1
		case "tool":
			name := msg.Name
			if name == "" {
				name = toolNames[msg.ToolCallID]
			}
			if name == "" {
				return nil, "", errors.New("vertex: tool result cannot be resolved to a function name (set message.name or match a prior assistant tool_call id)")
			}
			part := vertexReqPart{FunctionResponse: &vertexFunctionResponse{
				Name:     name,
				Response: vertexResponseObject(apiformat.ContentText(msg.Content)),
			}}
			// Gemini expects the responses to a parallel tool-call turn as
			// functionResponse parts of ONE user content — merge consecutive
			// tool messages accordingly.
			if frIdx >= 0 && frIdx == len(contents)-1 {
				contents[frIdx].Parts = append(contents[frIdx].Parts, part)
			} else {
				contents = append(contents, vertexContent{Role: "user", Parts: []vertexReqPart{part}})
				frIdx = len(contents) - 1
			}
		default:
			return nil, "", fmt.Errorf("vertex: unsupported message role %q; rejecting instead of silently dropping the message", msg.Role)
		}
	}
	if len(contents) == 0 {
		return nil, "", errors.New("vertex: request has no user/assistant messages to generate from")
	}
	out.Contents = contents
	if len(system) > 0 {
		out.SystemInstruction = &vertexContent{Parts: system}
	}

	if err := vertexMapTools(&out, &req.ChatRequest); err != nil {
		return nil, "", err
	}

	gc := &vertexGenerationConfig{}
	gc.MaxOutputTokens = req.MaxCompletionTokens
	if gc.MaxOutputTokens == nil {
		gc.MaxOutputTokens = req.MaxTokens
	}
	gc.Temperature = req.Temperature
	gc.TopP = req.TopP
	if len(req.Stop) > 0 {
		gc.StopSequences = req.Stop
	}
	if len(req.ResponseFormat) > 0 && string(req.ResponseFormat) != "null" {
		var rf struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(req.ResponseFormat, &rf); err != nil {
			return nil, "", errors.New("vertex: response_format is not a {type} object")
		}
		switch rf.Type {
		case "", "text":
			// Default behavior; nothing to set.
		case "json_object":
			gc.ResponseMimeType = "application/json"
		case "json_schema":
			return nil, "", errors.New("vertex: response_format json_schema is not mapped; rejecting instead of silently ignoring the schema guarantee")
		default:
			return nil, "", fmt.Errorf("vertex: unsupported response_format type %q", rf.Type)
		}
	}
	if gc.MaxOutputTokens != nil || gc.Temperature != nil || gc.TopP != nil ||
		len(gc.StopSequences) > 0 || gc.ResponseMimeType != "" {
		out.GenerationConfig = gc
	}

	gemini, err := json.Marshal(out)
	if err != nil {
		return nil, "", fmt.Errorf("vertex: encode generateContent request: %w", err)
	}
	return gemini, model, nil
}

// vertexMapTools maps the OpenAI tools/tool_choice pair onto Gemini
// functionDeclarations and the functionCallingConfig. tool_choice without
// tools is rejected (no OpenAI-declared semantics for it).
func vertexMapTools(out *vertexGenerateRequest, req *apiformat.ChatRequest) error {
	// N07-P01-T03 negative criterion: parallel_tool_calls=false is a
	// no-parallel contract Gemini cannot express (no disable flag) — a
	// silent drop would let the model fan out tool calls the client
	// explicitly forbade. Only meaningful with tools declared; without
	// tools no tool call can occur, so the field governs nothing and the
	// request stays valid.
	if len(req.Tools) > 0 && req.ParallelToolCalls != nil && !*req.ParallelToolCalls {
		return errors.New("vertex: parallel_tool_calls=false has no Gemini equivalent; rejecting instead of silently ignoring the no-parallel contract (I51)")
	}
	if len(req.Tools) > 0 {
		decls := make([]vertexFunctionDeclaration, 0, len(req.Tools))
		for _, t := range req.Tools {
			if t.Type != "function" {
				return fmt.Errorf("vertex: unsupported tool type %q; only function tools are mapped", t.Type)
			}
			if t.Function.Name == "" {
				return errors.New("vertex: tool without a function name; cannot declare it to Gemini")
			}
			if t.Function.Strict != nil && *t.Function.Strict {
				return fmt.Errorf("vertex: strict structured outputs for tool %q have no Gemini equivalent; rejecting instead of silently relaxing the schema guarantee", t.Function.Name)
			}
			decls = append(decls, vertexFunctionDeclaration{
				Name:        t.Function.Name,
				Description: t.Function.Description,
				Parameters:  t.Function.Parameters,
			})
		}
		out.Tools = []vertexTool{{FunctionDeclarations: decls}}
	}
	if req.ToolChoice == nil {
		return nil
	}
	if len(req.Tools) == 0 {
		return errors.New("vertex: tool_choice requires tools; rejecting instead of silently ignoring it")
	}
	mode, allowed, err := vertexToolChoice(req.ToolChoice)
	if err != nil {
		return err
	}
	out.ToolConfig = &vertexToolConfig{FunctionCallingConfig: vertexFunctionCallingConfig{
		Mode:                 mode,
		AllowedFunctionNames: allowed,
	}}
	return nil
}

// vertexToolChoice maps the OpenAI tool_choice values onto the Gemini
// function-calling modes: auto→AUTO, none→NONE, required→ANY, and
// {type:"function",function:{name}} → ANY restricted to that function.
func vertexToolChoice(raw json.RawMessage) (string, []string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		switch s {
		case "auto":
			return "AUTO", nil, nil
		case "none":
			return "NONE", nil, nil
		case "required":
			return "ANY", nil, nil
		default:
			return "", nil, fmt.Errorf("vertex: unsupported tool_choice %q", s)
		}
	}
	var obj struct {
		Type     string `json:"type"`
		Function struct {
			Name string `json:"name"`
		} `json:"function"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil || obj.Type != "function" || obj.Function.Name == "" {
		return "", nil, errors.New(`vertex: tool_choice must be "auto"|"none"|"required" or {"type":"function","function":{"name":…}}`)
	}
	return "ANY", []string{obj.Function.Name}, nil
}

// vertexTextOf extracts translatable text from an OpenAI content field
// (JSON string or content-part array). Media-bearing parts reject precisely:
// dropping them would silently change what the model sees (I61 media
// mapping is per-model and not shipped in the text path).
func vertexTextOf(raw json.RawMessage) (string, error) {
	if s, ok := rawJSONString(raw); ok {
		return s, nil
	}
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	var parts []apiformat.ContentPart
	if err := json.Unmarshal(raw, &parts); err != nil {
		return "", errors.New("vertex: message content is neither a string nor a content-part array")
	}
	var b strings.Builder
	for _, p := range parts {
		switch p.Type {
		case "text":
			b.WriteString(p.Text)
		case "image_url":
			// N07-P05-T02: typed so the gateway answers an explicit
			// 400 unsupported_feature (same text as before).
			return "", &UnsupportedFeatureError{
				Provider: "vertex",
				Reason:   "image inputs are not mapped in the text path; rejecting instead of silently dropping the image part",
			}
		default:
			return "", &UnsupportedFeatureError{
				Provider: "vertex",
				Reason:   fmt.Sprintf("content part type %q is not mapped; rejecting instead of silently dropping the part", p.Type),
			}
		}
	}
	return b.String(), nil
}

// vertexArgsBytes converts an OpenAI tool-call arguments STRING into the
// Gemini args JSON object. Empty arguments become {}.
func vertexArgsBytes(args string) (json.RawMessage, error) {
	trimmed := strings.TrimSpace(args)
	if trimmed == "" || trimmed == "null" {
		return json.RawMessage(`{}`), nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &obj); err != nil {
		return nil, errors.New("vertex: tool call arguments are not a JSON object; Gemini args must be an object")
	}
	return json.RawMessage(trimmed), nil
}

// vertexArgsString is the read-side inverse: Gemini args object → the OpenAI
// arguments string. Absent args become "{}".
func vertexArgsString(raw json.RawMessage) string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return "{}"
	}
	return trimmed
}

// vertexResponseObject converts an OpenAI tool result (a text string, often
// JSON-encoded) into the Gemini functionResponse object: a JSON object
// passes through verbatim, anything else is wrapped as {"result": text}.
// Wrapping is the documented adapter mapping for non-object tool output —
// the result content itself is never altered.
func vertexResponseObject(text string) json.RawMessage {
	trimmed := strings.TrimSpace(text)
	if trimmed != "" {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal([]byte(trimmed), &obj); err == nil {
			return json.RawMessage(trimmed)
		}
	}
	wrapped, err := json.Marshal(map[string]string{"result": text})
	if err != nil {
		// Marshal of a one-key string map cannot fail; defensive fallback.
		return json.RawMessage(`{}`)
	}
	return wrapped
}

// TranslateResponse converts a non-streaming generateContent body into the
// OpenAI ChatCompletionResponse shape. See vertexToChatResponse.
func (*Vertex) TranslateResponse(providerBody []byte) ([]byte, error) {
	return vertexToChatResponse(providerBody)
}

// vertexToChatResponse maps candidates to OpenAI choices. Text parts
// concatenate without a separator; thought parts (Gemini 2.5 thinking
// summaries) map to reasoning_content; functionCall parts map to complete
// tool_calls entries. Unmappable part kinds and a blocked prompt fail closed
// with the precise reason.
func vertexToChatResponse(body []byte) ([]byte, error) {
	var out vertexGenerateResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("vertex: decode generateContent response: %w", err)
	}
	// In-band upstream refusal (quota exhaustion, permission denial): the
	// provider's own status and message surface verbatim, in the same shape
	// the stream handler reports — never mapped to a successful (or empty)
	// chat completion, and never replaced by the vaguer "no candidates".
	if out.Error != nil {
		return nil, fmt.Errorf("vertex upstream error (status %s): %s", out.Error.Status, out.Error.Message)
	}
	if len(out.Candidates) == 0 {
		if out.PromptFeedback != nil && out.PromptFeedback.BlockReason != "" {
			return nil, fmt.Errorf("vertex: prompt blocked by the upstream safety filters (blockReason %s)", out.PromptFeedback.BlockReason)
		}
		return nil, errors.New("vertex: generateContent response has no candidates")
	}

	choices := make([]any, 0, len(out.Candidates))
	for i, cand := range out.Candidates {
		index := int(cand.Index)
		if cand.Index == 0 {
			index = i
		}
		var (
			text      strings.Builder
			reasoning strings.Builder
			toolCalls []any
		)
		if cand.Content != nil {
			for _, part := range cand.Content.Parts {
				switch part.kind() {
				case "text":
					if part.Thought {
						reasoning.WriteString(*part.Text)
					} else {
						text.WriteString(*part.Text)
					}
				case "functionCall":
					toolCalls = append(toolCalls, map[string]any{
						"id":   "call_" + vertexRandomHex(8),
						"type": "function",
						"function": map[string]any{
							"name":      part.FunctionCall.Name,
							"arguments": vertexArgsString(part.FunctionCall.Args),
						},
					})
				case "":
					// Empty part object: nothing to map.
				default:
					return nil, fmt.Errorf("vertex: response candidate carries unsupported part kind %q; refusing to map it to an OpenAI choice", part.kind())
				}
			}
		}
		finish, err := vertexFinishReason(cand.FinishReason, len(toolCalls) > 0)
		if err != nil {
			return nil, err
		}
		msg := map[string]any{
			"role":    "assistant",
			"content": any(text.String()),
		}
		if reasoning.Len() > 0 {
			msg["reasoning_content"] = reasoning.String()
		}
		if len(toolCalls) > 0 {
			msg["tool_calls"] = toolCalls
		}
		choices = append(choices, map[string]any{
			"index":         index,
			"message":       msg,
			"finish_reason": finish,
		})
	}

	resp := map[string]any{
		"id":      "chatcmpl-vertex-" + vertexRandomHex(16),
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   out.ModelVersion,
		"choices": choices,
	}
	// Omit the usage block when Vertex reported none: a zero usage object
	// would masquerade as provider-reported metering downstream
	// (ParseUsage shape-sniffs and would read prompt_tokens=0 as real).
	if out.UsageMetadata != nil {
		u := out.UsageMetadata.toUsage()
		usage := map[string]any{
			"prompt_tokens":     u.PromptTokens,
			"completion_tokens": u.CompletionTokens,
			"total_tokens":      u.TotalTokens,
		}
		if u.CacheReadTokens > 0 {
			usage["prompt_tokens_details"] = map[string]any{"cached_tokens": u.CacheReadTokens}
		}
		resp["usage"] = usage
	}
	return json.Marshal(resp)
}

// vertexFinishReason maps Gemini finishReason values to OpenAI
// finish_reason. A candidate that produced function calls reports
// "tool_calls" (Gemini itself stops with STOP for tool turns). MALFORMED_
// FUNCTION_CALL is an upstream generation failure — mapping it to a
// successful "stop" would masquerade a broken tool turn as success.
func vertexFinishReason(reason string, hasToolCalls bool) (string, error) {
	switch reason {
	case "", "STOP":
		if hasToolCalls {
			return "tool_calls", nil
		}
		return "stop", nil
	case "MAX_TOKENS":
		return "length", nil
	case "SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII", "IMAGE_SAFETY":
		return "content_filter", nil
	case "MALFORMED_FUNCTION_CALL":
		return "", errors.New("vertex: upstream aborted generation with MALFORMED_FUNCTION_CALL; refusing to report it as a successful stop")
	default:
		return "stop", nil
	}
}

// vertexRandomHex returns n crypto-random bytes hex-encoded. Used for
// chat.completion ids and tool-call ids — never for anything secret-bearing.
func vertexRandomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// Crypto/rand failure is catastrophic but must not panic the
		// request path; a time-derived fallback keeps the id unique enough.
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
