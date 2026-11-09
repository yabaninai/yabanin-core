// Package provider — Bedrock request/response translation (N08-P02-T02).
//
// OpenAI ChatCompletion ⇄ Bedrock Converse JSON. The internal envelope
// {"model":…,"converse":{…}} carries the modelId from TranslateRequest to
// PrepareRequest (Converse has modelId only as a URL path segment); the
// envelope never reaches the wire — PrepareRequest strips it.
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

// bedrockEnvelope is the adapter-internal TranslateRequest → PrepareRequest
// carrier. Adapter-internal only (see package comment): the converse payload
// is what goes on the wire, the model becomes the escaped path segment.
type bedrockEnvelope struct {
	Model    string          `json:"model"`
	Converse json.RawMessage `json:"converse"`
}

func parseBedrockEnvelope(body []byte) (bedrockEnvelope, error) {
	var env bedrockEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return bedrockEnvelope{}, errors.New("bedrock: request body is not a bedrock envelope; TranslateRequest must run first")
	}
	if strings.TrimSpace(env.Model) == "" {
		return bedrockEnvelope{}, errors.New("bedrock: request envelope has no model; cannot resolve the Converse modelId")
	}
	if len(env.Converse) == 0 {
		return bedrockEnvelope{}, errors.New("bedrock: request envelope has no converse payload")
	}
	return env, nil
}

// Bedrock Converse JSON shapes (aws.rest-json1 wire format, documented
// stable): system is a list of text blocks, message content is a list of
// typed blocks, inference parameters live under inferenceConfig.
type bedrockTextBlock struct {
	Text string `json:"text"`
}

type bedrockContentBlock struct {
	Text string `json:"text"`
}

type bedrockMessage struct {
	Role    string                `json:"role"`
	Content []bedrockContentBlock `json:"content"`
}

type bedrockInferenceConfig struct {
	MaxTokens     *int     `json:"maxTokens,omitempty"`
	Temperature   *float64 `json:"temperature,omitempty"`
	TopP          *float64 `json:"topP,omitempty"`
	StopSequences []string `json:"stopSequences,omitempty"`
}

type bedrockConverseInput struct {
	System          []bedrockTextBlock      `json:"system,omitempty"`
	Messages        []bedrockMessage        `json:"messages"`
	InferenceConfig *bedrockInferenceConfig `json:"inferenceConfig,omitempty"`
}

// bedrockTokens is the Converse usage object (inputTokens/outputTokens/
// totalTokens plus the prompt-cache fields Bedrock reports for models with
// prompt caching enabled).
type bedrockTokens struct {
	InputTokens           int64 `json:"inputTokens"`
	OutputTokens          int64 `json:"outputTokens"`
	TotalTokens           int64 `json:"totalTokens"`
	CacheReadInputTokens  int64 `json:"cacheReadInputTokens"`
	CacheWriteInputTokens int64 `json:"cacheWriteInputTokens"`
}

// toUsage applies the canonical fold: PromptTokens counts every input token
// including cache reads and writes (same convention as the anthropic
// adapter, whose per-model semantics Bedrock passes through). If live smoke
// shows Bedrock reporting inclusive counts for some model family, this is
// the single function to adjust (record: honest gaps).
func (t bedrockTokens) toUsage() Usage {
	prompt := t.InputTokens + t.CacheReadInputTokens + t.CacheWriteInputTokens
	total := t.TotalTokens
	if total == 0 {
		total = prompt + t.OutputTokens
	}
	return Usage{
		PromptTokens:        prompt,
		CompletionTokens:    t.OutputTokens,
		TotalTokens:         total,
		CacheReadTokens:     t.CacheReadInputTokens,
		CacheCreationTokens: t.CacheWriteInputTokens,
		Source:              UsageSourceProvider,
	}
}

// errBedrockUnsupportedTools is returned for any tool-bearing feature. Per
// I50/I51 the adapter REJECTS instead of silently dropping (an OpenAI client
// expecting tool calls must not receive a plain-text answer pretending
// success). Typed refusal: the gateway renders it 400
// capability_not_supported, chain-terminal.
var errBedrockUnsupportedTools = &CapabilityError{
	Provider:   "bedrock",
	Capability: CapabilityTools,
	Detail:     "bedrock adapter: tools/tool_choice are not supported yet (Converse toolUse mapping pending); refusing instead of silently dropping (I50/I51)",
}

// errBedrockUnsupportedMedia is returned for image content parts (I61 media
// deferred — explicit reject, no silent downgrade). Typed (N07-P05-T02): the
// gateway answers 400 unsupported_feature with this exact reason text.
var errBedrockUnsupportedMedia = &UnsupportedFeatureError{
	Provider: "bedrock",
	Reason:   "image inputs are not supported yet (I61 media deferred); text-only at T02",
}

// errBedrockUnsupportedReasoningEffort is returned for the modeled
// reasoning_effort field (N07-P01-T05): Converse has no reasoning-effort
// control mapped yet — loud refuse instead of a silent default-effort
// answer (I51).
var errBedrockUnsupportedReasoningEffort = errors.New("bedrock adapter: reasoning_effort is not mapped yet (Converse has no reasoning-effort control); refusing instead of silently dropping (I51)")

// TranslateRequest converts an OpenAI ChatCompletionRequest into the
// adapter-internal bedrock envelope. See chatToBedrockConverse.
func (*Bedrock) TranslateRequest(openaiBody []byte) ([]byte, error) {
	converse, model, err := chatToBedrockConverse(openaiBody)
	if err != nil {
		return nil, err
	}
	env := bedrockEnvelope{Model: model, Converse: converse}
	out, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("bedrock: encode envelope: %w", err)
	}
	return out, nil
}

// chatToBedrockConverse maps an OpenAI chat body to (converseJSON, modelId).
// Supported: system/developer→system blocks, user/assistant text (string or
// text-part arrays), max_tokens/max_completion_tokens, temperature, top_p,
// stop. Tools, image parts and unknown content-part types are explicit
// rejections (fail-closed, typed UnsupportedFeatureError for media/part
// rejections — N07-P05-T02).
func chatToBedrockConverse(body []byte) ([]byte, string, error) {
	body = coerceStopToArray(body)
	var req struct {
		apiformat.ChatRequest
		MaxCompletionTokens *int `json:"max_completion_tokens,omitempty"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, "", fmt.Errorf("bedrock: decode openai request: %w", err)
	}
	if len(req.Tools) > 0 || req.ToolChoice != nil {
		return nil, "", errBedrockUnsupportedTools
	}
	// N07-P01-T03: Converse has no JSON-mode guarantee — json_object /
	// json_schema would silently lose the schema contract. Reject loudly.
	if err := rejectUnmappedResponseFormat("bedrock", req.ResponseFormat); err != nil {
		return nil, "", err
	}
	// N07-P01-T05 (I51): modeled reasoning_effort has no Converse equivalent
	// yet — reject loudly instead of silently answering at a default effort.
	if req.ReasoningEffort != "" {
		return nil, "", errBedrockUnsupportedReasoningEffort
	}
	if strings.TrimSpace(req.Model) == "" {
		return nil, "", errors.New("bedrock: request body has no model field; cannot resolve the Converse modelId")
	}

	var (
		input    bedrockConverseInput
		messages []bedrockMessage
	)
	for _, msg := range req.Messages {
		switch msg.Role {
		case "system", "developer":
			blocks, err := bedrockTextBlocks(msg.Content)
			if err != nil {
				return nil, "", err
			}
			for _, b := range blocks {
				input.System = append(input.System, bedrockTextBlock{Text: b})
			}
		case "user":
			blocks, err := bedrockTextBlocks(msg.Content)
			if err != nil {
				return nil, "", err
			}
			messages = append(messages, bedrockMessage{Role: "user", Content: toBedrockContent(blocks)})
		case "assistant":
			if len(msg.ToolCalls) > 0 {
				return nil, "", errBedrockUnsupportedTools
			}
			blocks, err := bedrockTextBlocks(msg.Content)
			if err != nil {
				return nil, "", err
			}
			messages = append(messages, bedrockMessage{Role: "assistant", Content: toBedrockContent(blocks)})
		case "tool":
			return nil, "", errBedrockUnsupportedTools
		default:
			// Converse has no other roles; dropping avoids a 400 (same
			// convention as the anthropic adapter).
		}
	}
	if len(messages) == 0 {
		return nil, "", errors.New("bedrock: request has no user/assistant messages to converse with")
	}
	input.Messages = messages

	inference := &bedrockInferenceConfig{}
	inference.MaxTokens = req.MaxCompletionTokens
	if inference.MaxTokens == nil {
		inference.MaxTokens = req.MaxTokens
	}
	inference.Temperature = req.Temperature
	inference.TopP = req.TopP
	if len(req.Stop) > 0 {
		inference.StopSequences = req.Stop
	}
	input.InferenceConfig = inference

	out, err := json.Marshal(input)
	if err != nil {
		return nil, "", fmt.Errorf("bedrock: encode converse input: %w", err)
	}
	return out, req.Model, nil
}

// bedrockTextBlocks extracts text blocks from an OpenAI content field
// (JSON string or multipart array). Image parts reject explicitly.
func bedrockTextBlocks(raw json.RawMessage) ([]string, error) {
	if s, ok := rawJSONString(raw); ok {
		return []string{s}, nil
	}
	var parts []apiformat.ContentPart
	if err := json.Unmarshal(raw, &parts); err != nil {
		return nil, errors.New("bedrock: message content is neither a string nor a content-part array")
	}
	var out []string
	for _, p := range parts {
		switch p.Type {
		case "text":
			out = append(out, p.Text)
		case "image_url":
			return nil, errBedrockUnsupportedMedia
		default:
			// N07-P05-T02 / F1 (T01 finding): unknown part types are an
			// explicit rejection, never a silent drop — a client that sends
			// an unmappable part (audio, file, a future type) must not get a
			// text-only answer pretending the part never existed (I51).
			// Same fail-closed convention as the vertex adapter.
			return nil, &UnsupportedFeatureError{
				Provider: "bedrock",
				Reason:   fmt.Sprintf("content part type %q is not mapped; rejecting instead of silently dropping the part", p.Type),
			}
		}
	}
	return out, nil
}

func toBedrockContent(texts []string) []bedrockContentBlock {
	blocks := make([]bedrockContentBlock, 0, len(texts))
	for _, t := range texts {
		blocks = append(blocks, bedrockContentBlock{Text: t})
	}
	return blocks
}

// TranslateResponse converts a non-streaming ConverseOutput body into the
// OpenAI ChatCompletionResponse shape.
func (*Bedrock) TranslateResponse(providerBody []byte) ([]byte, error) {
	return bedrockToChatResponse(providerBody)
}

func bedrockToChatResponse(body []byte) ([]byte, error) {
	var out struct {
		Output *struct {
			Message *struct {
				Role    string `json:"role"`
				Content []struct {
					Text *string `json:"text"`
				} `json:"content"`
			} `json:"message"`
		} `json:"output"`
		StopReason string         `json:"stopReason"`
		Usage      *bedrockTokens `json:"usage"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("bedrock: decode converse output: %w", err)
	}
	if out.Output == nil || out.Output.Message == nil {
		return nil, errors.New("bedrock: converse output has no message")
	}

	// Text blocks concatenate without a separator — same convention as the
	// anthropic adapter; non-text blocks (toolUse etc.) are ignored (tools
	// are rejected upstream of this path anyway).
	var text strings.Builder
	for _, block := range out.Output.Message.Content {
		if block.Text != nil {
			text.WriteString(*block.Text)
		}
	}
	content := any(text.String())

	usage := Usage{Source: UsageSourceNone}
	if out.Usage != nil {
		usage = out.Usage.toUsage()
	}
	usageOut := map[string]any{
		"prompt_tokens":     usage.PromptTokens,
		"completion_tokens": usage.CompletionTokens,
		"total_tokens":      usage.TotalTokens,
	}
	if usage.CacheReadTokens > 0 || usage.CacheCreationTokens > 0 {
		details := map[string]any{}
		if usage.CacheReadTokens > 0 {
			details["cached_tokens"] = usage.CacheReadTokens
		}
		if usage.CacheCreationTokens > 0 {
			details["cache_creation_input_tokens"] = usage.CacheCreationTokens
		}
		usageOut["prompt_tokens_details"] = details
	}

	resp := map[string]any{
		"id":      "chatcmpl-bedrock-" + bedrockRandomHex(16),
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   "", // ConverseOutput does not echo the modelId; the gateway carries the registry model
		"choices": []any{map[string]any{
			"index":         0,
			"message":       map[string]any{"role": "assistant", "content": content},
			"finish_reason": mapBedrockStop(out.StopReason),
		}},
	}
	// Omit the usage block when Bedrock reported none: a zero usage object
	// would masquerade as provider-reported metering downstream
	// (ParseUsage shape-sniffs and would read prompt_tokens=0 as real).
	if usage.Source == UsageSourceProvider {
		resp["usage"] = usageOut
	}
	return json.Marshal(resp)
}

// mapBedrockStop converts Bedrock stopReason values to OpenAI finish_reason
// equivalents. Unknown reasons default to "stop" (anthropic convention);
// content_filter is explicit because Bedrock reports guardrail/moderation
// stops as first-class reasons.
func mapBedrockStop(reason string) string {
	switch reason {
	case "end_turn", "stop_sequence", "":
		return "stop"
	case "max_tokens":
		return "length"
	case "tool_use":
		return "tool_calls"
	case "content_filtered", "guardrail_intervened":
		return "content_filter"
	default:
		return "stop"
	}
}

// bedrockParseUsage extracts token counts from a non-streaming ConverseOutput
// body, shape-sniffing pointer-wise exactly like the anthropic adapter:
// native bodies carry inputTokens/outputTokens (camelCase), translated
// responses carry prompt_tokens/completion_tokens plus
// prompt_tokens_details (whose cache_creation_input_tokens must survive the
// translation round-trip for cache billing, D5). A missing usage block means
// the provider reported nothing — UsageSourceNone, not provider-reported
// zeros.
func bedrockParseUsage(body []byte) Usage {
	var resp struct {
		Usage *struct {
			// Native Converse fields.
			InputTokens           *int64 `json:"inputTokens"`
			OutputTokens          *int64 `json:"outputTokens"`
			TotalTokens           *int64 `json:"totalTokens"`
			CacheReadInputTokens  *int64 `json:"cacheReadInputTokens"`
			CacheWriteInputTokens *int64 `json:"cacheWriteInputTokens"`
			// OpenAI-contract fields, present only on translated bodies.
			PromptTokens     *int64 `json:"prompt_tokens"`
			CompletionTokens *int64 `json:"completion_tokens"`
			OpenAITotal      *int64 `json:"total_tokens"`
			Details          *struct {
				CachedTokens             int64 `json:"cached_tokens"`
				CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
			} `json:"prompt_tokens_details"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.Usage == nil {
		return Usage{Source: UsageSourceNone}
	}
	u := resp.Usage
	if u.InputTokens != nil {
		// Native ConverseOutput shape.
		return bedrockTokens{
			InputTokens:           *u.InputTokens,
			OutputTokens:          bedrockDeref(u.OutputTokens),
			TotalTokens:           bedrockDeref(u.TotalTokens),
			CacheReadInputTokens:  bedrockDeref(u.CacheReadInputTokens),
			CacheWriteInputTokens: bedrockDeref(u.CacheWriteInputTokens),
		}.toUsage()
	}
	if u.PromptTokens == nil {
		return Usage{Source: UsageSourceNone}
	}
	// Translated (OpenAI-contract) shape: the canonical prompt_tokens
	// already includes the cache read and write portions.
	prompt := *u.PromptTokens
	completion := bedrockDeref(u.CompletionTokens)
	total := prompt + completion
	if u.OpenAITotal != nil {
		total = *u.OpenAITotal
	}
	usage := Usage{
		PromptTokens:     prompt,
		CompletionTokens: completion,
		TotalTokens:      total,
		Source:           UsageSourceProvider,
	}
	if u.Details != nil {
		usage.CacheReadTokens = u.Details.CachedTokens
		usage.CacheCreationTokens = u.Details.CacheCreationInputTokens
	}
	return usage
}

// bedrockDeref tolerates Bedrock omitting optional usage members.
func bedrockDeref(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

// bedrockRandomHex returns n crypto-random bytes hex-encoded. Used for
// chat.completion ids — never for anything secret-bearing.
func bedrockRandomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// Crypto/rand failure is catastrophic but must not panic the
		// request path; a time-derived fallback keeps the id unique enough.
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
