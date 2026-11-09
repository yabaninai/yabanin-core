package apiformat

import (
	"encoding/json"
	"errors"
	"time"
)

// ErrNoChoices is returned when a chat completion has no choices.
// The handler maps it to 502 server_error.
var ErrNoChoices = errors.New("upstream returned no choices")

// ChatToResponses translates a non-streaming chat completion into a Responses
// API response object. Only choices[0] is used.
func ChatToResponses(chatResp []byte, meta ResponsesMeta, opts ResponsesOptions) ([]byte, error) {
	_ = opts.EmitReasoning // A1 §3: reasoning_content is not emitted in v1.
	idGen := opts.IDGen
	if idGen == nil {
		idGen = NewID
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	var chat ChatResponse
	if err := json.Unmarshal(chatResp, &chat); err != nil {
		return nil, err
	}
	if len(chat.Choices) == 0 {
		return nil, ErrNoChoices
	}
	choice := chat.Choices[0]
	msg := choice.Message

	created := chat.Created
	if created == 0 {
		created = now().Unix()
	}
	respID := idGen("resp_")
	model := chat.Model
	if model == "" {
		model = meta.RequestedModel
	}

	status := "completed"
	incomplete := json.RawMessage("null")
	switch choice.FinishReason {
	case "length":
		status = "incomplete"
		incomplete = json.RawMessage(`{"reason":"max_output_tokens"}`)
	case "content_filter":
		status = "incomplete"
		incomplete = json.RawMessage(`{"reason":"content_filter"}`)
	}

	var output []any
	text := ContentText(msg.Content)
	refusal := ""
	if msg.Refusal != nil {
		refusal = *msg.Refusal
	}
	if text != "" || refusal != "" {
		var parts []any
		if text != "" {
			parts = append(parts, map[string]any{
				"type":        "output_text",
				"text":        text,
				"annotations": []any{},
			})
		}
		if refusal != "" {
			parts = append(parts, map[string]any{
				"type":    "refusal",
				"refusal": refusal,
			})
		}
		output = append(output, map[string]any{
			"type":    "message",
			"id":      idGen("msg_"),
			"status":  "completed",
			"role":    "assistant",
			"content": parts,
		})
	}
	for _, call := range msg.ToolCalls {
		callID := call.ID
		if callID == "" {
			callID = idGen("call_")
		}
		if meta.CustomToolNames[call.Function.Name] {
			output = append(output, map[string]any{
				"type":    "custom_tool_call",
				"id":      idGen("ctc_"),
				"call_id": callID,
				"name":    call.Function.Name,
				"input":   customToolInput(call.Function.Arguments),
			})
			continue
		}
		args := call.Function.Arguments
		if args == "" {
			args = "{}"
		}
		output = append(output, map[string]any{
			"type":      "function_call",
			"id":        idGen("fc_"),
			"call_id":   callID,
			"name":      call.Function.Name,
			"arguments": args,
			"status":    "completed",
		})
	}
	if output == nil {
		output = []any{}
	}

	parallel := true
	if meta.Echo.ParallelToolCalls != nil {
		parallel = *meta.Echo.ParallelToolCalls
	}
	temperature := 1.0
	if meta.Echo.Temperature != nil {
		temperature = *meta.Echo.Temperature
	}
	topP := 1.0
	if meta.Echo.TopP != nil {
		topP = *meta.Echo.TopP
	}

	body := map[string]any{
		"id":                   respID,
		"object":               "response",
		"created_at":           created,
		"status":               status,
		"error":                json.RawMessage("null"),
		"incomplete_details":   incomplete,
		"instructions":         orRaw(meta.Echo.Instructions, "null"),
		"max_output_tokens":    maxOutput(meta.Echo.MaxOutputTokens),
		"model":                model,
		"output":               output,
		"parallel_tool_calls":  parallel,
		"previous_response_id": json.RawMessage("null"),
		"reasoning":            orRaw(meta.Echo.Reasoning, `{"effort":null,"summary":null}`),
		"store":                false,
		"temperature":          temperature,
		"text":                 orRaw(meta.Echo.Text, `{"format":{"type":"text"}}`),
		"tool_choice":          orRaw(meta.Echo.ToolChoice, `"auto"`),
		"tools":                orRaw(meta.Echo.Tools, "[]"),
		"top_p":                topP,
		"truncation":           "disabled",
		"usage":                responsesUsage(chat.Usage),
		"user":                 userRaw(meta.Echo.User),
		"metadata":             orRaw(meta.Echo.Metadata, "{}"),
	}
	return json.Marshal(body)
}

func customToolInput(arguments string) string {
	if arguments == "" {
		return ""
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal([]byte(arguments), &obj) != nil {
		return arguments
	}
	raw, ok := obj["input"]
	if !ok {
		return arguments
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return string(raw)
	}
	return s
}

func responsesUsage(u *ChatUsage) map[string]any {
	var prompt, completion, total, cached, reasoning int64
	if u != nil {
		prompt = u.PromptTokens
		completion = u.CompletionTokens
		total = u.TotalTokens
		if u.PromptTokensDetails != nil {
			cached = u.PromptTokensDetails.CachedTokens
		}
		if u.CompletionTokensDetails != nil {
			reasoning = u.CompletionTokensDetails.ReasoningTokens
		}
	}
	if total == 0 {
		total = prompt + completion
	}
	return map[string]any{
		"input_tokens":          prompt,
		"input_tokens_details":  map[string]any{"cached_tokens": cached},
		"output_tokens":         completion,
		"output_tokens_details": map[string]any{"reasoning_tokens": reasoning},
		"total_tokens":          total,
	}
}

func orRaw(raw json.RawMessage, fallback string) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage(fallback)
	}
	return raw
}

func maxOutput(n *int) any {
	if n == nil {
		return json.RawMessage("null")
	}
	return *n
}

func userRaw(user string) json.RawMessage {
	if user == "" {
		return json.RawMessage("null")
	}
	b, err := json.Marshal(user)
	if err != nil {
		return json.RawMessage("null")
	}
	return b
}
