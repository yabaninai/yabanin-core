package apiformat

import (
	"encoding/json"
	"strings"
)

// ChatRequest is a canonical OpenAI Chat Completions request.
type ChatRequest struct {
	Model             string          `json:"model"`
	Messages          []ChatMessage   `json:"messages"`
	Tools             []ChatTool      `json:"tools,omitempty"`
	ToolChoice        json.RawMessage `json:"tool_choice,omitempty"`
	ParallelToolCalls *bool           `json:"parallel_tool_calls,omitempty"`
	MaxTokens         *int            `json:"max_tokens,omitempty"`
	Temperature       *float64        `json:"temperature,omitempty"`
	TopP              *float64        `json:"top_p,omitempty"`
	Stop              []string        `json:"stop,omitempty"`
	Stream            bool            `json:"stream,omitempty"`
	StreamOptions     *StreamOptions  `json:"stream_options,omitempty"`
	ResponseFormat    json.RawMessage `json:"response_format,omitempty"`
	User              string          `json:"user,omitempty"`
	ReasoningEffort   string          `json:"reasoning_effort,omitempty"`
}

// StreamOptions is the chat stream_options object.
type StreamOptions struct {
	IncludeUsage bool `json:"include_usage"`
}

// ChatMessage is one canonical chat message.
type ChatMessage struct {
	Role       string          `json:"role"`
	Content    json.RawMessage `json:"content"`
	ToolCalls  []ToolCall      `json:"tool_calls,omitempty"`
	ToolCallID string          `json:"tool_call_id,omitempty"`
	Name       string          `json:"name,omitempty"`
}

// ContentPart is one element of a multipart message content array.
type ContentPart struct {
	Type     string    `json:"type"`
	Text     string    `json:"text,omitempty"`
	ImageURL *ImageURL `json:"image_url,omitempty"`
}

// ImageURL is an image_url content part.
type ImageURL struct {
	URL    string `json:"url"`
	Detail string `json:"detail,omitempty"`
}

// ToolCall is an assistant function call.
type ToolCall struct {
	ID       string           `json:"id"`
	Type     string           `json:"type"`
	Function ToolCallFunction `json:"function"`
}

// ToolCallFunction is the function name and JSON-encoded arguments.
type ToolCallFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// ChatTool is a function tool definition.
type ChatTool struct {
	Type     string       `json:"type"`
	Function ChatFunction `json:"function"`
}

// ChatFunction is the function schema advertised to the model.
type ChatFunction struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
	Strict      *bool           `json:"strict,omitempty"`
}

// ChatResponse is a non-streaming chat completion.
type ChatResponse struct {
	ID      string       `json:"id"`
	Object  string       `json:"object"`
	Created int64        `json:"created"`
	Model   string       `json:"model"`
	Choices []ChatChoice `json:"choices"`
	Usage   *ChatUsage   `json:"usage,omitempty"`
}

// ChatChoice is one completion choice.
type ChatChoice struct {
	Index        int             `json:"index"`
	Message      ChatRespMessage `json:"message"`
	FinishReason string          `json:"finish_reason"`
}

// ChatRespMessage is the assistant message inside a non-streaming choice.
type ChatRespMessage struct {
	Role             string          `json:"role"`
	Content          json.RawMessage `json:"content"`
	ToolCalls        []ToolCall      `json:"tool_calls,omitempty"`
	ReasoningContent *string         `json:"reasoning_content,omitempty"`
	Refusal          *string         `json:"refusal,omitempty"`
}

// ChatUsage is canonical token usage. PromptTokens includes cache tokens.
type ChatUsage struct {
	PromptTokens            int64                `json:"prompt_tokens"`
	CompletionTokens        int64                `json:"completion_tokens"`
	TotalTokens             int64                `json:"total_tokens"`
	PromptTokensDetails     *PromptTokensDetails `json:"prompt_tokens_details,omitempty"`
	CompletionTokensDetails *CompletionDetails   `json:"completion_tokens_details,omitempty"`
}

// PromptTokensDetails carries the cached subset of prompt tokens.
type PromptTokensDetails struct {
	CachedTokens int64 `json:"cached_tokens"`
}

// CompletionDetails carries reasoning tokens inside the completion count.
type CompletionDetails struct {
	ReasoningTokens int64 `json:"reasoning_tokens"`
}

// ChatChunk is one OpenAI chat completion stream chunk.
type ChatChunk struct {
	ID      string            `json:"id"`
	Object  string            `json:"object"`
	Created int64             `json:"created"`
	Model   string            `json:"model"`
	Choices []ChatChunkChoice `json:"choices"`
	Usage   *ChatUsage        `json:"usage,omitempty"`
	Error   json.RawMessage   `json:"error,omitempty"`
}

// ChatChunkChoice is one streamed choice.
type ChatChunkChoice struct {
	Index        int       `json:"index"`
	Delta        ChatDelta `json:"delta"`
	FinishReason *string   `json:"finish_reason"`
}

// ChatDelta is the incremental assistant update inside a chunk.
type ChatDelta struct {
	Role             string          `json:"role,omitempty"`
	Content          *string         `json:"content,omitempty"`
	ReasoningContent *string         `json:"reasoning_content,omitempty"`
	ToolCalls        []ChunkToolCall `json:"tool_calls,omitempty"`
}

// ChunkToolCall is one streamed tool-call fragment.
type ChunkToolCall struct {
	Index    int              `json:"index"`
	ID       string           `json:"id,omitempty"`
	Type     string           `json:"type,omitempty"`
	Function ToolCallFunction `json:"function"`
}

// ContentText returns the plain text of a chat content field.
// A JSON string is returned as-is. An array concatenates the text of parts
// whose type is text, input_text, or output_text, with no separator.
// Null, empty, and unrecognised shapes return "".
func ContentText(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return text
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &parts); err != nil {
		return ""
	}
	var b strings.Builder
	for _, part := range parts {
		switch part.Type {
		case "text", "input_text", "output_text":
			b.WriteString(part.Text)
		}
	}
	return b.String()
}
