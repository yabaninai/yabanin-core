package apiformat

import "encoding/json"

// AnthropicRequest is an Anthropic Messages request.
// These types describe input that translators inspect. Native passthrough
// (RM-26) forwards the original body and does not rebuild it from them.
type AnthropicRequest struct {
	Model         string               `json:"model"`
	MaxTokens     *int                 `json:"max_tokens,omitempty"`
	System        json.RawMessage      `json:"system,omitempty"`
	Messages      []AnthropicMessage   `json:"messages"`
	StopSequences []string             `json:"stop_sequences,omitempty"`
	Temperature   *float64             `json:"temperature,omitempty"`
	TopP          *float64             `json:"top_p,omitempty"`
	TopK          *int                 `json:"top_k,omitempty"`
	Stream        bool                 `json:"stream,omitempty"`
	Tools         []AnthropicTool      `json:"tools,omitempty"`
	ToolChoice    *AnthropicToolChoice `json:"tool_choice,omitempty"`
	Metadata      *AnthropicMetadata   `json:"metadata,omitempty"`
	Thinking      json.RawMessage      `json:"thinking,omitempty"`
}

// AnthropicMetadata is the optional user id Anthropic accepts on a request.
type AnthropicMetadata struct {
	UserID string `json:"user_id,omitempty"`
}

// AnthropicMessage is one Messages API turn. Content is a string or an array of blocks.
type AnthropicMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

// AnthropicBlock is one content block. Unused fields stay empty for a given type.
type AnthropicBlock struct {
	Type      string           `json:"type"`
	Text      string           `json:"text,omitempty"`
	Source    *AnthropicSource `json:"source,omitempty"`
	ID        string           `json:"id,omitempty"`
	Name      string           `json:"name,omitempty"`
	Input     json.RawMessage  `json:"input,omitempty"`
	ToolUseID string           `json:"tool_use_id,omitempty"`
	Content   json.RawMessage  `json:"content,omitempty"`
	IsError   bool             `json:"is_error,omitempty"`
}

// AnthropicSource is an image or document source.
type AnthropicSource struct {
	Type      string `json:"type"`
	MediaType string `json:"media_type,omitempty"`
	Data      string `json:"data,omitempty"`
	URL       string `json:"url,omitempty"`
}

// AnthropicTool is a tool definition. Type is inspected only to decide
// whether a tool is dropped; it is not used to rebuild a passthrough body.
type AnthropicTool struct {
	Type        string          `json:"type,omitempty"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
}

// AnthropicToolChoice selects how the model may call tools.
type AnthropicToolChoice struct {
	Type                   string `json:"type"`
	Name                   string `json:"name,omitempty"`
	DisableParallelToolUse bool   `json:"disable_parallel_tool_use,omitempty"`
}

// AnthropicResponse is a non-streaming Messages response.
type AnthropicResponse struct {
	ID           string           `json:"id"`
	Type         string           `json:"type"`
	Role         string           `json:"role"`
	Model        string           `json:"model"`
	Content      []AnthropicBlock `json:"content"`
	StopReason   string           `json:"stop_reason"`
	StopSequence *string          `json:"stop_sequence"`
	Usage        AnthropicUsage   `json:"usage"`
}

// AnthropicMeta is what AnthropicToChat keeps beside the chat JSON.
type AnthropicMeta struct {
	RequestedModel string
	Stream         bool
	Dropped        []string
}

// AnthropicUsage is the native Anthropic usage object.
// InputTokens does not include cache read or cache creation.
type AnthropicUsage struct {
	InputTokens              int64 `json:"input_tokens"`
	OutputTokens             int64 `json:"output_tokens"`
	CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
}
