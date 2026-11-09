package openai

import (
	"bytes"
	"encoding/json"
	"strings"
)

// ChatCompletionRequest mirrors the OpenAI API shape for gateway ingestion.
type ChatCompletionRequest struct {
	Model       string          `json:"model"`
	Messages    []ChatMessage   `json:"messages"`
	Stream      bool            `json:"stream"`
	Temperature *float64        `json:"temperature,omitempty"`
	MaxTokens   *int            `json:"max_tokens,omitempty"`
	Metadata    json.RawMessage `json:"metadata,omitempty"`
}

// ChatMessage represents a single message in the conversation.
// Content is normalized to plain text for validation and classifiers; the
// gateway still forwards the original request body, including tool_calls.
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// UnmarshalJSON accepts OpenAI content as a string, null, or text-part array
// so OpenCode tool-loop payloads do not fail request parsing.
func (m *ChatMessage) UnmarshalJSON(data []byte) error {
	var raw struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	m.Role = raw.Role
	text, err := normalizeMessageContent(raw.Content)
	if err != nil {
		return err
	}
	m.Content = text
	return nil
}

func normalizeMessageContent(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return "", nil
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", err
		}
		return s, nil
	}
	if raw[0] == '[' {
		var parts []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		if err := json.Unmarshal(raw, &parts); err != nil {
			return "", err
		}
		var b strings.Builder
		for _, p := range parts {
			if p.Type == "" || p.Type == "text" {
				b.WriteString(p.Text)
			}
		}
		return b.String(), nil
	}
	return string(raw), nil
}

// Usage holds token usage statistics from an upstream response.
type Usage struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
}

// ChatCompletionResponse mirrors the OpenAI API response shape for non-streaming responses.
type ChatCompletionResponse struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []Choice `json:"choices"`
	Usage   *Usage   `json:"usage,omitempty"`
}

// Choice mirrors a single choice in the response.
type Choice struct {
	Index        int     `json:"index"`
	Message      Message `json:"message"`
	FinishReason string  `json:"finish_reason"`
}

// Message represents the assistant's response message.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
