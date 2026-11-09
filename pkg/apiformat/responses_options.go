package apiformat

import "time"

// ResponsesOptions controls deterministic ids and clocks for ChatToResponses
// and the Responses stream writer. Zero IDGen uses NewID; zero Now uses
// time.Now. KeepAlive 0 means 15s; a negative duration disables comments.
// EmitReasoning is reserved: A1 §3 does not emit reasoning_content in v1.
type ResponsesOptions struct {
	IDGen         func(prefix string) string
	Now           func() time.Time
	KeepAlive     time.Duration
	EmitReasoning bool
}

// AnthropicOptions controls deterministic ids for ChatToAnthropic and the
// Anthropic stream writer. Zero IDGen uses NewID. Now and KeepAlive belong
// to the stream writer; a non-stream translation does not read them.
type AnthropicOptions struct {
	IDGen     func(prefix string) string
	Now       func() time.Time
	KeepAlive time.Duration
}
