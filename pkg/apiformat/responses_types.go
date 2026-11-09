package apiformat

import "encoding/json"

// ResponsesMeta is the side channel ResponsesToChat keeps for the response
// translator and the HTTP handler. It is not part of the chat JSON.
type ResponsesMeta struct {
	RequestedModel  string
	Stream          bool
	CustomToolNames map[string]bool
	Dropped         []string
	Echo            ResponsesEcho
	PromptCacheKey  string
}

// ResponsesEcho carries Responses fields that the response translator echoes
// unchanged. Absent inputs use the defaults from A1 §2.
type ResponsesEcho struct {
	Instructions      json.RawMessage
	Tools             json.RawMessage
	ToolChoice        json.RawMessage
	ParallelToolCalls *bool
	Temperature       *float64
	TopP              *float64
	MaxOutputTokens   *int
	Text              json.RawMessage
	Reasoning         json.RawMessage
	Metadata          json.RawMessage
	User              string
}
