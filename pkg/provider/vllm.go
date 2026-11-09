package provider

import (
	"bytes"
	"context"
	"net/http"
)

// VLLM is the adapter for vLLM (OpenAI-compatible /v1/chat/completions).
// Differences: usage may be absent on some streaming chunks; model name must
// match the --served-model-name flag. We pass bodies through unchanged.
type VLLM struct{}

// Name returns the provider name "vllm".
func (VLLM) Name() string { return "vllm" }

// Path returns the OpenAI-compatible chat completion path.
func (VLLM) Path(_ bool) string { return "/v1/chat/completions" }

// PrepareRequest builds a POST to the vLLM chat endpoint.
func (VLLM) PrepareRequest(ctx context.Context, baseURL, path string, body []byte, apiKey string, stream bool) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	if stream {
		req.Header.Set("Accept", "text/event-stream")
	}
	return req, nil
}

// ParseUsage extracts token counts from a vLLM response via the shared
// OpenAI-compat parser: vLLM with automatic prefix caching reports
// prompt_tokens_details.cached_tokens, which must reach billing.
func (VLLM) ParseUsage(respBody []byte) Usage { return openAIParseUsage(respBody) }

// TranslateRequest passes through unchanged for vLLM (OpenAI-compatible).
func (VLLM) TranslateRequest(b []byte) ([]byte, error) { return b, nil }

// TranslateResponse passes through unchanged for vLLM.
func (VLLM) TranslateResponse(b []byte) ([]byte, error) { return b, nil }
