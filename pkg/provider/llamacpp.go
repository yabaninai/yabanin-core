package provider

import (
	"bytes"
	"context"
	"net/http"
)

// LlamaCPP is a thin adapter for llama.cpp server and any OpenAI-compatible
// inference endpoint (vLLM, LM Studio, Ollama, ...). It passes requests and
// responses through unchanged, parsing only token usage for cost accounting.
type LlamaCPP struct{}

// Name returns the provider identifier "llamacpp".
func (LlamaCPP) Name() string { return "llamacpp" }

// Path returns the OpenAI-compatible chat completion path.
func (LlamaCPP) Path(_ bool) string { return "/v1/chat/completions" }

// PrepareRequest builds a POST to the llama.cpp /v1/chat/completions endpoint.
func (LlamaCPP) PrepareRequest(ctx context.Context, baseURL, path string, body []byte, apiKey string, stream bool) (*http.Request, error) {
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

// ParseUsage extracts token counts from a llama.cpp response body via the
// shared OpenAI-compat parser (llama.cpp sends no cache fields today, but
// the shared parser would carry them).
func (LlamaCPP) ParseUsage(respBody []byte) Usage { return openAIParseUsage(respBody) }

// TranslateRequest passes through unchanged for llama.cpp (OpenAI-compatible).
func (LlamaCPP) TranslateRequest(b []byte) ([]byte, error) { return b, nil }

// TranslateResponse passes through unchanged for llama.cpp.
func (LlamaCPP) TranslateResponse(b []byte) ([]byte, error) { return b, nil }
