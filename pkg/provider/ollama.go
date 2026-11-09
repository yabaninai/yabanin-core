package provider

import (
	"bytes"
	"context"
	"net/http"
)

// Ollama adapter. Ollama 0.1.20+ exposes an OpenAI-compatible
// /v1/chat/completions endpoint. Auth header optional (no key by default).
type Ollama struct{}

// Name returns the provider name "ollama".
func (Ollama) Name() string { return "ollama" }

// Path returns the OpenAI-compatible chat completion path.
func (Ollama) Path(_ bool) string { return "/v1/chat/completions" }

// PrepareRequest builds a POST to the Ollama chat endpoint.
func (Ollama) PrepareRequest(ctx context.Context, baseURL, path string, body []byte, apiKey string, stream bool) (*http.Request, error) {
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

// ParseUsage extracts token counts from an Ollama response via the shared
// OpenAI-compat parser (Ollama's /v1 surface reports the OpenAI usage shape;
// it sends no cache fields today, but the shared parser would carry them).
func (Ollama) ParseUsage(respBody []byte) Usage { return openAIParseUsage(respBody) }

// TranslateRequest passes through unchanged for Ollama (OpenAI-compatible).
func (Ollama) TranslateRequest(b []byte) ([]byte, error) { return b, nil }

// TranslateResponse passes through unchanged for Ollama.
func (Ollama) TranslateResponse(b []byte) ([]byte, error) { return b, nil }
