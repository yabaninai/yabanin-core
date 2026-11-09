package provider

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
)

// Mistral adapter (HQ Paris, FR). OpenAI-compatible at
// POST {base}/v1/chat/completions with Bearer auth. Mistral is a common
// Western vendor but is tagged sovereignty_tier=full for EU-jurisdiction
// buyers (FR HQ, EU data processing). Identity translate.
type Mistral struct{}

func (Mistral) Name() string { return "mistral" }

func (Mistral) Path(_ bool) string { return "/v1/chat/completions" }

func (Mistral) PrepareRequest(ctx context.Context, baseURL, path string, body []byte, apiKey string, stream bool) (*http.Request, error) {
	url := strings.TrimRight(baseURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build mistral request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	if stream {
		req.Header.Set("Accept", "text/event-stream")
	}
	return req, nil
}

func (Mistral) ParseUsage(respBody []byte) Usage { return openAIParseUsage(respBody) }

func (Mistral) TranslateRequest(b []byte) ([]byte, error)  { return b, nil }
func (Mistral) TranslateResponse(b []byte) ([]byte, error) { return b, nil }
