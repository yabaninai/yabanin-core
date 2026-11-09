package provider

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
)

// Sakana adapter. Sakana AI API (HQ Tokyo, JP) is OpenAI-compatible at
// POST {base}/v1/chat/completions with Bearer auth.
// Sovereignty tier: full (JP jurisdiction).
type Sakana struct{}

func (Sakana) Name() string { return "sakana" }

func (Sakana) Path(_ bool) string { return "/v1/chat/completions" }

func (Sakana) PrepareRequest(ctx context.Context, baseURL, path string, body []byte, apiKey string, stream bool) (*http.Request, error) {
	url := strings.TrimRight(baseURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build sakana request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	if stream {
		req.Header.Set("Accept", "text/event-stream")
	}
	return req, nil
}

func (Sakana) ParseUsage(respBody []byte) Usage { return openAIParseUsage(respBody) }

func (Sakana) TranslateRequest(b []byte) ([]byte, error)  { return b, nil }
func (Sakana) TranslateResponse(b []byte) ([]byte, error) { return b, nil }
