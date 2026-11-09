package provider

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
)

// Krutrim adapter. Krutrim (Ola, HQ Bengaluru, IN) cloud is OpenAI-compatible.
// Sovereignty tier: full (IN jurisdiction).
type Krutrim struct{}

func (Krutrim) Name() string { return "krutrim" }

func (Krutrim) Path(_ bool) string { return "/v1/chat/completions" }

func (Krutrim) PrepareRequest(ctx context.Context, baseURL, path string, body []byte, apiKey string, stream bool) (*http.Request, error) {
	url := strings.TrimRight(baseURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build krutrim request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	if stream {
		req.Header.Set("Accept", "text/event-stream")
	}
	return req, nil
}

func (Krutrim) ParseUsage(respBody []byte) Usage { return openAIParseUsage(respBody) }

func (Krutrim) TranslateRequest(b []byte) ([]byte, error)  { return b, nil }
func (Krutrim) TranslateResponse(b []byte) ([]byte, error) { return b, nil }
