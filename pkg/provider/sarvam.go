package provider

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
)

// Sarvam adapter. Sarvam AI (HQ Bengaluru, IN) is OpenAI-compatible.
// Sovereignty tier: full (IN jurisdiction).
type Sarvam struct{}

func (Sarvam) Name() string { return "sarvam" }

func (Sarvam) Path(_ bool) string { return "/v1/chat/completions" }

func (Sarvam) PrepareRequest(ctx context.Context, baseURL, path string, body []byte, apiKey string, stream bool) (*http.Request, error) {
	url := strings.TrimRight(baseURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build sarvam request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	if stream {
		req.Header.Set("Accept", "text/event-stream")
	}
	return req, nil
}

func (Sarvam) ParseUsage(respBody []byte) Usage { return openAIParseUsage(respBody) }

func (Sarvam) TranslateRequest(b []byte) ([]byte, error)  { return b, nil }
func (Sarvam) TranslateResponse(b []byte) ([]byte, error) { return b, nil }
