package provider

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
)

// Falcon adapter for TII (Technology Innovation Institute, HQ Abu Dhabi, UAE).
// TII exposes an OpenAI-compatible endpoint at {base}/v1/chat/completions
// with Bearer auth. Falcon weights are also available open-source (PB4.7
// self-host path uses provider="vllm" instead).
// Sovereignty tier: open_weights (seed) / full (TII cloud, GCC jurisdiction).
type Falcon struct{}

func (Falcon) Name() string { return "falcon" }

func (Falcon) Path(_ bool) string { return "/v1/chat/completions" }

func (Falcon) PrepareRequest(ctx context.Context, baseURL, path string, body []byte, apiKey string, stream bool) (*http.Request, error) {
	url := strings.TrimRight(baseURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build falcon request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	if stream {
		req.Header.Set("Accept", "text/event-stream")
	}
	return req, nil
}

func (Falcon) ParseUsage(respBody []byte) Usage { return openAIParseUsage(respBody) }

func (Falcon) TranslateRequest(b []byte) ([]byte, error)  { return b, nil }
func (Falcon) TranslateResponse(b []byte) ([]byte, error) { return b, nil }
