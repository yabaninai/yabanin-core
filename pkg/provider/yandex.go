package provider

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
)

// Yandex adapter for YandexGPT (HQ Moscow, RU). Yandex deliberately mirrors
// the OpenAI chat-completions shape, but:
//   - Endpoint path is /llm/v1/chat/completions (note the /llm prefix, NOT /v1).
//   - Auth is Bearer <IAM-token> PLUS a required x-folder-id header.
//   - The gateway's apiKey field carries BOTH, pipe-separated:
//     "<iam_token>|<folder_id>"
//
// IAM tokens are short-lived (~12h). Token refresh (Yandex OAuth exchange)
// is OUT OF SCOPE for the adapter — the buyer rotates the registry's
// upstream_api_key on refresh cadence (or wires an external sidecar).
//
// Sovereignty tier: full (RU jurisdiction).
type Yandex struct{}

func (Yandex) Name() string { return "yandex" }

func (Yandex) Path(_ bool) string { return "/llm/v1/chat/completions" }

func (Yandex) PrepareRequest(ctx context.Context, baseURL, path string, body []byte, apiKey string, stream bool) (*http.Request, error) {
	iam, folder, ok := splitPipe(apiKey)
	if !ok {
		return nil, fmt.Errorf("yandex apiKey must be '<iam_token>|<folder_id>'")
	}
	url := strings.TrimRight(baseURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build yandex request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+iam)
	req.Header.Set("x-folder-id", folder)
	if stream {
		req.Header.Set("Accept", "text/event-stream")
	}
	return req, nil
}

func (Yandex) ParseUsage(respBody []byte) Usage { return openAIParseUsage(respBody) }

func (Yandex) TranslateRequest(b []byte) ([]byte, error)  { return b, nil }
func (Yandex) TranslateResponse(b []byte) ([]byte, error) { return b, nil }
