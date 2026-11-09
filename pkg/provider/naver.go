package provider

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
)

// Naver adapter for HyperCLOVA X (HQ Seongnam, KR). Non-standard:
//   - Path includes the model id segment (HCX-003 / HCX-Dash-001).
//   - Auth uses two custom headers, NOT Bearer:
//     X-NCP-CLOVASTUDIO-API-KEY: <clova key>
//     X-NCP-APIGW-API-KEY:       <apigw key>
//   - The gateway's apiKey field carries BOTH, pipe-separated:
//     "<clova_key>|<apigw_key>"
//
// Sovereignty tier: full (KR jurisdiction).
type Naver struct{}

func (Naver) Name() string { return "naver" }

func (Naver) Path(stream bool) string {
	// Non-streaming and streaming use distinct path suffixes. The model-id
	// segment (HCX-003) is fixed at the adapter level; multi-model support
	// would require reading the body's "model" field — out of scope for MVP.
	if stream {
		return "/testapp/v1/chat-completions/HCX-Dash-001/stream"
	}
	return "/testapp/v1/chat-completions/HCX-Dash-001"
}

func (Naver) PrepareRequest(ctx context.Context, baseURL, path string, body []byte, apiKey string, stream bool) (*http.Request, error) {
	clova, apigw, ok := splitPipe(apiKey)
	if !ok {
		return nil, fmt.Errorf("naver apiKey must be '<clova_key>|<apigw_key>'")
	}
	url := strings.TrimRight(baseURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build naver request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-NCP-CLOVASTUDIO-API-KEY", clova)
	req.Header.Set("X-NCP-APIGW-API-KEY", apigw)
	if stream {
		req.Header.Set("Accept", "text/event-stream")
	}
	return req, nil
}

func (Naver) ParseUsage(respBody []byte) Usage {
	// Naver's response carries an OpenAI-shaped "usage" block (prompt_tokens /
	// completion_tokens), so the shared parser applies.
	return openAIParseUsage(respBody)
}

func (Naver) TranslateRequest(b []byte) ([]byte, error)  { return b, nil }
func (Naver) TranslateResponse(b []byte) ([]byte, error) { return b, nil }

// splitPipe splits "<a>|<b>". ok is false when the separator is absent or
// either half is empty.
func splitPipe(s string) (a, b string, ok bool) {
	idx := strings.Index(s, "|")
	if idx <= 0 || idx == len(s)-1 {
		return "", "", false
	}
	return s[:idx], s[idx+1:], true
}
