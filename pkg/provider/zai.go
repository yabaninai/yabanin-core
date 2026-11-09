package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// ZAICodingOfficialEndpoint is the only production Coding Plan base URL.
// Requests against other hosts do not consume GLM Coding Plan quota and are
// rejected by this adapter unless a test override is set on ZAICoding.endpoint.
const ZAICodingOfficialEndpoint = "https://api.z.ai/api/coding/paas/v4"

// ZAICoding is the OpenAI-compatible adapter for the Z.AI GLM Coding Plan.
// PrepareRequest always targets the official (or test-override) endpoint and
// ignores models_registry.upstream_url so a misconfigured row cannot send
// subscription traffic to an arbitrary host.
type ZAICoding struct {
	endpoint string // empty → official; tests may set a mock base URL
}

// NewZAICodingForTest returns an adapter pinned to mockBase instead of the
// official Coding Plan host. Production code must use ZAICoding{}.
func NewZAICodingForTest(mockBase string) ZAICoding {
	return ZAICoding{endpoint: strings.TrimRight(mockBase, "/")}
}

// Name returns the canonical provider identifier.
func (ZAICoding) Name() string { return "zai-coding" }

// Path is the Coding Plan chat-completions path. The official base URL already
// includes /v4, so the /v1 prefix used by generic OpenAI adapters is omitted.
func (ZAICoding) Path(_ bool) string { return "/chat/completions" }

// ZAICodingEndpoint returns the pinned Coding Plan base URL. override, when
// non-empty, is used by tests and local mock servers.
func ZAICodingEndpoint(override string) string {
	if u := strings.TrimRight(strings.TrimSpace(override), "/"); u != "" {
		return u
	}
	return ZAICodingOfficialEndpoint
}

func (z ZAICoding) base() string {
	return ZAICodingEndpoint(z.endpoint)
}

// PinZAICodingBaseURL returns the URL the adapter will actually call.
// Non-official hosts are replaced with the official endpoint except loopback
// addresses used by tests. models_registry.upstream_url cannot retarget
// production Coding Plan traffic.
func PinZAICodingBaseURL(poolURL string) string {
	pool := strings.TrimRight(strings.TrimSpace(poolURL), "/")
	if pool == "" || pool == ZAICodingOfficialEndpoint {
		return ZAICodingOfficialEndpoint
	}
	u, err := url.Parse(pool)
	if err != nil {
		return ZAICodingOfficialEndpoint
	}
	switch u.Hostname() {
	case "127.0.0.1", "localhost", "::1":
		return pool
	default:
		return ZAICodingOfficialEndpoint
	}
}

// PrepareRequest builds a Bearer-authenticated POST to the pinned endpoint.
func (z ZAICoding) PrepareRequest(ctx context.Context, baseURL, _ string, body []byte, apiKey string, stream bool) (*http.Request, error) {
	root := z.base()
	if z.endpoint == "" {
		root = PinZAICodingBaseURL(baseURL)
	}
	full := root + z.Path(stream)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, full, strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("build zai-coding request: %w", err)
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

// TranslateRequest is a no-op; Coding Plan accepts OpenAI-shaped JSON.
func (ZAICoding) TranslateRequest(body []byte) ([]byte, error) { return body, nil }

// TranslateResponse is a no-op; Coding Plan returns OpenAI-shaped JSON.
func (ZAICoding) TranslateResponse(body []byte) ([]byte, error) { return body, nil }

// ParseUsage reuses the OpenAI usage parser.
func (ZAICoding) ParseUsage(respBody []byte) Usage {
	return (OpenAI{}).ParseUsage(respBody)
}

// ZAICodingModelAllowed reports whether model is in the Coding Plan allowlist.
// Comparison is case-insensitive. GLM-5.2/GLM-5.1 aliases are accepted because
// Z.AI documents that they are routed to GLM-5.3.
func ZAICodingModelAllowed(model string) bool {
	switch strings.ToLower(strings.TrimSpace(model)) {
	case "glm-5.3", "glm-5.3-flash", "glm-5-turbo", "glm-4.7", "glm-5.2", "glm-5.1":
		return true
	default:
		return false
	}
}

// MapZAICodingStatus maps an upstream status to gateway HTTP status, OpenAI
// error type, and a stable code. 401/403 never leak upstream auth details.
func MapZAICodingStatus(upstreamStatus int) (httpStatus int, errType, code string) {
	switch {
	case upstreamStatus == 401 || upstreamStatus == 403:
		return http.StatusForbidden, "permission_denied_error", "provider_not_authorized"
	case upstreamStatus == 429:
		return http.StatusTooManyRequests, "rate_limit_exceeded", "quota_exhausted"
	case upstreamStatus >= 500:
		return http.StatusBadGateway, "api_error", ""
	case upstreamStatus >= 400:
		return http.StatusBadRequest, "invalid_request_error", ""
	default:
		return http.StatusBadGateway, "api_error", ""
	}
}
