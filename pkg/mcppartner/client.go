package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// GatewayClient is the thin HTTP client MCP handlers use to talk to the
// running gateway (:8082) and admin panel (:18086 on-prem). Gateway calls
// authenticate with the partner API key as a Bearer token; admin calls go to
// the stateless /internal service API and authenticate with X-Admin-Key
// (adminauth.AuthFromHeader). Timeouts are bounded so a hung upstream cannot
// stall the MCP stdio loop.
type GatewayClient struct {
	BaseURL  string // http://localhost:8082 (on-prem) or https://api.yabanin.io (saas)
	AdminURL string // http://localhost:18086 (on-prem) or https://admin.yabanin.io
	APIKey   string // partner key: Authorization Bearer for gateway calls
	AdminKey string // service key: X-Admin-Key for admin /internal calls
	HTTP     *http.Client
}

// NewGatewayClient creates a client. On-prem defaults to localhost; saas
// defaults are set by the caller (CLI/MCP binary reads config). adminKey may
// equal apiKey on single-operator stands; SaaS passes the dedicated service
// key issued for the /internal group.
func NewGatewayClient(base, admin, key, adminKey string) *GatewayClient {
	return &GatewayClient{
		BaseURL:  base,
		AdminURL: admin,
		APIKey:   key,
		AdminKey: adminKey,
		HTTP:     &http.Client{Timeout: 30 * time.Second},
	}
}

// Route sends a chat-completion request to the gateway and returns the raw
// decoded JSON. Used by the tr_route MCP tool.
func (c *GatewayClient) Route(ctx context.Context, model, prompt string) (map[string]any, error) {
	if c.APIKey == "" {
		return nil, fmt.Errorf("YABANIN_PARTNER_API_KEY not set")
	}
	body, _ := json.Marshal(map[string]any{
		"model":    model,
		"messages": []map[string]string{{"role": "user", "content": prompt}},
	})
	return c.doJSON(ctx, c.BaseURL+"/v1/chat/completions", body)
}

// SpendReport fetches the cost analytics for an org over N days via the
// admin /internal service API (stateless X-Admin-Key auth; the cookie-session
// dashboard routes are not reachable for machine callers).
func (c *GatewayClient) SpendReport(ctx context.Context, orgID string, days int) (map[string]any, error) {
	path := fmt.Sprintf("%s/internal/analytics/cost?org_id=%s&days=%d", c.AdminURL, url.QueryEscape(orgID), days)
	req, _ := http.NewRequestWithContext(ctx, "GET", path, nil)
	return c.doAdminRequest(ctx, "admin", req)
}

// SetPolicy updates the org routing mode + threshold.
func (c *GatewayClient) SetPolicy(ctx context.Context, orgID, mode string, threshold float64) (map[string]any, error) {
	body, _ := json.Marshal(map[string]any{
		"routing_mode":      mode,
		"routing_threshold": threshold,
	})
	path := fmt.Sprintf("%s/api/organizations/%s/routing", c.AdminURL, orgID)
	req, _ := http.NewRequestWithContext(ctx, "PATCH", path, bytes.NewReader(body))
	return c.doRequest(ctx, req)
}

// LineageVerify verifies the lineage attestation for a request ID.
// Calls the admin panel endpoint which performs full Ed25519 verification.
func (c *GatewayClient) LineageVerify(ctx context.Context, requestID string) (map[string]any, error) {
	path := fmt.Sprintf("%s/api/lineage/%s/verify", c.AdminURL, requestID)
	req, _ := http.NewRequestWithContext(ctx, "POST", path, nil)
	return c.doRequest(ctx, req)
}

func (c *GatewayClient) doJSON(ctx context.Context, url string, body []byte) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	return c.doRequest(ctx, req)
}

// doRequest performs a gateway-hop call: partner key as Bearer token.
func (c *GatewayClient) doRequest(ctx context.Context, req *http.Request) (map[string]any, error) {
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	return c.roundTrip(ctx, "gateway", req)
}

// doAdminRequest performs an admin /internal hop: X-Admin-Key only. The
// partner Bearer key must not leak onto the admin surface.
func (c *GatewayClient) doAdminRequest(ctx context.Context, label string, req *http.Request) (map[string]any, error) {
	req.Header.Set("X-Admin-Key", c.AdminKey)
	req.Header.Set("Content-Type", "application/json")
	return c.roundTrip(ctx, label, req)
}

func (c *GatewayClient) roundTrip(ctx context.Context, label string, req *http.Request) (map[string]any, error) {
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, &transportError{label: label, cause: err}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("%s %d", label, resp.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return out, nil
}

// transportError keeps errors.Is/errors.As useful to callers without exposing
// the URL or other request details included in the underlying HTTP error.
type transportError struct {
	label string
	cause error
}

func (e *transportError) Error() string { return e.label + " transport error" }

func (e *transportError) Unwrap() error { return e.cause }

var _ error = (*transportError)(nil)
