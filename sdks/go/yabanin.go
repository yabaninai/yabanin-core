// Package yabanin provides a Go client for the Yabanin AI gateway.
package yabanin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// Config holds the gateway client configuration.
type Config struct {
	BaseURL string
	APIKey  string
}

// envOr falls back to the legacy TOKENROUTER_* name so existing deployments
// keep working (BR-01 rename: YABANIN_* is canonical).
func envOr(name, legacy string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return os.Getenv(legacy)
}

// ConfigFromEnv reads YABANIN_BASE_URL and YABANIN_API_KEY from env (the
// legacy TOKENROUTER_* names are still honored as a fallback).
func ConfigFromEnv() (Config, error) {
	base := envOr("YABANIN_BASE_URL", "TOKENROUTER_BASE_URL")
	if base == "" {
		deployMode := os.Getenv("YABANIN_DEPLOY_MODE")
		if deployMode == "onprem" || os.Getenv("YABANIN_REGION") == "onprem" {
			base = "http://localhost:8082"
		} else {
			base = "https://api.yabanin.io"
		}
	}
	key := envOr("YABANIN_API_KEY", "TOKENROUTER_API_KEY")
	if key == "" {
		return Config{}, fmt.Errorf("YABANIN_API_KEY not set (legacy TOKENROUTER_API_KEY is honored)")
	}
	return Config{BaseURL: base, APIKey: key}, nil
}

// Client is a thin Yabanin gateway client (stdlib only).
type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// New creates a Yabanin client.
func New(cfg Config) (*Client, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("API key required")
	}
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("base URL required")
	}
	return &Client{
		baseURL: cfg.BaseURL,
		apiKey:  cfg.APIKey,
		http:    &http.Client{Timeout: 60 * time.Second},
	}, nil
}

// BaseURL returns the configured gateway URL.
func (c *Client) BaseURL() string { return c.baseURL }

// APIKey returns the configured API key (last 4 chars for safety).
func (c *Client) APIKey() string {
	if len(c.apiKey) > 4 {
		return "****" + c.apiKey[len(c.apiKey)-4:]
	}
	return c.apiKey
}

// Message is a single chat message (OpenAI-compatible).
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatRequest is the body posted to /v1/chat/completions.
type ChatRequest struct {
	Model    string    `json:"model,omitempty"`
	Messages []Message `json:"messages"`
	Stream   bool      `json:"stream,omitempty"`
	// Extra carries provider-extension fields on the request body
	// (extra_body semantics): keys are merged into the top-level JSON object
	// verbatim and take precedence over same-named typed fields. N07-P01-T04.
	Extra map[string]json.RawMessage `json:"-"`
}

// MarshalJSON merges the typed fields with Extra so provider extensions
// reach the gateway body verbatim (RawMessage values keep their exact bytes,
// including integer literals beyond float64's precision window).
func (r ChatRequest) MarshalJSON() ([]byte, error) {
	type alias ChatRequest
	known, err := json.Marshal(alias(r))
	if err != nil {
		return nil, err
	}
	if len(r.Extra) == 0 {
		return known, nil
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(known, &root); err != nil {
		return nil, err
	}
	for k, v := range r.Extra {
		root[k] = v
	}
	return json.Marshal(root)
}

// ChatResponse is the non-stream completion response. Provider-specific
// top-level fields beyond the typed ones are captured verbatim in Extra
// (explicit pass-through, N07-P01-T04): unknown keys keep their exact JSON
// bytes, so extension integers beyond float64's 2^53 window are not
// corrupted.
type ChatResponse struct {
	ID      string                     `json:"id"`
	Model   string                     `json:"model"`
	Choices []map[string]any           `json:"choices"`
	Usage   map[string]any             `json:"usage,omitempty"`
	Extra   map[string]json.RawMessage `json:"-"`
}

// UnmarshalJSON decodes the typed fields and captures every unknown
// top-level key into Extra verbatim. Nested unknown keys inside
// choices/usage ride the existing any-typed maps.
func (r *ChatResponse) UnmarshalJSON(data []byte) error {
	type alias ChatResponse
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for k, v := range raw {
		switch k {
		case "id", "model", "choices", "usage":
			continue
		}
		if a.Extra == nil {
			a.Extra = make(map[string]json.RawMessage, len(raw))
		}
		a.Extra[k] = v
	}
	*r = ChatResponse(a)
	return nil
}

// Chat creates a chat completion (non-stream). It returns an error for any
// non-2xx status (401 unauthorized, 403 whitelisted/budget-denied, 429 budget
// exceeded, 503 fail-closed datastore) rather than decoding the error body
// into a completion.
func (c *Client) Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("chat request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // read to EOF below before returning

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("chat failed: %s: %s", resp.Status, truncate(respBody, 512))
	}

	var out ChatResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &out, nil
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "…"
	}
	return string(b)
}
