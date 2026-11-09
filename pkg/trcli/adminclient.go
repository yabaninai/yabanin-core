package trcli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// defaultAdminURL matches the runbook default for YABANIN_ADMIN_LISTEN.
const defaultAdminURL = "http://localhost:8086"

const adminClientTimeout = 10 * time.Second

// AdminClient is a thin read-only client for the yabanin-admin /internal
// service API. The API key travels only in the X-Admin-Key header and is never
// logged or printed.
type AdminClient struct {
	baseURL string
	apiKey  string
	httpc   *http.Client
}

// NewAdminClient builds a client; an empty baseURL falls back to defaultAdminURL.
func NewAdminClient(baseURL, apiKey string) *AdminClient {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = defaultAdminURL
	}
	return &AdminClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		httpc:   &http.Client{Timeout: adminClientTimeout},
	}
}

// APIKey mirrors the displayable fields of adminstore.APIKey. There is no
// plaintext key material by design (the store keeps hashes only).
type APIKey struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
}

// TopModelRow is one row of the savings report top-models breakdown.
type TopModelRow struct {
	Model         string  `json:"model"`
	Requests      int     `json:"requests"`
	ActualCostUSD float64 `json:"actual_cost_usd"`
	SavingsPct    float64 `json:"savings_pct"`
}

// SavingsReportSummary holds the fields `yb spend` prints.
type SavingsReportSummary struct {
	Period             string        `json:"period"`
	TotalRequests      int           `json:"total_requests"`
	ActualCostUSD      float64       `json:"actual_cost_usd"`
	CounterfactualCost float64       `json:"counterfactual_cost_usd"`
	CombinedSavingsPct float64       `json:"combined_savings_pct"`
	TopModelsByCost    []TopModelRow `json:"top_models_by_cost"`
}

// APIKeyPage is one page of an org's API keys plus the server-side total.
type APIKeyPage struct {
	Data    []APIKey
	Total   int64
	HasMore bool
}

// ListAPIKeys fetches one page of the org's API keys. page/pageSize <= 0 fall
// back to the server defaults (page 1, size 50).
func (c *AdminClient) ListAPIKeys(ctx context.Context, orgID string, page, pageSize int) (*APIKeyPage, error) {
	q := url.Values{"org_id": {orgID}}
	if page > 0 {
		q.Set("page", fmt.Sprint(page))
	}
	if pageSize > 0 {
		q.Set("page_size", fmt.Sprint(pageSize))
	}
	var out struct {
		Data       []APIKey `json:"data"`
		Pagination struct {
			Page     int   `json:"page"`
			PageSize int   `json:"page_size"`
			Total    int64 `json:"total"`
		} `json:"pagination"`
	}
	if err := c.getJSON(ctx, "/internal/api-keys", q, &out); err != nil {
		return nil, err
	}
	p := out.Pagination
	hasMore := p.Page > 0 && int64(p.Page)*int64(p.PageSize) < p.Total
	return &APIKeyPage{Data: out.Data, Total: p.Total, HasMore: hasMore}, nil
}

// SavingsReport fetches the org savings analytics for a look-back window.
func (c *AdminClient) SavingsReport(ctx context.Context, orgID string, days int) (*SavingsReportSummary, error) {
	q := url.Values{"org_id": {orgID}}
	if days > 0 {
		q.Set("days", fmt.Sprint(days))
	}
	var out SavingsReportSummary
	if err := c.getJSON(ctx, "/internal/analytics/savings", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *AdminClient) getJSON(ctx context.Context, path string, q url.Values, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path+"?"+q.Encode(), nil)
	if err != nil {
		return fmt.Errorf("building admin request: %w", err)
	}
	req.Header.Set("X-Admin-Key", c.apiKey)

	resp, err := c.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("admin service unreachable at %s: %w", c.baseURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // bound: defensive cap on admin payloads
	if err != nil {
		return fmt.Errorf("reading admin response: %w", err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		if out == nil {
			return nil
		}
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("decoding admin response: %w", err)
		}
		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("admin service rejected the key: check --api-key and that yabanin-admin has YABANIN_ADMIN_API_KEY set")
	case http.StatusBadRequest:
		var e struct {
			Error string `json:"error"`
		}
		msg := "bad request"
		if json.Unmarshal(body, &e) == nil && e.Error != "" {
			msg = e.Error
		}
		return fmt.Errorf("admin service: %s", msg)
	default:
		return fmt.Errorf("admin service returned status %d from %s", resp.StatusCode, path)
	}
}

// resolveAdminFlags extracts the persistent admin flags and validates that an
// organization was supplied. Returns baseURL, apiKey, org or an error.
// TP-08: URL resolution follows the CLI-wide order — flag, then
// YABANIN_ADMIN_URL, then the admin client default (see resolveAdminURL).
func resolveAdminFlags(getString func(string) (string, error), flagName string) (baseURL, apiKey, org string, err error) {
	baseURL, _ = getString("admin-url")
	if strings.TrimSpace(baseURL) == "" {
		baseURL = strings.TrimSpace(os.Getenv("YABANIN_ADMIN_URL"))
	}
	apiKey, _ = getString("api-key")
	if apiKey == "" {
		return "", "", "", fmt.Errorf("--api-key required (send it as the X-Admin-Key service key)")
	}
	org, _ = getString(flagName)
	if org == "" {
		return "", "", "", fmt.Errorf("%s required (organization the request applies to)", flagName)
	}
	return baseURL, apiKey, org, nil
}
