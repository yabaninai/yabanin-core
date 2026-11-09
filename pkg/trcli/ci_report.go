package trcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/reireirei/yabanin/pkg/cictx"
	"github.com/reireirei/yabanin/pkg/labels"
	"github.com/spf13/cobra"
)

var (
	ciNow           = time.Now
	ciSleep         = time.Sleep
	ciUsageBudget   = 30 * time.Second
	sessionUsageGap = 2 * time.Second
	headerUsageGap  = 3 * time.Second
	errUsageDenied  = errors.New("usage read not allowed")
)

type ciUsage struct {
	Requests  int64        `json:"requests"`
	TokensIn  int64        `json:"tokens_in"`
	TokensOut int64        `json:"tokens_out"`
	CacheRead int64        `json:"cache_read_tokens"`
	CostUSD   float64      `json:"cost_usd"`
	Unpriced  int64        `json:"unpriced_requests"`
	ByModel   []ciUsageRow `json:"by_model"`
	Complete  bool         `json:"complete"`
	Groups    []ciUsageRow `json:"groups,omitempty"`
}

type ciUsageRow struct {
	Model     string  `json:"model,omitempty"`
	Value     string  `json:"value,omitempty"`
	Requests  int64   `json:"requests"`
	TokensIn  int64   `json:"tokens_in"`
	TokensOut int64   `json:"tokens_out"`
	CostUSD   float64 `json:"cost_usd"`
}

func collectCIUsage(ctx context.Context, cmd *cobra.Command, plan ciPlan, sessionID string, started, finished time.Time) *ciUsage {
	var usage *ciUsage
	var err error
	if sessionID != "" {
		usage, err = pollSessionUsage(ctx, plan.Gateway, plan.Key, sessionID)
	} else {
		usage, err = pollHeaderUsage(ctx, plan, started, finished)
	}
	if err != nil {
		msg := "usage unavailable"
		if errors.Is(err, errUsageDenied) {
			msg = "CI key cannot read usage; enable can_read_usage on the key"
		}
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), msg)
	}
	return usage
}

func pollSessionUsage(ctx context.Context, gateway, key, id string) (*ciUsage, error) {
	deadline := ciNow().Add(ciUsageBudget)
	var last *ciUsage
	for {
		usage, status, err := fetchUsage(ctx, gateway, key, "/session-keys/"+url.PathEscape(id)+"/usage")
		if status == http.StatusForbidden {
			return nil, errUsageDenied
		}
		if err != nil {
			return last, err
		}
		last = usage
		if usage.Complete || !ciNow().Before(deadline) {
			return usage, nil
		}
		ciSleep(sessionUsageGap)
	}
}

func pollHeaderUsage(ctx context.Context, plan ciPlan, started, finished time.Time) (*ciUsage, error) {
	q := url.Values{}
	q.Set("from", started.Add(-time.Minute).UTC().Format(time.RFC3339))
	q.Set("to", finished.Add(time.Minute).UTC().Format(time.RFC3339))
	if id := plan.Labels["ci.pipeline"]; id != "" {
		q.Set("label.ci.pipeline", id)
	}
	if id := plan.Labels["ci.job"]; id != "" {
		q.Set("label.ci.job", id)
	}
	path := "/usage?" + q.Encode()
	deadline := ciNow().Add(ciUsageBudget)
	var prev string
	var last *ciUsage
	for {
		usage, raw, status, err := fetchUsageRaw(ctx, plan.Gateway, plan.Key, path)
		if status == http.StatusForbidden {
			return nil, errUsageDenied
		}
		if err != nil {
			return last, err
		}
		last = usage
		cur := canonicalJSON(raw)
		if prev != "" && cur == prev {
			return usage, nil
		}
		prev = cur
		if !ciNow().Before(deadline) {
			return usage, nil
		}
		ciSleep(headerUsageGap)
	}
}

func fetchUsage(ctx context.Context, gateway, key, path string) (*ciUsage, int, error) {
	usage, _, status, err := fetchUsageRaw(ctx, gateway, key, path)
	return usage, status, err
}

func fetchUsageRaw(ctx context.Context, gateway, key, path string) (*ciUsage, []byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sessionBase(gateway)+path, nil)
	if err != nil {
		return nil, nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, 0, err
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusForbidden {
		return nil, payload, resp.StatusCode, errUsageDenied
	}
	if resp.StatusCode != http.StatusOK {
		return nil, payload, resp.StatusCode, fmt.Errorf("usage status %d", resp.StatusCode)
	}
	var usage ciUsage
	if err := json.Unmarshal(payload, &usage); err != nil {
		return nil, payload, resp.StatusCode, err
	}
	if usage.ByModel == nil {
		usage.ByModel = []ciUsageRow{}
	}
	return &usage, payload, resp.StatusCode, nil
}

func canonicalJSON(raw []byte) string {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return string(raw)
	}
	out, err := json.Marshal(value)
	if err != nil {
		return string(raw)
	}
	return string(out)
}

func dashboardURL(set labels.Set) string {
	admin := strings.TrimRight(strings.TrimSpace(os.Getenv("YABANIN_ADMIN_URL")), "/")
	if admin == "" {
		return ""
	}
	pipeline := set["ci.pipeline"]
	filter := fmt.Sprintf("label.ci.pipeline = %q", pipeline)
	return admin + "/#analytics?f=" + strings.ReplaceAll(url.QueryEscape(filter), "+", "%20") + "&g=label:ci.job_name&m=cost_usd,tokens_in,tokens_out"
}

func usageSummary(usage *ciUsage) string {
	if usage == nil {
		return "yabanin: usage unavailable\n"
	}
	note := ""
	if !usage.Complete {
		note = " (incomplete)"
	}
	return fmt.Sprintf("yabanin: %d requests, %.4f USD%s\n", usage.Requests, usage.CostUSD, note)
}

func githubStepSummary(path string, usage *ciUsage) error {
	if path == "" || usage == nil {
		return nil
	}
	var b strings.Builder
	b.WriteString("\n| Model | Requests | Tokens in | Tokens out | Cost USD |\n| --- | ---: | ---: | ---: | ---: |\n")
	for _, row := range usage.ByModel {
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %s |\n", row.Model, row.Requests, row.TokensIn, row.TokensOut, formatCost(row.CostUSD))
	}
	fmt.Fprintf(&b, "| Total | %d | %d | %d | %s |\n", usage.Requests, usage.TokensIn, usage.TokensOut, formatCost(usage.CostUSD))
	if !usage.Complete {
		b.WriteString("\nIncomplete data.\n")
	}
	if usage.Unpriced > 0 {
		fmt.Fprintf(&b, "\n%d requests have no price.\n", usage.Unpriced)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // G304: path is GITHUB_STEP_SUMMARY
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.WriteString(f, b.String())
	return err
}

func writeOpenMetrics(path string, usage *ciUsage) error {
	if path == "" {
		return nil
	}
	var b bytes.Buffer
	if usage == nil {
		fmt.Fprintf(&b, "yabanin_cost_usd 0\nyabanin_tokens_in 0\nyabanin_tokens_out 0\nyabanin_requests 0\n")
	} else {
		fmt.Fprintf(&b, "yabanin_cost_usd %s\nyabanin_tokens_in %d\nyabanin_tokens_out %d\nyabanin_requests %d\n",
			formatCost(usage.CostUSD), usage.TokensIn, usage.TokensOut, usage.Requests)
	}
	return os.WriteFile(path, b.Bytes(), 0o600)
}

func formatCost(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}

func failOverCost(flag string, usage *ciUsage) error {
	if strings.TrimSpace(flag) == "" || usage == nil {
		return nil
	}
	limit, err := strconv.ParseFloat(flag, 64)
	if err != nil {
		return fmt.Errorf("fail-over-cost: %w", err)
	}
	if usage.CostUSD > limit {
		return &cictx.ExitError{Code: 4}
	}
	return nil
}

func pipelineSince(flag string) (time.Time, error) {
	if os.Getenv("GITLAB_CI") == "true" {
		if raw := os.Getenv("CI_PIPELINE_CREATED_AT"); raw != "" && (flag == "" || flag == "24h") {
			parsed, err := time.Parse(time.RFC3339, raw)
			if err == nil {
				return parsed.UTC(), nil
			}
		}
	}
	if flag == "" {
		flag = "24h"
	}
	d, err := time.ParseDuration(flag)
	if err != nil {
		return time.Time{}, fmt.Errorf("since: %w", err)
	}
	return ciNow().Add(-d).UTC(), nil
}

func fetchPipelineUsage(ctx context.Context, plan ciPlan, since time.Time, groupBy string) (*ciUsage, error) {
	q := url.Values{}
	q.Set("from", since.UTC().Format(time.RFC3339))
	q.Set("to", ciNow().UTC().Format(time.RFC3339))
	if id := plan.Labels["ci.pipeline"]; id != "" {
		q.Set("label.ci.pipeline", id)
	}
	if groupBy != "" {
		q.Set("group_by", groupBy)
	}
	usage, status, err := fetchUsage(ctx, plan.Gateway, plan.Key, "/usage?"+q.Encode())
	if status == http.StatusForbidden {
		return nil, errUsageDenied
	}
	return usage, err
}
