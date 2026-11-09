package trcli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/cictx"
	"github.com/reireirei/yabanin/pkg/labels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCIUsageReport(t *testing.T) {
	prevBudget, prevSession, prevHeader := ciUsageBudget, sessionUsageGap, headerUsageGap
	ciUsageBudget = time.Minute
	sessionUsageGap = 0
	headerUsageGap = 0
	t.Cleanup(func() {
		ciUsageBudget = prevBudget
		sessionUsageGap = prevSession
		headerUsageGap = prevHeader
	})

	var sessionHits int
	var headerHits int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer deny" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if strings.Contains(r.URL.Path, "/session-keys/") {
			mu.Lock()
			sessionHits++
			n := sessionHits
			mu.Unlock()
			complete := n >= 2
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(ciUsage{
				Requests: 3, TokensIn: 10, TokensOut: 4, CostUSD: 0.5, Complete: complete,
				ByModel: []ciUsageRow{{Model: "m", Requests: 3, TokensIn: 10, TokensOut: 4, CostUSD: 0.5}},
			})
			return
		}
		mu.Lock()
		headerHits++
		n := headerHits
		mu.Unlock()
		body := ciUsage{Requests: int64(n), TokensIn: 1, TokensOut: 1, CostUSD: 1.5, Complete: true, ByModel: []ciUsageRow{}}
		if n >= 2 {
			body.Requests = 2
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer srv.Close()

	usage, err := pollSessionUsage(t.Context(), srv.URL, "parent", "sess-1")
	require.NoError(t, err)
	require.NotNil(t, usage)
	assert.True(t, usage.Complete)
	assert.Equal(t, 2, sessionHits)

	plan := ciPlan{Gateway: srv.URL, Key: "parent", Labels: labels.Set{"ci.pipeline": "9001", "ci.job": "9"}}
	headerHits = 0
	usage, err = pollHeaderUsage(t.Context(), plan, time.Now().Add(-time.Minute), time.Now())
	require.NoError(t, err)
	require.NotNil(t, usage)
	assert.GreaterOrEqual(t, headerHits, 2)

	plan.Key = "deny"
	usage, err = pollHeaderUsage(t.Context(), plan, time.Now().Add(-time.Minute), time.Now())
	require.ErrorIs(t, err, errUsageDenied)
	assert.Nil(t, usage)

	summary := t.TempDir()
	sumPath := filepath.Join(summary, "step.md")
	require.NoError(t, githubStepSummary(sumPath, &ciUsage{
		Requests: 12, TokensIn: 120000, TokensOut: 8000, CostUSD: 0.42, Unpriced: 2, Complete: false,
		ByModel: []ciUsageRow{{Model: "glm", Requests: 12, TokensIn: 120000, TokensOut: 8000, CostUSD: 0.42}},
	}))
	body, err := os.ReadFile(sumPath) //nolint:gosec // G304: path is a temp file created by this test
	require.NoError(t, err)
	assert.Contains(t, string(body), "| glm | 12 | 120000 | 8000 | 0.42 |")
	assert.Contains(t, string(body), "| Total | 12 | 120000 | 8000 | 0.42 |")
	assert.Contains(t, string(body), "Incomplete data.")
	assert.Contains(t, string(body), "2 requests have no price.")

	metrics := filepath.Join(summary, "metrics.txt")
	require.NoError(t, writeOpenMetrics(metrics, &ciUsage{Requests: 12, TokensIn: 120000, TokensOut: 8000, CostUSD: 0.42}))
	raw, err := os.ReadFile(metrics) //nolint:gosec // G304: path is a temp file created by this test
	require.NoError(t, err)
	assert.Equal(t, "yabanin_cost_usd 0.42\nyabanin_tokens_in 120000\nyabanin_tokens_out 8000\nyabanin_requests 12\n", string(raw))

	t.Setenv("YABANIN_ADMIN_URL", "https://admin.example")
	link := dashboardURL(labels.Set{"ci.pipeline": "9001"})
	assert.Contains(t, link, "label.ci.pipeline%20%3D%20%229001%22")
	assert.NotContains(t, link, " ")

	err = failOverCost("0.10", &ciUsage{CostUSD: 0.42})
	var exit *cictx.ExitError
	require.ErrorAs(t, err, &exit)
	assert.Equal(t, 4, exit.Code)
}
