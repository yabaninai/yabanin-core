package trcli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseCSVForTest(t *testing.T, csvText string) []invoiceLine {
	t.Helper()
	lines, err := parseInvoiceCSV(strings.NewReader(csvText))
	require.NoError(t, err)
	return lines
}

func TestParseInvoiceCSV(t *testing.T) {
	t.Run("happy path with quoting, blanks and extra columns", func(t *testing.T) {
		lines := parseCSVForTest(t, "date,usage_type,cost_usd,account\n"+
			"2026-10-01,completion,12.40,acme\n"+
			"2026-10-02,\"embedding, batch\",0.85,acme\n"+
			"\n"+
			"   ,  ,   \n"+
			"2026-10-03,audio,2.00,acme\n")
		require.Len(t, lines, 3)
		assert.Equal(t, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), lines[0].Date)
		assert.Equal(t, "completion", lines[0].UsageType)
		assert.InDelta(t, 12.40, lines[0].CostUSD, 1e-9)
		assert.Equal(t, "embedding, batch", lines[1].UsageType, "quoted comma field")
		assert.InDelta(t, 0.85, lines[1].CostUSD, 1e-9)
		assert.InDelta(t, 2.00, lines[2].CostUSD, 1e-9)
		assert.Equal(t, 5, lines[2].Line,
			"errors point at the record's line (encoding/csv swallows fully empty lines)")
	})

	t.Run("header order insensitive", func(t *testing.T) {
		lines := parseCSVForTest(t, "cost_usd,date,usage_type\n1.5,2026-10-02,completion\n")
		require.Len(t, lines, 1)
		assert.InDelta(t, 1.5, lines[0].CostUSD, 1e-9)
		assert.Equal(t, time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC), lines[0].Date)
	})

	t.Run("errors name the offending line", func(t *testing.T) {
		_, err := parseInvoiceCSV(strings.NewReader("date,usage_type,cost_usd\n2026-13-40,x,1\n"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "line 2")

		_, err = parseInvoiceCSV(strings.NewReader("date,usage_type,cost_usd\n2026-10-01,x,not-a-number\n"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cost_usd")

		_, err = parseInvoiceCSV(strings.NewReader("day,kind,amount\n"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "header")

		_, err = parseInvoiceCSV(strings.NewReader(""))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty file")
	})
}

func TestParseMonth(t *testing.T) {
	start, end, err := parseMonth("2026-10")
	require.NoError(t, err)
	assert.Equal(t, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), start)
	assert.Equal(t, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), end)

	for _, bad := range []string{"2026-13", "2026-1", "26-10", "2026/10", "2026-10-01", ""} {
		_, _, err := parseMonth(bad)
		require.Error(t, err, "period %q must be rejected", bad)
	}
}

// reconcileOpts returns options for a full-month 2026-10 openai comparison.
func spendReconcileOpts(org string, failOver float64) SpendReconcileOptions {
	return SpendReconcileOptions{
		OrgID: org, Provider: "openai", Period: "2026-10", FailOver: failOver,
	}
}

func TestReconcileSpendMath(t *testing.T) {
	periodStart := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	periodEnd := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	org := "00000000-0000-0000-0000-000000000001"

	t.Run("perfect match", func(t *testing.T) {
		lines := parseCSVForTest(t, "date,usage_type,cost_usd\n2026-10-01,completion,10\n2026-10-02,completion,5\n")
		our := map[string]float64{"2026-10-01": 10, "2026-10-02": 5}
		report, fail := reconcileSpend(spendReconcileOpts(org, 0), lines, our, periodStart, periodEnd, "openai.com")
		require.NoError(t, fail)
		assert.InDelta(t, 15, report.OurTotalUSD, 1e-9)
		assert.InDelta(t, 15, report.InvoiceTotalUSD, 1e-9)
		assert.InDelta(t, 100, report.CaptureRatePct, 1e-9)
		assert.InDelta(t, 0, report.ShortfallPct, 1e-9)
		require.Len(t, report.Days, 2)
		assert.InDelta(t, 0, report.Days[0].DiffUSD, 1e-9)
	})

	t.Run("20 percent undercapture", func(t *testing.T) {
		lines := parseCSVForTest(t, "date,usage_type,cost_usd\n2026-10-01,completion,100\n")
		our := map[string]float64{"2026-10-01": 80}
		report, fail := reconcileSpend(spendReconcileOpts(org, 0), lines, our, periodStart, periodEnd, "openai.com")
		require.NoError(t, fail)
		assert.InDelta(t, 80, report.CaptureRatePct, 1e-9)
		assert.InDelta(t, 20, report.ShortfallPct, 1e-9)
	})

	t.Run("fail-over breached", func(t *testing.T) {
		lines := parseCSVForTest(t, "date,usage_type,cost_usd\n2026-10-01,completion,100\n")
		our := map[string]float64{"2026-10-01": 80}
		_, fail := reconcileSpend(spendReconcileOpts(org, 19.9), lines, our, periodStart, periodEnd, "openai.com")
		require.Error(t, fail, "20% shortfall breaches --fail-over 19.9")
		_, fail = reconcileSpend(spendReconcileOpts(org, 20), lines, our, periodStart, periodEnd, "openai.com")
		require.NoError(t, fail, "fail-over triggers on shortfall strictly ABOVE the threshold")
	})

	t.Run("missing invoice day is visible as a diff", func(t *testing.T) {
		lines := parseCSVForTest(t, "date,usage_type,cost_usd\n2026-10-01,completion,10\n")
		our := map[string]float64{"2026-10-01": 10, "2026-10-02": 4}
		report, fail := reconcileSpend(spendReconcileOpts(org, 0), lines, our, periodStart, periodEnd, "openai.com")
		require.NoError(t, fail)
		require.Len(t, report.Days, 2)
		assert.InDelta(t, 4, report.Days[1].OurUSD, 1e-9)
		assert.InDelta(t, 4, report.Days[1].DiffUSD, 1e-9)
		assert.Greater(t, report.CaptureRatePct, 100.0, "overcapture exceeds 100%")
		assert.InDelta(t, 0, report.ShortfallPct, 1e-9, "shortfall floors at zero")
	})

	t.Run("missing captured day undercounts", func(t *testing.T) {
		lines := parseCSVForTest(t, "date,usage_type,cost_usd\n2026-10-01,completion,10\n2026-10-02,completion,7\n")
		our := map[string]float64{"2026-10-01": 10}
		report, _ := reconcileSpend(spendReconcileOpts(org, 0), lines, our, periodStart, periodEnd, "openai.com")
		require.Len(t, report.Days, 2)
		assert.InDelta(t, 0, report.Days[1].OurUSD, 1e-9)
		assert.InDelta(t, 10.0/17.0*100, report.CaptureRatePct, 1e-9, "10 captured of 17 invoiced")
	})

	t.Run("outside-period lines excluded and counted", func(t *testing.T) {
		lines := parseCSVForTest(t, "date,usage_type,cost_usd\n2026-10-01,completion,10\n2026-09-30,completion,50\n2026-11-01,completion,50\n")
		our := map[string]float64{"2026-10-01": 10}
		report, fail := reconcileSpend(spendReconcileOpts(org, 0), lines, our, periodStart, periodEnd, "openai.com")
		require.NoError(t, fail)
		assert.Equal(t, 2, report.OutsidePeriod)
		assert.InDelta(t, 10, report.InvoiceTotalUSD, 1e-9)
		assert.Len(t, report.Days, 1)
	})

	t.Run("empty invoice and empty capture", func(t *testing.T) {
		report, fail := reconcileSpend(spendReconcileOpts(org, 0), nil, nil, periodStart, periodEnd, "openai.com")
		require.NoError(t, fail)
		assert.InDelta(t, 100, report.CaptureRatePct, 1e-9)
		require.Len(t, report.Notes, 1)
	})
}

func TestProviderHostAliases(t *testing.T) {
	assert.Equal(t, "openai.com", providerHostAliases["openai"])
	assert.Equal(t, "anthropic.com", providerHostAliases["anthropic"])
	assert.NotContains(t, "https://api.openai.azure.com/v1", providerHostAliases["openai"],
		"azure hosts must not collide with the openai.com substring")
}

func TestSpendReconcileFlagValidation(t *testing.T) {
	store := &fakeSpendStore{}

	err := runSpendReconcile(&bytes.Buffer{}, store, SpendReconcileOptions{OrgID: "not-a-uuid", Period: "2026-10"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "UUID")

	err = runSpendReconcile(&bytes.Buffer{}, store, SpendReconcileOptions{
		OrgID: "00000000-0000-0000-0000-000000000001", Period: "October 2026",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--period")

	err = runSpendReconcile(&bytes.Buffer{}, store, SpendReconcileOptions{
		OrgID: "00000000-0000-0000-0000-000000000001", Period: "2026-10", Provider: "quantum-computing",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--upstream-host")
}

func TestSpendReconcileEndToEndWithFakeStore(t *testing.T) {
	// runSpendReconcile reads the CSV from disk; use the documented fixture
	// as the input document.
	store := &fakeSpendStore{daily: map[string]float64{
		"2026-10-01": 4.3125,
		"2026-10-02": 1.0, // undercaptured vs the fixture's 3.87
	}}
	opts := SpendReconcileOptions{
		OrgID:    "00000000-0000-0000-0000-000000000001",
		Provider: "openai",
		CSVPath:  "../../scripts/pricing/fixtures/invoice_openai_2026-10.csv",
		Period:   "2026-10",
		Format:   "json",
	}
	var out bytes.Buffer
	require.NoError(t, runSpendReconcile(&out, store, opts))
	report := out.String()
	assert.Contains(t, report, `"capture_rate_pct"`)
	assert.Contains(t, report, `"outside_period_lines": 1`)
	assert.Contains(t, report, `"invoice_total_usd": 43.7575`,
		"fixture sum inside 2026-10; the 2026-11-15 line is excluded")

	// Text rendering keeps the tabular daily breakdown.
	store2 := &fakeSpendStore{daily: store.daily}
	var textOut bytes.Buffer
	opts.Format = "text"
	require.NoError(t, runSpendReconcile(&textOut, store2, opts))
	text := textOut.String()
	assert.Contains(t, text, "capture_rate=")
	assert.Contains(t, text, "2026-10-01")
}

// fakeSpendStore is the SpendStore test double.
type fakeSpendStore struct {
	daily map[string]float64
}

func (f *fakeSpendStore) DailyProviderSpend(_ context.Context, _ string, _, _ time.Time, _ string) (map[string]float64, error) {
	return f.daily, nil
}

// ---------------------------------------------------------------------------
// Live test: the real pgStore SQL against the disposable stand (org filter,
// period window, provider host match, cost sum). Dockerless runs skip.
// ---------------------------------------------------------------------------

func TestSpendReconcilePGStore(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	org := "11111111-1111-1111-1111-111111111111"
	other := "22222222-2222-2222-2222-222222222222"

	for _, seed := range []struct{ id, slug string }{{org, "recon-org-a"}, {other, "recon-org-b"}} {
		_, err := pool.Exec(ctx,
			`INSERT INTO organizations (id, name, slug) VALUES ($1, $2, $2) ON CONFLICT (id) DO NOTHING`,
			seed.id, seed.slug)
		require.NoError(t, err)
		t.Cleanup(func() {
			_, _ = pool.Exec(ctx, `DELETE FROM request_logs WHERE org_id = $1`, seed.id)
			_, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, seed.id)
		})
	}

	seedLog := func(t *testing.T, orgID, upstream string, createdAt time.Time, cost float64) {
		t.Helper()
		_, err := pool.Exec(ctx,
			`INSERT INTO request_logs (org_id, model_requested, model_used, status_code,
				duration_ms, cost_in_usd, upstream_url, created_at, updated_at, home_region)
			 VALUES ($1, 'gpt-x', 'gpt-x', 200, 5, $2, $3, $4, $4, 'test-region')`,
			orgID, cost, upstream, createdAt)
		require.NoError(t, err)
	}
	oct1 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	seedLog(t, org, "https://api.openai.com/v1", oct1, 3.5)
	seedLog(t, org, "https://api.openai.com/v1", oct1.Add(2*time.Hour), 1.25)
	seedLog(t, org, "https://api.openai.com/v1", time.Date(2026, 9, 30, 23, 0, 0, 0, time.UTC), 99) // before the period
	seedLog(t, org, "https://api.anthropic.com/v1", oct1, 50)                                       // other provider
	seedLog(t, other, "https://api.openai.com/v1", oct1, 70)                                        // other org

	store := pgStore{pool: pool}
	got, err := store.DailyProviderSpend(ctx, org,
		time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), "openai.com")
	require.NoError(t, err)
	require.Len(t, got, 1, "org + provider + period filters")
	assert.InDelta(t, 4.75, got["2026-10-01"], 1e-9)
}
