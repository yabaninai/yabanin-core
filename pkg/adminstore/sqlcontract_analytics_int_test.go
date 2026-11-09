package adminstore

// exported method that executes SQL in cost_analytics.go, analytics.go,
// savings.go, shadow_compare.go, quality_compare.go, task_analytics.go,
// analytics_query.go (raw + rollup sources, YQL filter operators, the
// order-by allowlist) and analytics_views.go, run against the real disposable
// set/empty/unknown, provider, window, each sortable column in both
// directions, empty results) are matrix-generated; business answers (empty
// windows, missing ids) are asserted where they pin the contract, SQL
// rejections fail via contract().
//
// The 03a fixture lacks rollup rows, tool_calls, request_logs-joined
// evalgate verdicts and an agent-tagged log row, so seedAnalyticsExtension
// adds a per-test extension seed on top of seedContractFixture — the harness
// file is untouched.

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// seedAnalyticsExtension extends the shared 03a fixture with the analytics
// domain data the harness cannot know about: one fully-populated org-A log
// row (agent+team display names, task tag, ttft/retry/attempt counts, cache
// tokens, classifier fields, body snapshots, labels), three evalgate
// verdicts joined to seeded request_ids, hourly rollup rows for both rollup
// tables (the rollup writer lives in services/loggerd) and a tool_calls row
// for the YQL tool EXISTS. Cleanup removes exactly the rows the harness
// cleanup cannot reach (org-scoped request_logs/evalgate rows cascade through
// the harness teardown).
func seedAnalyticsExtension(t *testing.T, pool *pgxpool.Pool, fx *contractFixture) {
	t.Helper()
	ctx := context.Background()

	_, err := pool.Exec(ctx, `
		INSERT INTO request_logs (
			org_id, team_id, agent_id, model_requested, model_used, status_code, duration_ms,
			tokens_in, tokens_out, cache_read_tokens, created_at, request_id, cost_in_usd,
			counterfactual_cost_usd, cache_hit_type, tier_used, ab_group, labels, cost_status,
			usage_source, endpoint, home_region, task_id, first_token_ms, attempt_count,
			retry_count, classifier_class, classifier_confidence, upstream_request, response
		) VALUES (
			$1::uuid, $2::uuid, $3::uuid, $4, $4, 200, 250,
			200, 100, 40, $5, $6, 0.000020,
			0.000040, 'exact', 'smart', '', $7::jsonb, 'priced',
			'provider', 'responses', 'GLOBAL', 'code-gen', 120, 2,
			1, 'medium', 0.42, '{"probe":"imp03b"}'::jsonb, '{"out":"imp03b"}'::jsonb)`,
		fx.OrgA, fx.TeamA1, fx.AgentKeyA, fx.Token+"-m-smart",
		time.Now().Add(-time.Hour), fx.Token+"-rx",
		`{"env":"prod","issue":"PAY-9","custom":"v1"}`)
	require.NoError(t, err, "seed extension request_logs row")

	_, err = pool.Exec(ctx, `
		INSERT INTO evalgate_results (org_id, request_id, prompt, cheap_model, premium_model,
			cheap_quality, premium_quality, should_upgrade, reason, raw_confidence)
		VALUES ($1, $2, 'imp03b probe', $3, $4, 0.4, 0.9, true, 'quality gap', 0.7),
		       ($1, $5, 'imp03b probe', $3, $4, 0.6, 0.8, false, 'close enough', 0.6),
		       ($1, $6, 'imp03b probe', $3, $4, 0.5, 0.7, true, 'quality gap', 0.8)`,
		fx.OrgA, fx.Token+"-r1", fx.Token+"-m-fast", fx.Token+"-m-smart",
		fx.Token+"-r2", fx.Token+"-r3")
	require.NoError(t, err, "seed joined evalgate verdicts")

	// home_region is explicit: the NOT NULL default reads app.region, which
	// is unset on the stand.
	hour := time.Now().Add(-2 * time.Hour).Truncate(time.Hour)
	_, err = pool.Exec(ctx, `
		INSERT INTO analytics_rollup_hourly (home_region, org_id, hour, model_used, endpoint,
			team_id, agent_id, status_class, cache_type, requests, tokens_in, tokens_out,
			cache_read_tokens, cost_usd, unpriced_requests, legacy_rows, errors,
			retried_requests, fallback_requests, cache_hits)
		VALUES
		('GLOBAL', $1::uuid, $2, 'contract-m', 'chat.completions', $3::uuid, $4::uuid, '2xx', 'miss',
			5, 500, 300, 50, 0.000100, 1, 0, 0, 1, 1, 2),
		('GLOBAL', $1::uuid, $2, 'contract-m', 'chat.completions',
			'00000000-0000-0000-0000-000000000000'::uuid, '00000000-0000-0000-0000-000000000000'::uuid,
			'5xx', 'exact', 2, 100, 50, 0, 0, 2, 0, 2, 0, 0, 0),
		('GLOBAL', $1::uuid, $5, 'contract-n', 'responses',
			'00000000-0000-0000-0000-000000000000'::uuid, '00000000-0000-0000-0000-000000000000'::uuid,
			'2xx', 'miss', 1, 10, 5, 1, 0.000010, 0, 0, 0, 0, 0, 0)`,
		fx.OrgA, hour, fx.TeamA1, fx.AgentKeyA, hour.Add(time.Hour))
	require.NoError(t, err, "seed analytics_rollup_hourly")

	_, err = pool.Exec(ctx, `
		INSERT INTO label_rollup_hourly (home_region, org_id, hour, key, value, requests, tokens_in,
			tokens_out, cache_read_tokens, cost_usd, unpriced_requests, legacy_rows, errors,
			retried_requests, fallback_requests, cache_hits)
		VALUES
		('GLOBAL', $1::uuid, $2, 'issue', 'PAY-1', 3, 300, 200, 10, 0.000030, 1, 0, 0, 0, 0, 1),
		('GLOBAL', $1::uuid, $2, 'issue', 'PAY-2', 2, 200, 100, 5, 0.000020, 0, 0, 0, 0, 0, 1)`,
		fx.OrgA, hour)
	require.NoError(t, err, "seed label_rollup_hourly")

	_, err = pool.Exec(ctx, `
		INSERT INTO tool_calls (request_id, org_id, task_id, model_used, tool_name)
		VALUES ($1, $2::uuid, 'code-gen', 'contract-m', 'web_search')`,
		fx.Token+"-rx", fx.OrgA)
	require.NoError(t, err, "seed tool_calls")

	t.Cleanup(func() {
		cleanup := func(q string, args ...any) {
			if _, err := pool.Exec(ctx, q, args...); err != nil {
				t.Errorf("analytics extension cleanup: %v", err)
			}
		}
		cleanup(`DELETE FROM tool_calls WHERE request_id LIKE $1`, fx.Token+"%")
		cleanup(`DELETE FROM analytics_rollup_hourly WHERE org_id::text = ANY($1)`, []string{fx.OrgA})
		cleanup(`DELETE FROM label_rollup_hourly WHERE org_id::text = ANY($1)`, []string{fx.OrgA})
	})
}

// emptyWindow is a window far outside every seeded row — the contract-legal
// "no data" answer for every analytics read.
var emptyWindowFrom = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

// TestSQLContractAnalytics_Cost covers GetCostAnalytics (org × provider ×
// empty org × empty window), GetGlobalCostStats (window × empty window) and
// GetCacheAnalytics. The orgA run also drives buildPricingMetadata's
// unpriced-coverage queries against models_pricing/models_registry.
func TestSQLContractAnalytics_Cost(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)
	seedAnalyticsExtension(t, pool, fx)
	from, to := fx.From, fx.To

	cost := func(name, org, provider string) {
		t.Helper()
		contract(t, "GetCostAnalytics/"+name, func(ctx context.Context) error {
			report, err := store.GetCostAnalytics(ctx, org, from, to, provider)
			if err != nil {
				return err
			}
			if name == "empty-org" && report.RequestCount != 0 {
				t.Errorf("GetCostAnalytics/empty-org: unknown org must return an empty report, got %+v", report)
			}
			if name == "orgA" {
				if report.RequestCount < 6 {
					t.Errorf("GetCostAnalytics/orgA: expected the 6 seeded non-shadow rows, got %d", report.RequestCount)
				}
				if report.Pricing.CoverageStatus == "" || report.Pricing.UnpricedShare == nil {
					t.Errorf("GetCostAnalytics/orgA: pricing coverage must be measured, got %+v", report.Pricing)
				}
			}
			return nil
		})
	}
	cost("orgA", fx.OrgA, "")
	cost("orgA-provider", fx.OrgA, "openai-compat")
	cost("orgA-unknown-provider", fx.OrgA, "imp03b-none")
	cost("orgB", fx.OrgB, "")
	cost("empty-org", "00000000-0000-0000-0000-0000000000bb", "")

	contract(t, "GetCostAnalytics/empty-window", func(ctx context.Context) error {
		report, err := store.GetCostAnalytics(ctx, fx.OrgA, emptyWindowFrom, emptyWindowFrom.Add(24*time.Hour), "")
		if err != nil {
			return err
		}
		if report.RequestCount != 0 || report.Pricing.CoverageStatus != CoverageEmpty {
			t.Errorf("GetCostAnalytics/empty-window: got %+v, want empty report with coverage=empty", report)
		}
		return nil
	})

	contract(t, "GetGlobalCostStats", func(ctx context.Context) error {
		report, err := store.GetGlobalCostStats(ctx, from, to)
		if err != nil {
			return err
		}
		if report.RequestCount < 8 {
			t.Errorf("GetGlobalCostStats: expected both orgs' seeded rows, got %d", report.RequestCount)
		}
		return nil
	})
	contract(t, "GetGlobalCostStats/empty-window", func(ctx context.Context) error {
		_, err := store.GetGlobalCostStats(ctx, emptyWindowFrom, emptyWindowFrom.Add(24*time.Hour))
		return err
	})

	cache := func(name, org string) {
		t.Helper()
		contract(t, "GetCacheAnalytics/"+name, func(ctx context.Context) error {
			report, err := store.GetCacheAnalytics(ctx, org, from, to)
			if err != nil {
				return err
			}
			if name == "orgA" && report.HitsExact < 2 {
				t.Errorf("GetCacheAnalytics/orgA: expected the 2 seeded exact hits, got %+v", report)
			}
			return nil
		})
	}
	cache("orgA", fx.OrgA)
	cache("orgB", fx.OrgB)
	cache("empty-org", "00000000-0000-0000-0000-0000000000bb")
}

// TestSQLContractAnalytics_Savings covers GetSavingsReport over the full
// optional-filter matrix: global vs org vs unknown-org vs the legacy
// non-UUID org filter (empty report without touching the DB), provider
// narrowing, and a degenerate days=0 window.
func TestSQLContractAnalytics_Savings(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)
	seedAnalyticsExtension(t, pool, fx)

	savings := func(name, org, provider string, days int, wantRequests int) {
		t.Helper()
		contract(t, "GetSavingsReport/"+name, func(ctx context.Context) error {
			report, err := store.GetSavingsReport(ctx, org, days, provider)
			if err != nil {
				return err
			}
			if report.TotalRequests < wantRequests {
				t.Errorf("GetSavingsReport/%s: got %d requests, want >= %d", name, report.TotalRequests, wantRequests)
			}
			if wantRequests == 0 && report.Pricing.CoverageStatus != CoverageEmpty {
				t.Errorf("GetSavingsReport/%s: empty window must report coverage=empty, got %+v", name, report.Pricing)
			}
			return nil
		})
	}
	savings("global", "", "", 3, 8)
	savings("global-provider", "", "openai-compat", 3, 8)
	savings("orgA", fx.OrgA, "", 3, 6)
	savings("orgA-provider", fx.OrgA, "openai-compat", 3, 6)
	savings("orgA-unknown-provider", fx.OrgA, "imp03b-none", 3, 0)
	savings("unknown-org", "00000000-0000-0000-0000-0000000000bb", "", 3, 0)
	savings("non-uuid-org", "not-a-uuid", "", 3, 0)
	savings("empty-days", fx.OrgA, "", 0, 0)
}

// TestSQLContractAnalytics_ShadowQuality covers GetShadowComparison (global /
// org-scoped / default window / org without shadow traffic) and
// GetQualityScores (global / org with joined verdicts / org without / empty
// window). The org-scoped shadow variant stands as the regression guard.
// placeholder regression contract.
func TestSQLContractAnalytics_ShadowQuality(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)
	seedAnalyticsExtension(t, pool, fx)
	from, to := fx.From, fx.To

	shadow := func(name, org string, days, wantOverlap int) {
		t.Helper()
		contract(t, "GetShadowComparison/"+name, func(ctx context.Context) error {
			report, err := store.GetShadowComparison(ctx, org, days)
			if err != nil {
				return err
			}
			if report.Overlap < wantOverlap {
				t.Errorf("GetShadowComparison/%s: overlap %d < %d", name, report.Overlap, wantOverlap)
			}
			return nil
		})
	}
	shadow("global", "", 3, 1)
	shadow("global-default-days", "", 0, 1)
	shadow("orgA", fx.OrgA, 3, 1)
	shadow("orgB-no-shadow", fx.OrgB, 3, 0)

	quality := func(name, org string, from, to time.Time, wantVerdicts int) {
		t.Helper()
		contract(t, "GetQualityScores/"+name, func(ctx context.Context) error {
			report, err := store.GetQualityScores(ctx, org, from, to)
			if err != nil {
				return err
			}
			if name == "orgA" {
				// 3 seeded verdicts; the r1 verdict joins both the primary
				// log row and its shadow mirror (same request_id), so the
				// current join semantics report 4.
				if report.TotalVerdicts != wantVerdicts {
					t.Errorf("GetQualityScores/orgA: got %d verdicts, want %d (the joined seed)", report.TotalVerdicts, wantVerdicts)
				}
				if report.Verdict != "has_data" {
					t.Errorf("GetQualityScores/orgA: verdict %q, want has_data", report.Verdict)
				}
			}
			if wantVerdicts == 0 && report.TotalVerdicts != 0 {
				t.Errorf("GetQualityScores/%s: got %d verdicts, want 0", name, report.TotalVerdicts)
			}
			return nil
		})
	}
	quality("global", "", from, to, 4)
	quality("orgA", fx.OrgA, from, to, 4)
	quality("orgB-empty", fx.OrgB, from, to, 0)
	quality("empty-window", fx.OrgA, emptyWindowFrom, emptyWindowFrom.Add(24*time.Hour), 0)
}

// TestSQLContractAnalytics_Task covers GetTaskAnalytics over every group_by
// column (task/session/agent/user), the default limit path and the empty-org
// answer. An invalid group_by is a pure validation error (no SQL) and is
// excluded from the SQL contract.
func TestSQLContractAnalytics_Task(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)
	seedAnalyticsExtension(t, pool, fx)
	from, to := fx.From, fx.To

	task := func(name, org, groupBy string, limit int, wantGroups int) {
		t.Helper()
		contract(t, "GetTaskAnalytics/"+name, func(ctx context.Context) error {
			report, err := store.GetTaskAnalytics(ctx, org, from, to, groupBy, limit)
			if err != nil {
				return err
			}
			if len(report.Groups) < wantGroups {
				t.Errorf("GetTaskAnalytics/%s: got %d groups, want >= %d", name, len(report.Groups), wantGroups)
			}
			return nil
		})
	}
	task("task", fx.OrgA, "task", 100, 2)
	task("session", fx.OrgA, "session", 100, 1)
	task("agent", fx.OrgA, "agent", 100, 2)
	task("user", fx.OrgA, "user", 100, 1)
	task("default-limit", fx.OrgA, "task", 0, 2)
	task("empty-org", "00000000-0000-0000-0000-0000000000bb", "task", 100, 0)
}

// analyticsContractQuery builds a query through the production parser so the
// matrix runs exactly what GET /api/analytics/query accepts.
func analyticsContractQuery(t *testing.T, org string, from, to time.Time, metrics, groupBy, gran, filter string, top int, compare bool, tz string) *AnalyticsQuery {
	t.Helper()
	v := url.Values{
		"org_id":  {org},
		"from":    {from.Format(time.RFC3339)},
		"to":      {to.Format(time.RFC3339)},
		"metrics": {metrics},
	}
	if groupBy != "" {
		v.Set("group_by", groupBy)
	}
	if gran != "" {
		v.Set("granularity", gran)
	}
	if filter != "" {
		v.Set("filter", filter)
	}
	if top > 0 {
		v.Set("top", strconv.Itoa(top))
	}
	if compare {
		v.Set("compare", "previous")
	}
	if tz != "" {
		v.Set("tz", tz)
	}
	q, err := ParseAnalyticsQuery(v, "UTC", time.Now())
	require.NoError(t, err)
	return q
}

// runAnalyticsContract executes one RunAnalyticsQuery call under the
// contract: Postgres must accept every statement, and the totals map must
// carry every requested metric. wantSource pins the raw/rollup source
// decision when non-empty.
func runAnalyticsContract(t *testing.T, store *Store, name string, q *AnalyticsQuery, wantSource string) {
	t.Helper()
	contract(t, name, func(ctx context.Context) error {
		res, err := store.RunAnalyticsQuery(ctx, q)
		if err != nil {
			return err
		}
		if wantSource != "" && res.Source != wantSource {
			t.Errorf("%s: source %q, want %q", name, res.Source, wantSource)
		}
		for _, m := range q.Metrics {
			if _, ok := res.Totals[m]; !ok {
				t.Errorf("%s: totals missing metric %q", name, m)
			}
		}
		return nil
	})
}

// TestSQLContractAnalytics_QueryRaw covers the raw source of
// RunAnalyticsQuery: every metric in the allowlist, every dimension (incl.
// label dims, two-dim grouping), every granularity, the top/(other)
// truncation path, the team/agent display-name lookups, timezone handling,
// compare=previous and the empty-window answer.
func TestSQLContractAnalytics_QueryRaw(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)
	seedAnalyticsExtension(t, pool, fx)
	from, to := fx.From, fx.To

	run := func(name, metrics, groupBy, gran, filter string, top int, compare bool, tz, wantSource string) {
		t.Helper()
		q := analyticsContractQuery(t, fx.OrgA, from, to, metrics, groupBy, gran, filter, top, compare, tz)
		runAnalyticsContract(t, store, name, q, wantSource)
	}

	metrics := make([]string, 0, len(analyticsMetrics))
	for name := range analyticsMetrics {
		metrics = append(metrics, name)
	}
	sort.Strings(metrics)
	for _, m := range metrics {
		run("RunAnalyticsQuery/metric/"+m, m, "", "", "", 0, false, "", "")
	}
	run("RunAnalyticsQuery/multi-metric", "requests,cost_usd,errors,cache_hit_rate", "", "", "", 0, false, "", "")

	dims := make([]string, 0, len(analyticsDimExpr))
	for name := range analyticsDimExpr {
		dims = append(dims, name)
	}
	sort.Strings(dims)
	for _, d := range dims {
		run("RunAnalyticsQuery/dim/"+d, "requests,cost_usd", d, "", "", 20, false, "", "")
		run("RunAnalyticsQuery/dim-day/"+d, "requests", d, "day", "", 20, false, "", "")
	}
	run("RunAnalyticsQuery/dims-two", "requests", "model,status_class", "", "", 20, false, "", "")
	run("RunAnalyticsQuery/label-dim-non-rollup", "requests", "label:custom", "", "", 20, false, "", "raw")
	run("RunAnalyticsQuery/gran-hour", "requests", "", "hour", "", 0, false, "", "")
	run("RunAnalyticsQuery/gran-week", "requests", "", "week", "", 0, false, "", "")
	run("RunAnalyticsQuery/gran-month", "requests", "", "month", "", 0, false, "", "")
	run("RunAnalyticsQuery/tz-berlin", "requests", "model", "hour", "", 20, false, "Europe/Berlin", "")
	run("RunAnalyticsQuery/compare", "requests,cost_usd", "model", "day", "", 5, true, "", "")

	// top=1 over three seeded models must route the overflow through the
	// "(other)" bucket and flag truncation.
	contract(t, "RunAnalyticsQuery/top-truncated", func(ctx context.Context) error {
		q := analyticsContractQuery(t, fx.OrgA, from, to, "requests", "model", "", "", 1, false, "")
		res, err := store.RunAnalyticsQuery(ctx, q)
		if err != nil {
			return err
		}
		if !res.Truncated {
			t.Errorf("RunAnalyticsQuery/top-truncated: top=1 over multiple models must truncate, got %+v", res)
		}
		return nil
	})

	// team/agent UUIDs in the result rows must drive both display-name
	// lookups (organizations_teams and agent_keys).
	contract(t, "RunAnalyticsQuery/display-names", func(ctx context.Context) error {
		q := analyticsContractQuery(t, fx.OrgA, from, to, "requests", "team,agent", "", "", 20, false, "")
		res, err := store.RunAnalyticsQuery(ctx, q)
		if err != nil {
			return err
		}
		if res.DisplayNames["team"][fx.TeamA1] == "" {
			t.Errorf("RunAnalyticsQuery/display-names: team %s not resolved: %v", fx.TeamA1, res.DisplayNames)
		}
		if res.DisplayNames["agent"][fx.AgentKeyA] == "" {
			t.Errorf("RunAnalyticsQuery/display-names: agent %s not resolved: %v", fx.AgentKeyA, res.DisplayNames)
		}
		return nil
	})

	contract(t, "RunAnalyticsQuery/empty-window", func(ctx context.Context) error {
		// Additive metrics + calendar granularity with no filter route to the
		// rollup source even over an empty window — the empty rollup answer.
		q := analyticsContractQuery(t, fx.OrgA, emptyWindowFrom, emptyWindowFrom.Add(24*time.Hour),
			"requests,cost_usd", "", "day", "", 0, false, "")
		res, err := store.RunAnalyticsQuery(ctx, q)
		if err != nil {
			return err
		}
		if res.Source != "rollup" || len(res.Rows) != 0 || res.Totals["requests"] != float64(0) {
			t.Errorf("RunAnalyticsQuery/empty-window: got source=%s rows=%d totals=%v", res.Source, len(res.Rows), res.Totals)
		}
		return nil
	})

	// ListLabelKeys samples the newest rows' labels (jsonb_each_text over
	// request_logs): the extension row carries three distinct keys.
	contract(t, "ListLabelKeys/orgA", func(ctx context.Context) error {
		keys, err := store.ListLabelKeys(ctx, fx.OrgA, from, to)
		if err != nil {
			return err
		}
		if len(keys) < 3 {
			t.Errorf("ListLabelKeys/orgA: expected the seeded label keys, got %d (%v)", len(keys), keys)
		}
		return nil
	})
	contract(t, "ListLabelKeys/empty-org", func(ctx context.Context) error {
		keys, err := store.ListLabelKeys(ctx, "00000000-0000-0000-0000-0000000000bb", from, to)
		if err != nil {
			return err
		}
		if len(keys) != 0 {
			t.Errorf("ListLabelKeys/empty-org: expected no keys, got %d", len(keys))
		}
		return nil
	})
}

// TestSQLContractAnalytics_QueryRollup covers the rollup sources of
// RunAnalyticsQuery (analytics_rollup_hourly + label_rollup_hourly): every
// rollup metric, every rollup dimension, the two-dim and label-key paths,
// hour/day/week/month bucketing, compare=previous and the non-rollup metric
// that must fall back to raw.
func TestSQLContractAnalytics_QueryRollup(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)
	seedAnalyticsExtension(t, pool, fx)
	from, to := fx.From, fx.To

	run := func(name, metrics, groupBy, gran string, compare bool, wantSource string) {
		t.Helper()
		q := analyticsContractQuery(t, fx.OrgA, from, to, metrics, groupBy, gran, "", 20, compare, "")
		runAnalyticsContract(t, store, name, q, wantSource)
	}

	rollupMetrics := make([]string, 0, len(analyticsRollupMetrics))
	for name := range analyticsRollupMetrics {
		rollupMetrics = append(rollupMetrics, name)
	}
	sort.Strings(rollupMetrics)
	for _, m := range rollupMetrics {
		run("RunAnalyticsQuery/rollup-metric/"+m, m, "", "day", false, "rollup")
	}

	rollupDims := make([]string, 0, len(analyticsRollupDims))
	for name := range analyticsRollupDims {
		rollupDims = append(rollupDims, name)
	}
	sort.Strings(rollupDims)
	for _, d := range rollupDims {
		run("RunAnalyticsQuery/rollup-dim/"+d, "requests,cost_usd", d, "day", false, "rollup")
	}
	run("RunAnalyticsQuery/rollup-dims-two", "requests", "model,status_class", "hour", false, "rollup")
	run("RunAnalyticsQuery/rollup-label-key", "requests", "label:issue", "day", false, "rollup")
	run("RunAnalyticsQuery/rollup-label-key-empty", "requests", "label:env", "day", false, "rollup")
	run("RunAnalyticsQuery/rollup-gran-week", "requests", "", "week", false, "rollup")
	run("RunAnalyticsQuery/rollup-gran-month", "requests", "", "month", false, "rollup")
	run("RunAnalyticsQuery/rollup-compare", "requests,cost_usd", "model", "day", true, "rollup")
	// A non-rollup metric forces the raw source even with rollup-friendly
	// grouping and granularity.
	run("RunAnalyticsQuery/non-rollup-metric-is-raw", "latency_p50", "model", "day", false, "raw")
}

// yqlContractSpecs deduplicates the yqlFields registry into canonical field
// specs in a stable order.
func yqlContractSpecs() []*yqlFieldSpec {
	seen := map[string]bool{}
	specs := make([]*yqlFieldSpec, 0, len(yqlFields))
	for _, spec := range yqlFields {
		if !seen[spec.name] {
			seen[spec.name] = true
			specs = append(specs, spec)
		}
	}
	sort.Slice(specs, func(i, j int) bool { return specs[i].name < specs[j].name })
	return specs
}

// yqlContractFilter renders one filter clause for a field/op pair using a
// representative value per field kind.
func yqlContractFilter(spec *yqlFieldSpec, op string) string {
	one := map[yqlKind]string{
		yqlText: "imp03b-zzz", yqlNumber: "200", yqlTime: "-1d",
		yqlCache: "exact", yqlTool: "web_search", yqlBody: "imp03b",
	}[spec.kind]
	two := map[yqlKind]string{
		yqlText: "imp03b-zzz, imp03b-yyy", yqlNumber: "200, 500",
		yqlTime: "-2d, now", yqlCache: "exact, miss",
	}[spec.kind]
	if op == "in" || op == "not in" {
		return fmt.Sprintf("%s %s (%s)", spec.name, op, two)
	}
	return fmt.Sprintf("%s %s %s", spec.name, op, one)
}

// TestSQLContractAnalytics_QueryFilters drives every YQL filter operator of
// the allowlist through RunAnalyticsQuery (the filter forces the raw
// source): each field kind's scalar/list/regex operators, the nullable
// fields' is [not] empty, the label.<key> family, and the boolean
// and/or/not combinations with an order-by tail.
func TestSQLContractAnalytics_QueryFilters(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)
	seedAnalyticsExtension(t, pool, fx)
	from, to := fx.From, fx.To

	run := func(name, filter string) {
		t.Helper()
		q := analyticsContractQuery(t, fx.OrgA, from, to, "requests,cost_usd", "", "", filter, 20, false, "")
		runAnalyticsContract(t, store, name, q, "raw")
	}

	for _, spec := range yqlContractSpecs() {
		for op := range yqlOpsFor(spec.kind) {
			run("RunAnalyticsQuery/filter/"+spec.name+" "+op, yqlContractFilter(spec, op))
		}
		if spec.nullable {
			run("RunAnalyticsQuery/filter/"+spec.name+" is empty", spec.name+" is empty")
			run("RunAnalyticsQuery/filter/"+spec.name+" is not empty", spec.name+" is not empty")
		}
	}

	// The label.<key> family is compiled dynamically and never appears in the
	// static registry: cover every label operator plus a non-rollup key.
	labelFilters := []string{
		"label.env = prod",
		"label.env != prod",
		"label.env ~ pr",
		"label.env !~ zz",
		"label.env in (prod, dev)",
		"label.env not in (qa)",
		"label.env is empty",
		"label.env is not empty",
		"label.issue in (PAY-1, PAY-9)",
		"label.custom = v1",
	}
	for _, filter := range labelFilters {
		run("RunAnalyticsQuery/filter/"+filter, filter)
	}

	combined := []string{
		"status >= 200 and status < 300",
		"model ~ smart or model ~ fast",
		"not (status >= 400)",
		"(status = 200 or status = 500) and cost >= 0",
		"cache = exact and tokens >= 100",
		"tool ~ web and task = code-gen",
		"status = 200 order by cost desc",
	}
	for _, filter := range combined {
		run("RunAnalyticsQuery/filter/"+filter, filter)
	}
}

// TestSQLContractAnalytics_YQLOrderBy executes the production order-by
// expression (QueryOrder.sql) of every orderable allowlist field in both
// directions against the real stand. RunAnalyticsQuery ignores the YQL order
// tail by design (aggregates), and the end-to-end list ordering belongs to
// itself (column names, casts, NULLS LAST, tiebreakers). Ordering by labels
// is rejected at parse time and carries no SQL.
func TestSQLContractAnalytics_YQLOrderBy(t *testing.T) {
	pool := openAdminTestPool(t)
	fx := seedContractFixture(t, pool)
	seedAnalyticsExtension(t, pool, fx)

	for _, spec := range yqlContractSpecs() {
		if !spec.orderable {
			continue
		}
		for _, desc := range []bool{false, true} {
			dir := "asc"
			if desc {
				dir = "desc"
			}
			order := &QueryOrder{Field: spec.name, Desc: desc}
			contract(t, "YQLOrderBy/"+spec.name+"/"+dir, func(ctx context.Context) error {
				rows, err := pool.Query(ctx,
					`SELECT rl.request_id FROM request_logs rl WHERE rl.org_id = $1::uuid ORDER BY `+order.sql(),
					fx.OrgA)
				if err != nil {
					return err
				}
				return contractRows(rows, func(pgx.Rows) error { return nil })
			})
		}
	}
}

// TestSQLContractAnalytics_Views covers the analytics_views CRUD: create
// (private + shared, two owners), list scoping (own + org-shared, no
// cross-org leak), count, get/update/delete on existing and missing ids.
func TestSQLContractAnalytics_Views(t *testing.T) {
	pool := openAdminTestPool(t)
	store := New(pool, slog.Default(), nil)
	fx := seedContractFixture(t, pool)
	ctx := context.Background()

	ownerA, ownerB := fx.Token+"-owner-a", fx.Token+"-owner-b"
	created := map[string]AnalyticsView{}
	create := func(name, owner string, shared bool) {
		t.Helper()
		view := AnalyticsView{
			OrgID: fx.OrgA, OwnerID: owner, Name: fx.Token + "-" + name,
			Query: map[string]string{"metrics": "requests", "granularity": "day"}, Shared: shared,
		}
		contract(t, "CreateAnalyticsView/"+name, func(ctx context.Context) error {
			got, err := store.CreateAnalyticsView(ctx, view)
			if err != nil {
				return err
			}
			if got.ID == "" || got.Name != view.Name || got.Shared != shared {
				t.Errorf("CreateAnalyticsView/%s: stored %+v", name, got)
			}
			created[name] = got
			return nil
		})
	}
	create("private-a", ownerA, false)
	create("private-a2", ownerA, false)
	create("shared-a", ownerA, true)
	create("private-b", ownerB, false)
	require.Len(t, created, 4, "all four views must be created before the read contract")

	contract(t, "ListAnalyticsViews/owner-a", func(ctx context.Context) error {
		views, err := store.ListAnalyticsViews(ctx, fx.OrgA, ownerA)
		if err != nil {
			return err
		}
		if len(views) != 3 {
			t.Errorf("ListAnalyticsViews/owner-a: got %d views, want 2 own + 1 org-shared", len(views))
		}
		return nil
	})
	contract(t, "ListAnalyticsViews/owner-b", func(ctx context.Context) error {
		views, err := store.ListAnalyticsViews(ctx, fx.OrgA, ownerB)
		if err != nil {
			return err
		}
		if len(views) != 2 {
			t.Errorf("ListAnalyticsViews/owner-b: got %d views, want 1 own + 1 org-shared", len(views))
		}
		return nil
	})
	contract(t, "ListAnalyticsViews/org-scoped", func(ctx context.Context) error {
		views, err := store.ListAnalyticsViews(ctx, fx.OrgB, ownerA)
		if err != nil {
			return err
		}
		if len(views) != 0 {
			t.Errorf("ListAnalyticsViews/org-scoped: org B must not see org A views, got %d", len(views))
		}
		return nil
	})

	count := func(name, org, owner string, want int) {
		t.Helper()
		contract(t, "CountAnalyticsViews/"+name, func(ctx context.Context) error {
			n, err := store.CountAnalyticsViews(ctx, org, owner)
			if err != nil {
				return err
			}
			if n != want {
				t.Errorf("CountAnalyticsViews/%s: got %d, want %d", name, n, want)
			}
			return nil
		})
	}
	count("owner-a", fx.OrgA, ownerA, 3)
	count("owner-b", fx.OrgA, ownerB, 1)
	count("empty-org", "00000000-0000-0000-0000-0000000000bb", ownerA, 0)

	contract(t, "GetAnalyticsView/found", func(ctx context.Context) error {
		view, err := store.GetAnalyticsView(ctx, created["private-a"].ID)
		if err != nil {
			return err
		}
		if view.Query["metrics"] != "requests" {
			t.Errorf("GetAnalyticsView/found: query json not round-tripped: %+v", view.Query)
		}
		return nil
	})
	_, err := store.GetAnalyticsView(ctx, "00000000-0000-0000-0000-0000000000cc")
	require.ErrorIs(t, err, ErrNotFound, "GetAnalyticsView of a missing id must be ErrNotFound")

	contract(t, "UpdateAnalyticsView/found", func(ctx context.Context) error {
		view := created["private-a"]
		view.Name = fx.Token + "-renamed"
		view.Shared = true
		return store.UpdateAnalyticsView(ctx, view)
	})
	// The rename turned private-a shared: owner B now sees 3 org views.
	contract(t, "ListAnalyticsViews/after-share", func(ctx context.Context) error {
		views, err := store.ListAnalyticsViews(ctx, fx.OrgA, ownerB)
		if err != nil {
			return err
		}
		if len(views) != 3 {
			t.Errorf("ListAnalyticsViews/after-share: got %d views, want 1 own + 2 org-shared", len(views))
		}
		return nil
	})
	err = store.UpdateAnalyticsView(ctx, AnalyticsView{ID: "00000000-0000-0000-0000-0000000000cc"})
	require.ErrorIs(t, err, ErrNotFound, "UpdateAnalyticsView of a missing id must be ErrNotFound")

	contract(t, "DeleteAnalyticsView/found", func(ctx context.Context) error {
		return store.DeleteAnalyticsView(ctx, created["private-a2"].ID)
	})
	err = store.DeleteAnalyticsView(ctx, created["private-a2"].ID)
	require.ErrorIs(t, err, ErrNotFound, "DeleteAnalyticsView must be ErrNotFound on the second delete")
}
