package adminstore

import (
	"fmt"
	"strings"

	"github.com/reireirei/yabanin/pkg/labels"
)

// Metric and dimension SQL for the raw request_logs source (A2 §9).
// Every aggregate is float8 so a zero-row ratio stays NULL and pgx scans
// one type. Keys and values are never interpolated.

const analyticsTimeExpr = "date_trunc($4::text, rl.created_at AT TIME ZONE $5::text) AT TIME ZONE $5::text"

type analyticsMetric struct {
	sql  string
	unit string
}

var analyticsMetrics = map[string]analyticsMetric{
	"requests":           {sql: "COUNT(*)::float8", unit: "count"},
	"tokens_in":          {sql: "COALESCE(SUM(rl.tokens_in),0)::float8", unit: "tokens"},
	"tokens_out":         {sql: "COALESCE(SUM(rl.tokens_out),0)::float8", unit: "tokens"},
	"cache_read_tokens":  {sql: "COALESCE(SUM(COALESCE(rl.cache_read_tokens,0)),0)::float8", unit: "tokens"},
	"cost_usd":           {sql: "COALESCE(SUM(rl.cost_in_usd) FILTER (WHERE rl.cost_status IN ('priced','cache_hit','legacy')),0)::float8", unit: "usd"},
	"unpriced_requests":  {sql: "COUNT(*) FILTER (WHERE rl.cost_status IN ('unknown_price','no_usage'))::float8", unit: "count"},
	"errors":             {sql: "COUNT(*) FILTER (WHERE rl.status_code >= 400)::float8", unit: "count"},
	"retried_requests":   {sql: "COUNT(*) FILTER (WHERE COALESCE(rl.retry_count,0) > 0)::float8", unit: "count"},
	"fallback_requests":  {sql: "COUNT(*) FILTER (WHERE COALESCE(rl.attempt_count,1) > 1)::float8", unit: "count"},
	"error_rate":         {sql: "(COUNT(*) FILTER (WHERE rl.status_code >= 400))::float8 / NULLIF(COUNT(*),0)", unit: "ratio"},
	"cache_hit_rate":     {sql: "(COUNT(*) FILTER (WHERE rl.cache_hit_type IN ('exact','semantic')))::float8 / NULLIF(COUNT(*),0)", unit: "ratio"},
	"prompt_cache_ratio": {sql: "SUM(COALESCE(rl.cache_read_tokens,0))::float8 / NULLIF(SUM(rl.tokens_in),0)", unit: "ratio"},
	"cost_per_request":   {sql: "(SUM(rl.cost_in_usd) FILTER (WHERE rl.cost_status IN ('priced','cache_hit','legacy')))::float8 / NULLIF(COUNT(*),0)", unit: "usd"},
	"latency_p50":        {sql: "(percentile_cont(0.5) WITHIN GROUP (ORDER BY rl.duration_ms))::float8", unit: "ms"},
	"latency_p95":        {sql: "(percentile_cont(0.95) WITHIN GROUP (ORDER BY rl.duration_ms))::float8", unit: "ms"},
	"ttft_p50":           {sql: "(percentile_cont(0.5) WITHIN GROUP (ORDER BY rl.first_token_ms))::float8", unit: "ms"},
	"ttft_p95":           {sql: "(percentile_cont(0.95) WITHIN GROUP (ORDER BY rl.first_token_ms))::float8", unit: "ms"},
	"sessions":           {sql: "COUNT(DISTINCT rl.session_id)::float8", unit: "count"},
}

var analyticsDimExpr = map[string]string{
	"model":           "COALESCE(NULLIF(rl.model_used, ''), '(none)')",
	"model_requested": "COALESCE(NULLIF(rl.model_requested, ''), '(none)')",
	"endpoint":        "COALESCE(NULLIF(rl.endpoint, ''), '(none)')",
	"team":            "COALESCE(rl.team_id::text, '(none)')",
	"agent":           "COALESCE(rl.agent_id::text, '(none)')",
	"task":            "COALESCE(NULLIF(rl.task_id, ''), '(untagged)')",
	"status_class":    "CASE WHEN rl.status_code < 300 THEN '2xx' WHEN rl.status_code < 400 THEN '3xx' WHEN rl.status_code = 429 THEN '429' WHEN rl.status_code < 500 THEN '4xx' ELSE '5xx' END",
	"cache":           "COALESCE(NULLIF(rl.cache_hit_type, ''), 'miss')",
}

// analyticsBuilt is the three statements of one analytics read.
// MainArgs does not yet include the top-key array; the executor appends it
// when GroupBy is set. TotalsArgs is the WHERE argument list.
type analyticsBuilt struct {
	TopSQL     string
	TopArgs    []any
	MainSQL    string
	MainArgs   []any
	TotalsSQL  string
	TotalsArgs []any
	HasTime    bool
	DimExprs   []string
	Metrics    []string
}

func analyticsWhere(filter *RequestQuery, args []any) (string, []any) {
	where := "rl.org_id = $1::uuid AND rl.created_at >= $2 AND rl.created_at < $3 AND COALESCE(rl.ab_group, '') <> 'shadow' AND $4::text IS NOT NULL AND $5::text IS NOT NULL"
	if filter == nil {
		return where, args
	}
	frag, args := filter.whereSQL(args)
	if frag != "" {
		where += " AND " + frag
	}
	return where, args
}

func analyticsDim(name string, args []any) (string, []any, bool) {
	if expr, ok := analyticsDimExpr[name]; ok {
		return expr, args, true
	}
	const prefix = "label:"
	if !strings.HasPrefix(name, prefix) {
		return "", args, false
	}
	key := name[len(prefix):]
	args = append(args, key)
	expr := fmt.Sprintf("COALESCE(rl.labels ->> $%d::text, '(none)')", len(args))
	return expr, args, true
}

func buildAnalyticsSQL(q *AnalyticsQuery) (analyticsBuilt, error) {
	if analyticsSource(q) != "raw" {
		return buildRollupSQL(q)
	}
	args := []any{q.OrgID, q.From, q.To, q.Granularity, q.TZ.String()}
	dims := make([]string, len(q.GroupBy))
	for i, name := range q.GroupBy {
		expr, next, ok := analyticsDim(name, args)
		if !ok {
			return analyticsBuilt{}, fmt.Errorf("unknown dimension %q", name)
		}
		dims[i] = expr
		args = next
	}
	where, args := analyticsWhere(q.Filter, args)
	for i := 6; i <= len(args); i++ {
		if !usesPlaceholder(where, i) {
			where += fmt.Sprintf(" AND $%d::text IS NOT NULL", i)
		}
	}
	metrics := make([]string, len(q.Metrics))
	for i, name := range q.Metrics {
		m, ok := analyticsMetrics[name]
		if !ok {
			return analyticsBuilt{}, fmt.Errorf("unknown metric %q", name)
		}
		metrics[i] = m.sql
	}
	hasTime := q.Granularity != "" && q.Granularity != "none"
	out := analyticsBuilt{
		TotalsSQL:  "SELECT " + strings.Join(metrics, ", ") + ", count(*) FILTER (WHERE rl.cost_status IN ('unknown_price','no_usage')), count(*) FILTER (WHERE rl.cost_status = 'legacy'), count(*) FROM request_logs rl WHERE " + where,
		TotalsArgs: append([]any{}, args...),
		HasTime:    hasTime,
		DimExprs:   dims,
		Metrics:    metrics,
	}
	if len(dims) > 0 {
		group := concatWS(dims)
		out.TopSQL = "SELECT " + group + " AS g FROM request_logs rl WHERE " + where +
			" GROUP BY 1 ORDER BY " + metrics[0] + " DESC NULLS LAST, 1 LIMIT " + fmt.Sprint(q.Top)
		out.TopArgs = append([]any{}, args...)
		ph := fmt.Sprintf("$%d::text[]", len(args)+1)
		selects := make([]string, 0, 1+len(dims)+len(metrics))
		if hasTime {
			selects = append(selects, analyticsTimeExpr+" AS t")
		}
		for _, d := range dims {
			selects = append(selects, "CASE WHEN "+group+" = ANY("+ph+") THEN "+d+" ELSE '(other)' END")
		}
		selects = append(selects, metrics...)
		groupBy := make([]string, 0, 1+len(dims))
		for i := 1; i <= len(dims)+boolToInt(hasTime); i++ {
			groupBy = append(groupBy, fmt.Sprint(i))
		}
		order := "1"
		if hasTime || len(dims) > 0 {
			order = "1, " + metrics[0] + " DESC"
		}
		out.MainSQL = "SELECT " + strings.Join(selects, ", ") + " FROM request_logs rl WHERE " + where +
			" GROUP BY " + strings.Join(groupBy, ", ") + " ORDER BY " + order
		out.MainArgs = append([]any{}, args...)
		return out, nil
	}
	selects := make([]string, 0, 1+len(metrics))
	if hasTime {
		selects = append(selects, analyticsTimeExpr+" AS t")
	}
	selects = append(selects, metrics...)
	out.MainSQL = "SELECT " + strings.Join(selects, ", ") + " FROM request_logs rl WHERE " + where
	if hasTime {
		out.MainSQL += " GROUP BY 1 ORDER BY 1"
	}
	out.MainArgs = append([]any{}, args...)
	return out, nil
}

func usesPlaceholder(sql string, n int) bool {
	token := fmt.Sprintf("$%d", n)
	rest := sql
	for {
		i := strings.Index(rest, token)
		if i < 0 {
			return false
		}
		end := i + len(token)
		if end >= len(rest) || rest[end] < '0' || rest[end] > '9' {
			return true
		}
		rest = rest[end:]
	}
}

func concatWS(dims []string) string {
	return `concat_ws(E'\x1f', ` + strings.Join(dims, ", ") + ")"
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

const labelKeysSQL = `SELECT k, count(*), count(DISTINCT v) FROM (
  SELECT key AS k, value AS v FROM (
    SELECT labels FROM request_logs rl
    WHERE rl.org_id = $1::uuid AND rl.created_at >= $2 AND rl.created_at < $3
      AND COALESCE(rl.ab_group, '') <> 'shadow'
    ORDER BY rl.created_at DESC LIMIT 100000
  ) s, jsonb_each_text(s.labels)
) x GROUP BY k ORDER BY 2 DESC LIMIT 200`

const rollupTimeExpr = "date_trunc($4::text, ru.hour AT TIME ZONE $5::text) AT TIME ZONE $5::text"

var analyticsRollupMetrics = map[string]string{ //nolint:gosec // metric SQL; "token" names a usage column, not a credential
	"requests":           "COALESCE(SUM(ru.requests),0)::float8",
	"tokens_in":          "COALESCE(SUM(ru.tokens_in),0)::float8",
	"tokens_out":         "COALESCE(SUM(ru.tokens_out),0)::float8",
	"cache_read_tokens":  "COALESCE(SUM(ru.cache_read_tokens),0)::float8",
	"cost_usd":           "COALESCE(SUM(ru.cost_usd),0)::float8",
	"unpriced_requests":  "COALESCE(SUM(ru.unpriced_requests),0)::float8",
	"errors":             "COALESCE(SUM(ru.errors),0)::float8",
	"retried_requests":   "COALESCE(SUM(ru.retried_requests),0)::float8",
	"fallback_requests":  "COALESCE(SUM(ru.fallback_requests),0)::float8",
	"error_rate":         "SUM(ru.errors)::float8 / NULLIF(SUM(ru.requests),0)",
	"cache_hit_rate":     "SUM(ru.cache_hits)::float8 / NULLIF(SUM(ru.requests),0)",
	"prompt_cache_ratio": "SUM(ru.cache_read_tokens)::float8 / NULLIF(SUM(ru.tokens_in),0)",
	"cost_per_request":   "SUM(ru.cost_usd)::float8 / NULLIF(SUM(ru.requests),0)",
}

var analyticsRollupDims = map[string]string{
	"model":        "COALESCE(NULLIF(ru.model_used, ''), '(none)')",
	"endpoint":     "COALESCE(NULLIF(ru.endpoint, ''), '(none)')",
	"team":         "CASE WHEN ru.team_id = '00000000-0000-0000-0000-000000000000'::uuid THEN '(none)' ELSE ru.team_id::text END",
	"agent":        "CASE WHEN ru.agent_id = '00000000-0000-0000-0000-000000000000'::uuid THEN '(none)' ELSE ru.agent_id::text END",
	"status_class": "ru.status_class",
	"cache":        "ru.cache_type",
}

func analyticsPublicSource(q *AnalyticsQuery) string {
	if analyticsSource(q) == "raw" {
		return "raw"
	}
	return "rollup"
}

// analyticsSource reports raw, hourly, or label. Rollups apply only when the
// filter is empty, every metric is additive or derived from additive columns,
// granularity is a calendar bucket, and the dimensions fit one rollup table.
func analyticsSource(q *AnalyticsQuery) string {
	if q == nil || q.FilterText != "" || (q.Filter != nil && q.FilterText != "") {
		return "raw"
	}
	switch q.Granularity {
	case "hour", "day", "week", "month":
	default:
		return "raw"
	}
	if len(q.Metrics) == 0 {
		return "raw"
	}
	for _, m := range q.Metrics {
		if _, ok := analyticsRollupMetrics[m]; !ok {
			return "raw"
		}
	}
	if len(q.GroupBy) == 1 && strings.HasPrefix(q.GroupBy[0], "label:") {
		if rollupKeyAllowed(q.GroupBy[0][len("label:"):]) {
			return "label"
		}
		return "raw"
	}
	for _, d := range q.GroupBy {
		if _, ok := analyticsRollupDims[d]; !ok {
			return "raw"
		}
	}
	return "hourly"
}

func rollupKeyAllowed(key string) bool {
	for _, k := range defaultRollupKeys() {
		if k == key {
			return true
		}
	}
	return false
}

func defaultRollupKeys() []string {
	return labels.DefaultPolicy().RollupKeys
}

func buildRollupSQL(q *AnalyticsQuery) (analyticsBuilt, error) {
	kind := analyticsSource(q)
	args := []any{q.OrgID, q.From, q.To, q.Granularity, q.TZ.String()}
	from := "analytics_rollup_hourly ru"
	where := "ru.org_id = $1::uuid AND ru.hour >= $2 AND ru.hour < $3 AND $4::text IS NOT NULL AND $5::text IS NOT NULL"
	dims := make([]string, len(q.GroupBy))
	if kind == "label" {
		from = "label_rollup_hourly ru"
		key := q.GroupBy[0][len("label:"):]
		args = append(args, key)
		where += fmt.Sprintf(" AND ru.key = $%d::text", len(args))
		dims[0] = "COALESCE(NULLIF(ru.value, ''), '(none)')"
	} else {
		for i, name := range q.GroupBy {
			expr, ok := analyticsRollupDims[name]
			if !ok {
				return analyticsBuilt{}, fmt.Errorf("unknown rollup dimension %q", name)
			}
			dims[i] = expr
		}
	}
	metrics := make([]string, len(q.Metrics))
	for i, name := range q.Metrics {
		sql, ok := analyticsRollupMetrics[name]
		if !ok {
			return analyticsBuilt{}, fmt.Errorf("unknown rollup metric %q", name)
		}
		metrics[i] = sql
	}
	coverage := "COALESCE(SUM(ru.unpriced_requests),0), COALESCE(SUM(ru.legacy_rows),0), COALESCE(SUM(ru.requests),0)"
	out := analyticsBuilt{
		TotalsSQL:  "SELECT " + strings.Join(metrics, ", ") + ", " + coverage + " FROM " + from + " WHERE " + where,
		TotalsArgs: append([]any{}, args...),
		HasTime:    true,
		DimExprs:   dims,
		Metrics:    metrics,
	}
	if len(dims) > 0 {
		group := concatWS(dims)
		out.TopSQL = "SELECT " + group + " AS g FROM " + from + " WHERE " + where +
			" GROUP BY 1 ORDER BY " + metrics[0] + " DESC NULLS LAST, 1 LIMIT " + fmt.Sprint(q.Top)
		out.TopArgs = append([]any{}, args...)
		ph := fmt.Sprintf("$%d::text[]", len(args)+1)
		selects := []string{rollupTimeExpr + " AS t"}
		for _, d := range dims {
			selects = append(selects, "CASE WHEN "+group+" = ANY("+ph+") THEN "+d+" ELSE '(other)' END")
		}
		selects = append(selects, metrics...)
		groupBy := make([]string, 0, 1+len(dims))
		for i := 1; i <= 1+len(dims); i++ {
			groupBy = append(groupBy, fmt.Sprint(i))
		}
		out.MainSQL = "SELECT " + strings.Join(selects, ", ") + " FROM " + from + " WHERE " + where +
			" GROUP BY " + strings.Join(groupBy, ", ") + " ORDER BY 1, " + metrics[0] + " DESC"
		out.MainArgs = append([]any{}, args...)
		return out, nil
	}
	out.MainSQL = "SELECT " + rollupTimeExpr + " AS t, " + strings.Join(metrics, ", ") + " FROM " + from + " WHERE " + where + " GROUP BY 1 ORDER BY 1"
	out.MainArgs = append([]any{}, args...)
	return out, nil
}
