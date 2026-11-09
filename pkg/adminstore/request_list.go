package adminstore

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// RequestListFilters narrows the request-log list query. All fields optional
// except OrgID; a zero filter returns the newest rows for the org.
// The numeric ranges mirror the Bifrost log explorer (min/max latency,
// tokens, cost) so the dashboard offers the same slicing power.
type RequestListFilters struct {
	OrgID string
	// PayloadUserID scopes payload search to human-owned rows unless
	// PayloadGrant is an explicit request-scoped permission.
	PayloadUserID           string
	PayloadGrant            bool
	PayloadDenied           bool
	OwnerUserID             string
	OrgWideMetadata         bool
	PayloadSearchAllowed    bool
	PayloadAuthorizationSet bool
	Model                   string
	From                    time.Time
	To                      time.Time
	MinStatus               int
	ErrorOnly               bool
	TaskID                  string
	AgentID                 string
	// DelegateAgentID is the trusted attribution scope for a subject acting
	// under a principal delegation (N04-P05 T03): rows are pinned to
	// agent_id = DelegateAgentID. It is set ONLY from the authenticated
	// subject, never from a query parameter — the ?agent_id filter above stays
	// client-controlled and cannot widen the delegation.
	DelegateAgentID string
	// DelegatePayload marks that the delegation also carries the payload
	// scope for those own-attributed rows.
	DelegatePayload bool
	// RequestID is an exact primary-key-style lookup (Bifrost `request_id`
	// filter): when set it collapses the list to that one request.
	RequestID string
	// RuleID narrows to rows whose stored routing_decision names this
	// routing rule (CORE-TRACE-04 rule→requests lookup). The stored column
	// is legacy TEXT: the probe is guarded so a malformed historical value
	// can never fail the cast. Scoped by the org term like every other
	// filter here.
	RuleID string
	// Numeric ranges; zero means unbounded.
	MinLatencyMs int64
	MaxLatencyMs int64
	MinTokens    int64
	MaxTokens    int64
	MinCostUSD   float64
	MaxCostUSD   float64
	// CacheHit filters by cache_hit_type: "exact", "semantic", or "miss".
	CacheHit string
	// ContentSearch does a case-insensitive substring match over the stored
	// error text and the (already PH.1-redacted/truncated) upstream request
	// and response snapshots. It never reads data that the detail view would
	// hide behind privacy mode.
	ContentSearch string
	// Query is a parsed YQL expression (ParseYQL). It is AND-combined with
	// the flat filters above and can also carry an ORDER BY (list only).
	Query *RequestQuery
	Page  int
	// PageSize bounds the page (1..200, default 50).
	PageSize int
}

// RequestListRow is one request_logs row as returned to the request explorer.
type RequestListRow struct {
	RequestID      string  `json:"request_id"`
	OrgID          string  `json:"org_id"`
	ModelRequested string  `json:"model_requested,omitempty"`
	ModelUsed      string  `json:"model_used"`
	StatusCode     int     `json:"status_code"`
	CostUSD        float64 `json:"cost_usd"`
	TokensIn       int64   `json:"tokens_in"`
	TokensOut      int64   `json:"tokens_out"`
	TaskID         string  `json:"task_id,omitempty"`
	SessionID      string  `json:"session_id,omitempty"`
	DurationMs     int64   `json:"duration_ms"`
	CacheHitType   string  `json:"cache_hit_type,omitempty"`
	// Observability parity (Bifrost attempt trail): nil = unknown (legacy
	// row or non-streaming), so aggregates never confuse "no data" with 0.
	FirstTokenMs *int64    `json:"first_token_ms,omitempty"`
	AttemptCount *int64    `json:"attempt_count,omitempty"`
	RetryCount   *int64    `json:"retry_count,omitempty"`
	ErrorMsg     string    `json:"error,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	// Distinct tool/function names recorded for THIS request (loggerd,
	// pre-truncation; org-scoped — same guarantee as the detail view).
	// nil/empty = none recorded (plain chat or legacy row); the inspector
	// remains the source for ids and arguments. The list needs names only.
	ToolCalls []string `json:"tool_calls,omitempty"`
	// Labels is the attribution object stored on the row. Empty is omitted.
	Labels       map[string]string `json:"labels,omitempty"`
	PayloadOwned bool              `json:"-"`
}

// RequestListStats is the aggregate block computed over the same filter set
// as the list (Bifrost returns an equivalent stats object with every log
// query: total, success rate, average latency, tokens, cost). P95 latency is
// our addition — agent-loop traffic is long-tailed, and the average alone
// hides upstream stalls.
type RequestListStats struct {
	TotalRequests  int64   `json:"total_requests"`
	SuccessRate    float64 `json:"success_rate"`
	AvgLatencyMs   float64 `json:"average_latency_ms"`
	P95LatencyMs   float64 `json:"p95_latency_ms"`
	TotalTokensIn  int64   `json:"total_tokens_in"`
	TotalTokensOut int64   `json:"total_tokens_out"`
	TotalCostUSD   float64 `json:"total_cost_usd"`
}

// requestListWhere builds the shared WHERE clause + args for the list, count,
// and stats queries so all three always agree on the filter semantics.
func requestListWhere(f RequestListFilters) (string, []interface{}) {
	where := []string{"org_id = $1", "COALESCE(ab_group, '') <> 'shadow'"}
	args := []interface{}{f.OrgID}
	add := func(cond string, val interface{}) {
		args = append(args, val)
		where = append(where, fmt.Sprintf(cond, len(args)))
	}
	if f.DelegateAgentID != "" {
		// Delegated subject (N04-P05 T03): the trusted attribution scope.
		// Applied before the deny branch so a deny still yields nothing.
		add("agent_id::text = $%d", f.DelegateAgentID)
	}
	if f.PayloadDenied && f.PayloadUserID != "" {
		// Deny-own-history removes a person's rows before list/count/stats,
		// avoiding both direct reads and aggregate side channels.
		add("(user_id::text <> $%d OR agent_id IS NOT NULL OR api_key_id IS NOT NULL OR user_id IS NULL)", f.PayloadUserID)
	} else if f.PayloadDenied {
		where = append(where, "FALSE")
	}
	if !f.OrgWideMetadata && f.OwnerUserID != "" {
		add("(user_id::text = $%d AND agent_id IS NULL AND api_key_id IS NULL)", f.OwnerUserID)
	}
	if f.RequestID != "" {
		add("request_id = $%d", f.RequestID)
	}
	if f.RuleID != "" {
		// pg_input_is_valid + CASE guard the legacy TEXT column (PG16 core,
		// non-raising): rows holding NULL, empty or malformed decision
		// payloads evaluate to false instead of failing the cast — the list
		// can never 500 on historical data.
		add("CASE WHEN routing_decision IS NOT NULL AND pg_input_is_valid(routing_decision, 'jsonb') "+
			"THEN routing_decision::jsonb->'rule'->>'id' = $%d ELSE false END", f.RuleID)
	}
	if f.Model != "" {
		add("model_used = $%d", f.Model)
	}
	if !f.From.IsZero() {
		add("created_at >= $%d::timestamptz", f.From)
	}
	if !f.To.IsZero() {
		add("created_at <= $%d::timestamptz", f.To)
	}
	if f.ErrorOnly {
		where = append(where, "status_code >= 400")
	} else if f.MinStatus > 0 {
		add("status_code >= $%d", f.MinStatus)
	}
	if f.TaskID != "" {
		add("task_id = $%d", f.TaskID)
	}
	if f.AgentID != "" {
		// Compare ::text like the YQL `agent` field: an invalid uuid value can
		// never surface as a 500 from a failed cast, it just matches nothing.
		add("agent_id::text = $%d", f.AgentID)
	}
	if f.MinLatencyMs > 0 {
		add("COALESCE(duration_ms, 0) >= $%d", f.MinLatencyMs)
	}
	if f.MaxLatencyMs > 0 {
		add("COALESCE(duration_ms, 0) <= $%d", f.MaxLatencyMs)
	}
	if f.MinTokens > 0 {
		add("(COALESCE(tokens_in, 0) + COALESCE(tokens_out, 0)) >= $%d", f.MinTokens)
	}
	if f.MaxTokens > 0 {
		add("(COALESCE(tokens_in, 0) + COALESCE(tokens_out, 0)) <= $%d", f.MaxTokens)
	}
	if f.MinCostUSD > 0 {
		add("COALESCE(cost_in_usd, 0) >= $%d", f.MinCostUSD)
	}
	if f.MaxCostUSD > 0 {
		add("COALESCE(cost_in_usd, 0) <= $%d", f.MaxCostUSD)
	}
	switch f.CacheHit {
	case "exact", "semantic":
		add("cache_hit_type = $%d", f.CacheHit)
	case "miss":
		where = append(where, "COALESCE(cache_hit_type, '') = ''")
	}
	if f.ContentSearch != "" {
		if f.PayloadAuthorizationSet && (!f.PayloadSearchAllowed || f.PayloadDenied) {
			where = append(where, "FALSE")
		} else if scope := payloadContentScope(f, len(args)+1); scope != "" {
			if f.DelegateAgentID != "" {
				args = append(args, f.DelegateAgentID)
			} else {
				args = append(args, f.PayloadUserID)
			}
			where = append(where, scope)
		}
		pat := "%" + f.ContentSearch + "%"
		args = append(args, pat)
		n := len(args)
		where = append(where, fmt.Sprintf(
			"(COALESCE(error, '') ILIKE $%d OR COALESCE(upstream_request::text, '') ILIKE $%d OR COALESCE(response::text, '') ILIKE $%d)",
			n, n, n))
	}
	if f.Query != nil {
		if f.Query.hasBodySearch() {
			if f.PayloadAuthorizationSet && (!f.PayloadSearchAllowed || f.PayloadDenied) {
				where = append(where, "FALSE")
			} else if scope := payloadContentScope(f, len(args)+1); scope != "" {
				if f.DelegateAgentID != "" {
					args = append(args, f.DelegateAgentID)
				} else {
					args = append(args, f.PayloadUserID)
				}
				// Scope the entire boolean expression; local scoping can be
				// escaped by NOT/OR in a YQL query.
				where = append(where, scope)
			}
		}
		// ParseYQL validated and dry-ran the tree, so compilation here is
		// total; placeholders continue the numbering of the flat filters.
		// An order-only query contributes no fragment.
		frag, fragArgs := f.Query.whereSQL(args)
		if frag != "" {
			where = append(where, frag)
		}
		args = fragArgs
	}
	return strings.Join(where, " AND "), args
}

// payloadContentScope returns the common authorization predicate for q and
// YQL `text` content search. A grant is never used for list-wide searches.
// A delegated subject searches only its own attributed rows.
func payloadContentScope(f RequestListFilters, placeholder int) string {
	if f.DelegateAgentID != "" {
		return fmt.Sprintf("rl.agent_id::text = $%d", placeholder)
	}
	if f.PayloadUserID == "" {
		return ""
	}
	return fmt.Sprintf("(rl.user_id::text = $%d AND rl.agent_id IS NULL AND rl.api_key_id IS NULL)", placeholder)
}

// RequestQueryRunner is the exported read surface for list/count helpers that
// run on either the pool or a snapshot transaction: it is satisfied by pgx.Tx
// and by the pool adapter, so callers can pin one consistent snapshot the same
// way StreamRequestExport does.
type RequestQueryRunner = exportQueryRunner

// RequestListWhere exposes the shared list predicate so history-operation
// previews and plans can count with the exact filter semantics the explorer
// shows — one predicate, never a drifting second builder.
func RequestListWhere(f RequestListFilters) (string, []interface{}) {
	return requestListWhere(f)
}

// CountRequests counts request_logs rows matching the exact list predicate —
// the counting half shared by exports and history-operation previews, so a
// cleanup preview and the list the operator saw can never disagree on scope.
func CountRequests(ctx context.Context, ex RequestQueryRunner, f RequestListFilters) (int64, error) {
	w, args := requestListWhere(f)
	var n int64
	if err := ex.QueryRow(ctx, "SELECT COUNT(*) FROM request_logs rl WHERE "+w, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("request count: %w", err)
	}
	return n, nil
}

// ListRequests returns a page of request_logs rows for an org with
// server-side filters and a total count (honest pagination for the request
// explorer). Shadow mirror rows are excluded.
func (s *Store) ListRequests(ctx context.Context, f RequestListFilters) ([]RequestListRow, int, error) {
	if s.db == nil {
		return nil, 0, fmt.Errorf("database not available")
	}
	return listRequestsOn(ctx, s.db, f)
}

// listRequestsOn runs one request list page on the given executor — the pool
// or an export snapshot transaction — so the export walk reads its pages and
// the count from one consistent snapshot.
func listRequestsOn(ctx context.Context, ex exportQueryRunner, f RequestListFilters) ([]RequestListRow, int, error) {
	if f.Page < 1 {
		f.Page = 1
	}
	if f.PageSize < 1 || f.PageSize > 200 {
		f.PageSize = 50
	}

	w, args := requestListWhere(f)

	// The rl alias lets YQL fragments (EXISTS over tool_calls) reference the
	// outer request_logs row unambiguously; the same alias is used here, in
	// the list query and in RequestStats so the shared WHERE always applies.
	var total int
	if err := ex.QueryRow(ctx, "SELECT COUNT(*) FROM request_logs rl WHERE "+w, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("request list count: %w", err)
	}

	// Deterministic ordering: YQL's ORDER BY when present (parse-validated
	// against the field whitelist), newest-first otherwise, always with the
	// request_id tiebreak so equal keys page stably.
	orderSQL := "rl.created_at DESC, rl.request_id"
	if f.Query != nil && f.Query.Order != nil {
		orderSQL = f.Query.Order.sql()
	}

	// The tool_calls column is an org-scoped correlated subquery, not a
	// join: rows of a foreign org that merely shadow the same request_id
	// can never leak names into this org's list (mirror of the detail
	// view's org scoping, and its regression test).
	q := "SELECT COALESCE(rl.request_id, ''), COALESCE(rl.org_id::text, ''), COALESCE(rl.model_requested, ''), " +
		"COALESCE(rl.model_used, ''), rl.status_code, COALESCE(rl.cost_in_usd, 0), COALESCE(rl.tokens_in, 0), COALESCE(rl.tokens_out, 0), " +
		"COALESCE(rl.task_id, ''), COALESCE(rl.session_id::text, ''), COALESCE(rl.duration_ms, 0), COALESCE(rl.cache_hit_type, ''), " +
		"rl.first_token_ms, rl.attempt_count, rl.retry_count, COALESCE(rl.error, ''), rl.created_at, " +
		"COALESCE((SELECT array_agg(DISTINCT tc.tool_name ORDER BY tc.tool_name) FROM tool_calls tc " +
		"WHERE tc.request_id = rl.request_id AND tc.org_id = rl.org_id), '{}'), COALESCE(rl.labels, '{}'::jsonb), COALESCE(rl.user_id::text, '') " +
		", (rl.agent_id IS NULL AND rl.api_key_id IS NULL), COALESCE(rl.agent_id::text, '') " +
		"FROM request_logs rl WHERE " + w + " ORDER BY " + orderSQL + " LIMIT $" + fmt.Sprint(len(args)+1) +
		" OFFSET $" + fmt.Sprint(len(args)+2)
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)

	rows, err := ex.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("request list query: %w", err)
	}
	defer rows.Close()
	var out []RequestListRow
	for rows.Next() {
		var r RequestListRow
		var labelsRaw []byte
		var ownerID string
		var humanRequest bool
		var agentID string
		if err := rows.Scan(&r.RequestID, &r.OrgID, &r.ModelRequested, &r.ModelUsed, &r.StatusCode, &r.CostUSD,
			&r.TokensIn, &r.TokensOut, &r.TaskID, &r.SessionID, &r.DurationMs, &r.CacheHitType,
			&r.FirstTokenMs, &r.AttemptCount, &r.RetryCount, &r.ErrorMsg, &r.CreatedAt, &r.ToolCalls, &labelsRaw, &ownerID, &humanRequest, &agentID); err != nil {
			return nil, 0, fmt.Errorf("request list scan: %w", err)
		}
		r.Labels = decodeLabels(labelsRaw)
		// Payload visibility per row: a human's own rows, or — under a live
		// delegation carrying the payload scope — the delegated subject's own
		// attributed rows. A deny never marks rows as owned.
		r.PayloadOwned = !f.PayloadDenied &&
			((humanRequest && f.PayloadUserID != "" && ownerID == f.PayloadUserID) ||
				(f.DelegateAgentID != "" && f.DelegatePayload && agentID == f.DelegateAgentID))
		out = append(out, r)
	}
	return out, total, rows.Err()
}

func decodeLabels(raw []byte) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	var out map[string]string
	if err := json.Unmarshal(raw, &out); err != nil || len(out) == 0 {
		return nil
	}
	return out
}

// RequestStats computes the aggregate block over the same filters as
// ListRequests (minus pagination): totals, success rate, latency percentiles,
// token and cost sums. Success = HTTP < 400; duration zero (cache hits,
// rejects) is excluded from the latency averages but kept in the totals.
func (s *Store) RequestStats(ctx context.Context, f RequestListFilters) (*RequestListStats, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	w, args := requestListWhere(f)
	// rl alias: matches ListRequests so YQL EXISTS fragments resolve the
	// outer row the same way here (see ListRequests).
	q := `SELECT COUNT(*),
       COALESCE(COUNT(*) FILTER (WHERE status_code < 400), 0),
       COALESCE(AVG(duration_ms) FILTER (WHERE COALESCE(duration_ms, 0) > 0), 0),
       COALESCE(percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms) FILTER (WHERE COALESCE(duration_ms, 0) > 0), 0),
       COALESCE(SUM(tokens_in), 0), COALESCE(SUM(tokens_out), 0),
       COALESCE(SUM(cost_in_usd), 0)
       FROM request_logs rl WHERE ` + w
	var st RequestListStats
	var success int64
	if err := s.db.QueryRow(ctx, q, args...).Scan(&st.TotalRequests, &success, &st.AvgLatencyMs,
		&st.P95LatencyMs, &st.TotalTokensIn, &st.TotalTokensOut, &st.TotalCostUSD); err != nil {
		return nil, fmt.Errorf("request stats query: %w", err)
	}
	if st.TotalRequests > 0 {
		st.SuccessRate = float64(success) / float64(st.TotalRequests)
	}
	return &st, nil
}
