package adminstore

// OP-9 (OUTPLAY-PLAN-2026-10-06 §3): read side of the policy decision log —
// the admin-plane list over the policy_decisions table the loggerd consumer
// writes (writer: services/loggerd/consumer, event `policy` field contract
// OP-8). Read-only by design: decisions are an immutable audit log, the only
// mutation is the consumer INSERT and the 90d retention purge.
//
// RLS contract (orgcredentials.go / policystore.go parity): every operation
// runs inside withPolicyTx — one transaction with the app.current_org GUC
// pinned to the org, the org_isolation contract of the policy_decisions RLS
// policy (migration 0009, ENABLE+FORCE). Without the GUC the FORCE policy
// denies every row (fail-closed); a foreign org id therefore reads as an
// empty list, never a leak.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// PolicyDecision is one stored policy evaluation (policy_decisions row).
// Findings carry detector classes/severities/steps only — never request
// content (the consumer strips finding evidence before storage).
type PolicyDecision struct {
	ID string `json:"id"`
	// OrgID is immutable: decisions never move between orgs.
	OrgID string `json:"org_id"`
	// RequestID is the lightweight join key with request_logs ('' when the
	// event carried none).
	RequestID string `json:"request_id"`
	// PolicyID is the pipeline that produced the decision (no FK: the log
	// survives policy deletion).
	PolicyID string `json:"policy_id"`
	// PolicyVersion is the evaluated pipeline version (0 = unknown).
	PolicyVersion int    `json:"policy_version"`
	Mode          string `json:"mode"`
	Verdict       string `json:"verdict"`
	// Findings is the stored findings jsonb, verbatim (CORE-TRACE-01: a raw
	// JSON message, NOT a []byte — a []byte marshals as a base64 STRING and
	// that was the wire bug). The HTTP array/validity contract lives in the
	// handler: jsonb storage guarantees valid JSON, not an array, so legacy
	// or buggy rows may hold null / objects — the read API normalizes them
	// with an explicit findings_valid=false, never a silent clean array.
	Findings   json.RawMessage `json:"findings"`
	DurationMs int64           `json:"duration_ms"`
	CreatedAt  time.Time       `json:"created_at"`
}

// PolicyDecisionFilters narrows the admin list. Empty strings / nil pointers
// mean "no filter"; the values are bound as query arguments (never
// interpolated).
type PolicyDecisionFilters struct {
	Verdict  string // allow | flag | mask | deny
	Mode     string // shadow | enforce
	PolicyID string
	// PolicyVersion filters the evaluated pipeline version exactly. A pointer
	// because 0 is a REAL value here (the writer's "unknown/legacy version"),
	// not the absence of a filter (CORE-TRACE-02).
	PolicyVersion *int
	// RequestID narrows to one request's evaluations (exact match; the join
	// key with request_logs).
	RequestID string
	// Step matches decisions whose findings carry at least one finding with
	// this step (jsonb containment probe, bound — never interpolated).
	Step string
	// CreatedFrom/CreatedTo bound the evaluation-time window with INCLUSIVE
	// bounds (created_at >= / <=); nil leaves that side unbounded.
	CreatedFrom *time.Time
	CreatedTo   *time.Time

	PageFilter
}

// withDefaultPage copies the filters with a normalized page: a zero
// PageFilter means "no explicit pagination" — defaults apply, every filter
// field survives (CORE-TRACE-02 widened the struct; the old field-by-field
// copy would silently drop the new filters on the default path).
func (f PolicyDecisionFilters) withDefaultPage() PolicyDecisionFilters {
	if f.PageSize > 0 {
		return f
	}
	f.PageFilter = NewPageFilter(f.Page, f.PageSize)
	return f
}

// policyDecisionColumns is the canonical SELECT list for decision reads.
const policyDecisionColumns = `id::text, org_id::text, request_id, policy_id, policy_version, mode, verdict, findings, duration_ms, created_at`

// ListPolicyDecisions returns one page of the org's decision log, newest
// first (created_at DESC, id DESC as the stable tiebreak), with the honest
// total for the org's filtered set. Rows are read through the org-scoped RLS
// transaction, so a foreign org yields (empty, 0, nil).
func (s *Store) ListPolicyDecisions(ctx context.Context, orgID string, filters PolicyDecisionFilters) ([]PolicyDecision, int64, error) {
	if orgID == "" {
		return nil, 0, fmt.Errorf("org id is required")
	}
	filters = filters.withDefaultPage()

	var decisions []PolicyDecision
	var total int64
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		// Explicit org scope (the store contract everywhere): the org GUC +
		// FORCE RLS is the application-role safety net, the WHERE clause is
		// the statement-level guarantee (dev/test stands may run as owner).
		where, args, err := policyDecisionWhere(orgID, filters)
		if err != nil {
			return err
		}

		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM policy_decisions`+where,
			args...,
		).Scan(&total); err != nil {
			return fmt.Errorf("count policy decisions: %w", err)
		}

		listArgs := append(append([]any{}, args...), filters.PageSize, filters.Offset()) //nolint:gocritic // appendCombine: bound args stay last by contract
		rows, err := tx.Query(ctx,
			`SELECT `+policyDecisionColumns+` FROM policy_decisions`+where+
				` ORDER BY created_at DESC, id DESC LIMIT $`+fmt.Sprint(len(args)+1)+` OFFSET $`+fmt.Sprint(len(args)+2),
			listArgs...,
		)
		if err != nil {
			return fmt.Errorf("list policy decisions: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var d PolicyDecision
			if err := rows.Scan(&d.ID, &d.OrgID, &d.RequestID, &d.PolicyID, &d.PolicyVersion,
				&d.Mode, &d.Verdict, &d.Findings, &d.DurationMs, &d.CreatedAt); err != nil {
				return fmt.Errorf("scan policy decision: %w", err)
			}
			decisions = append(decisions, d)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, 0, err
	}
	if decisions == nil {
		decisions = []PolicyDecision{}
	}
	return decisions, total, nil
}

// policyDecisionWhere renders the filter clause (always org-scoped first)
// and its bound arguments. The arg count stays dynamic so every value is a
// placeholder, never text.
func policyDecisionWhere(orgID string, filters PolicyDecisionFilters) (string, []any, error) {
	args := []any{orgID}
	conditions := []string{fmt.Sprintf("org_id = $%d", len(args))}
	add := func(col, value string) {
		args = append(args, value)
		conditions = append(conditions, fmt.Sprintf("%s = $%d", col, len(args)))
	}
	if filters.Verdict != "" {
		add("verdict", filters.Verdict)
	}
	if filters.Mode != "" {
		add("mode", filters.Mode)
	}
	if filters.PolicyID != "" {
		add("policy_id", filters.PolicyID)
	}
	if filters.PolicyVersion != nil {
		args = append(args, *filters.PolicyVersion)
		conditions = append(conditions, fmt.Sprintf("policy_version = $%d", len(args)))
	}
	if filters.RequestID != "" {
		add("request_id", filters.RequestID)
	}
	if filters.Step != "" {
		// jsonb containment: a decision matches when ANY finding element is a
		// superset of the {"step": ...} probe. The probe is marshaled and
		// bound as $n::jsonb — the step value is never interpolated.
		//
		// CORE-TRACE-05: the stored payload is the versioned envelope OBJECT
		// (the findings array moved under the "findings" key; legacy rows
		// keep the bare top-level array). The probe matches both layouts:
		// array rows via the direct containment, envelope rows via the
		// nested probe guarded by jsonb_typeof (a scalar/object findings
		// value without the key can never false-positive).
		probe, err := json.Marshal([]map[string]string{{"step": filters.Step}})
		if err != nil {
			return "", nil, fmt.Errorf("encode step filter: %w", err)
		}
		args = append(args, string(probe))
		conditions = append(conditions, fmt.Sprintf(
			"(findings @> $%d::jsonb OR (jsonb_typeof(findings) = 'object' AND findings->'findings' @> $%d::jsonb))",
			len(args), len(args)))
	}
	if filters.CreatedFrom != nil {
		args = append(args, *filters.CreatedFrom)
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", len(args)))
	}
	if filters.CreatedTo != nil {
		args = append(args, *filters.CreatedTo)
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", len(args)))
	}
	return " WHERE " + joinConditions(conditions), args, nil
}

// PolicyDecisionRequestSummary is one row of the distinct-request view: the
// request identity plus its evaluation footprint. Evaluations counts the
// matching decision rows for that request (a request legitimately carries
// several — different hooks/attempts); first/last seen bound that activity.
type PolicyDecisionRequestSummary struct {
	RequestID   string    `json:"request_id"`
	Evaluations int64     `json:"evaluations"`
	FirstSeenAt time.Time `json:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
}

// ListPolicyDecisionRequests returns the REQUEST entity of the decision log
// (CORE-TRACE-02, the inverse direction of ListPolicyDecisions): one row per
// DISTINCT request_id that has at least one decision matching the filters —
// so a request with three evaluations is ONE row with evaluations=3, never
// three. The honest total and the page bounds count unique requests, not
// decisions. Decisions stored without a request_id (legacy events) have no
// navigable request and are excluded here — they stay visible in the
// decisions entity. Rows are read through the same org-scoped RLS
// transaction (a foreign org yields empty, 0, nil), ordered by most-recent
// activity with request_id DESC as the stable tiebreak.
func (s *Store) ListPolicyDecisionRequests(ctx context.Context, orgID string, filters PolicyDecisionFilters) ([]PolicyDecisionRequestSummary, int64, error) {
	if orgID == "" {
		return nil, 0, fmt.Errorf("org id is required")
	}
	filters = filters.withDefaultPage()

	var requests []PolicyDecisionRequestSummary
	var total int64
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		where, args, err := policyDecisionWhere(orgID, filters)
		if err != nil {
			return err
		}
		where += " AND request_id <> ''"

		if err := tx.QueryRow(ctx,
			`SELECT count(DISTINCT request_id) FROM policy_decisions`+where,
			args...,
		).Scan(&total); err != nil {
			return fmt.Errorf("count policy decision requests: %w", err)
		}

		listArgs := append(append([]any{}, args...), filters.PageSize, filters.Offset()) //nolint:gocritic // appendCombine: bound args stay last by contract
		rows, err := tx.Query(ctx,
			`SELECT request_id, count(*) AS evaluations,
					min(created_at) AS first_seen, max(created_at) AS last_seen
			 FROM policy_decisions`+where+`
			 GROUP BY request_id
			 ORDER BY max(created_at) DESC, request_id DESC
			 LIMIT $`+fmt.Sprint(len(args)+1)+` OFFSET $`+fmt.Sprint(len(args)+2),
			listArgs...,
		)
		if err != nil {
			return fmt.Errorf("list policy decision requests: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var r PolicyDecisionRequestSummary
			if err := rows.Scan(&r.RequestID, &r.Evaluations, &r.FirstSeenAt, &r.LastSeenAt); err != nil {
				return fmt.Errorf("scan policy decision request: %w", err)
			}
			requests = append(requests, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, 0, err
	}
	if requests == nil {
		requests = []PolicyDecisionRequestSummary{}
	}
	return requests, total, nil
}
