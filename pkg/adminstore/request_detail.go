package adminstore

import (
	"context"
	"encoding/json"
	"fmt"
)

// RequestToolCall is one tool/function call recorded for the request in the
// tool_calls table. loggerd extracts the names from the PRE-truncation
// upstream sample, so this list stays authoritative where the stored
// upstream_response snapshot is cut short (streamed reasoning can push the
// tool-call fragments past the 4000-char storage cap). The table holds one
// row per distinct tool name — arguments are NOT recorded there; the
// inspector enriches them from the sample when it survived.
type RequestToolCall struct {
	ToolName string `json:"tool_name"`
}

// RequestToolCallInvocation is one tool-call OCCURRENCE with its reassembled
// arguments, from the tool_call_invocations table (0014). loggerd extracts
// these from the PRE-truncation upstream sample, so the arguments survive
// even when the stored snapshot is cut before the fragments. CallID and
// Arguments are nil when absent (provider omitted the id; args never
// captured or empty).
type RequestToolCallInvocation struct {
	Seq       int     `json:"seq"`
	CallID    *string `json:"call_id"`
	ToolName  string  `json:"tool_name"`
	Arguments *string `json:"arguments"`
}

// RequestPayloadAccess is the authorization result supplied by the API
// boundary. Direct store consumers retain the trusted legacy call form.
type RequestPayloadAccess struct {
	UserID          string
	Grant           bool
	Originals       bool
	DenyOwnHistory  bool
	SubjectType     RequestPayloadSubjectType
	AgentID         string
	APIKeyID        string
	OrgWideMetadata bool
	// Delegated marks that the non-human subject acts under a live principal
	// delegation (N04-P05 T03). When set with AgentID, request rows are pinned
	// to that subject's own attribution (agent_id = AgentID) and Grant may add
	// the payload scope for exactly those rows. Originals are never implied —
	// requests.read_originals is not delegatable.
	Delegated bool
}

// RequestPayloadSubjectType distinguishes people from autonomous principals.
type RequestPayloadSubjectType string

const (
	// RequestPayloadHuman denotes a person authenticated as themselves.
	RequestPayloadHuman RequestPayloadSubjectType = "human"
	// RequestPayloadAgent denotes an autonomous agent principal.
	RequestPayloadAgent RequestPayloadSubjectType = "agent"
	// RequestPayloadCI denotes a CI principal.
	RequestPayloadCI RequestPayloadSubjectType = "ci"
	// RequestPayloadAPIKey denotes a service principal authenticated by key.
	RequestPayloadAPIKey RequestPayloadSubjectType = "api_key"
)

// RequestPayloadSubject is set by an authenticated ingress when it knows the
// non-human source identity. API keys and CI/agent keys never inherit a human's
// request history, even if request_logs.user_id contains their issuer.
type RequestPayloadSubject struct {
	Type     RequestPayloadSubjectType
	AgentID  string
	APIKeyID string
}

type requestPayloadSubjectKey struct{}
type requestPayloadDenyOwnHistoryKey struct{}

// WithRequestPayloadSubject marks an authenticated non-human principal.
func WithRequestPayloadSubject(ctx context.Context, subject RequestPayloadSubject) context.Context {
	return context.WithValue(ctx, requestPayloadSubjectKey{}, subject)
}

// RequestPayloadSubjectFromContext returns the marked request subject.
func RequestPayloadSubjectFromContext(ctx context.Context) (RequestPayloadSubject, bool) {
	subject, ok := ctx.Value(requestPayloadSubjectKey{}).(RequestPayloadSubject)
	return subject, ok
}

// WithRequestPayloadDenyOwnHistory is the explicit policy extension point for
// denying a human access to their own history. It overrides grants and roles.
func WithRequestPayloadDenyOwnHistory(ctx context.Context, denied bool) context.Context {
	return context.WithValue(ctx, requestPayloadDenyOwnHistoryKey{}, denied)
}

// RequestPayloadDenyOwnHistoryFromContext reports the explicit deny policy.
func RequestPayloadDenyOwnHistoryFromContext(ctx context.Context) bool {
	denied, _ := ctx.Value(requestPayloadDenyOwnHistoryKey{}).(bool)
	return denied
}

type requestPayloadAccessKey struct{}

// resolveDelegatedRowAccess is the pure row-level decision for a delegated
// subject (N04-P05 T03). delegated = the access is pinned to the subject's
// own attribution; payload = the payload columns may be selected for exactly
// those rows (the handler sets Grant only when the delegation carries the
// payload scope). An explicit deny overrides the delegation, and originals
// are never implied (they are gated separately by RequestPayloadAccess.
// Originals, which no delegation can set).
func resolveDelegatedRowAccess(access RequestPayloadAccess) (delegated, payload bool) {
	human := access.SubjectType == "" || access.SubjectType == RequestPayloadHuman
	delegated = !human && access.Delegated && access.AgentID != ""
	return delegated, access.Grant && !access.DenyOwnHistory
}

// WithRequestPayloadAccess carries the API's fail-closed decision into the
// store without changing the stable Store interface used by other consumers.
func WithRequestPayloadAccess(ctx context.Context, access RequestPayloadAccess) context.Context {
	return context.WithValue(ctx, requestPayloadAccessKey{}, access)
}

// RequestPayloadAccessFromContext returns the boundary decision when present.
func RequestPayloadAccessFromContext(ctx context.Context) (RequestPayloadAccess, bool) {
	access, ok := ctx.Value(requestPayloadAccessKey{}).(RequestPayloadAccess)
	return access, ok
}

// RequestDetail is one request_logs row in full, as returned to the request
// explorer detail view (PO-04). Response is the stored (redacted/truncated)
// response snapshot as raw JSON; PromptHash is the one-way prompt hash. The
// request body is intentionally NOT stored (privacy by design, PH.1), so this
// struct has no request-body field and the UI must not claim one.
type RequestDetail struct {
	RequestID            string          `json:"request_id"`
	OrgID                string          `json:"org_id"`
	ModelRequested       string          `json:"model_requested"`
	ModelUsed            string          `json:"model_used"`
	UpstreamURL          string          `json:"upstream_url,omitempty"`
	Method               string          `json:"method"`
	StatusCode           int             `json:"status_code"`
	DurationMs           int64           `json:"duration_ms"`
	TokensIn             int64           `json:"tokens_in"`
	TokensOut            int64           `json:"tokens_out"`
	Error                string          `json:"error,omitempty"`
	CreatedAt            json.RawMessage `json:"created_at"`
	PromptHash           string          `json:"prompt_hash,omitempty"`
	Response             json.RawMessage `json:"response,omitempty"`
	UpstreamRequest      json.RawMessage `json:"upstream_request,omitempty"`
	UpstreamResponse     json.RawMessage `json:"upstream_response,omitempty"`
	CacheHitType         string          `json:"cache_hit_type,omitempty"`
	Counterfactual       float64         `json:"counterfactual_cost_usd"`
	CostUSD              float64         `json:"cost_in_usd"`
	ClassifierClass      string          `json:"classifier_class,omitempty"`
	ClassifierConfidence float32         `json:"classifier_confidence,omitempty"`
	ClassifierSource     string          `json:"classifier_source,omitempty"`
	TierUsed             string          `json:"tier_used,omitempty"`
	ABGroup              string          `json:"ab_group,omitempty"`
	TaskID               string          `json:"task_id,omitempty"`
	AgentID              string          `json:"agent_id,omitempty"`
	SessionID            string          `json:"session_id,omitempty"`
	RoutingDecision      string          `json:"routing_decision,omitempty"`
	HomeRegion           string          `json:"home_region"`
	// Observability parity (Bifrost attempt trail). nil = unknown: legacy
	// rows predate the columns and non-streaming requests have no first
	// token — the API must not collapse that into a fake 0.
	FirstTokenMs *int64 `json:"first_token_ms"`
	AttemptCount *int64 `json:"attempt_count"`
	RetryCount   *int64 `json:"retry_count"`
	// Tool/function calls loggerd recorded for this request (distinct names
	// from the pre-truncation sample). Always a list — empty means "none
	// recorded", never null, so the contract is stable for clients.
	ToolCalls []RequestToolCall `json:"tool_calls"`
	// Per-occurrence tool calls with reassembled arguments (0014; rows exist
	// only for requests logged after that migration). Same always-a-list
	// contract as ToolCalls.
	ToolCallInvocations []RequestToolCallInvocation `json:"tool_call_invocations"`
	Labels              map[string]string           `json:"labels,omitempty"`
	// ResponseView is the parsed FIX-20 envelope of the processed,
	// client-facing response (nil for legacy rows, SQL NULL and anything
	// that is not a v1 model-response envelope — ParseResponseEnvelope
	// decides). The raw Response field is unchanged: audit surfaces keep
	// reading the verbatim column.
	ResponseView *RequestResponseView `json:"response_view,omitempty"`
}

// GetRequestDetail returns the full request_logs row for an org, scoped by
// org_id + request_id. A request belonging to a different org (or not found)
// returns ErrNotFound so the handler maps it to 404 without leaking existence.
func (s *Store) GetRequestDetail(ctx context.Context, orgID, requestID string) (*RequestDetail, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	return getRequestDetailOn(ctx, s.db, orgID, requestID)
}

// getRequestDetailOn loads one authorized request detail on the given
// executor — the pool or an export snapshot transaction — so the export walk
// reads each detail from the same snapshot its pages came from.
func getRequestDetailOn(ctx context.Context, ex exportQueryRunner, orgID, requestID string) (*RequestDetail, error) {
	if orgID == "" || requestID == "" {
		return nil, ErrNotFound
	}
	access, _ := ctx.Value(requestPayloadAccessKey{}).(RequestPayloadAccess)
	payloadUserID := access.UserID
	human := access.SubjectType == "" || access.SubjectType == RequestPayloadHuman
	payloadDeny := access.DenyOwnHistory
	payloadOwner := access.UserID != "" && human
	// Delegated subject (N04-P05 T03): rows are pinned to the subject's own
	// attribution, and the payload columns additionally require the delegated
	// payload scope. An explicit deny still overrides the delegation.
	delegated, payloadGrantSQL := resolveDelegatedRowAccess(access)
	q := `
		SELECT COALESCE(request_id, ''),
		       COALESCE(org_id::text, ''),
		       COALESCE(model_requested, ''),
		       COALESCE(model_used, ''),
	       CASE WHEN NOT $5::boolean AND $7::boolean THEN COALESCE(upstream_url, '') ELSE '' END,
		       COALESCE(method, 'POST'),
		       status_code,
		       COALESCE(duration_ms, 0),
		       COALESCE(tokens_in, 0),
		       COALESCE(tokens_out, 0),
		       CASE WHEN NOT $5::boolean AND ($4::boolean OR ($6::boolean AND $3::text <> '' AND user_id::text = $3::text AND agent_id IS NULL AND api_key_id IS NULL)) THEN COALESCE(error, '') ELSE '' END,
		       to_jsonb(created_at),
		       COALESCE(prompt_hash, ''),
		       COALESCE(CASE WHEN NOT $5::boolean AND ($4::boolean OR ($6::boolean AND $3::text <> '' AND user_id::text = $3::text AND agent_id IS NULL AND api_key_id IS NULL)) THEN response ELSE NULL END, 'null'::jsonb),
	       CASE WHEN NOT $5::boolean AND $7::boolean THEN upstream_request ELSE NULL END,
	       CASE WHEN NOT $5::boolean AND $7::boolean THEN upstream_response ELSE NULL END,
		       COALESCE(cache_hit_type, ''),
		       COALESCE(counterfactual_cost_usd, 0),
		       COALESCE(cost_in_usd, 0),
		       COALESCE(classifier_class, ''),
		       COALESCE(classifier_confidence, 0),
		       COALESCE(classifier_source, ''),
		       COALESCE(tier_used, ''),
		       COALESCE(ab_group, ''),
		       COALESCE(task_id, ''),
		       COALESCE(agent_id::text, ''),
		       COALESCE(session_id::text, ''),
		       COALESCE(routing_decision, ''),
		       COALESCE(home_region, ''),
		       first_token_ms,
		       attempt_count,
		       retry_count,
		       COALESCE(labels, '{}'::jsonb), user_id::text
	FROM request_logs
	WHERE org_id = $1::uuid AND request_id = $2`
	args := []interface{}{orgID, requestID, payloadUserID, payloadGrantSQL, payloadDeny, payloadOwner, access.Originals}
	if delegated {
		// Scope-pin the lookup to the delegated subject's own attribution: a
		// delegated agent/CI subject can never address another subject's row.
		args = append(args, access.AgentID)
		q += fmt.Sprintf(" AND agent_id::text = $%d", len(args))
	}
	var d RequestDetail
	var labelsRaw []byte
	var ownerID *string
	err := ex.QueryRow(ctx, q, args...).Scan(
		&d.RequestID, &d.OrgID, &d.ModelRequested, &d.ModelUsed, &d.UpstreamURL,
		&d.Method, &d.StatusCode, &d.DurationMs, &d.TokensIn, &d.TokensOut,
		&d.Error, &d.CreatedAt, &d.PromptHash, &d.Response, &d.UpstreamRequest, &d.UpstreamResponse, &d.CacheHitType,
		&d.Counterfactual, &d.CostUSD, &d.ClassifierClass, &d.ClassifierConfidence,
		&d.ClassifierSource, &d.TierUsed, &d.ABGroup, &d.TaskID, &d.AgentID, &d.SessionID,
		&d.RoutingDecision, &d.HomeRegion, &d.FirstTokenMs, &d.AttemptCount, &d.RetryCount, &labelsRaw, &ownerID,
	)
	if err != nil {
		if IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("request detail: %w", err)
	}
	d.Labels = decodeLabels(labelsRaw)
	// FIX-20: parse the stored response value into the view projection when
	// it is a v1 model-response envelope; legacy rows and denied/absent
	// values stay nil (the raw Response field is unchanged either way).
	d.ResponseView = ParseResponseEnvelope(d.Response)
	if payloadDeny && payloadOwner && ownerID != nil && *ownerID == payloadUserID {
		// Deny-own-history removes the resource itself from the caller's view;
		// returning metadata would still disclose that their history exists.
		return nil, ErrNotFound
	}
	owned := ownerID != nil && payloadOwner && *ownerID == payloadUserID
	if !owned && !delegated && !access.Grant && !access.OrgWideMetadata {
		return nil, ErrNotFound
	}
	if payloadDeny || (!owned && !payloadGrantSQL) {
		// Return metadata without selecting related payload rows. The main-row
		// projection above also returns only redacted payload columns.
		d.ToolCalls = []RequestToolCall{}
		d.ToolCallInvocations = []RequestToolCallInvocation{}
		return &d, nil
	}
	// Tool calls recorded for this request, org-scoped exactly like the row
	// above. Sourced from the tool_calls table (populated pre-truncation by
	// loggerd), so names survive when the stored upstream_response sample is
	// cut before the tool-call fragments. An empty result is a valid "none
	// recorded" state; a transport/scan failure is surfaced, not swallowed.
	d.ToolCalls = []RequestToolCall{}
	tcRows, err := ex.Query(ctx, `
		SELECT tool_name FROM tool_calls
		WHERE org_id = $1::uuid AND request_id = $2
		ORDER BY id`, orgID, requestID)
	if err != nil {
		return nil, fmt.Errorf("request detail tool calls: %w", err)
	}
	defer tcRows.Close()
	for tcRows.Next() {
		var name string
		if err := tcRows.Scan(&name); err != nil {
			return nil, fmt.Errorf("request detail tool calls scan: %w", err)
		}
		d.ToolCalls = append(d.ToolCalls, RequestToolCall{ToolName: name})
	}
	if err := tcRows.Err(); err != nil {
		return nil, fmt.Errorf("request detail tool calls rows: %w", err)
	}
	// Per-occurrence invocations with arguments (0014), same org scoping.
	// Rows only exist for post-0014 requests; empty = legacy/sample-only.
	d.ToolCallInvocations = []RequestToolCallInvocation{}
	invRows, err := ex.Query(ctx, `
		SELECT seq, call_id, tool_name, arguments FROM tool_call_invocations
		WHERE org_id = $1::uuid AND request_id = $2
		ORDER BY seq, id`, orgID, requestID)
	if err != nil {
		return nil, fmt.Errorf("request detail tool call invocations: %w", err)
	}
	defer invRows.Close()
	for invRows.Next() {
		var inv RequestToolCallInvocation
		if err := invRows.Scan(&inv.Seq, &inv.CallID, &inv.ToolName, &inv.Arguments); err != nil {
			return nil, fmt.Errorf("request detail tool call invocations scan: %w", err)
		}
		d.ToolCallInvocations = append(d.ToolCallInvocations, inv)
	}
	if err := invRows.Err(); err != nil {
		return nil, fmt.Errorf("request detail tool call invocations rows: %w", err)
	}
	return &d, nil
}
