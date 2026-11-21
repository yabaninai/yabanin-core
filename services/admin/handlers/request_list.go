package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// selectedRequestRowKey reads the optional decimal row identity sent by the list.
func selectedRequestRowKey(w http.ResponseWriter, r *http.Request) (int64, bool) {
	values, present := r.URL.Query()["row_key"]
	if !present {
		return 0, true
	}
	if len(values) != 1 || values[0] == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid row_key: exactly one non-empty value required"})
		return 0, false
	}
	key, err := strconv.ParseInt(values[0], 10, 64)
	if err != nil || key <= 0 {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid row_key: must be a positive decimal request_logs row key"})
		return 0, false
	}
	return key, true
}

// apiOrgRequestDetail handles GET /api/organizations/{id}/requests/{request_id}
// — the full request_logs row (PO-04): the stored (redacted/truncated) response
// snapshot as raw JSON, prompt_hash, classifier/cache/tier/routing fields, and
// the G2 columns (task_id, agent_id, routing_decision). Org-scoped by the path
// {id}; a request from another org (or unknown) is 404. The request body is not
// stored (PH.1) and is not part of this response.
//
// Grant redemption follows the export refusal/replay contract (FIX-08 option
// (a+), owner-confirmed 2026-10-24): every non-disclosing precheck (scope,
// grant usability, retention, content verdict) runs before the one-time
// consume; the row read that decides 404/500 is a discarded pre-consume read,
// so a missing row or a store failure denies with the grant still redeemable;
// the atomic consume is the last step before the payload write; any failure
// after the 200 write begins is final (token stays consumed, never refunded).
// A grant redemption discloses exactly the one physical row the grant is
// bound to (peek + read by immutable row key): a correlation several rows
// may share (0028) can never widen or retarget the disclosure, and a legacy
// pre-binding grant denies generically without burning.
func (h *AdminHandlers) apiOrgRequestDetail() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		selectedKey, ok := selectedRequestRowKey(w, r)
		if !ok {
			return
		}
		orgID := chi.URLParam(r, "id")
		requestID := requestIDParam(r)
		userID := requestUserID(r)
		// ---- Phase: prechecks (read-only, no disclosure, grant untouched) ----
		// FIX-08 detail symmetry: a request without a bearer token takes
		// the metadata-only path and never consumes.
		grantScope, grant, originalsGrant, ok := h.authorizeRequestDetailGrant(w, r, orgID, requestID)
		if !ok {
			return
		}
		token := requestPayloadGrantToken(r)
		access := h.requestDetailAccess(r, orgID, requestID, userID, grant, originalsGrant)
		// ---- Phase: pre-consume target resolution and row read (the discarded read) ----
		ctx := adminstore.WithRequestPayloadAccess(r.Context(), access)
		d, rowKey, ok := h.readRequestDetailRow(ctx, w, r, orgID, requestID, userID, token, grantScope, selectedKey)
		if !ok {
			return
		}
		// ---- Phase: atomic one-time consume (last step before disclosure) ----
		if token != "" && !h.consumeRequestDetailGrant(w, r, orgID, requestID, userID, token, rowKey, grantScope) {
			return
		}
		// ---- Phase: disclosure (the 200 commits; later failures are final) ----
		// writeJSON writes the status header before it encodes, so once this
		// runs the attempt is final: an encode/write failure after a
		// successful consume leaves the token consumed (never refunded, never
		// re-served; a replay gets the same generic 403 as an unknown grant).
		writeJSON(w, http.StatusOK, d)
		if token != "" {
			auditRequestDetailDecision(h, r, orgID, requestID, grantScope, true, 1, "completed")
		}
	}
}

// requestDetailAccess builds the store visibility predicate for the authenticated subject.
func (h *AdminHandlers) requestDetailAccess(r *http.Request, orgID, requestID, userID string, grant, originalsGrant bool) adminstore.RequestPayloadAccess {
	subject, _ := adminstore.RequestPayloadSubjectFromContext(r.Context())
	access := adminstore.RequestPayloadAccess{SubjectType: subject.Type, AgentID: subject.AgentID, APIKeyID: subject.APIKeyID}
	if subject.Type != "" && subject.Type != adminstore.RequestPayloadHuman {
		read, payload := h.evaluateSubjectDelegation(r, orgID, subject)
		verdict := h.authorizeRequestContent(r, orgID, requestID, grant, read || payload)
		if read && verdict.Allowed {
			access.Grant = payload
			access.Delegated = true
		} else {
			access.Grant = grant
			access.DenyOwnHistory = true
		}
		return access
	}

	verdict := h.authorizeRequestContent(r, orgID, requestID, grant, false)
	role, member := h.callerRoleOnOrg(r, orgID)
	roleGrant := false
	if member {
		roleGrant = adminstore.RoleHas(string(role), adminstore.PermRequestsPayloads)
		access.OrgWideMetadata = adminstore.RoleHas(string(role), adminstore.PermRequestsRead)
	}
	access.UserID = userID
	access.Grant = verdict.Allowed && (grant || roleGrant)
	access.Originals = verdict.Allowed && originalsGrant
	access.DenyOwnHistory = adminstore.RequestPayloadDenyOwnHistoryFromContext(r.Context())
	return access
}

// authorizeRequestDetailGrant runs the non-disclosing grant prechecks (scope
// validation, grant usability, retention gate) so a 400/403/503 denies with
// the grant still redeemable and journalled as a denial. It returns the
// resolved scope and the grant/originals flags; ok=false once a denial is
// written. A bearer grant is a root self-grant: a caller without the grant
// capability or under an explicit policy deny must neither use nor burn it —
// fail closed loudly (the export contract) instead of silently degrading to
// a metadata read. Retention gates originals fail-closed BEFORE the consume:
// a lookup error never opens originals and never burns the token.
func (h *AdminHandlers) authorizeRequestDetailGrant(w http.ResponseWriter, r *http.Request, orgID, requestID string) (grantScope string, grant, originalsGrant, ok bool) {
	if requestPayloadGrantToken(r) == "" {
		return "", false, false, true
	}
	grantScope = r.URL.Query().Get("scope")
	if grantScope == "" {
		grantScope = adminstore.RequestPayloadScopeRead
	}
	if grantScope != adminstore.RequestPayloadScopeRead && grantScope != adminstore.RequestPayloadScopeOriginals {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid payload scope"})
		return "", false, false, false
	}
	_, hasGrantStore := h.store.(requestPayloadGrantStore)
	if !hasGrantStore || !isRoot(r) || adminstore.RequestPayloadDenyOwnHistoryFromContext(r.Context()) {
		auditRequestDetailDecision(h, r, orgID, requestID, grantScope, false, 0, "grant_unusable")
		writeJSON(w, http.StatusForbidden, apiError{Error: "request payload grant cannot be used"})
		return "", false, false, false
	}
	if grantScope == adminstore.RequestPayloadScopeOriginals {
		originalsGrant, ok = h.allowRequestDetailOriginals(w, r, orgID, requestID, grantScope)
		if !ok {
			return "", false, false, false
		}
	}
	// Grant-hypothetical from here (the export preflight pattern): the
	// verdict and the row read run under the widened access the verified
	// consume would grant. Nothing from those reads is ever disclosed
	// unless the atomic consume succeeds — on a failed consume the read
	// result is discarded with a generic 403.
	return grantScope, true, originalsGrant, true
}

// allowRequestDetailOriginals enforces the originals retention gate for a
// detail grant redemption. Returns false once the fail-closed denial is
// written; a lookup error never opens originals and never burns the token.
func (h *AdminHandlers) allowRequestDetailOriginals(w http.ResponseWriter, r *http.Request, orgID, requestID, grantScope string) (allowed, ok bool) {
	retention, isRetention := h.store.(orgOriginalRetentionStore)
	if !isRetention {
		auditRequestDetailDecision(h, r, orgID, requestID, grantScope, false, 0, "retention_unavailable")
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "original retention setting is unavailable"})
		return false, false
	}
	setting, err := retention.GetOrgOriginalRetention(r.Context(), orgID)
	if err != nil {
		auditRequestDetailDecision(h, r, orgID, requestID, grantScope, false, 0, "retention_unavailable")
		h.respondError(w, r, err, http.StatusServiceUnavailable)
		return false, false
	}
	if setting == nil || !setting.Effective {
		auditRequestDetailDecision(h, r, orgID, requestID, grantScope, false, 0, "original_retention_disabled")
		writeJSON(w, http.StatusForbidden, apiError{Error: "original payload retention is disabled"})
		return false, false
	}
	return true, true
}

// readRequestDetailRow performs the discarded pre-consume read that only
// decides 404/500: a missing (or not-visible) row and a store failure deny
// with the grant still redeemable instead of burning it on a response that
// carries no payload. A grant redemption resolves its one bound physical row
// first (peek, never a consume) and reads exactly that row by key — a
// correlation several rows may share (0028) can never widen or retarget the
// disclosure; a legacy pre-binding grant is unusable (generic denial, no
// burn). The read runs under the grant-hypothetical access the caller built;
// its result is discarded unless the verified atomic consume succeeds — no
// byte of it is written before that, so the hypothetical widening can never
// turn into disclosure.
func (h *AdminHandlers) readRequestDetailRow(ctx context.Context, w http.ResponseWriter, r *http.Request, orgID, requestID, userID, token, grantScope string, selectedKey int64) (*adminstore.RequestDetail, int64, bool) {
	if token == "" {
		var d *adminstore.RequestDetail
		var err error
		if selectedKey != 0 {
			d, err = h.store.GetRequestDetailRowInCorrelation(ctx, orgID, requestID, selectedKey)
		} else {
			d, err = h.store.GetRequestDetail(ctx, orgID, requestID)
		}
		if err != nil {
			h.respondRequestDetailReadError(w, r, err, orgID, requestID, token, grantScope)
			return nil, 0, false
		}
		return d, 0, true
	}
	grantStore, ok := h.store.(requestPayloadGrantStore)
	if !ok {
		auditRequestDetailDecision(h, r, orgID, requestID, grantScope, false, 0, "grant_unusable")
		writeJSON(w, http.StatusForbidden, apiError{Error: "request payload grant cannot be used"})
		return nil, 0, false
	}
	rowKey, err := grantStore.PeekRequestPayloadGrantTarget(r.Context(), token, orgID, requestID, userID, time.Now().UTC())
	if err != nil {
		// Invalid, expired, revoked, replayed, wrong org/grantee/request,
		// unbound legacy, or a grant-store failure: the same fail-closed
		// generic 403, token untouched.
		auditRequestDetailDecision(h, r, orgID, requestID, grantScope, false, 0, "grant_invalid_or_unavailable")
		writeJSON(w, http.StatusForbidden, apiError{Error: "request payload grant is invalid or unavailable"})
		return nil, 0, false
	}
	if selectedKey != 0 && selectedKey != rowKey {
		auditRequestDetailDecision(h, r, orgID, requestID, grantScope, false, 0, "row_key_mismatch")
		writeJSON(w, http.StatusBadRequest, apiError{Error: "row_key does not match the row the payload grant is bound to"})
		return nil, 0, false
	}
	d, err := h.store.GetRequestDetailRow(ctx, orgID, rowKey)
	if err != nil {
		h.respondRequestDetailReadError(w, r, err, orgID, requestID, token, grantScope)
		return nil, 0, false
	}
	return d, rowKey, true
}

// respondRequestDetailReadError maps a failed pre-consume read to 404/500
// and journals the denial for grant redemptions.
func (h *AdminHandlers) respondRequestDetailReadError(w http.ResponseWriter, r *http.Request, err error, orgID, requestID, token, grantScope string) {
	if token != "" {
		reason := "store_error"
		if adminstore.IsNotFound(err) {
			reason = "row_not_found"
		}
		auditRequestDetailDecision(h, r, orgID, requestID, grantScope, false, 0, reason)
	}
	if adminstore.IsNotFound(err) {
		h.respondError(w, r, err, http.StatusNotFound)
		return
	}
	h.respondError(w, r, err, http.StatusInternalServerError)
}

// consumeRequestDetailGrant performs the atomic one-time consume — the last
// step before disclosure. Invalid, expired, revoked, wrong-scope, bound to a
// different row, request or organization, already consumed (replay), or a
// grant-store failure: the same fail-closed generic 403 with zero row bytes.
// The pre-consume read is discarded here, so invalid and replayed grants
// stay indistinguishable (anti-oracle), and a failed consume never burns the
// token.
func (h *AdminHandlers) consumeRequestDetailGrant(w http.ResponseWriter, r *http.Request, orgID, requestID, userID, token string, rowKey int64, grantScope string) bool {
	grantStore, ok := h.store.(requestPayloadGrantStore)
	if !ok {
		auditRequestDetailDecision(h, r, orgID, requestID, grantScope, false, 0, "grant_unusable")
		writeJSON(w, http.StatusForbidden, apiError{Error: "request payload grant cannot be used"})
		return false
	}
	if _, err := grantStore.ConsumeRequestPayloadGrantScope(token, orgID, requestID, rowKey, userID, grantScope, time.Now().UTC()); err != nil {
		auditRequestDetailDecision(h, r, orgID, requestID, grantScope, false, 0, "grant_invalid_or_unavailable")
		writeJSON(w, http.StatusForbidden, apiError{Error: "request payload grant is invalid or unavailable"})
		return false
	}
	return true
}

// requestDetailAuditDetail is the journal payload of one grant-relevant detail
// decision. It must be serialized with json.Marshal, never fmt.Sprintf %q:
// request_id is path-controlled and may carry control characters or invalid
// UTF-8, and %q emits \x1b-style escapes that strict JSON parsers reject.
type requestDetailAuditDetail struct {
	OrgID     string `json:"org_id"`
	RequestID string `json:"request_id"`
	Scope     string `json:"scope"`
	Payload   bool   `json:"payload"`
	Originals bool   `json:"originals"`
	Outcome   string `json:"outcome"`
	Rows      int    `json:"rows"`
}

// auditRequestDetailDecision journals grant-relevant detail decisions (every
// redemption denial and every allowed redemption) via the durable admin audit
// seam (AF-10). Metadata-only reads without a bearer token are the everyday
// explorer path and stay unjournalled. Details carry only identifiers and
// content flags — never payload content and never the bearer grant token.
// Audit degradation (outbox / memory-pending) follows the shared journal path,
// so it never turns a denial into an allow.
func auditRequestDetailDecision(h *AdminHandlers, r *http.Request, orgID, requestID, scope string, allowed bool, rows int, outcome string) {
	action := "request_detail"
	if !allowed {
		action = "request_detail.denied"
	}
	if scope == "" {
		scope = adminstore.RequestPayloadScopeRead
	}
	details, err := json.Marshal(requestDetailAuditDetail{
		OrgID:     orgID,
		RequestID: requestID,
		Scope:     scope,
		Payload:   allowed,
		Originals: allowed && scope == adminstore.RequestPayloadScopeOriginals,
		Outcome:   outcome,
		Rows:      rows,
	})
	if err != nil {
		// Unreachable for this all-scalar struct; fall back to a fixed,
		// valid-JSON marker rather than ever storing malformed JSON.
		details = []byte(`{"outcome":"detail_marshal_error"}`)
	}
	h.auditLogAction(r, action, "organization:"+orgID, string(details))
}

// parseRequestListFilters is the single parser shared by the list and stats
// endpoints so the two always accept the same query surface (the stats block
// must describe exactly what the table shows). Query params: model, from, to
// (RFC3339), errors=true, task_id, agent_id, request_id (exact), min_latency_ms,
// max_latency_ms, min_tokens, max_tokens, min_cost_usd, max_cost_usd,
// cache_hit=exact|semantic|miss, q (content search), query (YQL expression —
// combined with the flat filters, may carry "order by").
func parseRequestListFilters(r *http.Request, orgID string) (adminstore.RequestListFilters, error) {
	q := r.URL.Query()
	f := adminstore.RequestListFilters{OrgID: orgID}
	f.Model = q.Get("model")
	f.TaskID = q.Get("task_id")
	f.AgentID = q.Get("agent_id")
	f.RequestID = q.Get("request_id")
	// rule_id: routing-rule identity filter (CORE-TRACE-04). Strict uuid:
	// routing_rules.id is a uuid, so garbage is an explicit 400 — never a
	// silently-ignored filter.
	f.RuleID = q.Get("rule_id")
	if f.RuleID != "" {
		if _, err := uuid.Parse(f.RuleID); err != nil {
			return f, errInvalidRuleID(f.RuleID)
		}
	}
	f.ErrorOnly = q.Get("errors") == "true" || q.Get("errors") == "1"
	f.CacheHit = q.Get("cache_hit")
	f.ContentSearch = q.Get("q")
	page, _ := strconv.Atoi(q.Get("page"))
	pageSize, _ := strconv.Atoi(q.Get("page_size"))
	f.Page, f.PageSize = page, pageSize
	f.MinLatencyMs = parsePositiveI64(q.Get("min_latency_ms"))
	f.MaxLatencyMs = parsePositiveI64(q.Get("max_latency_ms"))
	f.MinTokens = parsePositiveI64(q.Get("min_tokens"))
	f.MaxTokens = parsePositiveI64(q.Get("max_tokens"))
	f.MinCostUSD = parsePositiveF64(q.Get("min_cost_usd"))
	f.MaxCostUSD = parsePositiveF64(q.Get("max_cost_usd"))
	if v := q.Get("from"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return f, errInvalidTime("from")
		}
		f.From = t
	}
	if v := q.Get("to"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return f, errInvalidTime("to")
		}
		f.To = t
	}
	if v := q.Get("query"); v != "" {
		rq, err := adminstore.ParseYQL(v)
		if err != nil {
			return f, err
		}
		f.Query = rq
	}
	return f, nil
}

func parsePositiveI64(v string) int64 {
	n, _ := strconv.ParseInt(v, 10, 64)
	if n < 0 {
		return 0
	}
	return n
}

func parsePositiveF64(v string) float64 {
	n, _ := strconv.ParseFloat(v, 64)
	if n < 0 || n != n { // NaN guard
		return 0
	}
	return n
}

// apiOrgRequests handles GET /api/organizations/{id}/requests — the unified
// request explorer list: server-side filters (model, time window, error-only,
// task/agent, request-id lookup, latency/token/cost ranges, cache-hit and
// content search) over request_logs with honest pagination (total from COUNT).
func (h *AdminHandlers) apiOrgRequests() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		f, err := parseRequestListFilters(r, chi.URLParam(r, "id"))
		if err != nil {
			h.respondError(w, r, err, http.StatusBadRequest)
			return
		}
		authorizeRequestList(h, r, &f)

		rows, total, err := h.store.ListRequests(r.Context(), f)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		if rows == nil {
			rows = []adminstore.RequestListRow{}
		}
		for i := range rows {
			if !f.PayloadDenied && (f.PayloadGrant || rows[i].PayloadOwned) {
				continue
			}
			rows[i].ErrorMsg = ""
			rows[i].ToolCalls = nil
		}
		pf := adminstore.NewPageFilter(f.Page, f.PageSize)
		writePaginated(w, pf, rows, int64(total))
	}
}

// apiOrgRequestStats handles GET /api/organizations/{id}/requests/stats —
// the aggregate block over the SAME filters as the list (Bifrost-parity
// stats: total, success rate, average latency, tokens, cost; plus p95 which
// agent-loop traffic needs). Kept as a separate endpoint so the paginated
// list envelope stays unchanged.
func (h *AdminHandlers) apiOrgRequestStats() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		f, err := parseRequestListFilters(r, chi.URLParam(r, "id"))
		if err != nil {
			h.respondError(w, r, err, http.StatusBadRequest)
			return
		}
		authorizeRequestList(h, r, &f)
		stats, err := h.store.RequestStats(r.Context(), f)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, stats)
	}
}

// Root is an installation operator, but org-wide request metadata still
// requires an explicit requests.read grant on that organization. Root can
// grant the permission to itself through the normal role-management path.
func (h *AdminHandlers) hasOrgWideRequestMetadata(r *http.Request, orgID string) bool {
	role, ok := h.callerRoleOnOrg(r, orgID)
	return ok && adminstore.RoleHas(string(role), adminstore.PermRequestsRead)
}

func errInvalidTime(field string) error {
	return &timeParseError{field: field}
}

type timeParseError struct{ field string }

func (e *timeParseError) Error() string {
	return "invalid " + e.field + " format, use RFC3339"
}

// errInvalidRuleID rejects a non-uuid rule_id filter value with an explicit
// message (CORE-TRACE-04): the filter is contract, so invalid input is a 400
// naming the field — never a silently dropped filter.
func errInvalidRuleID(v string) error {
	return &invalidRuleIDError{value: v}
}

type invalidRuleIDError struct{ value string }

func (e *invalidRuleIDError) Error() string {
	return "invalid rule_id: must be a routing rule uuid (routing_rules.id)"
}

// apiOrgToolCalls returns the org's tool-call aggregate (top tools,
// per-model usage) for the analytics screen. days is optional (default 30).
func (h *AdminHandlers) apiOrgToolCalls() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		days := 30
		if v := r.URL.Query().Get("days"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				days = n
			}
		}
		rep, err := h.store.GetToolCallsReport(r.Context(), chi.URLParam(r, "id"), days)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, rep)
	}
}
