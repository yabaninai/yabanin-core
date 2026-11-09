package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

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
func (h *AdminHandlers) apiOrgRequestDetail() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		orgID := chi.URLParam(r, "id")
		requestID := requestIDParam(r)
		userID := requestUserID(r)
		orgWideMetadata := h.hasOrgWideRequestMetadata(r, orgID)
		subject, hasSubject := adminstore.RequestPayloadSubjectFromContext(r.Context())
		human := !hasSubject || subject.Type == "" || subject.Type == adminstore.RequestPayloadHuman
		// ---- Phase: prechecks (read-only, no disclosure, grant untouched) ----
		// FIX-08 detail symmetry: scope validation, grant usability and the
		// retention gate are safe prechecks and must run BEFORE the one-time
		// consume, so a 400/403/503 here denies with the grant still
		// redeemable and is journalled as a denial. A request without a
		// bearer token takes the metadata-only path and never consumes.
		grant := false
		originalsGrant := false
		grantScope := ""
		token := requestPayloadGrantToken(r)
		if token != "" {
			grantScope = r.URL.Query().Get("scope")
			if grantScope == "" {
				grantScope = adminstore.RequestPayloadScopeRead
			}
			if grantScope != adminstore.RequestPayloadScopeRead && grantScope != adminstore.RequestPayloadScopeOriginals {
				writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid payload scope"})
				return
			}
			// A bearer grant is a root self-grant: a caller without the grant
			// capability or under an explicit policy deny must neither use
			// nor burn it. Fail closed loudly (the export contract) instead
			// of silently degrading to a metadata read.
			_, hasGrantStore := h.store.(requestPayloadGrantStore)
			if !hasGrantStore || !isRoot(r) || adminstore.RequestPayloadDenyOwnHistoryFromContext(r.Context()) {
				auditRequestDetailDecision(h, r, orgID, requestID, grantScope, false, 0, "grant_unusable")
				writeJSON(w, http.StatusForbidden, apiError{Error: "request payload grant cannot be used"})
				return
			}
			if grantScope == adminstore.RequestPayloadScopeOriginals {
				// Retention gates originals fail-closed BEFORE the consume:
				// a lookup error never opens originals and never burns the
				// token.
				retention, ok := h.store.(orgOriginalRetentionStore)
				if !ok {
					auditRequestDetailDecision(h, r, orgID, requestID, grantScope, false, 0, "retention_unavailable")
					writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "original retention setting is unavailable"})
					return
				}
				setting, err := retention.GetOrgOriginalRetention(r.Context(), orgID)
				if err != nil {
					auditRequestDetailDecision(h, r, orgID, requestID, grantScope, false, 0, "retention_unavailable")
					h.respondError(w, r, err, http.StatusServiceUnavailable)
					return
				}
				if setting == nil || !setting.Effective {
					auditRequestDetailDecision(h, r, orgID, requestID, grantScope, false, 0, "original_retention_disabled")
					writeJSON(w, http.StatusForbidden, apiError{Error: "original payload retention is disabled"})
					return
				}
				originalsGrant = true
			}
			// Grant-hypothetical from here (the export preflight pattern):
			// the verdict and the row read below run under the widened access
			// the verified consume would grant. Nothing from these reads is
			// ever disclosed unless the atomic consume succeeds — on a failed
			// consume the read result is discarded with a generic 403.
			grant = true
		}
		delegRead, delegPayload := false, false
		if !human {
			// N04-P05 T03: a marked agent/CI subject acts under a live
			// principal delegation, or not at all. The delegation can only
			// ever surface the subject's OWN attributed rows (the store pins
			// the lookup), and originals are never delegatable.
			delegRead, delegPayload = h.evaluateSubjectDelegation(r, orgID, subject)
		}
		verdict := h.authorizeRequestContent(r, orgID, requestID, grant, delegRead || delegPayload)
		role, member := h.callerRoleOnOrg(r, orgID)
		roleGrant := human && member && adminstore.RoleHas(string(role), adminstore.PermRequestsPayloads)
		var access adminstore.RequestPayloadAccess
		switch {
		case !human && delegRead && verdict.Allowed:
			access = adminstore.RequestPayloadAccess{
				Grant: delegPayload, Delegated: true, DenyOwnHistory: false,
				SubjectType: subject.Type, AgentID: subject.AgentID, APIKeyID: subject.APIKeyID,
			}
		case !human:
			// No delegation: the legacy fail-closed path (deny-own-history,
			// no bearer grant, 404 unless another visibility branch applies).
			access = adminstore.RequestPayloadAccess{
				Grant: grant, DenyOwnHistory: true, SubjectType: subject.Type, AgentID: subject.AgentID, APIKeyID: subject.APIKeyID,
			}
		default:
			access = adminstore.RequestPayloadAccess{
				UserID: userID, Grant: verdict.Allowed && (grant || roleGrant), Originals: verdict.Allowed && originalsGrant, DenyOwnHistory: adminstore.RequestPayloadDenyOwnHistoryFromContext(r.Context()),
				SubjectType: subject.Type, AgentID: subject.AgentID, APIKeyID: subject.APIKeyID, OrgWideMetadata: orgWideMetadata,
			}
		}
		// ---- Phase: pre-consume row read (the discarded read) ----
		// Reading the row before the consume only decides 404/500: a missing
		// (or not-visible) row and a store failure deny with the grant still
		// redeemable instead of burning it on a response that carries no
		// payload. The read runs under the grant-hypothetical access built
		// above; its result is discarded unless the verified atomic consume
		// below succeeds — no byte of it is written before that, so the
		// hypothetical widening can never turn into disclosure.
		ctx := adminstore.WithRequestPayloadAccess(r.Context(), access)
		d, err := h.store.GetRequestDetail(ctx, orgID, requestID)
		if err != nil {
			if adminstore.IsNotFound(err) {
				if token != "" {
					auditRequestDetailDecision(h, r, orgID, requestID, grantScope, false, 0, "row_not_found")
				}
				h.respondError(w, r, err, http.StatusNotFound)
				return
			}
			if token != "" {
				auditRequestDetailDecision(h, r, orgID, requestID, grantScope, false, 0, "store_error")
			}
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		// ---- Phase: atomic one-time consume (last step before disclosure) ----
		if token != "" {
			grantStore, ok := h.store.(requestPayloadGrantStore)
			if !ok || grantStore.ConsumeRequestPayloadGrantScope(token, orgID, requestID, userID, grantScope, time.Now().UTC()) != nil {
				// Invalid, expired, revoked, wrong-scope, bound to a different
				// request or organization, already consumed (replay), or a
				// grant-store failure: the same fail-closed generic 403 with
				// zero row bytes. The pre-consume read is discarded here, so
				// invalid and replayed grants stay indistinguishable
				// (anti-oracle), and a failed consume never burns the token.
				auditRequestDetailDecision(h, r, orgID, requestID, grantScope, false, 0, "grant_invalid_or_unavailable")
				writeJSON(w, http.StatusForbidden, apiError{Error: "request payload grant is invalid or unavailable"})
				return
			}
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
