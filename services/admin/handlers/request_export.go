package handlers

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

const (
	maxRequestExportRows  = 1000
	maxRequestExportBytes = 10 << 20
)

type requestHistoryExportStore interface {
	StreamRequestExport(context.Context, adminstore.RequestListFilters, adminstore.RequestPayloadAccess, int, func(*adminstore.RequestDetail) error) (int, error)
}

// apiOrgRequestExport streams authorized request-detail records as JSONL.
// The one-request limit on a bearer grant is deliberate: grants are bound to
// an exact request ID and may not silently expand to an organization export.
func (h *AdminHandlers) apiOrgRequestExport() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		orgID := chi.URLParam(r, "id")
		filters, err := parseRequestListFilters(r, orgID)
		if err != nil {
			h.respondError(w, r, err, http.StatusBadRequest)
			return
		}
		grantToken := requestPayloadGrantToken(r)
		if grantToken != "" && filters.RequestID == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "payload grants require request_id filter"})
			return
		}
		// N04-P05 T03 negative: an agent/CI subject requesting the originals
		// scope is a scope-escalation attempt — requests.read_originals is
		// never delegatable. Deny loudly (no silent downgrade to payload.read)
		// and journal the attempt.
		if subject, hasSubject := adminstore.RequestPayloadSubjectFromContext(r.Context()); hasSubject &&
			subject.Type != "" && subject.Type != adminstore.RequestPayloadHuman &&
			r.URL.Query().Get("scope") == adminstore.RequestPayloadScopeOriginals {
			auditRequestExportDecision(h, r, orgID, filters, adminstore.RequestPayloadScopeOriginals, false, "scope_escalation_denied", 0)
			writeJSON(w, http.StatusForbidden, apiError{Error: "request payload scope is not available for this subject"})
			return
		}
		filters.Page, filters.PageSize = 1, 200
		if !authorizeRequestList(h, r, &filters) {
			auditRequestExportDecision(h, r, orgID, filters, "", false, "authorization_denied", 0)
			writeJSON(w, http.StatusForbidden, apiError{Error: "request history access denied"})
			return
		}
		payloadAllowed := filters.PayloadGrant
		grantScope := ""
		if grantToken != "" {
			grantScope = r.URL.Query().Get("scope")
			if grantScope == "" {
				grantScope = adminstore.RequestPayloadScopeRead
			}
			if grantScope != adminstore.RequestPayloadScopeRead && grantScope != adminstore.RequestPayloadScopeOriginals {
				writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid payload scope"})
				return
			}
			if !isRoot(r) || adminstore.RequestPayloadDenyOwnHistoryFromContext(r.Context()) {
				// Explicit policy deny must not burn the token, and a bearer
				// grant is a root self-grant: never a delegation to a subject.
				auditRequestExportDecision(h, r, orgID, filters, grantScope, false, "grant_unusable", 0)
				writeJSON(w, http.StatusForbidden, apiError{Error: "request payload grant cannot be used"})
				return
			}
		}
		originalsAllowed := grantScope == adminstore.RequestPayloadScopeOriginals
		if originalsAllowed {
			retention, ok := h.store.(orgOriginalRetentionStore)
			if !ok {
				auditRequestExportDecision(h, r, orgID, filters, grantScope, false, "retention_unavailable", 0)
				writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "original retention setting is unavailable"})
				return
			}
			setting, err := retention.GetOrgOriginalRetention(r.Context(), orgID)
			if err != nil {
				// Fail closed: a retention lookup error never opens originals.
				auditRequestExportDecision(h, r, orgID, filters, grantScope, false, "retention_unavailable", 0)
				h.respondError(w, r, err, http.StatusServiceUnavailable)
				return
			}
			if !setting.Effective {
				auditRequestExportDecision(h, r, orgID, filters, grantScope, false, "original_retention_disabled", 0)
				writeJSON(w, http.StatusForbidden, apiError{Error: "original payload retention is disabled"})
				return
			}
		}
		// ---- Phase: prechecks (read-only, no disclosure, grant untouched) ----
		// FIX-08 (OBS-01): the export-capability check and the pre-flight
		// count are safe prechecks and must run BEFORE the one-time consume,
		// so a 503/500/413 here denies with the grant still redeemable and is
		// journalled as a denial. The consume below stays the last step
		// before the 200 response commit; any failure after disclosure starts
		// is final (token stays consumed, never refunded).
		exporter, ok := h.store.(requestHistoryExportStore)
		if !ok {
			auditRequestExportDecision(h, r, orgID, filters, grantScope, false, "export_unavailable", 0)
			writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "request export is unavailable"})
			return
		}
		// ---- Phase: grant target resolution (peek — never a consume) ----
		// A grant redemption discloses exactly the one physical row the
		// grant is bound to: the peek resolves its immutable row key, and
		// the pinned predicate below makes match, count, and emission all
		// address that row. A legacy pre-binding grant denies generically
		// without burning. Like every precheck this runs before the
		// one-time consume, so its denials leave the token redeemable.
		rowKey := int64(0)
		grantStore, hasGrantStore := h.store.(requestPayloadGrantStore)
		if grantToken != "" {
			if !hasGrantStore {
				auditRequestExportDecision(h, r, orgID, filters, grantScope, false, "grant_unusable", 0)
				writeJSON(w, http.StatusForbidden, apiError{Error: "request payload grant cannot be used"})
				return
			}
			var perr error
			rowKey, perr = grantStore.PeekRequestPayloadGrantTarget(r.Context(), grantToken, orgID, filters.RequestID, requestUserID(r), time.Now().UTC())
			if perr != nil {
				// Invalid, expired, revoked, replayed, wrong org/grantee/
				// request, unbound legacy, or a grant-store failure: the
				// same fail-closed generic 403, token untouched.
				auditRequestExportDecision(h, r, orgID, filters, grantScope, false, "grant_invalid_or_unavailable", 0)
				writeJSON(w, http.StatusForbidden, apiError{Error: "request payload grant is invalid or unavailable"})
				return
			}
		}
		// The pre-flight count is a discarded metadata read over the SAME
		// predicate the disclosure stream will walk — user filters included —
		// so the row cap matches what the stream would emit. For a grant
		// redemption the predicate is pinned to the bound physical row key
		// (0031): the count decides whether the bound row still exists AND
		// matches the caller's filters (zero → 404, token untouched), while
		// correlation siblings sharing request_id (0028) can neither satisfy
		// the pin nor trip the 1000-row cap against an exactly-one-row grant.
		// No row from this call is ever emitted; disclosure still requires
		// the verified atomic consume before any payload byte is written.
		preflight := filters
		if grantToken != "" {
			preflight.OrgWideMetadata = true
			preflight.OwnerUserID = ""
			preflight.PayloadGrant = true
			preflight.PayloadSearchAllowed = true
			preflight.PayloadUserID = ""
			preflight.RowKey = rowKey
		}
		_, total, err := h.store.ListRequests(r.Context(), preflight)
		if err != nil {
			auditRequestExportDecision(h, r, orgID, filters, grantScope, false, "store_error", 0)
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		if grantToken != "" && total == 0 {
			// Bound row purged, cross-org, or not matching the caller's
			// filters: deny without burning, indistinguishable from absent.
			auditRequestExportDecision(h, r, orgID, filters, grantScope, false, "row_not_found", 0)
			h.respondError(w, r, adminstore.ErrNotFound, http.StatusNotFound)
			return
		}
		if total > maxRequestExportRows {
			auditRequestExportDecision(h, r, orgID, filters, grantScope, false, "row_limit", 0)
			writeJSON(w, http.StatusRequestEntityTooLarge, apiError{Error: "export exceeds 1000-row limit; narrow the time range or filters"})
			return
		}
		// ---- Phase: atomic one-time consume (last step before disclosure) ----
		if grantToken != "" {
			if _, err := grantStore.ConsumeRequestPayloadGrantScope(grantToken, orgID, filters.RequestID, rowKey, requestUserID(r), grantScope, time.Now().UTC()); err != nil {
				// Grant-store failures and invalid, expired, revoked,
				// wrong-scope, or already-consumed tokens have the same
				// fail-closed response: a rolled-back consume leaves the
				// token redeemable.
				auditRequestExportDecision(h, r, orgID, filters, grantScope, false, "grant_invalid_or_unavailable", 0)
				writeJSON(w, http.StatusForbidden, apiError{Error: "request payload grant is invalid or unavailable"})
				return
			}
			// Stream the exact predicate the pre-flight verified: the
			// caller's filters pinned to the bound row under the widened
			// grant view. authorizeRequestList owner-scopes filters to the
			// caller, which would mask a bound row owned by a different
			// user or agent — pre-flight would pass, the token would burn,
			// and the stream would emit an empty 200. Retention and role
			// constraints ran unchanged above. From here the grant is
			// consumed: the attempt is final.
			filters = preflight
			payloadAllowed = true
		}
		// ---- Phase: disclosure (the 200 commits; stream failures are final) ----
		access := adminstore.RequestPayloadAccess{
			UserID: filters.PayloadUserID, Grant: payloadAllowed,
			Originals:      originalsAllowed,
			DenyOwnHistory: filters.PayloadDenied, OrgWideMetadata: filters.OrgWideMetadata,
		}
		if filters.DelegateAgentID != "" {
			// Delegated subject (N04-P05 T03): the stream is pinned to the
			// subject's own attribution; payload scope only when delegated.
			// Originals stay closed — never delegatable.
			subject, _ := adminstore.RequestPayloadSubjectFromContext(r.Context())
			access = adminstore.RequestPayloadAccess{
				Delegated: true, Grant: filters.DelegatePayload, Originals: false, DenyOwnHistory: false,
				SubjectType: subject.Type, AgentID: subject.AgentID, APIKeyID: subject.APIKeyID,
			}
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", `attachment; filename="requests.jsonl"`)
		w.Header().Add("Trailer", "X-Export-Error")
		w.WriteHeader(http.StatusOK)
		bw := bufio.NewWriter(w)
		written := 0
		emitted := 0
		_, err = exporter.StreamRequestExport(r.Context(), filters, access, maxRequestExportRows, func(detail *adminstore.RequestDetail) error {
			line, err := json.Marshal(detail)
			if err != nil || written+len(line)+1 > maxRequestExportBytes {
				w.Header().Set("X-Export-Error", "byte_limit")
				return errors.New("request export byte limit exceeded")
			}
			line = append(line, '\n')
			n, err := bw.Write(line)
			written += n
			if err != nil || bw.Flush() != nil {
				w.Header().Set("X-Export-Error", "write_error")
				return errors.New("request export write failed")
			}
			emitted++
			return nil
		})
		outcome := "completed"
		if err != nil {
			if errors.Is(err, adminstore.ErrRequestExportTooLarge) {
				outcome = "row_limit"
				w.Header().Set("X-Export-Error", "row_limit")
			} else if w.Header().Get("X-Export-Error") == "" {
				outcome = "store_error"
				w.Header().Set("X-Export-Error", "store_error")
			} else {
				outcome = w.Header().Get("X-Export-Error")
			}
		}
		auditRequestExportDecision(h, r, orgID, filters, grantScope, true, outcome, emitted)
	}
}

// requestExportAuditDetail is the journal payload of one export decision.
// It must be serialized with json.Marshal, never fmt.Sprintf %q: request_id
// is query-controlled and may carry control characters or invalid UTF-8, and
// %q emits \x1b-style escapes that strict JSON parsers reject — a single
// hostile request_id would corrupt the whole journal payload.
type requestExportAuditDetail struct {
	OrgID     string `json:"org_id"`
	RequestID string `json:"request_id"`
	Scope     string `json:"scope"`
	Payload   bool   `json:"payload"`
	Originals bool   `json:"originals"`
	Outcome   string `json:"outcome"`
	Rows      int    `json:"rows"`
}

// auditRequestExportDecision journals every export authorization decision via
// the durable admin audit seam (AF-10): allowed streams and every fail-closed
// denial. Details carry only identifiers and content flags — never payload
// content and never the bearer grant token. Audit degradation (outbox /
// memory-pending) follows the shared journal path, so it never turns a denial
// into an allow.
func auditRequestExportDecision(h *AdminHandlers, r *http.Request, orgID string, f adminstore.RequestListFilters, scope string, allowed bool, outcome string, rows int) {
	action := "request_export"
	if !allowed {
		action = "request_export.denied"
	}
	if scope == "" {
		scope = adminstore.RequestPayloadScopeRead
	}
	details, err := json.Marshal(requestExportAuditDetail{
		OrgID:     orgID,
		RequestID: f.RequestID,
		Scope:     scope,
		Payload:   f.PayloadGrant && allowed,
		Originals: scope == adminstore.RequestPayloadScopeOriginals && allowed,
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

func requestPayloadGrantToken(r *http.Request) string {
	if token := r.Header.Get("X-Request-Payload-Grant"); token != "" {
		return token
	}
	return r.URL.Query().Get("payload_grant")
}

// authorizeRequestList applies the same content decision and row scoping used
// by the request explorer list and stats endpoints. For a marked agent/CI
// subject it evaluates the principal delegation chain (N04-P05 T03): rows are
// scoped to the subject's own attribution, payload scope only when the
// delegation carries it.
func authorizeRequestList(h *AdminHandlers, r *http.Request, f *adminstore.RequestListFilters) bool {
	subject, hasSubject := adminstore.RequestPayloadSubjectFromContext(r.Context())
	human := !hasSubject || subject.Type == "" || subject.Type == adminstore.RequestPayloadHuman
	delegRead, delegPayload := false, false
	if !human && subject.AgentID != "" {
		delegRead, delegPayload = h.evaluateSubjectDelegation(r, f.OrgID, subject)
	}
	verdict := h.authorizeRequestContent(r, f.OrgID, f.RequestID, false, delegRead || delegPayload)
	if human {
		f.PayloadUserID = requestUserID(r)
	} else if delegRead && verdict.Allowed {
		// Trusted attribution scope from the authenticated subject — never a
		// query parameter. Only a live delegation sets it.
		f.DelegateAgentID = subject.AgentID
		f.DelegatePayload = delegPayload
	}
	f.OwnerUserID = f.PayloadUserID
	f.OrgWideMetadata = h.hasOrgWideRequestMetadata(r, f.OrgID)
	f.PayloadDenied = !verdict.Allowed
	role, member := h.callerRoleOnOrg(r, f.OrgID)
	f.PayloadGrant = human && member && adminstore.RoleHas(string(role), adminstore.PermRequestsPayloads) && verdict.Allowed
	f.PayloadSearchAllowed = verdict.Allowed && (f.PayloadUserID != "" || f.PayloadGrant || f.DelegatePayload)
	f.PayloadAuthorizationSet = true
	return verdict.Allowed || f.OrgWideMetadata
}
