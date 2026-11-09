package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/inbox"
	"github.com/reireirei/yabanin/pkg/secevents"
)

// E06-P01 W01-C03: read-only security-inbox endpoints for the admin API.
//
// GET /api/organizations/{id}/security-inbox            list, newest first
//   ?severity=low|medium|high          exact-match filter (W03-C02)
//   ?confidence_min=0&confidence_max=1  inclusive range filter (W03-C02)
//   ?sort=last_seen|severity|confidence descending, default last_seen (W03-C02)
// GET /api/organizations/{id}/security-inbox/{incident_id}
// PATCH /api/organizations/{id}/security-inbox/{incident_id}
//   {"status": "...", "assignee": "<uuid>"|null}     operator writes (W04-C02)
//
// Reads sit behind RequireOrgPermission(PermSecurityRead): root passes, a
// non-root caller needs a role holding security.read on the path organization
// (org_admin, security_auditor). PATCH sits behind PermSecurityManage
// (W04-C02): org_admin only — the operator write surface is deliberately
// narrower than the read surface. The middleware resolves the org from the
// path and pins the scope; a caller with no role there is 403 before the
// handler runs (the house-wide unjournaled middleware denial, same as every
// other org-permission route). The handler journals the outcomes it does see
// — allowed reads, 404s, patch outcomes — through the shared audit path.
//
// The W03-C02 filter/sort params are handler-level (v1: the org's incidents
// are listed, then filtered/sorted in the handler); documented in
// docs/api/OPENAPI-DELTA.md (shape change of an existing endpoint).

// securityInboxStore is the store capability these handlers need — the exact
// surface of *inbox.Store. The production delegate is built from the admin
// pool (see securityInboxDelegate; the adapter lives here because
// pkg/adminstore cannot import pkg/inbox — that would close an import cycle
// through pkg/eventpublisher).
type securityInboxStore interface {
	List(ctx context.Context, orgID uuid.UUID) ([]inbox.Incident, error)
	Get(ctx context.Context, orgID, incidentID uuid.UUID) (inbox.Incident, bool, error)
}

// securityInboxPoolStore is the pool capability the production adminstore.Store
// exposes; the delegate inbox store is org-pinned per read.
type securityInboxPoolStore interface {
	DB() *pgxpool.Pool
}

// securityInboxDelegate resolves the inbox store for this handler set: a
// store implementing the capability directly (tests), else the shared admin
// pool. False means the capability is absent (503).
func (h *AdminHandlers) securityInboxDelegate() (securityInboxStore, bool) {
	if st, ok := h.store.(securityInboxStore); ok {
		return st, true
	}
	if ps, ok := h.store.(securityInboxPoolStore); ok && ps.DB() != nil {
		return inbox.NewStore(ps.DB()), true
	}
	return nil, false
}

// securityIncidentJSON is the wire shape of one incident. The handler layer
// owns the API casing; pkg/inbox stays storage-shaped.
type securityIncidentJSON struct {
	ID           uuid.UUID               `json:"id"`
	OrgID        uuid.UUID               `json:"org_id"`
	GroupKey     string                  `json:"group_key"`
	Summary      string                  `json:"summary"`
	Severity     string                  `json:"severity"`
	Confidence   float64                 `json:"confidence"`
	Status       string                  `json:"status"`
	Assignee     *uuid.UUID              `json:"assignee,omitempty"`
	FirstSeen    time.Time               `json:"first_seen"`
	LastSeen     time.Time               `json:"last_seen"`
	EventCount   int64                   `json:"event_count"`
	FirstEventID string                  `json:"first_event_id"`
	LastEventID  string                  `json:"last_event_id"`
	Evidence     []secevents.EvidenceRef `json:"evidence"`
}

func newSecurityIncidentJSON(inc inbox.Incident) securityIncidentJSON {
	out := securityIncidentJSON{
		ID:           inc.ID,
		OrgID:        inc.OrgID,
		GroupKey:     inc.GroupKey,
		Summary:      inc.Summary,
		Severity:     inc.Severity,
		Confidence:   inc.Confidence,
		Status:       inc.Status,
		Assignee:     inc.Assignee,
		FirstSeen:    inc.FirstSeen,
		LastSeen:     inc.LastSeen,
		EventCount:   inc.EventCount,
		FirstEventID: inc.FirstEventID,
		LastEventID:  inc.LastEventID,
		Evidence:     inc.Evidence,
	}
	if out.Evidence == nil {
		out.Evidence = []secevents.EvidenceRef{}
	}
	return out
}

// securityInboxAuditDetail is the audit journal payload. It is always
// marshaled (never Sprintf'd) so values with control characters cannot
// corrupt the row.
type securityInboxAuditDetail struct {
	OrgID      string `json:"org_id"`
	IncidentID string `json:"incident_id,omitempty"`
	Outcome    string `json:"outcome"`
	Rows       int    `json:"rows,omitempty"`
}

func (h *AdminHandlers) auditSecurityInbox(r *http.Request, orgID uuid.UUID, incidentID string, outcome string, rows int) {
	detail := securityInboxAuditDetail{
		OrgID:      orgID.String(),
		IncidentID: incidentID,
		Outcome:    outcome,
		Rows:       rows,
	}
	action := "security_inbox"
	if outcome == "denied" {
		action = "security_inbox.denied"
	}
	b, err := json.Marshal(detail)
	if err != nil {
		// The struct is marshal-infallible; keep the journal write anyway.
		b = []byte(`{"outcome":"` + outcome + `"}`)
	}
	h.auditLogAction(r, action, "organization:"+orgID.String(), string(b))
}

// securityInboxOrg resolves and authorizes the target organization for the
// request. It returns false after writing the error response.
func (h *AdminHandlers) securityInboxOrg(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	raw := chi.URLParam(r, "id")
	orgID, err := uuid.Parse(raw)
	if err != nil {
		h.respondError(w, r, errors.New("invalid organization id"), http.StatusBadRequest)
		return uuid.Nil, false
	}
	if h.requireOrgScope(w, r, orgID.String()) == "" {
		// Defensive: under RequireOrgPermission the scope is pinned to the
		// path org, so this arm is not normally reachable; journal it as a
		// denial if the scope machinery ever evolves.
		h.auditSecurityInbox(r, orgID, chi.URLParam(r, "incident_id"), "denied", 0)
		return uuid.Nil, false
	}
	return orgID, true
}

// securityInboxListParams is the parsed W03-C02 query surface of the list
// endpoint. Zero values mean "not supplied" (no filtering, default sort).
type securityInboxListParams struct {
	Severity string   // exact dictionary match when non-empty
	ConfMin  *float64 // inclusive lower bound when non-nil
	ConfMax  *float64 // inclusive upper bound when non-nil
	Sort     string   // last_seen | severity | confidence (never empty after parse)
}

// securityInboxSortDictionary is the closed sort-key dictionary. Every key
// sorts DESCENDING (worst/newest first — an operator inbox); ties break
// deterministically by incident id so equal keys are never unstable.
const (
	sortLastSeen   = "last_seen"
	sortSeverity   = "severity"
	sortConfidence = "confidence"
)

// severityRankDesc mirrors the inbox severity order for sorting (high
// first). The dictionary itself is owned by pkg/inbox (model.go).
func severityRankDesc(s string) int {
	switch s {
	case inbox.SeverityHigh:
		return 0
	case inbox.SeverityMedium:
		return 1
	default:
		return 2
	}
}

// parseSecurityInboxListParams validates the W03-C02 query surface. Every
// invalid value is a 400 (the card's fail-loud law): an unknown severity
// word, a non-numeric or out-of-[0,1] confidence bound, an inverted range,
// or an unknown sort key. Absent params keep the pre-W03-C02 behavior
// (unfiltered, newest first) byte-for-byte.
func parseSecurityInboxListParams(q url.Values) (securityInboxListParams, error) {
	p := securityInboxListParams{Sort: sortLastSeen}
	if s := q.Get("severity"); s != "" {
		switch s {
		case inbox.SeverityLow, inbox.SeverityMedium, inbox.SeverityHigh:
			p.Severity = s
		default:
			return p, fmt.Errorf("invalid severity filter %q (dictionary: low|medium|high)", s)
		}
	}
	for _, b := range []struct {
		name   string
		target **float64
	}{
		{"confidence_min", &p.ConfMin},
		{"confidence_max", &p.ConfMax},
	} {
		raw := q.Get(b.name)
		if raw == "" {
			continue
		}
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil || v < 0 || v > 1 {
			return p, fmt.Errorf("invalid %s %q (must be a number in [0,1])", b.name, raw)
		}
		*b.target = &v
	}
	if p.ConfMin != nil && p.ConfMax != nil && *p.ConfMin > *p.ConfMax {
		return p, fmt.Errorf("confidence_min %g must be <= confidence_max %g", *p.ConfMin, *p.ConfMax)
	}
	if s := q.Get("sort"); s != "" {
		switch s {
		case sortLastSeen, sortSeverity, sortConfidence:
			p.Sort = s
		default:
			return p, fmt.Errorf("invalid sort %q (dictionary: last_seen|severity|confidence)", s)
		}
	}
	return p, nil
}

// applySecurityInboxListParams filters and orders the org's incidents per
// the parsed params (handler-level, v1). The returned slice is always a
// fresh copy — the store's slice is never mutated.
func applySecurityInboxListParams(incidents []inbox.Incident, p securityInboxListParams) []inbox.Incident {
	out := make([]inbox.Incident, 0, len(incidents))
	for _, inc := range incidents {
		if p.Severity != "" && inc.Severity != p.Severity {
			continue
		}
		if p.ConfMin != nil && inc.Confidence < *p.ConfMin {
			continue
		}
		if p.ConfMax != nil && inc.Confidence > *p.ConfMax {
			continue
		}
		out = append(out, inc)
	}
	less := func(a, b inbox.Incident) bool {
		switch p.Sort {
		case sortSeverity:
			if ra, rb := severityRankDesc(a.Severity), severityRankDesc(b.Severity); ra != rb {
				return ra < rb
			}
		case sortConfidence:
			if a.Confidence != b.Confidence {
				return a.Confidence > b.Confidence
			}
		}
		// last_seen (and every tie): newest first, then incident id — a
		// deterministic total order under equal keys.
		if !a.LastSeen.Equal(b.LastSeen) {
			return a.LastSeen.After(b.LastSeen)
		}
		return a.ID.String() < b.ID.String()
	}
	sort.Slice(out, func(i, j int) bool { return less(out[i], out[j]) })
	return out
}

func (h *AdminHandlers) apiOrgSecurityInbox() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		orgID, ok := h.securityInboxOrg(w, r)
		if !ok {
			return
		}
		params, err := parseSecurityInboxListParams(r.URL.Query())
		if err != nil {
			h.respondError(w, r, err, http.StatusBadRequest)
			return
		}
		st, ok := h.securityInboxDelegate()
		if !ok {
			h.respondError(w, r, errors.New("security inbox is unavailable"), http.StatusServiceUnavailable)
			return
		}
		incidents, err := st.List(r.Context(), orgID)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		rows := make([]securityIncidentJSON, 0, len(incidents))
		for _, inc := range applySecurityInboxListParams(incidents, params) {
			rows = append(rows, newSecurityIncidentJSON(inc))
		}
		h.auditSecurityInbox(r, orgID, "", "allowed", len(rows))
		writeJSON(w, http.StatusOK, struct {
			Data []securityIncidentJSON `json:"data"`
		}{Data: rows})
	}
}

func (h *AdminHandlers) apiOrgSecurityIncident() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		orgID, ok := h.securityInboxOrg(w, r)
		if !ok {
			return
		}
		incidentID, err := uuid.Parse(chi.URLParam(r, "incident_id"))
		if err != nil {
			h.respondError(w, r, errors.New("invalid incident id"), http.StatusBadRequest)
			return
		}
		st, ok := h.securityInboxDelegate()
		if !ok {
			h.respondError(w, r, errors.New("security inbox is unavailable"), http.StatusServiceUnavailable)
			return
		}
		incident, found, err := st.Get(r.Context(), orgID, incidentID)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		if !found {
			// Foreign-org and missing incidents are indistinguishable: the
			// store scopes by (org_id, id) and the caller has no role on
			// other orgs, so 404 without leaking existence.
			h.auditSecurityInbox(r, orgID, incidentID.String(), "not_found", 0)
			h.respondError(w, r, errors.New("incident not found"), http.StatusNotFound)
			return
		}
		h.auditSecurityInbox(r, orgID, incidentID.String(), "allowed", 1)
		writeJSON(w, http.StatusOK, struct {
			Data securityIncidentJSON `json:"data"`
		}{Data: newSecurityIncidentJSON(incident)})
	}
}

// securityInboxPatchStore is the write capability the PATCH endpoint needs
// on top of the read surface (the exact signature of *inbox.Store's
// ApplyOperatorPatch, W04-C01). Kept separate so read-only test stores
// (batch A) compile untouched and the patch route degrades to 503 instead
// of breaking reads.
type securityInboxPatchStore interface {
	ApplyOperatorPatch(ctx context.Context, orgID, incidentID uuid.UUID, patch inbox.OperatorPatch) (inbox.Incident, bool, error)
}

// securityInboxPatchDelegate resolves the patch capability: a store
// implementing it directly, else the shared admin pool (production
// *inbox.Store satisfies both). False means 503.
func (h *AdminHandlers) securityInboxPatchDelegate() (securityInboxPatchStore, bool) {
	if st, ok := h.store.(securityInboxPatchStore); ok {
		return st, true
	}
	if ps, ok := h.store.(securityInboxPoolStore); ok && ps.DB() != nil {
		return inbox.NewStore(ps.DB()), true
	}
	return nil, false
}

// securityInboxPatchRequest is the W04-C02 wire body. Status absent means
// untouched; Assignee distinguishes all three states on the wire — absent
// (nil raw message: untouched), null (clear) and a uuid string (set). A
// non-pointer RawMessage is required: a *RawMessage collapses JSON null to
// a nil pointer, erasing the null-vs-absent distinction.
type securityInboxPatchRequest struct {
	Status   *string         `json:"status"`
	Assignee json.RawMessage `json:"assignee"`
}

// securityInboxPatchOutcomes are the journaled PATCH outcomes (one row per
// request, action security_inbox.patch).
const (
	patchOutcomePatched  = "patched"
	patchOutcomeNoop     = "noop"
	patchOutcomeConflict = "conflict"
	patchOutcomeNotFound = "not_found"
)

func (h *AdminHandlers) auditSecurityInboxPatch(r *http.Request, orgID, incidentID uuid.UUID, outcome string) {
	detail := securityInboxAuditDetail{
		OrgID:      orgID.String(),
		IncidentID: incidentID.String(),
		Outcome:    outcome,
	}
	b, err := json.Marshal(detail)
	if err != nil {
		b = []byte(`{"outcome":"` + outcome + `"}`)
	}
	h.auditLogAction(r, "security_inbox.patch", "organization:"+orgID.String(), string(b))
}

// parseSecurityInboxPatch validates the body into the store's OperatorPatch
// (fail-loud 400s: malformed JSON, an empty patch, an unknown status word,
// a non-uuid assignee). The transition itself is NOT checked here — its
// from-state comes from the row, so it stays store law (409).
func parseSecurityInboxPatch(body []byte) (inbox.OperatorPatch, error) {
	var req securityInboxPatchRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return inbox.OperatorPatch{}, errors.New("malformed JSON body")
	}
	var out inbox.OperatorPatch
	if req.Status != nil {
		switch *req.Status {
		case inbox.StatusNew, inbox.StatusAcknowledged, inbox.StatusInProgress, inbox.StatusResolved, inbox.StatusDismissed:
			out.Status = req.Status
		default:
			return out, fmt.Errorf("unknown status %q (dictionary: new|acknowledged|in_progress|resolved|dismissed)", *req.Status)
		}
	}
	if req.Assignee != nil {
		out.AssigneeSet = true
		if trimmed := strings.TrimSpace(string(req.Assignee)); trimmed != "null" {
			if err := json.Unmarshal(req.Assignee, &out.Assignee); err != nil {
				return out, errors.New("assignee must be a uuid or null")
			}
			if out.Assignee == uuid.Nil {
				return out, errors.New("assignee must be a uuid or null")
			}
		}
	}
	if out.Status == nil && !out.AssigneeSet {
		return out, errors.New("empty patch: at least one of status, assignee is required")
	}
	return out, nil
}

// apiOrgSecurityIncidentPatch is the W04-C02 operator write: one status
// transition and/or one assignee change per request. Same-state patches are
// legal no-ops (200, row untouched — the store law) and are journaled as
// outcome noop so the trail shows intent. Classification reads the row
// first; it is advisory only — under a concurrent patch the journaled
// outcome may say noop where the store applied the write, never the
// reverse, and the row itself stays store-law exact.
func (h *AdminHandlers) apiOrgSecurityIncidentPatch() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		orgID, ok := h.securityInboxOrg(w, r)
		if !ok {
			return
		}
		incidentID, err := uuid.Parse(chi.URLParam(r, "incident_id"))
		if err != nil {
			h.respondError(w, r, errors.New("invalid incident id"), http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			h.respondError(w, r, err, http.StatusBadRequest)
			return
		}
		patch, err := parseSecurityInboxPatch(body)
		if err != nil {
			h.respondError(w, r, err, http.StatusBadRequest)
			return
		}
		pst, ok := h.securityInboxPatchDelegate()
		if !ok {
			h.respondError(w, r, errors.New("security inbox is unavailable"), http.StatusServiceUnavailable)
			return
		}
		// Advisory noop classification (see comment above): the row's
		// pre-state, read through the read capability.
		var before *inbox.Incident
		if st, ok := h.securityInboxDelegate(); ok {
			if current, found, gerr := st.Get(r.Context(), orgID, incidentID); gerr == nil && found {
				before = &current
			}
		}
		updated, found, err := pst.ApplyOperatorPatch(r.Context(), orgID, incidentID, patch)
		if err != nil {
			if errors.Is(err, inbox.ErrInvalidTransition) {
				h.auditSecurityInboxPatch(r, orgID, incidentID, patchOutcomeConflict)
				h.respondError(w, r, err, http.StatusConflict)
				return
			}
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		if !found {
			// Foreign-org and missing incidents are indistinguishable (404),
			// exactly like the read path.
			h.auditSecurityInboxPatch(r, orgID, incidentID, patchOutcomeNotFound)
			h.respondError(w, r, errors.New("incident not found"), http.StatusNotFound)
			return
		}
		outcome := patchOutcomePatched
		if patchIsNoop(before, &updated) {
			outcome = patchOutcomeNoop
		}
		h.auditSecurityInboxPatch(r, orgID, incidentID, outcome)
		writeJSON(w, http.StatusOK, struct {
			Data securityIncidentJSON `json:"data"`
		}{Data: newSecurityIncidentJSON(updated)})
	}
}

// patchIsNoop reports whether the patch changed nothing: the pre-state and
// post-state agree on both operator fields. (The store skips the UPDATE
// exactly when the intent equals the row, so row equality is the law.)
func patchIsNoop(before, after *inbox.Incident) bool {
	if before == nil {
		return false // pre-state unknown: classify as patched (advisory only)
	}
	return before.Status == after.Status && equalIncidentAssignee(before.Assignee, after.Assignee)
}

// equalIncidentAssignee compares two optional assignee values.
func equalIncidentAssignee(a, b *uuid.UUID) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// sameWireAssignee compares the row's optional assignee with the patch's
// (uuid.Nil means clear). Mirrors the store's sameAssignee.
func sameWireAssignee(current *uuid.UUID, patch uuid.UUID) bool {
	if patch == uuid.Nil {
		return current == nil
	}
	return current != nil && *current == patch
}

// mountSecurityInbox registers the security-inbox API. Reads are GET behind
// PermSecurityRead; the W04-C02 operator write is PATCH behind the narrower
// PermSecurityManage (org_admin only).
func (h *AdminHandlers) mountSecurityInbox(protected chi.Router) {
	g := protected.With(h.RequireOrgPermission(adminstore.PermSecurityRead))
	g.Get("/api/organizations/{id}/security-inbox", h.apiOrgSecurityInbox())
	g.Get("/api/organizations/{id}/security-inbox/{incident_id}", h.apiOrgSecurityIncident())
	gp := protected.With(h.RequireOrgPermission(adminstore.PermSecurityManage))
	gp.Patch("/api/organizations/{id}/security-inbox/{incident_id}", h.apiOrgSecurityIncidentPatch())
}
