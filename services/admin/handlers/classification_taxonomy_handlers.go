package handlers

// E04-P01 W02-C03: admin API access to the org-scoped classification
// taxonomy (the W02-C01 model, the W02-C02 store).
//
// SPI-first after the pkg/secevents and inventory precedents: the store
// seam is a PARAMETER — nothing is added to AdminHandlers; the router
// wiring card mounts the routes when the release hardening window
// closes. admin.openapi.yaml is FROZEN for the window (orchestrator
// byte-frozen rule, 2026-11-07 — supersedes the dispatch's
// additive-blocks allowance; the drift gate stays green trivially). The
// wiring card will register the permission org:taxonomy.manage — not yet
// in the closed permission matrix (outside this delivery's write scope);
// until then the org-scope gate below is the enforcement: root operators
// and org-scoped admins on their own org (membership-only check, the
// requireOrgScope no-perm posture).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/reireirei/yabanin/pkg/dataclass"
)

// ClassificationTaxonomyStore is the seam the taxonomy API needs.
// *dataclass.Store satisfies it; the narrow interface keeps the handler
// testable without a database.
type ClassificationTaxonomyStore interface {
	GetTaxonomy(ctx context.Context, orgID string) (dataclass.Taxonomy, bool, error)
	PutTaxonomy(ctx context.Context, orgID string, t dataclass.Taxonomy, updatedBy string) (dataclass.Taxonomy, bool, error)
}

// taxonomyPutRequest is the write API body: labels ONLY. The org comes
// from the request scope (never the body), the version is store-managed
// (never client-supplied) — a client echoing back a GET response's
// org_id/version fields is harmless extra noise, the decode ignores them.
type taxonomyPutRequest struct {
	Labels []dataclass.Label `json:"labels"`
}

// taxonomyPutResponse is the write result: the stored taxonomy plus the
// idempotence signal (changed=false means the canonical label set was
// identical and the stored version did not move).
type taxonomyPutResponse struct {
	OrgID   string            `json:"org_id"`
	Labels  []dataclass.Label `json:"labels"`
	Version int64             `json:"version"`
	Changed bool              `json:"changed"`
}

// taxonomyReadAuditDetail is the journal payload of one read decision.
// It must be serialized with json.Marshal, never fmt.Sprintf %q: org_id
// is request-controlled and may carry control characters (the
// request_export rule, the inventory parity).
type taxonomyReadAuditDetail struct {
	OrgID   string `json:"org_id"`
	Scope   string `json:"scope,omitempty"`
	Outcome string `json:"outcome"`
	Labels  int    `json:"labels"`
}

// taxonomyWriteAuditDetail is the journal payload of one write decision
// (same posture as the read detail).
type taxonomyWriteAuditDetail struct {
	OrgID   string `json:"org_id"`
	Scope   string `json:"scope,omitempty"`
	Outcome string `json:"outcome"`
	Labels  int    `json:"labels"`
	Version int64  `json:"version,omitempty"`
	Changed bool   `json:"changed"`
}

// auditTaxonomyRead journals allowed reads and every authorization
// denial (allowed streams and fail-closed denials both land in the
// durable journal). Parameter noise (400s) and store failures (500s) do
// not journal — they are not authorization decisions.
func auditTaxonomyRead(h *AdminHandlers, r *http.Request, orgID, scope, outcome string, labels int) {
	action := "taxonomy_read"
	if outcome != "ok" {
		action = "taxonomy_read.denied"
	}
	details, err := json.Marshal(taxonomyReadAuditDetail{
		OrgID: orgID, Scope: scope, Outcome: outcome, Labels: labels,
	})
	if err != nil {
		// Unreachable for this all-scalar struct; fall back to a fixed,
		// valid-JSON marker rather than ever storing malformed JSON.
		details = []byte(`{"outcome":"detail_marshal_error"}`)
	}
	h.auditLogAction(r, action, "organization:"+orgID, string(details))
}

// auditTaxonomyWrite journals allowed writes and authorization denials
// (same posture as auditTaxonomyRead).
func auditTaxonomyWrite(h *AdminHandlers, r *http.Request, orgID, scope, outcome string, labels int, version int64, changed bool) {
	action := "taxonomy_write"
	if outcome != "ok" {
		action = "taxonomy_write.denied"
	}
	details, err := json.Marshal(taxonomyWriteAuditDetail{
		OrgID: orgID, Scope: scope, Outcome: outcome,
		Labels: labels, Version: version, Changed: changed,
	})
	if err != nil {
		details = []byte(`{"outcome":"detail_marshal_error"}`)
	}
	h.auditLogAction(r, action, "organization:"+orgID, string(details))
}

// GetClassificationTaxonomy serves the org taxonomy read
// (GET .../classification/taxonomy?org_id= or the {id} path value).
// Root may target any org (org_id required); an org-scoped admin is
// pinned to the middleware scope — a foreign org is 403 with a denied
// audit entry. A never-written org is 200 with the empty taxonomy
// (labels: [], version 0): absence of stored labels is not an error (the
// W02-C01 fixed choice — an explicitly stored empty list is
// distinguishable only by found/version, the API surfaces version 0 for
// never-written).
func (h *AdminHandlers) GetClassificationTaxonomy(store ClassificationTaxonomyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if store == nil {
			writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "classification taxonomy store is not wired"})
			return
		}
		providedOrg := r.URL.Query().Get("org_id")
		if providedOrg == "" {
			providedOrg = r.PathValue("id")
		}
		orgID := h.requireOrgScope(w, r, providedOrg)
		if orgID == "" {
			auditTaxonomyRead(h, r, providedOrg, OrgScopeFromRequest(r), "forbidden", 0)
			return
		}
		tax, found, err := store.GetTaxonomy(r.Context(), orgID)
		if err != nil {
			if errors.Is(err, dataclass.ErrEmptyOrgID) || errors.Is(err, dataclass.ErrInvalidOrgID) {
				writeJSON(w, http.StatusBadRequest, apiError{Error: "org_id must be a uuid"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, apiError{Error: "taxonomy read failed"})
			return
		}
		if !found {
			tax = dataclass.Taxonomy{OrgID: orgID, Labels: []dataclass.Label{}, Version: 0}
		}
		if tax.Labels == nil {
			tax.Labels = []dataclass.Label{} // labels marshal as [], never null
		}
		auditTaxonomyRead(h, r, orgID, OrgScopeFromRequest(r), "ok", len(tax.Labels))
		writeJSON(w, http.StatusOK, tax)
	}
}

// PutClassificationTaxonomy serves the org taxonomy write (PUT
// .../classification/taxonomy?org_id= or the {id} path value; body
// {"labels": [...]}). The org comes from the scope, the version is
// store-managed: the write is idempotent — an unchanged label set keeps
// the stored version (changed=false in the response). Validation
// failures are 400 with the W02-C01 ValidationError list verbatim
// ({"error": "invalid taxonomy", "errors": [...]}) — parameter noise is
// not journaled. Authorization denials journal as taxonomy_write.denied.
func (h *AdminHandlers) PutClassificationTaxonomy(store ClassificationTaxonomyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if store == nil {
			writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "classification taxonomy store is not wired"})
			return
		}
		providedOrg := r.URL.Query().Get("org_id")
		if providedOrg == "" {
			providedOrg = r.PathValue("id")
		}
		orgID := h.requireOrgScope(w, r, providedOrg)
		if orgID == "" {
			auditTaxonomyWrite(h, r, providedOrg, OrgScopeFromRequest(r), "forbidden", 0, 0, false)
			return
		}

		var req taxonomyPutRequest
		if err := decodeJSONBody(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid request body"})
			return
		}

		tax := dataclass.Taxonomy{OrgID: orgID, Labels: req.Labels}
		if err := tax.Validate(); err != nil {
			var verr *dataclass.ValidationError
			if errors.As(err, &verr) {
				writeJSON(w, http.StatusBadRequest, taxonomyValidationError{Error: "invalid taxonomy", Errors: verr.Errors})
				return
			}
			writeJSON(w, http.StatusInternalServerError, apiError{Error: "taxonomy validation failed"})
			return
		}

		stored, changed, err := store.PutTaxonomy(r.Context(), orgID, tax, adminIDFromContext(r))
		if err != nil {
			var verr *dataclass.ValidationError
			if errors.As(err, &verr) {
				writeJSON(w, http.StatusBadRequest, taxonomyValidationError{Error: "invalid taxonomy", Errors: verr.Errors})
				return
			}
			if errors.Is(err, dataclass.ErrEmptyOrgID) || errors.Is(err, dataclass.ErrInvalidOrgID) {
				writeJSON(w, http.StatusBadRequest, apiError{Error: "org_id must be a uuid"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, apiError{Error: "taxonomy write failed"})
			return
		}
		if stored.Labels == nil {
			stored.Labels = []dataclass.Label{}
		}
		auditTaxonomyWrite(h, r, orgID, OrgScopeFromRequest(r), "ok", len(stored.Labels), stored.Version, changed)
		writeJSON(w, http.StatusOK, taxonomyPutResponse{
			OrgID:   stored.OrgID,
			Labels:  stored.Labels,
			Version: stored.Version,
			Changed: changed,
		})
	}
}

// taxonomyValidationError renders the W02-C01 refusal with its full
// error list verbatim (the adversarial AC: «отказ со списком ошибок»,
// not a first-error refusal).
type taxonomyValidationError struct {
	Error  string   `json:"error"`
	Errors []string `json:"errors"`
}
