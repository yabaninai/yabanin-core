package handlers

// issues and revokes the /scim/v2 credentials.
//
//	POST   /api/organizations/{id}/scim/tokens              — issue (raw token shown ONCE)
//	GET    /api/organizations/{id}/scim/tokens              — list (metadata only)
//	DELETE /api/organizations/{id}/scim/tokens/{tokenID}    — revoke
//
// Gate: org:members.manage (root or the org's owners — the same gate that
// guards member invitations; SCIM provisioning is member administration).
// The raw token exists exactly once — in the create response. The database
// and every read path here see only its sha256 (W-SECADM parity with API
// keys and member invites). Every action writes an audit entry.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// CreateScimToken — POST /api/organizations/{id}/scim/tokens. Body:
// {"label": "okta-prod"} (optional). Response 201 carries the RAW token —
// the only time it ever leaves the server; the store keeps its sha256.
func (h *AdminHandlers) CreateScimToken() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store, ok := h.scimTokenStoreGuard(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("id")
		if h.requireOrgScope(w, r, orgID, adminstore.PermMembersManage) == "" {
			return
		}
		var req struct {
			Label string `json:"label"`
		}
		// An empty body is fine (the label is optional); anything unparseable
		// is a 400.
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		req.Label = trimLabel(req.Label)

		token, raw, err := store.CreateScimToken(r.Context(), orgID, req.Label, requestUserID(r))
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		h.auditLogAction(r, "create", "scim_token",
			"org="+orgID+",token="+token.ID+",label="+req.Label)
		// The raw token is returned NOWHERE else. Metadata never carries
		// hash material (ScimToken.TokenHash is json:"-").
		writeJSON(w, http.StatusCreated, map[string]any{
			"token":        raw,
			"token_record": token,
		})
	}
}

// ListScimTokens — GET /api/organizations/{id}/scim/tokens (metadata only).
func (h *AdminHandlers) ListScimTokens() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store, ok := h.scimTokenStoreGuard(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("id")
		if h.requireOrgScope(w, r, orgID, adminstore.PermMembersManage) == "" {
			return
		}
		tokens, err := store.ListScimTokens(r.Context(), orgID)
		if err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": tokens, "count": len(tokens)})
	}
}

// RevokeScimToken — DELETE /api/organizations/{id}/scim/tokens/{tokenID}.
// A revoked token answers 401 on /scim/v2 immediately (revoked_at is
// checked on every request).
func (h *AdminHandlers) RevokeScimToken() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store, ok := h.scimTokenStoreGuard(w, r)
		if !ok {
			return
		}
		orgID, tokenID := r.PathValue("id"), r.PathValue("tokenID")
		if h.requireOrgScope(w, r, orgID, adminstore.PermMembersManage) == "" {
			return
		}
		if err := store.RevokeScimToken(r.Context(), orgID, tokenID); err != nil {
			if errors.Is(err, adminstore.ErrNotFound) {
				h.respondError(w, r, fmt.Errorf("not found"), http.StatusNotFound)
				return
			}
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		h.auditLogAction(r, "revoke", "scim_token", "org="+orgID+",token="+tokenID)
		w.WriteHeader(http.StatusNoContent)
	}
}

// scimTokenStoreGuard writes the 503/500 for a missing store or capability.
func (h *AdminHandlers) scimTokenStoreGuard(w http.ResponseWriter, r *http.Request) (ScimStore, bool) {
	if !h.requireStore(w, r) {
		return nil, false
	}
	store := h.scimStore()
	if store == nil {
		h.respondError(w, r, fmt.Errorf("scim store not available"), http.StatusNotImplemented)
		return nil, false
	}
	return store, true
}

// trimLabel bounds the token label length.
func trimLabel(label string) string {
	const maxLabel = 128
	if len(label) > maxLabel {
		return label[:maxLabel]
	}
	return label
}
