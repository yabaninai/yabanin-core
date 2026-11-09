package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

type requestPayloadGrantStore interface {
	CreateRequestPayloadGrant(orgID, requestID, rootID string, ttl time.Duration, now time.Time) (adminstore.RequestPayloadGrant, error)
	CreateRequestPayloadGrantScope(orgID, requestID, rootID, scope string, ttl time.Duration, now time.Time) (adminstore.RequestPayloadGrant, error)
	ConsumeRequestPayloadGrant(token, orgID, requestID, rootID string, now time.Time) bool
	ConsumeRequestPayloadGrantScope(token, orgID, requestID, rootID, scope string, now time.Time) error
	RevokeRequestPayloadGrant(token, rootID string) error
	ListRequestPayloadGrants(ctx context.Context, rootID string) ([]adminstore.RequestPayloadGrant, error)
}

// apiRootRequestPayloadGrant performs an explicit root self-grant for one
// request. The returned bearer token is single-use and expires within 15m.
// It is available only on the root-only route.
func (h *AdminHandlers) apiRootRequestPayloadGrant() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		if !isRoot(r) || requestUserID(r) == "" {
			writeJSON(w, http.StatusForbidden, apiError{Error: "root self-grant is required"})
			return
		}
		store, ok := h.store.(requestPayloadGrantStore)
		if !ok {
			writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "request payload grants are unavailable"})
			return
		}
		var body struct {
			Action     string `json:"action"`
			Scope      string `json:"scope"`
			TTLSeconds int    `json:"ttl_seconds"`
			OrgID      string `json:"org_id"`
			RequestID  string `json:"request_id"`
			Token      string `json:"payload_grant"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid request payload grant action"})
			return
		}
		switch body.Action {
		case "list":
			grants, err := store.ListRequestPayloadGrants(r.Context(), requestUserID(r))
			if err != nil {
				writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "request payload grants are unavailable"})
				return
			}
			writeJSON(w, http.StatusOK, grants)
			return
		case "revoke":
			if body.Token == "" {
				writeJSON(w, http.StatusBadRequest, apiError{Error: "payload_grant is required"})
				return
			}
			if err := store.RevokeRequestPayloadGrant(body.Token, requestUserID(r)); err != nil {
				writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "request payload grant revocation failed"})
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		case "", "issue":
		default:
			writeJSON(w, http.StatusBadRequest, apiError{Error: "unknown request payload grant action"})
			return
		}
		if body.TTLSeconds < 1 || body.TTLSeconds > int(adminstore.MaxRequestPayloadGrantTTL/time.Second) {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "ttl_seconds must be between 1 and 900"})
			return
		}
		now := time.Now().UTC()
		orgID, requestID, rootID := body.OrgID, body.RequestID, requestUserID(r)
		if orgID == "" || requestID == "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "org_id and request_id are required"})
			return
		}
		scope := body.Scope
		if scope == "" {
			scope = adminstore.RequestPayloadScopeRead
		}
		if scope != adminstore.RequestPayloadScopeRead && scope != adminstore.RequestPayloadScopeOriginals {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "scope must be payload.read or payload.read_originals"})
			return
		}
		grant, err := store.CreateRequestPayloadGrantScope(orgID, requestID, rootID, scope, time.Duration(body.TTLSeconds)*time.Second, now)
		if err != nil {
			status := http.StatusServiceUnavailable
			if errors.Is(err, adminstore.ErrInvalidRequestPayloadGrant) {
				status = http.StatusBadRequest
			}
			writeJSON(w, status, apiError{Error: "request payload grant could not be issued"})
			return
		}
		writeJSON(w, http.StatusCreated, struct {
			GrantID   string    `json:"grant_id"`
			Token     string    `json:"payload_grant"`
			OrgID     string    `json:"org_id"`
			RequestID string    `json:"request_id"`
			ExpiresAt time.Time `json:"expires_at"`
		}{grant.ID, grant.Token, grant.OrgID, grant.RequestID, grant.ExpiresAt})
	}
}
