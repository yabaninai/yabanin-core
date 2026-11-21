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
	// PeekRequestPayloadGrantTarget resolves the bound physical row a
	// redeemable grant addresses without consuming it (FIX-08 precheck).
	PeekRequestPayloadGrantTarget(ctx context.Context, token, orgID, requestID, rootID string, now time.Time) (int64, error)
	ConsumeRequestPayloadGrant(token, orgID, requestID, rootID string, now time.Time) bool
	ConsumeRequestPayloadGrantScope(token, orgID, requestID string, rowKey int64, rootID, scope string, now time.Time) (adminstore.RequestPayloadGrant, error)
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
		body, ok := decodeRequestPayloadGrantAction(w, r)
		if !ok {
			return
		}
		switch body.Action {
		case "list":
			respondRequestPayloadGrantList(w, r, store)
			return
		case "revoke":
			respondRequestPayloadGrantRevoke(w, r, store, body.Token)
			return
		case "", "issue":
		default:
			writeJSON(w, http.StatusBadRequest, apiError{Error: "unknown request payload grant action"})
			return
		}
		orgID, requestID, scope, ttl, ok := parseRequestPayloadGrantIssue(w, body)
		if !ok {
			return
		}
		grant, err := store.CreateRequestPayloadGrantScope(orgID, requestID, requestUserID(r), scope, ttl, time.Now().UTC())
		if err != nil {
			respondRequestPayloadGrantIssueError(w, err)
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

// requestPayloadGrantAction is the root grant endpoint body: one of list,
// revoke or issue (the default).
type requestPayloadGrantAction struct {
	Action     string `json:"action"`
	Scope      string `json:"scope"`
	TTLSeconds int    `json:"ttl_seconds"`
	OrgID      string `json:"org_id"`
	RequestID  string `json:"request_id"`
	Token      string `json:"payload_grant"`
}

// decodeRequestPayloadGrantAction decodes the bounded action body. Returns
// false once the malformed-body 400 is written.
func decodeRequestPayloadGrantAction(w http.ResponseWriter, r *http.Request) (requestPayloadGrantAction, bool) {
	var body requestPayloadGrantAction
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid request payload grant action"})
		return body, false
	}
	return body, true
}

// respondRequestPayloadGrantList writes the caller's grant metadata list.
func respondRequestPayloadGrantList(w http.ResponseWriter, r *http.Request, store requestPayloadGrantStore) {
	grants, err := store.ListRequestPayloadGrants(r.Context(), requestUserID(r))
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "request payload grants are unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, grants)
}

// respondRequestPayloadGrantRevoke revokes one of the caller's grants.
// Returns false once a denial is written.
func respondRequestPayloadGrantRevoke(w http.ResponseWriter, r *http.Request, store requestPayloadGrantStore, token string) bool {
	if token == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "payload_grant is required"})
		return false
	}
	if err := store.RevokeRequestPayloadGrant(token, requestUserID(r)); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "request payload grant revocation failed"})
		return false
	}
	w.WriteHeader(http.StatusNoContent)
	return true
}

// parseRequestPayloadGrantIssue validates the issue fields: bounded TTL,
// required identifiers, exact-match scope enum (empty scope defaults to
// payload.read). Returns ok=false once the 400 is written.
func parseRequestPayloadGrantIssue(w http.ResponseWriter, body requestPayloadGrantAction) (orgID, requestID, scope string, ttl time.Duration, ok bool) {
	if body.TTLSeconds < 1 || body.TTLSeconds > int(adminstore.MaxRequestPayloadGrantTTL/time.Second) {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "ttl_seconds must be between 1 and 900"})
		return "", "", "", 0, false
	}
	if body.OrgID == "" || body.RequestID == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "org_id and request_id are required"})
		return "", "", "", 0, false
	}
	scope = body.Scope
	if scope == "" {
		scope = adminstore.RequestPayloadScopeRead
	}
	if scope != adminstore.RequestPayloadScopeRead && scope != adminstore.RequestPayloadScopeOriginals {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "scope must be payload.read or payload.read_originals"})
		return "", "", "", 0, false
	}
	return body.OrgID, body.RequestID, scope, time.Duration(body.TTLSeconds) * time.Second, true
}

// respondRequestPayloadGrantIssueError maps store issuance failures to the
// endpoint contract: invalid input 400, missing target 404, ambiguous
// target 409, everything else a fail-closed 503.
func respondRequestPayloadGrantIssueError(w http.ResponseWriter, err error) {
	status, message := http.StatusServiceUnavailable, "request payload grant could not be issued"
	switch {
	case errors.Is(err, adminstore.ErrInvalidRequestPayloadGrant):
		status = http.StatusBadRequest
	case errors.Is(err, adminstore.ErrRequestPayloadGrantTargetMissing):
		status, message = http.StatusNotFound, "request payload grant target not found"
	case errors.Is(err, adminstore.ErrRequestPayloadGrantTargetAmbiguous):
		status, message = http.StatusConflict, "request payload grant target is ambiguous; bind one physical row"
	}
	writeJSON(w, status, apiError{Error: message})
}
