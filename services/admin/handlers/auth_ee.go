package handlers

// D-UI-4 (owner decision 2026-11-06): the internal EE session-validation
// endpoint. The enterprise backend (A2 same-origin architecture,
// entitlement stays EE-side) relays the browser's raw Cookie header to
// POST /auth/ee/session and receives a fail-closed verdict produced by the
// SAME session-validation path as this console's own middleware
// (pkg/adminauth.ValidateSessionCookieHeader — no second parser, no new
// crypto). The route is guarded by a shared internal token and is
// feature-dark by default: without EE_INTERNAL_TOKEN the route is not
// mounted at all and the path answers the standard 404.

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"time"

	"github.com/reireirei/yabanin/pkg/adminauth"
)

// eeInternalTokenHeader is the shared-secret header EE must present on
// every call. A bearer-style header (not a cookie) keeps the endpoint
// stateless and out of the browser CSRF/cookie chain, like the /internal
// service API.
const eeInternalTokenHeader = "X-EE-Internal" //nolint:gosec // G101: header name, not a credential

// eeSessionMaxBody bounds the request envelope. It is tiny by contract
// ({"cookie": "..."}); the global admin body limit already applies, this is
// defense in depth for direct handler use.
const eeSessionMaxBody = 64 << 10

// SetEEInternalToken enables the EE session-validation endpoint
// (POST /auth/ee/session) by arming the X-EE-Internal guard. An empty token
// keeps the endpoint disabled — the route is then not mounted and the path
// answers 404 (feature-dark, zero surface by default).
func (h *AdminHandlers) SetEEInternalToken(token string) {
	h.eeInternalToken = token
}

// eeInternalGuard enforces the shared internal token. The comparison is
// constant-time (subtle.ConstantTimeCompare — the same primitive as the
// /metrics bearer guard; the existing AuthFromHeader/metricsBearerMatch
// helpers are bound to their own header names, so this guard states its
// own). A missing or wrong token is a bare 401 that does not vary with the
// failure mode.
func (h *AdminHandlers) eeInternalGuard(next http.Handler) http.Handler {
	token := h.eeInternalToken
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get(eeInternalTokenHeader)
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// eeSessionRequest is the pinned request contract: the raw Cookie header
// value exactly as the browser sent it and EE forwarded it.
type eeSessionRequest struct {
	Cookie string `json:"cookie"`
}

// eeSessionResponse is the pinned response contract. Every session verdict
// is HTTP 200 with this shape — invalid sessions are never a 401/403, and
// an invalid verdict always carries the same degenerate fields (no oracle:
// nothing about the rejection reason leaks through status code or payload).
type eeSessionResponse struct {
	Valid     bool   `json:"valid"`
	Subject   string `json:"subject"`
	ExpiresAt string `json:"expires_at"`
}

// invalidEESessionResponse is the uniform fail-closed verdict: subject is
// empty and expires_at is the RFC3339 zero time.
func invalidEESessionResponse() eeSessionResponse {
	return eeSessionResponse{
		Valid:     false,
		Subject:   "",
		ExpiresAt: time.Time{}.UTC().Format(time.RFC3339),
	}
}

// eeSessionValidation implements POST /auth/ee/session. Wiring mirrors
// sessionAuthMiddleware field-for-field (secret + rotation grace, the
// invalidation watermark, the durable RevocationStore and the live user
// revalidator), so a session is acceptable to EE exactly when it would be
// acceptable to the admin console on the same request.
func (h *AdminHandlers) eeSessionValidation() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req eeSessionRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, eeSessionMaxBody)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid request body"})
			return
		}

		verdict := adminauth.ValidateSessionCookieHeader(r.Context(), req.Cookie,
			h.sessionSecret, h.previousSessionSecret, h.sessionGraceStarted, h.sessionGrace,
			h.adminSessionsInvalidatedAt, h.sessionRevocations, h.adminSessionRevalidate)
		if verdict.Valid && verdict.UsedPrevious {
			h.logger.Warn("ee session validated with previous signing secret", "subject", verdict.Subject)
		}

		resp := invalidEESessionResponse()
		if verdict.Valid {
			resp.Valid = true
			resp.Subject = verdict.Subject
			resp.ExpiresAt = verdict.ExpiresAt.UTC().Format(time.RFC3339)
		}
		writeJSON(w, http.StatusOK, resp)
	}
}
