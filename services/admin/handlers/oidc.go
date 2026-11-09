package handlers

// OIDC SSO endpoints for the admin console (Authorization Code + PKCE +
// nonce, see pkg/adminauth/oidc.go). Mounted only when the admin config
// carries a complete issuer/client/secret/redirect tuple — the password
// flow stays the default. User mapping is fail-closed: a verified email
// must match an EXISTING active admin user; SSO never provisions accounts,
// never widens roles (the session carries the same IsRoot as the password
// flow) and only redirects to a validated same-origin return path on success.

import (
	"crypto/hmac"
	"fmt"
	"net/http"
	"time"

	"github.com/reireirei/yabanin/pkg/adminauth"
)

const maxOIDCReturnTargetBytes = 2048

// W-SECADM: the SSO flow issues sessions with the same adminauth.
// SessionDuration as the password flow (no local override anymore).

// OIDCLogin starts the SSO flow: a fresh state/nonce/PKCE triple and
// validated return path stored in a short-lived cookie, then redirects to
// the provider.
func (h *AdminHandlers) OIDCLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.oidcClient == nil {
			http.NotFound(w, r)
			return
		}
		flow, err := adminauth.NewOIDCFlow()
		if err != nil {
			h.logger.Error("oidc: flow generation failed", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		flow.Next = safeOIDCReturnTarget(r.URL.Query().Get("next"))
		cookie, err := adminauth.NewOIDCFlowCookie(flow)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, cookie)
		http.Redirect(w, r, h.oidcClient.AuthCodeURL(flow), http.StatusFound)
	}
}

// OIDCCallback finishes the SSO flow: state check (constant time), code
// exchange + ID token verification, fail-closed user mapping, session
// issuance. The one-time cookie is cleared on EVERY outcome — its secrets
// are single-use by construction.
func (h *AdminHandlers) OIDCCallback() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.oidcClient == nil {
			http.NotFound(w, r)
			return
		}
		if !h.requireStore(w, r) {
			return
		}
		flowCookie, err := r.Cookie(adminauth.OIDCFlowCookieName)
		if err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		flow, err := adminauth.ParseOIDCFlowCookie(flowCookie.Value)
		if err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next := safeOIDCReturnTarget(flow.Next)
		http.SetCookie(w, adminauth.ClearOIDCFlowCookie())

		q := r.URL.Query()
		if q.Get("error") != "" {
			// Provider-signalled failure (user denied, network at the IdP…).
			h.logger.Warn("oidc callback: provider error", "error", q.Get("error"))
			http.Error(w, "sso login failed", http.StatusUnauthorized)
			return
		}
		state := q.Get("state")
		if state == "" || !hmac.Equal([]byte(flow.State), []byte(state)) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		code := q.Get("code")
		if code == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		ident, err := h.oidcClient.ExchangeAndVerify(r.Context(), code, flow.Nonce, flow.PKCEVerifier)
		if err != nil {
			// Verification failure (signature/audience/nonce/expiry): fail
			// closed; log the reason, never the code or token material.
			h.logger.Warn("oidc callback: verification failed", "error", err)
			http.Error(w, "sso login failed", http.StatusUnauthorized)
			return
		}
		if !ident.EmailVerified {
			http.Error(w, "email not verified at the provider", http.StatusForbidden)
			return
		}
		// Fail-closed mapping: the verified email must match an existing
		// ACTIVE admin user. Same error for unknown and disabled accounts.
		user, err := h.store.GetAdminUserByEmailWithHash(r.Context(), ident.Email)
		if err != nil || !user.Active {
			h.logger.Warn("oidc callback: user mapping refused", "email_domain", domainOf(ident.Email))
			http.Error(w, "sso login refused", http.StatusForbidden)
			return
		}

		// N04-P01: reconcile the caller's org memberships with the
		// org-declared group→role rules at every SSO login (the sync point).
		// The verified token identity and the DB user are already
		// established; the sync itself is fail-open per step (logged, retried
		// at the next login) and never widens the session beyond the DB user.
		h.applySSORoleMapping(r.Context(), r, user.ID, ident.Groups, "oidc")

		issuedAt := time.Now()
		session := adminauth.AdminSession{
			UserID:    user.ID,
			Email:     user.Email,
			IsRoot:    user.IsRoot,
			SessionID: generateSessionID(),
			IssuedAt:  issuedAt,
			ExpiresAt: issuedAt.Add(adminauth.SessionDuration),
		}
		cookie, err := adminauth.CreateAdminSessionCookie(session, h.sessionSecret)
		if err != nil {
			h.respondError(w, r, fmt.Errorf("session error"), http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, cookie)
		http.Redirect(w, r, next, http.StatusFound)
	}
}

// safeOIDCReturnTarget bounds the value copied into the short-lived browser
// flow cookie. The cookie is client-held and unsigned, so callbacks also run
// this check before using it as a redirect target.
func safeOIDCReturnTarget(next string) string {
	target := safeRedirectTarget(next)
	if len(target) > maxOIDCReturnTargetBytes {
		return "/"
	}
	return target
}

// domainOf is a coarse attribution aid for the refusal log line — the local
// part of the email never reaches the logs.
func domainOf(email string) string {
	for i := len(email) - 1; i >= 0; i-- {
		if email[i] == '@' {
			return email[i+1:]
		}
	}
	return ""
}
