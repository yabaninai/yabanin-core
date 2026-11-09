package handlers

// flow (oidc.go): opt-in mounting, a one-time flow cookie, fail-closed user
// mapping, and a session issued by adminauth with the shared SessionDuration.
// The SAML protocol work — signature, issuer, audience, recipient, timestamps,
// InResponseTo, XML hardening — is github.com/crewjam/saml (pkg/adminauth/
// saml.go); this file owns only the HTTP/session semantics. User mapping is
// fail-closed exactly like OIDC: the asserted email must match an EXISTING
// active admin user; SAML never provisions accounts and never widens roles.

import (
	"crypto/sha256"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/crewjam/saml"

	"github.com/reireirei/yabanin/pkg/adminauth"
)

// SetSAMLSP enables the SAML SSO routes. Pass nil (or never call) to keep the
// console on the password flow — the default and a zero behavior change for
// deployments without the SAML IdP metadata URL.
func (h *AdminHandlers) SetSAMLSP(sp *adminauth.SAMLSP) {
	h.samlSP = sp
}

// SAMLMetadata serves the SP metadata XML for IdP-side import (the ACS and
// entity ID are pinned there). Mounted only when SAML is wired.
func (h *AdminHandlers) SAMLMetadata() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.samlSP == nil {
			http.NotFound(w, r)
			return
		}
		buf, err := xml.MarshalIndent(h.samlSP.SPMetadata(), "", "  ")
		if err != nil {
			h.logger.Error("saml metadata marshal", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(buf)
	}
}

// SAMLLogin starts the SAML flow: an AuthnRequest bound for the IdP
// (redirect, or an auto-submitting form when only POST binding exists) with
// the request ID sealed in a short-lived flow cookie.
func (h *AdminHandlers) SAMLLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.samlSP == nil {
			http.NotFound(w, r)
			return
		}
		authn, err := h.samlSP.NewAuthnRequest("")
		if err != nil {
			h.logger.Error("saml login: authn request failed", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		cookie, err := adminauth.NewSAMLFlowCookie(authn.Flow)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, cookie)
		if authn.RedirectURL != "" {
			http.Redirect(w, r, authn.RedirectURL, http.StatusFound)
			return
		}
		// POST binding fallback: crewjam's auto-submitting form. The CSP
		// mirrors samlsp's (inline script carries the submit, everything
		// else is locked down).
		w.Header().Add("Content-Security-Policy",
			"default-src; "+
				"script-src 'sha256-AjPdJSbZmeWHnEc5ykvJFay8FTWeTeRbs9dutfZ0HqE='; "+
				"reflected-xss block; referrer no-referrer;")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body>`))
		_, _ = w.Write(authn.PostForm)
		_, _ = w.Write([]byte(`</body></html>`))
	}
}

// SAMLACS is the Assertion Consumer Service: crewjam validates the response
// (signature against the IdP metadata, issuer, audience, ACS recipient,
// timestamps, InResponseTo against the flow cookie), then the replay guard,
// the fail-closed user mapping and the session issuance run — the same shape
// as OIDCCallback. The one-time flow cookie is cleared on EVERY outcome.
func (h *AdminHandlers) SAMLACS() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.samlSP == nil {
			http.NotFound(w, r)
			return
		}
		if !h.requireStore(w, r) {
			return
		}
		flowCookie, err := r.Cookie(adminauth.SAMLFlowCookieName)
		if err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		flow, err := adminauth.ParseSAMLFlowCookie(flowCookie.Value)
		if err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		http.SetCookie(w, adminauth.ClearSAMLFlowCookie())

		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		// This deployment does not use RelayState for navigation. Reject any
		// returned value rather than accepting an unbound or substituted target.
		if r.Form.Get("RelayState") != "" {
			http.Error(w, "sso login failed", http.StatusUnauthorized)
			return
		}
		assertion, err := h.samlSP.ParseACSResponse(r, flow.RequestID)
		if err != nil {
			// Verification failure (signature/issuer/audience/expiry/
			// InResponseTo): fail closed; log the library's private reason,
			// never response material.
			var invalid *saml.InvalidResponseError
			if errors.As(err, &invalid) && invalid.PrivateErr != nil {
				err = invalid.PrivateErr
			}
			h.logger.Warn("saml acs: verification failed", "error", err)
			http.Error(w, "sso login failed", http.StatusUnauthorized)
			return
		}
		// crewjam does not dedupe assertion IDs: a byte-for-byte replay of
		// a still-valid response would re-run the mapping. The replay guard
		// refuses the second presentation.
		if !h.samlSP.MarkAssertionSeen(assertion.ID) {
			h.logger.Warn("saml acs: assertion replay refused", "assertion_id_hash", hashForLog(assertion.ID))
			http.Error(w, "sso login failed", http.StatusUnauthorized)
			return
		}
		email, err := adminauth.AssertionEmail(assertion)
		if err != nil {
			h.logger.Warn("saml acs: no usable email identity", "error", err)
			http.Error(w, "sso login failed", http.StatusUnauthorized)
			return
		}
		// Fail-closed mapping: the asserted email must match an existing
		// ACTIVE admin user. Same error for unknown and disabled accounts
		// (no user enumeration) — identical to the OIDC flow.
		user, err := h.store.GetAdminUserByEmailWithHash(r.Context(), email)
		if err != nil || !user.Active {
			h.logger.Warn("saml acs: user mapping refused", "email_domain", domainOf(email))
			http.Error(w, "sso login refused", http.StatusForbidden)
			return
		}

		// IssuedAt participates in the password-change watermark defense
		// (sessionInvalidated): a zero issued-at is the legacy marker that
		// fails closed once any password change is recorded, so omitting it
		// here would brick every SAML login after a password/SCIM change.
		// Stamp the ACS wall-clock — the assertion itself is already fully
		// validated above (signature, issuer, audience, timestamps); this is
		// the moment the LOCAL session begins, same as the OIDC callback and
		// password login. A session held across a later password change keeps
		// its earlier issued-at and stays rejected (fail-closed).
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
		// Login audit trail: the actor columns are context-derived and
		// this request carries no session yet, so the mapped user is part
		// of the details. The asserted role attribute (when the
		// deployment set YABANIN_SAML_ROLE_ATTR) is recorded for
		// information only — the session's authority is the DB user,
		// never the assertion.
		details := "sso=saml,idp=" + h.samlSP.IDPEntityID() + ",user=" + user.ID
		if assertedRole := adminauth.AssertionAttribute(assertion, h.samlSP.RoleAttribute); assertedRole != "" {
			details += ",asserted_role=" + assertedRole
		}
		h.auditLogActionWithCtx(r.Context(), r, "login", "admin_user", details)
		http.SetCookie(w, cookie)
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

// hashForLog renders a stable non-reversible marker of an identifier so
// replay refusals can be correlated in the logs without leaking raw IDs.
func hashForLog(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum[:6])
}

// SAMLSLO is the local Single Logout endpoint the SP metadata advertises
// (SloURL /auth/saml/slo): it clears the LOCAL admin session and redirects
// to the login page — deliberately not a full SAML SLO protocol exchange, so
// mount the local session-clear variant). Mirrors HandleLogout: the session
// and CSRF cookies expire; the IdP-side session is the IdP's own concern.
func (h *AdminHandlers) SAMLSLO() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.samlSP == nil {
			http.NotFound(w, r)
			return
		}
		if cookie, err := r.Cookie("yabanin_admin_session"); err == nil && cookie.Value != "" {
			session, _, parseErr := adminauth.ParseAdminSessionCookieRotating(
				cookie.Value, h.sessionSecret, h.previousSessionSecret,
				h.sessionGraceStarted, h.sessionGrace, time.Now(),
			)
			if parseErr == nil {
				// Match password logout: invalidate immediately in this process,
				// then persist the revocation for other replicas.
				adminauth.RevokeSessionID(session.SessionID, session.ExpiresAt)
				if h.sessionRevocations == nil {
					h.respondError(w, r, fmt.Errorf("durable session revocation unavailable"), http.StatusServiceUnavailable)
					return
				}
				if err := h.sessionRevocations.Revoke(r.Context(), session.SessionID, session.ExpiresAt); err != nil {
					if h.logger != nil {
						h.logger.Error("admin SAML session revocation failed", "error", err)
					}
					// Do not confirm logout while another replica may still
					// accept the durable session. Retain the cookie for retry.
					h.respondError(w, r, fmt.Errorf("could not complete logout"), http.StatusServiceUnavailable)
					return
				}
			}
		}
		http.SetCookie(w, adminauth.ClearSessionCookie())
		http.SetCookie(w, &http.Cookie{
			Name:     "yabanin_csrf_token",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   -1,
		})
		http.Redirect(w, r, "/auth/login", http.StatusFound)
	}
}

// Constant-time note: this handler introduces no new secret comparison. The
// InResponseTo match happens inside crewjam against the flow cookie's request
// ID — a 128-bit random value issued per login whose knowledge is worthless
// without a valid signature — and the replay guard is a keyed map lookup.
// The session cookie itself stays HMAC-verified by adminauth (hmac.Equal).
