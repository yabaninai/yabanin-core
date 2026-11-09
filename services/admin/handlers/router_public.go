package handlers

// scrape, and the auth subrouter (login/logout/CSRF/OIDC SSO). Mounted by
// SetupRouter; the only guards are the login rate limiter, the /metrics
// bearer key (W-SECADM) and, for /auth/csrf, the session re-validation
// middleware (TP-02).

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/adminauth"
	"github.com/reireirei/yabanin/pkg/httpmw"
	"github.com/reireirei/yabanin/pkg/metrics"
)

// SetMetricsBearerKey wires the /metrics bearer credential (W-SECADM). When
// set, every /metrics scrape must carry "Authorization: Bearer <key>"
// (constant-time compare, 401 otherwise). An empty key keeps the legacy
// behavior — the scrape is protected by network restriction only, as
// documented in config.yaml — so existing single-host deployments keep
// working until an operator opts in.
func (h *AdminHandlers) SetMetricsBearerKey(key string) {
	h.metricsBearerKey = key
}

// metricsBearerGuard enforces the /metrics bearer key when one is
// configured. The comparison is constant-time and the check runs before the
// method guard so an unauthenticated probe learns nothing, not even which
// methods are allowed.
func (h *AdminHandlers) metricsBearerGuard(next http.Handler) http.Handler {
	key := h.metricsBearerKey
	if key == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !metricsBearerMatch(key, r.Header.Get("Authorization")) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// metricsBearerMatch parses the Authorization header and compares the bearer
// token against the configured key in constant time.
func metricsBearerMatch(key, authorization string) bool {
	const prefix = "Bearer "
	token, ok := strings.CutPrefix(authorization, prefix)
	if !ok || token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(key)) == 1
}

// mountPublic registers the routes that need no admin session: health,
// metrics, and the auth subrouter.
func (h *AdminHandlers) mountPublic(r chi.Router) {
	// Public routes — no auth required
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// W-SECADM: /metrics is no longer freely readable when a bearer key is
	// configured (SetMetricsBearerKey).
	r.With(h.metricsBearerGuard, httpmw.MethodGuard(http.MethodGet, http.MethodHead)).Handle("/metrics", metrics.PrometheusHandler())

	authR := chi.NewRouter()
	authR.Get("/login", h.LoginPage())
	// Rate limit login attempts per client IP
	authR.With(adminauth.OriginValidation()).Post("/login", h.loginRateLimitMiddleware(h.HandleLogin()))
	authR.With(adminauth.OriginValidation()).Get("/logout", h.HandleLogout())
	// Logout as a POST form action carries CSRF (adminauth.
	// CSRFValidation: cookie vs X-CSRF-Token header or _csrf form field);
	// GET stays for backward compatibility.
	authR.With(adminauth.OriginValidation(), adminauth.CSRFValidation()).Post("/logout", h.HandleLogout())
	// TP-02: the CSRF endpoint re-validates the session user like the
	// protected group — a deleted/deactivated admin cannot mint tokens.
	authR.With(h.sessionAuthMiddleware()).Get("/csrf", h.CSRFToken())
	// OIDC SSO (opt-in): mounted only when the client is wired. The flow
	// START carries its own per-IP budget (N04-P01 T10, ssoStartLimit): it
	// mints a state/PKCE flow and redirects to the IdP, so an unthrottled
	// entry would let one address turn the console into an amplification
	// vector against the provider. The budget is looser than the password
	// login's (no credential guessing happens here) but well under the
	// global limiter. The callback stays outside — it is gated by the
	// state-bound one-time flow cookie before any expensive work, and
	// limiting it could strand a mid-flow user.
	if h.oidcClient != nil {
		authR.Get("/oidc/login", h.ssoStartRateLimitMiddleware(h.OIDCLogin()))
		authR.Get("/oidc/callback", h.OIDCCallback())
	}
	// SAML SSO (opt-in): mounted only when the SP is wired — no
	// IdP metadata configuration means the routes answer 404 (bit-for-bit
	// parity with the unconfigured-OIDC behavior). The SP-initiated flow
	// start is throttled like the OIDC one; the ACS POST is not — its XML
	// is parsed before any verification and every assertion is bound to a
	// state this SP minted.
	if h.samlSP != nil {
		authR.Get("/saml/metadata", h.SAMLMetadata())
		authR.Get("/saml/login", h.ssoStartRateLimitMiddleware(h.SAMLLogin()))
		authR.Post("/saml/acs", h.SAMLACS())
		// Local SLO — the SP metadata advertises SloURL (Redirect
		// and POST binding); both verbs clear the local session.
		authR.Get("/saml/slo", h.SAMLSLO())
		authR.Post("/saml/slo", h.SAMLSLO())
	}
	// D-UI-4 (owner decision 2026-11-06): internal EE session-validation
	// endpoint. The enterprise backend relays the browser's raw Cookie
	// header and gets a fail-closed verdict from the SAME validation path
	// as this console's session middleware. Guarded by the shared internal
	// token (X-EE-Internal; env EE_INTERNAL_TOKEN, wired in services/run).
	// Feature-dark: without the token the route is not mounted at all and
	// POST /auth/ee/session answers the standard 404 — zero surface by
	// default. Like the /internal service API, header auth is stateless, so
	// the route deliberately sits outside the cookie session + CSRF chain.
	if h.eeInternalToken != "" {
		authR.With(h.eeInternalGuard).Post("/ee/session", h.eeSessionValidation())
	}

	r.Mount("/auth", authR)

	// W-INV: the public invite-acceptance page (no admin session — the
	// one-time token IS the authority). GET renders the form in the token's
	// state; POST consumes the invite (form POST + CSRF pair, same
	// discipline as the login form).
	inviteR := chi.NewRouter()
	inviteR.Get("/{token}", h.InvitePage())
	inviteR.Post("/{token}", h.HandleInviteAccept())
	r.Mount("/invite", inviteR)
}
