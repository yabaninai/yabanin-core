package adminauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const sessionCookieName = "yabanin_admin_session"

// macEncoding is the only base64 variant used for session-cookie MACs, for
// signing and for verification. Strict mode rejects non-canonical spellings
// (non-zero discarded trailing bits in the final base64 character): lenient
// decoding accepted ~1/1024 of tampered spellings whose decoded MAC bytes
// were identical (suffix "XU" re-spelled "XX"), so a cookie could verify
// under a second text form. Signature verification must accept only the
// exact issued spelling. (AUTHFLAKESEC1, 2026-11-02.)
var macEncoding = base64.RawURLEncoding.Strict()

// AdminSession represents the contents of a signed admin session cookie.
type AdminSession struct {
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
	IsRoot    bool      `json:"is_root"`
	SessionID string    `json:"session_id"`
	IssuedAt  time.Time `json:"issued_at"` // Set at login; checked against the password-change watermark
	ExpiresAt time.Time `json:"expires_at"`
}

// RevocationStore is the durable source of truth for logged-out sessions.
type RevocationStore interface {
	IsRevoked(context.Context, string) (bool, error)
	Revoke(context.Context, string, time.Time) error
}

// SessionDuration is the default lifetime for an admin session cookie.
var SessionDuration = 24 * time.Hour

// CreateAdminSessionCookie creates a signed HMAC cookie containing the admin session.
func CreateAdminSessionCookie(session AdminSession, secret string) (*http.Cookie, error) {
	payload := fmt.Sprintf("%s|%s|%t|%s|%d|%d",
		session.UserID,
		session.Email,
		session.IsRoot,
		session.SessionID,
		session.ExpiresAt.Unix(),
		issuedAtUnixMillis(session.IssuedAt),
	)

	mac := createHMAC(payload, secret)
	token := payload + "|" + macEncoding.EncodeToString(mac)

	maxAge := int(time.Until(session.ExpiresAt).Seconds())
	if maxAge < 0 {
		maxAge = 0
	}
	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
	}, nil
}

// ParseAdminSessionCookie reads and verifies a signed admin session cookie.
func ParseAdminSessionCookie(cookieValue string, secret string) (*AdminSession, error) {
	lastSep := strings.LastIndex(cookieValue, "|")
	if lastSep < 0 {
		return nil, fmt.Errorf("invalid session cookie format")
	}

	payloadPart := cookieValue[:lastSep]
	givenMacStr := cookieValue[lastSep+1:]

	givenMac, err := macEncoding.DecodeString(givenMacStr)
	if err != nil {
		return nil, fmt.Errorf("decode session mac: %w", err)
	}

	expectedMac := createHMAC(payloadPart, secret)
	if !hmac.Equal(expectedMac, givenMac) {
		return nil, fmt.Errorf("session cookie signature mismatch")
	}

	parts := strings.Split(payloadPart, "|")
	if len(parts) < 5 {
		return nil, fmt.Errorf("invalid session payload format")
	}

	expiresAtUnix, err := strconv.ParseInt(parts[4], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse session expiry: %w", err)
	}

	// Issued-at is written by current cookies; legacy 5-part
	// cookies parse with a zero IssuedAt (fail-closed under the
	// invalidation guard, accepted while no password change is recorded).
	var issuedAt time.Time
	if len(parts) >= 6 {
		issuedMillis, perr := strconv.ParseInt(parts[5], 10, 64)
		if perr != nil {
			return nil, fmt.Errorf("parse session issued-at: %w", perr)
		}
		if issuedMillis > 0 {
			issuedAt = time.UnixMilli(issuedMillis)
		}
	}

	return &AdminSession{
		UserID:    parts[0],
		Email:     parts[1],
		IsRoot:    parts[2] == "true",
		SessionID: parts[3],
		IssuedAt:  issuedAt,
		ExpiresAt: time.Unix(expiresAtUnix, 0),
	}, nil
}

// ParseAdminSessionCookieRotating validates with the active key first and the
// previous key only while the process-local grace deadline has not elapsed.
// The bool reports successful validation with the previous key.
func ParseAdminSessionCookieRotating(cookieValue, secret, previous string, graceStarted time.Time, grace time.Duration, now time.Time) (*AdminSession, bool, error) {
	session, err := ParseAdminSessionCookie(cookieValue, secret)
	if err == nil {
		return session, false, nil
	}
	if previous == "" || previous == secret || grace <= 0 || now.Sub(graceStarted) >= grace || now.Before(graceStarted) {
		return nil, false, err
	}
	session, previousErr := ParseAdminSessionCookie(cookieValue, previous)
	if previousErr != nil {
		return nil, false, err
	}
	return session, true, nil
}

// EESessionVerdict is the fail-closed result of the internal EE
// session-validation endpoint (owner decision D-UI-4, 2026-11-06). Valid is
// true only when the shared admin session-validation sequence fully accepts
// the session. Subject and ExpiresAt come from the session record on
// success and are zero on every failure, so an invalid verdict carries no
// information about WHY the session was rejected — revoked, expired,
// malformed, store error and every other doubt are indistinguishable (no
// oracle). UsedPrevious mirrors the middleware's rotation-grace signal for
// operational logging on the caller's side.
type EESessionVerdict struct {
	Valid        bool
	Subject      string
	ExpiresAt    time.Time
	UsedPrevious bool
}

// ValidateSessionCookieHeader validates an admin session forwarded as a raw
// Cookie header value: the EE backend relays the browser's Cookie header
// verbatim ({"cookie": "<raw Cookie header value>"}), so the session cookie
// is extracted with net/http's own cookie parser — the same single parser
// the admin middleware relies on when it reads the cookie out of a live
// request — and then run through validateSession, the SAME validation
// sequence as the admin console middleware (signature + rotation grace,
// expiry, process-local revocation, durable RevocationStore, invalidation
// watermark, live user revalidation). There is no second parser and no new
// crypto here. Any doubt — missing or malformed cookie, bad signature,
// expired, revoked (process-locally or durably), watermark-invalidated,
// store error, deleted or deactivated user — collapses into the single
// invalid verdict.
func ValidateSessionCookieHeader(ctx context.Context, rawCookieHeader, secret, previous string, graceStarted time.Time, grace time.Duration, invalidatedAt SessionsInvalidatedAt, revocations RevocationStore, revalidate ...SessionRevalidator) EESessionVerdict {
	cookieValue, ok := sessionCookieValueFromHeader(rawCookieHeader)
	if !ok {
		return EESessionVerdict{}
	}
	verdict := validateSession(ctx, cookieValue, secret, previous, graceStarted, grace, nil, invalidatedAt, revocations, nil, revalidate...)
	if !verdict.ok {
		return EESessionVerdict{}
	}
	return EESessionVerdict{
		Valid:        true,
		Subject:      verdict.session.UserID,
		ExpiresAt:    verdict.session.ExpiresAt,
		UsedPrevious: verdict.usedPrevious,
	}
}

// sessionCookieValueFromHeader extracts the admin session cookie value from
// a raw Cookie header value using net/http's cookie parsing — the identical
// code path (readCookie) that extracts it from a live admin request.
func sessionCookieValueFromHeader(rawCookieHeader string) (string, bool) {
	if rawCookieHeader == "" {
		return "", false
	}
	header := http.Header{}
	header.Add("Cookie", rawCookieHeader)
	cookie, err := (&http.Request{Header: header}).Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return "", false
	}
	return cookie.Value, true
}

// ClearSessionCookie returns an expired cookie to clear the admin session.
func ClearSessionCookie() *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	}
}

// ContextKeyUserID keys the authenticated admin user ID in request context.
type ContextKeyUserID struct{}

// ContextKeyEmail keys the admin email in request context.
type ContextKeyEmail struct{}

// ContextKeyIsRoot keys the root-admin flag in request context.
type ContextKeyIsRoot struct{}

var (
	_ = ContextKeyUserID{} // no-op to avoid "imported and not used" if unused
)

// AuthProvider abstracts admin authentication. The default implementation
// uses DB-backed passwords; SSO providers can be swapped in later.
type AuthProvider interface {
	// Authenticate validates credentials and returns the admin user.
	Authenticate(ctx context.Context, email, password string) (*AdminUser, error)
	// GetUserByID retrieves an admin user by ID (without sensitive fields).
	GetUserByID(ctx context.Context, id string) (*AdminUser, error)
}

// AdminUser is a minimal representation of an authenticated admin.
type AdminUser struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	IsRoot      bool   `json:"is_root"`
	Active      bool   `json:"active"`
}

// DBProvider implements AuthProvider using the admin store.
type DBProvider struct {
	GetPasswordHash func(ctx context.Context, email string) (string, error)
	GetUserByIDFn   func(ctx context.Context, id string) (*AdminUser, error)
}

// Authenticate implements AuthProvider using DB password verification.
func (p *DBProvider) Authenticate(ctx context.Context, email, password string) (*AdminUser, error) {
	hash, err := p.GetPasswordHash(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("lookup password hash: %w", err)
	}
	if err := VerifyPassword(password, hash); err != nil {
		return nil, fmt.Errorf("invalid password")
	}
	user, err := p.GetUserByIDFn(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("get user by email: %w", err)
	}
	return user, nil
}

// GetUserByID implements AuthProvider.
func (p *DBProvider) GetUserByID(ctx context.Context, id string) (*AdminUser, error) {
	return p.GetUserByIDFn(ctx, id)
}

// writeUnauthorized answers an unauthenticated request. API paths (/api/*)
// get a JSON body for machine clients; everything else keeps the legacy
// plain-text response so the browser SPA and other consumers are unaffected.
func writeUnauthorized(w http.ResponseWriter, r *http.Request, msg string) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprintf(w, `{"error":%q}`, msg)
		return
	}
	http.Error(w, msg, http.StatusUnauthorized)
}

// SessionRevalidator re-checks the session's user against the live store on
// every request. The returned isRoot/active values come from the store and
// replace the role recorded in the cookie, so a deleted or demoted admin
// loses privileges when the DB says so, not when the cookie expires.
type SessionRevalidator func(ctx context.Context, userID string) (isRoot bool, active bool, err error)

// SessionsInvalidatedAt reports when the user's sessions were last
// invalidated (the admin_users.sessions_changed_at watermark). A zero
// time means no invalidation is recorded.
type SessionsInvalidatedAt func(ctx context.Context, userID string) (time.Time, error)

// sessionInvalidated reports whether the session predates the recorded
// invalidation. Legacy cookies (no issued-at) fail closed once an
// invalidation exists, and pass while none does.
func sessionInvalidated(issuedAt time.Time, invalidatedAt time.Time) bool {
	if invalidatedAt.IsZero() {
		return false
	}

	// Millisecond granularity: the cookie carries unix millis, so a
	// watermark in the same second must not swallow a session issued
	// moments later (login right after a password change).
	// Equality fails closed: a login issued in the same truncated
	// millisecond as the recorded change is treated as pre-change.
	return issuedAt.IsZero() || !issuedAt.After(invalidatedAt.Truncate(time.Millisecond))
}

// ChiAuthMiddleware is the unguarded middleware: signature and expiry only,
// plus the optional session revalidator (TP-02).
func ChiAuthMiddleware(secret string, revalidate ...SessionRevalidator) func(http.Handler) http.Handler {
	return ChiAuthMiddlewareGuarded(secret, nil, revalidate...)
}

// ChiAuthMiddlewareGuarded additionally checks the session against the
// invalidation watermark: a cookie issued before the recorded
// sessions_changed_at — or a legacy cookie without issued-at once an
// invalidation exists — is a 401, as is any guard lookup error (fail-closed).
func ChiAuthMiddlewareGuarded(secret string, invalidatedAt SessionsInvalidatedAt, revalidate ...SessionRevalidator) func(http.Handler) http.Handler {
	return ChiAuthMiddlewareGuardedWithRevocation(secret, invalidatedAt, nil, revalidate...)
}

// ChiAuthMiddlewareGuardedWithRevocation adds durable session revocation to
// the watermark and user-state checks. Store lookup errors fail closed.
func ChiAuthMiddlewareGuardedWithRevocation(secret string, invalidatedAt SessionsInvalidatedAt, revocations RevocationStore, revalidate ...SessionRevalidator) func(http.Handler) http.Handler {
	return ChiAuthMiddlewareRotatingWithRevocation(secret, "", time.Time{}, 0, time.Now, nil, invalidatedAt, revocations, revalidate...)
}

// ChiAuthMiddlewareRotating accepts the previous session key for a bounded
// process-start grace period. onPrevious is called after full authentication.
func ChiAuthMiddlewareRotating(secret, previous string, graceStarted time.Time, grace time.Duration, clock func() time.Time, onPrevious func(*http.Request, *AdminSession), invalidatedAt SessionsInvalidatedAt, revalidate ...SessionRevalidator) func(http.Handler) http.Handler {
	return ChiAuthMiddlewareRotatingWithRevocation(secret, previous, graceStarted, grace, clock, onPrevious, invalidatedAt, nil, revalidate...)
}

// sessionVerdict is the outcome of the one shared session-validation
// sequence (validateSession). ok=false means the session is rejected:
// message carries the 401 detail for the HTTP path ("unauthorized" or
// "session expired") and clearCookie says the client's cookie should be
// cleared (a session that was issued by us but is no longer acceptable).
type sessionVerdict struct {
	session      *AdminSession
	isRoot       bool // effective root flag (the revalidator's value overrides the cookie)
	usedPrevious bool
	ok           bool
	clearCookie  bool
	message      string
}

// validateSession is the ONE session-validation sequence shared by the
// admin HTTP middleware and the internal EE validation endpoint (D-UI-4):
// HMAC signature (with the optional previous-key rotation grace) → expiry
// → process-local revocation → durable revocation store → invalidation
// watermark → live user revalidation. Store lookup errors fail closed.
// onPreviousKey is invoked exactly where the middleware has always run its
// onPrevious hook — after the revocation/watermark checks and before the
// live revalidation, only when the previous signing key validated the
// cookie — and runs even when revalidation subsequently fails, preserving
// the pre-refactor middleware's audit behavior.
func validateSession(ctx context.Context, cookieValue string, secret, previous string, graceStarted time.Time, grace time.Duration, clock func() time.Time, invalidatedAt SessionsInvalidatedAt, revocations RevocationStore, onPreviousKey func(*AdminSession), revalidate ...SessionRevalidator) sessionVerdict {
	if clock == nil {
		clock = time.Now
	}
	session, usedPrevious, err := ParseAdminSessionCookieRotating(cookieValue, secret, previous, graceStarted, grace, clock())
	if err != nil {
		return sessionVerdict{message: "unauthorized"}
	}

	if time.Now().After(session.ExpiresAt) {
		return sessionVerdict{clearCookie: true, message: "session expired"}
	}
	if IsSessionIDRevoked(session.SessionID) {
		return sessionVerdict{clearCookie: true, message: "unauthorized"}
	}
	if revocations != nil {
		revoked, err := revocations.IsRevoked(ctx, session.SessionID)
		if err != nil || revoked {
			return sessionVerdict{clearCookie: true, message: "unauthorized"}
		}
	}

	if invalidatedAt != nil {
		watermark, err := invalidatedAt(ctx, session.UserID)
		if err != nil {
			return sessionVerdict{message: "unauthorized"}
		}
		if sessionInvalidated(session.IssuedAt, watermark) {
			return sessionVerdict{clearCookie: true, message: "unauthorized"}
		}
	}
	if usedPrevious && onPreviousKey != nil {
		onPreviousKey(session)
	}

	isRoot := session.IsRoot
	if len(revalidate) > 0 && revalidate[0] != nil {
		dbRoot, active, err := revalidate[0](ctx, session.UserID)
		if err != nil || !active {
			return sessionVerdict{message: "unauthorized"}
		}
		isRoot = dbRoot
	}

	return sessionVerdict{session: session, isRoot: isRoot, usedPrevious: usedPrevious, ok: true}
}

// ChiAuthMiddlewareRotatingWithRevocation validates sessions against the
// durable revocation store as well as the process-local fast path.
func ChiAuthMiddlewareRotatingWithRevocation(secret, previous string, graceStarted time.Time, grace time.Duration, clock func() time.Time, onPrevious func(*http.Request, *AdminSession), invalidatedAt SessionsInvalidatedAt, revocations RevocationStore, revalidate ...SessionRevalidator) func(http.Handler) http.Handler {
	if clock == nil {
		clock = time.Now
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := r.Cookie(sessionCookieName)
			if err != nil || token.Value == "" {
				writeUnauthorized(w, r, "unauthorized")
				return
			}

			var onPreviousKey func(*AdminSession)
			if onPrevious != nil {
				onPreviousKey = func(session *AdminSession) { onPrevious(r, session) }
			}
			verdict := validateSession(r.Context(), token.Value, secret, previous, graceStarted, grace, clock, invalidatedAt, revocations, onPreviousKey, revalidate...)
			if !verdict.ok {
				if verdict.clearCookie {
					http.SetCookie(w, ClearSessionCookie())
				}
				writeUnauthorized(w, r, verdict.message)
				return
			}

			ctx := context.WithValue(r.Context(), ContextKeyUserID{}, verdict.session.UserID)
			ctx = context.WithValue(ctx, ContextKeyEmail{}, verdict.session.Email)
			ctx = context.WithValue(ctx, ContextKeyIsRoot{}, verdict.isRoot)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// issuedAtUnixMillis renders a zero time as 0 (legacy marker) instead of
// a negative timestamp; millis keep sub-second logins distinct from a
// watermark written in the same second.
func issuedAtUnixMillis(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

// MustBeRoot returns a chi middleware that requires the current admin to be root.
func MustBeRoot() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			isRoot, _ := r.Context().Value(ContextKeyIsRoot{}).(bool)
			if !isRoot {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// AdminUserFromContext extracts the admin user info from a chi request context.
func AdminUserFromContext(r *http.Request) (*AdminUser, bool) {
	userID, ok := r.Context().Value(ContextKeyUserID{}).(string)
	if !ok || userID == "" {
		return nil, false
	}
	email, _ := r.Context().Value(ContextKeyEmail{}).(string)
	isRoot, _ := r.Context().Value(ContextKeyIsRoot{}).(bool)
	return &AdminUser{
		ID:     userID,
		Email:  email,
		IsRoot: isRoot,
	}, true
}

// AuthFromHeader returns a chi middleware that reads an X-Admin-Key header.
// Useful for internal service-to-service auth in the admin panel.
func AuthFromHeader(key string) func(http.Handler) http.Handler {
	if key == "" {
		panic("adminauth: AuthFromHeader requires a non-empty API key")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got := r.Header.Get("X-Admin-Key")
			if !hmac.Equal([]byte(got), []byte(key)) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ExtractAdminEmail is a convenience helper used by handlers that need the email.
func ExtractAdminEmail(r *http.Request) string {
	email, _ := r.Context().Value(ContextKeyEmail{}).(string)
	return email
}

// SanitizeForURL converts an admin email into a URL-safe identifier.
func SanitizeForURL(email string) string {
	parts := strings.SplitN(email, "@", 2)
	local := strings.ReplaceAll(parts[0], ".", "_")
	if len(parts) == 2 {
		return local + "_at_" + parts[1]
	}
	return local
}

const (
	csrfCookieName  = "yabanin_csrf_token"
	csrfHeaderName  = "X-CSRF-Token"
	csrfTokenLength = 32
)

// GenerateCSRFToken creates a cryptographically secure CSRF token, stores it in
// the response cookie and returns the token value for embedding in forms.
func GenerateCSRFToken(w http.ResponseWriter) string {
	b := make([]byte, csrfTokenLength)
	if _, err := rand.Read(b); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return ""
	}
	token := hex.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(SessionDuration.Seconds()),
	})
	return token
}

// CSRFValidation returns a chi-compatible middleware that validates the CSRF
// token present in the request cookie against the value sent in the X-CSRF-Token
// header. GET/HEAD/OPTIONS requests are exempted so they remain idempotent.
func CSRFValidation() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}
			if !sameOriginBrowserRequest(r) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			csrfCookie, err := r.Cookie(csrfCookieName)
			if err != nil || csrfCookie.Value == "" {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			givenCSRF := r.Header.Get(csrfHeaderName)
			if givenCSRF == "" {
				givenCSRF = r.FormValue("_csrf")
			}

			if !hmac.Equal([]byte(csrfCookie.Value), []byte(givenCSRF)) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// sameOriginBrowserRequest rejects explicit browser cross-origin markers.
// Requests without Origin or Fetch Metadata remain compatible with API clients.
func sameOriginBrowserRequest(r *http.Request) bool {
	if site := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))); site != "" && site != "same-origin" {
		return false
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host) && strings.EqualFold(u.Scheme, requestScheme(r))
}

// OriginValidation rejects hostile browser Origin and Fetch Metadata markers.
// Missing markers are accepted for non-browser/API clients.
func OriginValidation() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !sameOriginBrowserRequest(r) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func requestScheme(r *http.Request) string {
	if forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]); forwarded == "http" || forwarded == "https" {
		return forwarded
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

var processSessionRevocations = struct {
	sync.Mutex
	sessions map[string]time.Time
}{sessions: make(map[string]time.Time)}

// RevokeSessionID revokes a session in this process until its cookie expiry.
// Durable deployments should provide a shared store revocation interface.
func RevokeSessionID(sessionID string, expiresAt time.Time) {
	if sessionID == "" {
		return
	}
	processSessionRevocations.Lock()
	for id, expiry := range processSessionRevocations.sessions {
		if !expiry.IsZero() && time.Now().After(expiry) {
			delete(processSessionRevocations.sessions, id)
		}
	}
	processSessionRevocations.sessions[sessionID] = expiresAt
	processSessionRevocations.Unlock()
}

// IsSessionIDRevoked checks the process-local fallback revocation list.
func IsSessionIDRevoked(sessionID string) bool {
	processSessionRevocations.Lock()
	defer processSessionRevocations.Unlock()
	expiresAt, ok := processSessionRevocations.sessions[sessionID]
	if !ok {
		return false
	}
	if !expiresAt.IsZero() && time.Now().After(expiresAt) {
		delete(processSessionRevocations.sessions, sessionID)
		return false
	}
	return true
}

// --- helpers ---

func createHMAC(data string, secret string) []byte {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return h.Sum(nil)
}
