package adminauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// PortalSessionCookieName is the developer-portal session. It is not the
// admin console cookie, and a portal token does not satisfy ChiAuthMiddleware.
const PortalSessionCookieName = "yabanin_portal_session"

const portalCSRFCookieName = "yabanin_portal_csrf"

// PortalSession is the signed contents of a developer portal cookie.
type PortalSession struct {
	UserID    string
	Email     string
	SessionID string
	ExpiresAt time.Time
}

// ContextKeyPortalUserID keys the portal user id. It is distinct from the
// admin user id so the two sessions cannot be confused.
type ContextKeyPortalUserID struct{}

// CreatePortalSessionCookie signs a portal session. The payload has no
// is_root field, so it cannot be replayed as an admin session.
func CreatePortalSessionCookie(session PortalSession, secret string) (*http.Cookie, error) {
	payload := fmt.Sprintf("%s|%s|%s|%d", session.UserID, session.Email, session.SessionID, session.ExpiresAt.Unix())
	mac := createHMAC(payload, secret)
	token := payload + "|" + macEncoding.EncodeToString(mac)
	maxAge := int(time.Until(session.ExpiresAt).Seconds())
	if maxAge < 0 {
		maxAge = 0
	}
	return &http.Cookie{
		Name:     PortalSessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	}, nil
}

// ParsePortalSessionCookie verifies a portal session token.
func ParsePortalSessionCookie(cookieValue, secret string) (*PortalSession, error) {
	last := strings.LastIndex(cookieValue, "|")
	if last < 0 {
		return nil, fmt.Errorf("invalid portal session")
	}
	payload, macPart := cookieValue[:last], cookieValue[last+1:]
	given, err := macEncoding.DecodeString(macPart)
	if err != nil {
		return nil, fmt.Errorf("decode portal session mac: %w", err)
	}
	if !hmac.Equal(createHMAC(payload, secret), given) {
		return nil, fmt.Errorf("portal session signature mismatch")
	}
	parts := strings.Split(payload, "|")
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid portal session payload")
	}
	exp, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse portal session expiry: %w", err)
	}
	return &PortalSession{
		UserID:    parts[0],
		Email:     parts[1],
		SessionID: parts[2],
		ExpiresAt: time.Unix(exp, 0),
	}, nil
}

// ClearPortalSessionCookie expires the portal session.
func ClearPortalSessionCookie() *http.Cookie {
	return &http.Cookie{
		Name:     PortalSessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
}

// PortalAuthMiddleware requires a live portal session. It does not set the
// admin root flag.
func PortalAuthMiddleware(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := r.Cookie(PortalSessionCookieName)
			if err != nil || c.Value == "" {
				writeUnauthorized(w, r, "unauthorized")
				return
			}
			session, err := ParsePortalSessionCookie(c.Value, secret)
			if err != nil || time.Now().After(session.ExpiresAt) {
				http.SetCookie(w, ClearPortalSessionCookie())
				writeUnauthorized(w, r, "unauthorized")
				return
			}
			ctx := context.WithValue(r.Context(), ContextKeyPortalUserID{}, session.UserID)
			ctx = context.WithValue(ctx, ContextKeyEmail{}, session.Email)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// PortalUserID returns the portal user id set by PortalAuthMiddleware.
func PortalUserID(r *http.Request) string {
	id, _ := r.Context().Value(ContextKeyPortalUserID{}).(string)
	return id
}

// GeneratePortalCSRFToken sets the portal CSRF cookie and returns the token.
func GeneratePortalCSRFToken(w http.ResponseWriter) string {
	b := make([]byte, csrfTokenLength)
	if _, err := rand.Read(b); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return ""
	}
	token := hex.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{
		Name:     portalCSRFCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(SessionDuration.Seconds()),
	})
	return token
}

// PortalCSRFValidation checks the portal CSRF cookie against X-CSRF-Token.
// GET, HEAD and OPTIONS are exempt. The admin CSRF cookie is not accepted.
func PortalCSRFValidation() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}
			c, err := r.Cookie(portalCSRFCookieName)
			if err != nil || c.Value == "" {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			given := r.Header.Get(csrfHeaderName)
			if given == "" {
				given = r.FormValue("_csrf")
			}
			if !hmac.Equal([]byte(c.Value), []byte(given)) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
