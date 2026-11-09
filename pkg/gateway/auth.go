package cli

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"

	"github.com/reireirei/yabanin/pkg/auth"

	"github.com/reireirei/yabanin/pkg/config"
	apierrors "github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/labels"
)

func (gw *gateway) authMiddlewareFunc(next http.Handler) http.Handler {
	return gw.auth.ServeHTTP(next)
}

// AuthMiddleware implements http.Handler for token-based auth.
type AuthMiddleware struct {
	mode        string
	apiKey      string
	fallbackKey string
	resolver    *auth.Resolver
	// lastUsed optionally records api_keys.last_used_at asynchronously
	// (). Nil = feature off. Touch is throttled and non-blocking, so
	// the hot path never waits on the database for it.
	lastUsed *auth.LastUsedTracker
	// accounts without static keys). Nil = feature off; the legacy API-key
	// path below is then bit-for-bit unchanged.
	jwt *JWTAuthenticator
}

// NewAuthMiddleware creates an auth middleware handler.
func NewAuthMiddleware(cfg config.Gateway, resolver *auth.Resolver) *AuthMiddleware {
	return &AuthMiddleware{
		mode:        cfg.AuthMode,
		apiKey:      cfg.APIKey,
		fallbackKey: cfg.FallbackKey,
		resolver:    resolver,
	}
}

// SetLastUsedTracker installs the last-used tracker before the middleware starts serving.
func (a *AuthMiddleware) SetLastUsedTracker(t *auth.LastUsedTracker) {
	a.lastUsed = t
}

// SetJWTAuthenticator installs the authenticator before the middleware starts serving; nil disables the JWT path.
func (a *AuthMiddleware) SetJWTAuthenticator(j *JWTAuthenticator) {
	a.jwt = j
}

func (a *AuthMiddleware) ServeHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Del("X-Org-Id")
		r.Header.Del("X-API-Key-Id")
		r.Header.Del("X-Team-Id")
		// MCP-03: X-Agent-Id is set ONLY from the resolved yag_ principal
		// below (G1). A client-supplied copy must not survive — otherwise a
		// regular api_key could claim an agent identity and pass the
		// agent-only MCP tool-call gate (or spoof agent attribution).
		r.Header.Del("X-Agent-Id")
		// RM-44: X-User-Id is set only from the resolved personal key. A
		// client-supplied value must not attribute spend to another user.
		r.Header.Del("X-User-Id")
		// AT-14: X-Session-Key-Id is set only from a resolved ybs_ key.
		r.Header.Del("X-Session-Key-Id")

		// Claude Code sends the key in x-api-key. Authorization wins when both
		// are present. The client header is always removed so it is not forwarded.
		if r.Header.Get("Authorization") == "" {
			if key := r.Header.Get("x-api-key"); key != "" {
				r.Header.Set("Authorization", "Bearer "+key)
			}
		}
		r.Header.Del("x-api-key")

		var resolved *auth.ResolveResult
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			apierrors.Write(w, http.StatusUnauthorized, apierrors.ErrorCodeAuthentication,
				"missing or invalid Authorization header")
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == authHeader {
			token = strings.TrimPrefix(authHeader, "bearer ")
		}

		// optional JWT path. Recognition is by FORM only (three base64url
		// segments plus a kid JOSE header) and only while the JWT path is
		// wired — see tokenLooksLikeJWT for the collision contract. Gateway
		// API keys (yag_/ypk_/ybs_ + hex) never contain dots, so no real key
		// is ever mistaken for a JWT; conversely a JWT-shaped token never
		// falls through to the resolver (no legacy fallback for JWTs).
		// With jwt == nil this is one nil check: bit-for-bit legacy behavior.
		if a.jwt != nil && tokenLooksLikeJWT(token) {
			a.serveJWT(w, r, next, token)
			return
		}

		valid := false
		switch a.mode {
		case "strict":
			if a.apiKey != "" && subtle.ConstantTimeCompare([]byte(token), []byte(a.apiKey)) == 1 {
				valid = true
			} else if a.fallbackKey != "" && subtle.ConstantTimeCompare([]byte(token), []byte(a.fallbackKey)) == 1 {
				valid = true
			}
			if !valid {
				apierrors.Write(w, http.StatusUnauthorized, apierrors.ErrorCodeAuthentication,
					"invalid API key")
				return
			}
		case "header":
			// header mode: static key is optional; allow resolver-only auth
			if a.apiKey != "" && subtle.ConstantTimeCompare([]byte(token), []byte(a.apiKey)) == 1 {
				valid = true
			} else if a.fallbackKey != "" && subtle.ConstantTimeCompare([]byte(token), []byte(a.fallbackKey)) == 1 {
				valid = true
			}
		default:
			if a.apiKey != "" && subtle.ConstantTimeCompare([]byte(token), []byte(a.apiKey)) == 1 {
				valid = true
			} else if a.fallbackKey != "" && subtle.ConstantTimeCompare([]byte(token), []byte(a.fallbackKey)) == 1 {
				valid = true
			}
		}

		if a.resolver != nil && token != "" && r.Header.Get("X-Org-Id") == "" {
			res, err := a.resolver.Resolve(r.Context(), token)
			if err == nil && res != nil && res.OrgID != "" {
				resolved = res
				r.Header.Set("X-Org-Id", res.OrgID)
				r.Header.Set("X-API-Key-Id", res.APIKeyID)
				// resolve to their parent api key, so session traffic keeps
				// the parent's last_used_at fresh too. Agent principals have
				// no api_keys row and are skipped.
				if res.APIKeyID != "" {
					a.lastUsed.Touch(res.APIKeyID)
				}
				if res.TeamID != "" {
					r.Header.Set("X-Team-Id", res.TeamID)
				}
				// G1/G2: propagate the agent principal so the gateway can
				// enforce per-agent budgets and tag spend by agent.
				if res.AgentID != "" {
					r.Header.Set("X-Agent-Id", res.AgentID)
				}
				if res.UserID != "" {
					r.Header.Set("X-User-Id", res.UserID)
				}
				if res.SessionKeyID != "" {
					r.Header.Set("X-Session-Key-Id", res.SessionKeyID)
				}
			} else if err != nil {
				// failure — 401 with stable code "key_expired".
				if errors.Is(err, auth.ErrKeyExpired) {
					apierrors.WriteWithCode(w, http.StatusUnauthorized, apierrors.ErrorCodeAuthentication,
						"API key has expired", apierrors.CodeKeyExpired)
					return
				}
				switch a.mode {
				case "header", "strict":
					apierrors.Write(w, http.StatusUnauthorized, apierrors.ErrorCodeAuthentication,
						"org resolution failed")
					return
				default:
					// Unknown mode — treat as strict (fail-closed).
					apierrors.Write(w, http.StatusUnauthorized, apierrors.ErrorCodeAuthentication,
						"org resolution failed")
					return
				}
			}
		}

		if !valid && r.Header.Get("X-Org-Id") == "" {
			apierrors.Write(w, http.StatusUnauthorized, apierrors.ErrorCodeAuthentication,
				"invalid API key")
			return
		}

		if resolved != nil {
			keyLabels := resolved.Labels
			if keyLabels == nil {
				keyLabels = labels.Set{}
			}
			sources := []labels.Source{{
				Name: "key", Labels: keyLabels, Locked: resolved.LabelsLocked,
			}}
			if resolved.SessionKeyID != "" {
				sessionLabels := resolved.SessionLabels
				if sessionLabels == nil {
					sessionLabels = labels.Set{}
				}
				sources = append(sources, labels.Source{
					Name: "session", Labels: sessionLabels, Locked: resolved.SessionLabelsLocked,
				})
			}
			ctx := withPrincipalLabelSources(r.Context(), sources)
			ctx = withPrincipal(ctx, principal{
				APIKeyID:          resolved.APIKeyID,
				AgentID:           resolved.AgentID,
				CanMintSessions:   resolved.CanMintSessions,
				CanReadUsage:      resolved.CanReadUsage,
				SessionKeyID:      resolved.SessionKeyID,
				SessionMaxTokens:  resolved.SessionMaxTokens,
				SessionMaxCostUSD: resolved.SessionMaxCostUSD,
				SessionExpiresAt:  resolved.SessionExpiresAt,
				KeyExpiresAt:      resolved.KeyExpiresAt,
			})
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}
