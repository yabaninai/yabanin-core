package adminauth

// OIDC SSO for the admin console: Authorization Code flow with PKCE (S256),
// a state CSRF token and a nonce, per RFC 6749/7636 and the OpenID Connect
// Core spec. Opt-in: the client is constructed only when the admin config
// carries the full issuer/client/secret/redirect tuple; the console keeps
// the password-only flow otherwise (zero behavior change).
//
// Trust boundary: the ID token is verified against the provider's published
// JWKS (signature, issuer, audience, expiry — via go-oidc); the nonce is
// verified against the value generated for THIS login, so a token from
// another session cannot be replayed. User mapping is fail-closed: the
// verified email must match an existing active admin user; OIDC never
// provisions accounts.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCFlowCookieName carries the one-time login secrets through the redirect
// to the provider and back.
const OIDCFlowCookieName = "yabanin_oidc_flow"

// PortalOIDCFlowCookieName is the same secret set for the developer portal.
// A separate name and path keep an admin login from completing a portal
// callback and the other way around.
const PortalOIDCFlowCookieName = "yabanin_portal_oidc_flow"

// OIDCClient is an initialized provider binding. Construct once at startup
// (NewOIDCClient fetches the discovery document); the per-request methods
// are safe for concurrent use.
type OIDCClient struct {
	provider *oidc.Provider
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
	http     *http.Client
}

// NewOIDCClient discovers the provider and prepares the code-flow verifier
// bound to clientID. The issuer must be an https URL (or a loopback test
// server); anything unparsable fails closed.
func NewOIDCClient(ctx context.Context, issuer, clientID, clientSecret, redirectURL string) (*OIDCClient, error) {
	if issuer == "" || clientID == "" || clientSecret == "" || redirectURL == "" {
		return nil, errors.New("adminauth: oidc requires issuer, client_id, client_secret and redirect_url")
	}
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("adminauth: oidc issuer must be an absolute URL: %q", issuer)
	}
	// Production issuers are https; plain http is allowed only for loopback
	// hosts (local test providers). Anything else fails closed.
	if u.Scheme != "https" && !isLoopbackHost(u.Host) {
		return nil, fmt.Errorf("adminauth: oidc issuer must be https (or a loopback test provider): %q", issuer)
	}
	hc := &http.Client{Timeout: 15 * time.Second}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, hc), issuer)
	if err != nil {
		return nil, fmt.Errorf("adminauth: oidc discovery failed: %w", err)
	}
	return &OIDCClient{
		provider: provider,
		oauth: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "email"},
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: clientID}),
		http:     hc,
	}, nil
}

// isLoopbackHost reports whether host[:port] is a loopback literal.
func isLoopbackHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	return (ip != nil && ip.IsLoopback()) || host == "localhost"
}

// OIDCFlow is the per-login one-time secret set: state (CSRF), nonce
// (replay binding) and the PKCE code verifier. All three are generated
// fresh for every login redirect and live at most 10 minutes.
type OIDCFlow struct {
	State        string `json:"state"`
	Nonce        string `json:"nonce"`
	PKCEVerifier string `json:"pkce_verifier"`
	Next         string `json:"next,omitempty"`
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// NewOIDCFlow generates a fresh state/nonce/PKCE triple.
func NewOIDCFlow() (OIDCFlow, error) {
	state, err := randomHex(32)
	if err != nil {
		return OIDCFlow{}, err
	}
	nonce, err := randomHex(32)
	if err != nil {
		return OIDCFlow{}, err
	}
	// PKCE verifier: 64 base64url chars (43..128 required by RFC 7636).
	vb := make([]byte, 48)
	if _, err := rand.Read(vb); err != nil {
		return OIDCFlow{}, err
	}
	return OIDCFlow{
		State:        state,
		Nonce:        nonce,
		PKCEVerifier: base64.RawURLEncoding.EncodeToString(vb),
	}, nil
}

// PKCEChallengeS256 derives the code_challenge sent with the redirect.
func (f OIDCFlow) PKCEChallengeS256() string {
	sum := sha256.Sum256([]byte(f.PKCEVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// AuthCodeURL builds the provider redirect with state, nonce and the S256
// PKCE challenge attached.
func (c *OIDCClient) AuthCodeURL(f OIDCFlow) string {
	return c.oauth.AuthCodeURL(f.State,
		oidc.Nonce(f.Nonce),
		oauth2.SetAuthURLParam("code_challenge", f.PKCEChallengeS256()),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

// OIDCIdentity is the verified caller identity taken from the ID token.
type OIDCIdentity struct {
	Subject       string
	Email         string
	EmailVerified bool
	// Groups is the raw `groups` claim of the ID token (empty when the
	// provider does not include one). adminauth never interprets it: the
	// org-declared group→role mapping (pkg/adminstore) is applied by the
	// login handlers after this verification succeeds.
	Groups []string
}

// ExchangeAndVerify runs the authorization-code exchange (PKCE verifier
// attached) and verifies the returned ID token: signature, issuer, audience
// and expiry via the provider verifier, the nonce against this flow's value.
func (c *OIDCClient) ExchangeAndVerify(ctx context.Context, code, nonce, pkceVerifier string) (OIDCIdentity, error) {
	ctx = oidc.ClientContext(ctx, c.http)
	tok, err := c.oauth.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", pkceVerifier))
	if err != nil {
		return OIDCIdentity{}, fmt.Errorf("oidc code exchange: %w", err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok {
		return OIDCIdentity{}, errors.New("oidc: token response carries no id_token")
	}
	idTok, err := c.verifier.Verify(ctx, rawID)
	if err != nil {
		return OIDCIdentity{}, fmt.Errorf("oidc id_token verification: %w", err)
	}
	if idTok.Nonce == "" || idTok.Nonce != nonce {
		return OIDCIdentity{}, errors.New("oidc: nonce mismatch")
	}
	var claims struct {
		Sub           string   `json:"sub"`
		Email         string   `json:"email"`
		EmailVerified bool     `json:"email_verified"`
		Groups        []string `json:"groups"`
	}
	if err := idTok.Claims(&claims); err != nil {
		return OIDCIdentity{}, fmt.Errorf("oidc id_token claims: %w", err)
	}
	if claims.Email == "" {
		return OIDCIdentity{}, errors.New("oidc: id_token carries no email claim")
	}
	return OIDCIdentity{
		Subject:       claims.Sub,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		Groups:        claims.Groups,
	}, nil
}

// NewOIDCFlowCookie seals the one-time secrets for the redirect round-trip.
// SameSite=Lax (not Strict): the callback arrives as a top-level navigation
// from the provider's domain, which Strict would strip. HttpOnly + Secure +
// 10-minute lifetime; the path is scoped to the oidc callback routes.
func NewOIDCFlowCookie(f OIDCFlow) (*http.Cookie, error) {
	return oidcFlowCookie(OIDCFlowCookieName, "/auth/oidc", f)
}

// NewPortalOIDCFlowCookie seals a portal login. Path /portal so the cookie
// is presented only to the portal callback.
func NewPortalOIDCFlowCookie(f OIDCFlow) (*http.Cookie, error) {
	return oidcFlowCookie(PortalOIDCFlowCookieName, "/portal", f)
}

func oidcFlowCookie(name, path string, f OIDCFlow) (*http.Cookie, error) {
	raw, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	return &http.Cookie{
		Name:     name,
		Value:    base64.RawURLEncoding.EncodeToString(raw),
		Path:     path,
		MaxAge:   600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}, nil
}

// ParseOIDCFlowCookie decodes the callback cookie.
func ParseOIDCFlowCookie(value string) (OIDCFlow, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return OIDCFlow{}, err
	}
	var f OIDCFlow
	if err := json.Unmarshal(raw, &f); err != nil {
		return OIDCFlow{}, err
	}
	if f.State == "" || f.Nonce == "" || f.PKCEVerifier == "" {
		return OIDCFlow{}, errors.New("adminauth: oidc flow cookie incomplete")
	}
	return f, nil
}

// ClearOIDCFlowCookie expires the one-time cookie (issued on every callback,
// success or not — the secrets are single-use).
func ClearOIDCFlowCookie() *http.Cookie {
	return clearOIDCFlowCookie(OIDCFlowCookieName, "/auth/oidc")
}

// ClearPortalOIDCFlowCookie expires the portal one-time cookie.
func ClearPortalOIDCFlowCookie() *http.Cookie {
	return clearOIDCFlowCookie(PortalOIDCFlowCookieName, "/portal")
}

func clearOIDCFlowCookie(name, path string) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     path,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}
