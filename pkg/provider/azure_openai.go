package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/reireirei/yabanin/pkg/ssrf"
)

const (
	// azureEntraAuthority is the production Entra ID (Azure AD) authority.
	// The tenant-qualified token URL is {authority}/{tenant_id}/oauth2/v2.0/token.
	azureEntraAuthority = "https://login.microsoftonline.com"
	// azureEntraScope is the OAuth2 client-credentials scope for Azure
	// OpenAI (Cognitive Services) resource.
	azureEntraScope = "https://cognitiveservices.azure.com/.default"
	// azureOpenAIAPIVersion pins the Azure OpenAI api-version query
	// parameter (GA chat-completions surface).
	azureOpenAIAPIVersion = "2024-10-21"
	// azureTokenSkew refreshes the Entra access token 5 min before expiry
	// to avoid a 401 mid-request.
	azureTokenSkew = 5 * time.Minute
	// azureTokenRefreshTimeout bounds one Entra token exchange. The refresh
	// runs on a detached context so one caller's disconnect cannot abort
	// the shared exchange (sber precedent).
	azureTokenRefreshTimeout = 10 * time.Second
	// azureTokenDefaultTTL is the defensive cache TTL when Entra omits
	// expires_in (real tokens live 60-90 min; 25 min is conservative).
	azureTokenDefaultTTL = 25 * time.Minute
	// azureRateLimitCooldown* pin this card's rate-limit boundaries (this
	// comment is the record; no package-level contract doc was committed):
	//   - a throttled (HTTP 429) exchange NEVER sleeps in the caller's
	//     request path — it fails closed immediately with a diagnostic;
	//   - the credential key enters a cooldown window during which further
	//     exchanges fail fast without network, so sequential requests do
	//     not hammer an already-throttled authority (singleflight bounds
	//     the concurrent case to one exchange);
	//   - the window is azureRateLimitCooldownBase (1s) by default and is
	//     extended by Entra's Retry-After delta-seconds when present,
	//     clamped to azureRateLimitCooldownMax (60s) so a hostile or
	//     misbehaving authority cannot park a tenant indefinitely.
	azureRateLimitCooldownBase = 1 * time.Second
	azureRateLimitCooldownMax  = 60 * time.Second
)

// AzureEntraCredentials is the JSON secret stored per provider in
// org_provider_credentials.api_key_ct for azure-openai rows (ratified D2/D4,
// 2026-10-16): Entra ID client-credentials only. Values are never logged and
// never appear in error messages.
type AzureEntraCredentials struct {
	TenantID     string `json:"tenant_id"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// ParseAzureEntraCredentials decodes and validates the JSON credential blob.
// The returned error names only the missing FIELD names, never their values.
//
// N08-P01-T03 (tenant-keyed cache verification): tenant_id and client_id are
// rejected when they contain the cache-key separator '|' (see entraCacheKey).
// No Entra issuer name (GUID or contoso.onmicrosoft.com domain) can contain
// that character, so the rejection only excludes values that could never
// authenticate anyway — and it makes the cache key provably injective over
// the admitted credential space (fail-fast, I51) instead of aliasing two
// identities onto one cache slot.
func ParseAzureEntraCredentials(blob string) (AzureEntraCredentials, error) {
	var c AzureEntraCredentials
	if err := json.Unmarshal([]byte(blob), &c); err != nil {
		return AzureEntraCredentials{}, errors.New("azure-openai: Entra ID credentials must be JSON {tenant_id,client_id,client_secret}")
	}
	switch {
	case c.TenantID == "":
		return AzureEntraCredentials{}, errors.New("azure-openai: Entra ID credentials missing tenant_id")
	case strings.Contains(c.TenantID, "|"):
		return AzureEntraCredentials{}, errors.New("azure-openai: Entra ID credentials tenant_id must not contain the cache-key separator '|'")
	case c.ClientID == "":
		return AzureEntraCredentials{}, errors.New("azure-openai: Entra ID credentials missing client_id")
	case strings.Contains(c.ClientID, "|"):
		return AzureEntraCredentials{}, errors.New("azure-openai: Entra ID credentials client_id must not contain the cache-key separator '|'")
	case c.ClientSecret == "":
		return AzureEntraCredentials{}, errors.New("azure-openai: Entra ID credentials missing client_secret")
	}
	return c, nil
}

// azureToken is one cached Entra access token.
type azureToken struct {
	accessToken string
	tokenExp    time.Time
}

// AzureOpenAI is an OpenAI-compatible adapter with an Azure-styled upstream surface (scope 2026-10-16):
// Azure-styled:
//
//   - deployment-qualified URLs:
//     {base}/openai/deployments/{deployment}/chat/completions?api-version=…
//     where {deployment} is the body's model field (the gateway overrides it
//     to the models_registry.model_name, which doubles as the deployment
//     name);
//   - Entra ID (OAuth2 client-credentials) bearer auth: the secret passed to
//     PrepareRequest is the JSON blob parsed by ParseAzureEntraCredentials.
//
// The adapter is stateful: the upstream Pool caches one *Client per
// (provider, URL), so this instance is shared by every org routing to the
// same models_registry row while apiKey (the org's own credential blob)
// still arrives per request. The token cache is therefore keyed by the
// credential identity (tenant|client) — two orgs on different Entra tenants
// never ride each other's token (sber precedent for the exchange mechanics).
type AzureOpenAI struct {
	// entraHost overrides the Entra authority for tests; empty → production
	// login.microsoftonline.com.
	entraHost string
	// httpClient performs only the Entra token exchange; chat calls ride
	// the upstream pool's own SSRF-guarded transport.
	httpClient *http.Client
	// refreshGroup deduplicates concurrent refreshes per credential key so
	// N cold callers trigger exactly one exchange per tenant.
	refreshGroup singleflight.Group
	mu           sync.Mutex
	// tokens maps "tenant|client" → cached access token. Entries are
	// pruned on write once fully expired, so the map stays bounded by the
	// number of distinct active org credentials. N08-P01-T03 verification:
	// the prune touches only entries that are already fully expired, so a
	// refresh for one credential can never evict another org's FRESH token,
	// and a secret rotation (same tenant+client, new secret) keeps serving
	// the still-valid cached bearer until its natural refresh — Entra
	// bearer tokens outlive the secret that minted them; the rotation only
	// changes what the NEXT exchange posts on the wire.
	tokens map[string]azureToken
	// cooldowns maps "tenant|client" → the instant a rate-limited Entra
	// exchange may be retried. See the azureRateLimitCooldown* constants
	// for the boundaries. Entries are deleted lazily once elapsed and on
	// any successful exchange for the key.
	cooldowns map[string]time.Time
}

// NewAzureOpenAI constructs the adapter with a token-exchange client built
// on the shared SSRF transport constructor (sber precedent: no client-wide
// timeout — the exchange itself is bounded by azureTokenRefreshTimeout).
// N01-P07: the guarded dialer is mandatory on the Entra exchange; the
// production authority is a hostname, so no reserved-range waiver applies
// and the dial guard stays unconditional.
func NewAzureOpenAI() *AzureOpenAI {
	a := &AzureOpenAI{tokens: map[string]azureToken{}, cooldowns: map[string]time.Time{}}
	a.httpClient = newAzureEntraHTTPClient(trustedExactHostPin(azureEntraAuthority))
	return a
}

// NewAzureOpenAIWithClient is the test hook: inject a client (httptest) and
// optionally an Entra authority override. Production code uses
// NewAzureOpenAI.
func NewAzureOpenAIWithClient(c *http.Client, entraHost string) *AzureOpenAI {
	authority := entraHost
	if authority == "" {
		authority = azureEntraAuthority
	}
	a := &AzureOpenAI{
		entraHost: strings.TrimRight(entraHost, "/"),
		tokens:    map[string]azureToken{},
		cooldowns: map[string]time.Time{},
	}
	if c == nil {
		c = newAzureEntraHTTPClient(trustedExactHostPin(authority))
	}
	a.httpClient = c
	return a
}

// newAzureEntraHTTPClient builds the token-exchange client on the shared
// SSRF transport constructor, mirroring the sber token client. N01-P07: the
// guarded dialer is enabled — the Entra exchange previously rode the
// legacy/dev transport (GuardDialedIP unset), so the token URL bypassed the
// dial-time guard that protects the chat path. The only reserved-range
// waiver is the D-4 exact literal-IP pin of the configured authority (test
// rigs pin 127.0.0.1; the production hostname is never waived).
//
// Proxy stays nil: pkg/ssrf forbids environment proxy settings as a
// substitute for an allow-list-checked URL.
//
// No http.Client.Timeout: the exchange is bounded per call by
// azureTokenRefreshTimeout instead.
func newAzureEntraHTTPClient(trustedExactHosts func(host string) bool) *http.Client {
	tr := ssrf.NewTransport(ssrf.TransportOptions{
		DialTimeout:           10 * time.Second,
		KeepAlive:             30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		GuardDialedIP:         true,
		TrustedExactHosts:     trustedExactHosts,
	})
	return &http.Client{Transport: tr}
}

// Name returns the canonical provider identifier.
func (*AzureOpenAI) Name() string { return "azure-openai" }

// Path returns the deployment-qualified chat-completions path TEMPLATE. The
// real path is built per request in PrepareRequest because the deployment
// name is the per-model registry name; the template documents the shape and
// is not directly usable as a URL.
func (*AzureOpenAI) Path(_ bool) string {
	return "/openai/deployments/{deployment}/chat/completions"
}

// PrepareRequest builds the Azure-style request: deployment-qualified URL
// with api-version query and an Entra ID bearer token. apiKey must be the
// JSON credential blob (ParseAzureEntraCredentials shape); incomplete
// credentials fail fast here instead of sending an unauthenticated request
// upstream.
func (a *AzureOpenAI) PrepareRequest(ctx context.Context, baseURL, _ string, body []byte, apiKey string, stream bool) (*http.Request, error) {
	creds, err := ParseAzureEntraCredentials(apiKey)
	if err != nil {
		return nil, err
	}
	deployment, err := azureDeploymentFromBody(body)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(baseURL) == "" {
		return nil, errors.New("azure-openai: base URL is required (models_registry.upstream_url)")
	}
	//nolint:contextcheck // the refresh deliberately runs on a detached, self-bounded context (sber precedent) — one caller's request ctx must not own the shared token exchange
	if err := a.ensureToken(creds); err != nil {
		return nil, fmt.Errorf("azure-openai: ensure token: %w", err)
	}
	full := strings.TrimRight(baseURL, "/") +
		"/openai/deployments/" + url.PathEscape(deployment) +
		"/chat/completions?" + url.Values{"api-version": {azureOpenAIAPIVersion}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, full, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build azure-openai request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.currentToken(entraCacheKey(creds)))
	if stream {
		req.Header.Set("Accept", "text/event-stream")
	}
	return req, nil
}

// azureDeploymentFromBody extracts the deployment name: the body's model
// field, which the upstream client has already overridden to the registry
// model_name. Missing or empty → fail fast (misrouted request).
func azureDeploymentFromBody(body []byte) (string, error) {
	var payload struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", errors.New("azure-openai: request body is not JSON; cannot resolve deployment name")
	}
	if strings.TrimSpace(payload.Model) == "" {
		return "", errors.New("azure-openai: request body has no model field; cannot resolve deployment name")
	}
	return payload.Model, nil
}

// entraCacheKey derives the token-cache key from the credential identity.
// It deliberately excludes the client secret: the key names the tenant+client
// pair, never secret material.
//
// N08-P01-T03 verification: over the credential space admitted by
// ParseAzureEntraCredentials (no '|' inside tenant_id/client_id) the joined
// form contains exactly one separator, so its split is unique and the key is
// injective — tenant1|client1 == tenant2|client2 implies
// tenant1==tenant2 && client1==client2. Two orgs therefore can never alias
// one cache slot, and no code path can serve another org's token
// (packet negative criterion). The cooldown map shares this key, so a
// rate-limit penalty for one credential cannot throttle another.
func entraCacheKey(creds AzureEntraCredentials) string {
	return creds.TenantID + "|" + creds.ClientID
}

// ensureToken returns quickly when the credential's cached token is still
// fresh; otherwise it joins a singleflight refresh keyed by tenant+client so
// concurrent cold callers for the SAME credential share exactly one exchange
// while other tenants' cached tokens are left untouched. A credential whose
// last exchange was rate-limited (429) fails fast for the cooldown window
// instead of re-hammering the throttled authority (see the
// azureRateLimitCooldown* boundary constants).
func (a *AzureOpenAI) ensureToken(creds AzureEntraCredentials) error {
	key := entraCacheKey(creds)
	if d, active := a.cooldownRemaining(key); active {
		return fmt.Errorf("azure-openai: entra token exchange rate-limited; retry allowed in %s", d.Truncate(time.Millisecond))
	}
	if a.tokenFresh(key) {
		return nil
	}
	_, err, _ := a.refreshGroup.Do(key, func() (any, error) {
		// Double-check: a waiter that joined after the winner's refresh
		// completed must not exchange again while the token is FRESH.
		if a.tokenFresh(key) {
			return struct{}{}, nil
		}
		// A sibling exchange may have just been rate-limited between the
		// outer check and acquiring the singleflight slot: fail with the
		// cooldown diagnostic instead of exchanging against a throttled
		// authority. Returning an error (not a silent success) keeps the
		// fail-closed contract — no token exists yet.
		if d, active := a.cooldownRemaining(key); active {
			return nil, fmt.Errorf("entra token exchange rate-limited; retry allowed in %s", d.Truncate(time.Millisecond))
		}
		if err := a.refreshToken(key, creds); err != nil {
			return nil, err
		}
		return struct{}{}, nil
	})
	return err
}

// cooldownRemaining reports the credential's remaining rate-limit cooldown.
// The second return is false when no (unexpired) cooldown is recorded; stale
// entries are removed lazily so the map cannot grow unboundedly.
func (a *AzureOpenAI) cooldownRemaining(key string) (time.Duration, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cooldowns == nil {
		return 0, false
	}
	until, ok := a.cooldowns[key]
	if !ok {
		return 0, false
	}
	remaining := time.Until(until)
	if remaining <= 0 {
		delete(a.cooldowns, key)
		return 0, false
	}
	return remaining, true
}

// tokenFresh reports whether the credential's cached token is present and
// outside the refresh skew window.
func (a *AzureOpenAI) tokenFresh(key string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	t, ok := a.tokens[key]
	return ok && t.accessToken != "" && time.Now().Before(t.tokenExp.Add(-azureTokenSkew))
}

// currentToken returns the credential's cached access token; callers must
// have called ensureToken for the same credential first.
func (a *AzureOpenAI) currentToken(key string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.tokens[key].accessToken
}

// refreshToken performs the Entra client-credentials exchange on a detached,
// self-bounded context (sber precedent). Error messages carry status codes
// only — token endpoints never echo credentials and neither does this code.
func (a *AzureOpenAI) refreshToken(key string, creds AzureEntraCredentials) error {
	host := azureEntraAuthority
	if a.entraHost != "" {
		host = a.entraHost
	}
	tokenURL := host + "/" + url.PathEscape(creds.TenantID) + "/oauth2/v2.0/token"
	refreshCtx, cancel := context.WithTimeout(context.Background(), azureTokenRefreshTimeout)
	defer cancel()
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {creds.ClientID},
		"client_secret": {creds.ClientSecret},
		"scope":         {azureEntraScope},
	}
	req, err := http.NewRequestWithContext(refreshCtx, http.MethodPost, tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("entra token endpoint unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusTooManyRequests {
		cooldown := azureRateLimitCooldownBase
		if ra := azureRetryAfterSeconds(resp.Header.Get("Retry-After")); ra > cooldown {
			cooldown = ra
		}
		if cooldown > azureRateLimitCooldownMax {
			cooldown = azureRateLimitCooldownMax
		}
		a.mu.Lock()
		if a.cooldowns == nil {
			a.cooldowns = map[string]time.Time{}
		}
		a.cooldowns[key] = time.Now().Add(cooldown)
		a.mu.Unlock()
		return fmt.Errorf("entra token exchange HTTP 429 (rate-limited, cooldown %s)", cooldown)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("entra token exchange HTTP %d", resp.StatusCode)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"` // seconds
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok); err != nil {
		return fmt.Errorf("decode entra token response: %w", err)
	}
	if tok.AccessToken == "" {
		return errors.New("empty access_token in entra token response")
	}
	ttl := azureTokenDefaultTTL
	if tok.ExpiresIn > 0 {
		ttl = time.Duration(tok.ExpiresIn) * time.Second
	}
	a.mu.Lock()
	if a.tokens == nil {
		a.tokens = map[string]azureToken{}
	}
	a.tokens[key] = azureToken{accessToken: tok.AccessToken, tokenExp: time.Now().Add(ttl)}
	// A successful exchange invalidates any stale rate-limit cooldown for
	// the credential.
	if a.cooldowns != nil {
		delete(a.cooldowns, key)
	}
	// Prune fully expired entries so a long-lived shared adapter does not
	// accumulate one slot per credential ever seen.
	now := time.Now()
	for k, t := range a.tokens {
		if now.After(t.tokenExp) {
			delete(a.tokens, k)
		}
	}
	a.mu.Unlock()
	return nil
}

// azureRetryAfterSeconds parses a Retry-After delta-seconds header (the only
// form the Entra token endpoint emits). Unparsable, negative and zero values
// return 0 so the caller keeps its default cooldown; the
// azureRateLimitCooldownMax clamp is applied by the caller.
func azureRetryAfterSeconds(header string) time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(header))
	if err != nil || seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

// ParseUsage extracts token counts from the OpenAI-shaped Azure response.
func (*AzureOpenAI) ParseUsage(respBody []byte) Usage { return openAIParseUsage(respBody) }

// TranslateRequest is identity; Azure OpenAI accepts OpenAI-shaped JSON.
func (*AzureOpenAI) TranslateRequest(b []byte) ([]byte, error) { return b, nil }

// TranslateResponse is identity; Azure OpenAI returns OpenAI-shaped JSON.
func (*AzureOpenAI) TranslateResponse(b []byte) ([]byte, error) { return b, nil }
