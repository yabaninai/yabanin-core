package provider

// Google Application Default Credentials (ADC) chain for the Vertex
// adapter.
//
// Resolution order (Google-documented ADC semantics, fail-closed):
//  1. GOOGLE_APPLICATION_CREDENTIALS → key file. SET but missing/invalid is
//     a HARD error — an explicitly configured credential source must never
//     silently fall back to a weaker one (packet negative: no fallback to
//     foreign credentials). Both documented file types are supported:
//     service_account (JWT-bearer exchange, RS256, stdlib crypto) and
//     authorized_user (refresh-token grant).
//  2. gcloud ADC well-known file
//     ($HOME/.config/gcloud/application_default_credentials.json) — the
//     authorized_user flow. MISSING → continue to 3; EXISTS but invalid →
//     hard error (Google ADC refuses broken well-known files rather than
//     silently going keyless).
//  3. GCE metadata server, dialed at the documented literal address with
//     the Metadata-Flavor: Google header. The literal (169.254.169.254) is
//     the ONE TrustedExactHosts pin on the ADC transport — an exact
//     IP-literal operator-pin in the D-4 sense: the verified address is
//     exactly the connected address. Hostnames are never pinned.
//
// Source resolution happens ONCE per adapter, lazily on the first token
// request — the Google SDK posture (credentials resolve at client
// construction), singleflight-deduplicated across concurrent cold callers.
// A successful walk pins the source for the adapter's lifetime: cache hits
// never depend on the credential file staying readable (a rotation race or
// transient I/O failure cannot break a request that holds a fresh token),
// and a binding's cache identity cannot flip mid-life. A FAILED walk is
// never pinned — the next request re-walks the chain fail-closed, so a
// credential volume mounted after start recovers on its own.
//
// Secret discipline (go-security-analysis): private keys, refresh tokens,
// client secrets and access tokens NEVER appear in error messages or cache
// keys. Errors carry field names and HTTP status codes only; token-exchange
// diagnostics mirror the azure/sber precedent.
//
// Token cache: keyed by (source identity, project, location). The
// project/location binding is deliberate — the packet negative scenario
// ("project or audience mismatch must not use fallback foreign
// credentials") holds even when two orgs share the same ambient ADC
// credential: a cached entry minted for one (project, location) is never
// handed out for another.
//
// Refresh alignment per binding: a cached token is served only while it
// sits OUTSIDE the refresh skew window (5 min before expiry), so a token
// is re-exchanged before it can go stale mid-request; tokens whose TTL
// does not exceed the skew window are never reused at all (azure parity),
// refreshes are singleflight-deduplicated, and a 429 exchange parks the
// binding behind a bounded cooldown instead of re-hammering the throttled
// endpoint in the request path.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/reireirei/yabanin/pkg/ssrf"
)

const (
	// vertexCloudPlatformScope is the standard OAuth scope for calling
	// Vertex AI generateContent endpoints with an ADC-derived token.
	vertexCloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"
	// vertexOAuthTokenURL is the fixed Google OAuth2 token endpoint for
	// the authorized_user refresh-token grant (the gcloud ADC file does
	// not carry a token_uri; the endpoint is part of the flow).
	vertexOAuthTokenURL = "https://oauth2.googleapis.com/token" //nolint:gosec // G101: the fixed public Google OAuth2 endpoint, not a credential
	// vertexMetadataBaseURL is the documented GCE metadata server literal.
	// Kept as an IP literal: the guarded ADC transport pins EXACTLY this
	// address (D-4), and no DNS lookup can rebind a literal.
	vertexMetadataBaseURL = "http://169.254.169.254"
	// vertexJWTTTL is the signed JWT assertion lifetime in the SA
	// JWT-bearer grant. The aud claim is the token endpoint per Google's SA
	// flow (the token endpoint checks it); the Vertex project/location
	// audience binding happens via the cache key + endpoint URL.
	vertexJWTTTL = time.Hour
)

// vertexWellKnownRelPath is the gcloud ADC file location relative to the
// user config dir (Linux/macOS form; the well-known Windows location
// %APPDATA%/gcloud/… maps to the same relative path under the roaming
// config dir). Declared as var because filepath.Join is not constant.
var vertexWellKnownRelPath = filepath.Join(".config", "gcloud", "application_default_credentials.json")

// errVertexNoADCFile marks "the optional ADC file is simply not there" —
// the only chain-continuation condition. Every other resolution failure is
// terminal (fail closed).
var errVertexNoADCFile = errors.New("vertex: ADC file not found")

// osUserHomeDir is the test seam for the user config dir (env.go
// osGetenv precedent). Production wiring must keep it unset so
// os.UserHomeDir runs.
var osUserHomeDir = func() (string, error) { return os.UserHomeDir() }

// vertexToken is one cached ADC access token.
type vertexToken struct {
	accessToken string
	tokenExp    time.Time
}

// vertexTokenSource is one resolved ADC credential source. identity() MUST
// be secret-free: it enters cache keys and singleflight keys.
type vertexTokenSource interface {
	// accessToken returns a fresh access token and its TTL (0 → default).
	accessToken(ctx context.Context, client *http.Client) (string, time.Duration, error)
	identity() string
}

// vertexADC owns the chain resolution, the token cache, singleflight
// deduplication and the rate-limit cooldown for one *Vertex adapter.
// Field-swapable members (httpClient, metadataURL, oauthTokenURL) are the
// test seams; production construction is newVertexADC(nil).
type vertexADC struct {
	httpClient     *http.Client // SA/user token-exchange client (guarded in production)
	metadataClient *http.Client // metadata probe client (short timeouts, pinned literal)
	metadataURL    string       // default vertexMetadataBaseURL; test seam
	oauthTokenURL  string       // default vertexOAuthTokenURL; test seam

	refreshGroup singleflight.Group
	sourceGroup  singleflight.Group // deduplicates the first chain walk
	mu           sync.Mutex
	tokens       map[string]vertexToken
	cooldowns    map[string]time.Time
	resolved     vertexTokenSource // pinned ADC source after the first successful walk
	pinned       bool              // resolved is valid; failed walks are never pinned
}

// newVertexADC builds the production ADC machinery: both token paths ride
// the shared SSRF transport constructor (azure/sber precedent). The only
// exact-literal pin is the metadata server address — a hostname is never
// waived, so a key file whose token_uri points into a reserved range
// fails closed at dial time.
func newVertexADC(tokenClient *http.Client) *vertexADC {
	a := &vertexADC{
		tokens:        map[string]vertexToken{},
		cooldowns:     map[string]time.Time{},
		metadataURL:   vertexMetadataBaseURL,
		oauthTokenURL: vertexOAuthTokenURL,
	}
	if tokenClient == nil {
		tokenClient = newVertexGuardedClient(10*time.Second, 20*time.Second, nil)
	}
	a.httpClient = tokenClient
	a.metadataClient = newVertexGuardedClient(vertexMetadataDialTimeout, vertexMetadataTimeout, vertexMetadataHostPin())
	return a
}

// newVertexGuardedClient builds an SSRF-guarded client. trustedExactHosts
// is the D-4 predicate for reserved-range literal pins (production passes
// only the metadata literal; tests pass their rig pin).
func newVertexGuardedClient(dialTimeout, responseTimeout time.Duration, trustedExactHosts func(host string) bool) *http.Client {
	tr := ssrf.NewTransport(ssrf.TransportOptions{
		DialTimeout:           dialTimeout,
		KeepAlive:             30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: responseTimeout,
		IdleConnTimeout:       90 * time.Second,
		GuardDialedIP:         true,
		TrustedExactHosts:     trustedExactHosts,
	})
	return &http.Client{Transport: tr}
}

// vertexMetadataHost is the host literal of the metadata URL (kept in sync
// with vertexMetadataBaseURL; declared as var because const expressions
// cannot call functions).
var vertexMetadataHost = strings.TrimPrefix(vertexMetadataBaseURL, "http://")

// vertexMetadataHostPin returns the exact-literal predicate for the
// metadata server dial. Only the literal passes — the documented Google
// metadata address, a fixed operator-independent constant, so the D-4
// "operator-configured literal pin" invariant holds.
func vertexMetadataHostPin() func(host string) bool {
	return func(host string) bool { return host == vertexMetadataHost }
}

// token returns a valid access token for exactly this (source, project,
// location) triple. Cache hit → no network and no chain I/O (the source is
// pinned after its first successful walk). Miss → singleflight refresh
// keyed by the full binding so concurrent cold callers share one exchange
// while other bindings' tokens stay untouched (azure precedent). Like the
// azure/sber exchanges, the refresh runs detached: the caller's ctx does
// not own the shared exchange.
func (a *vertexADC) token(creds VertexCredentials) (string, error) {
	src, err := a.source()
	if err != nil {
		return "", err
	}
	key := src.identity() + "|p:" + creds.Project + "|l:" + creds.Location
	if d, active := a.cooldownRemaining(key); active {
		return "", fmt.Errorf("vertex: ADC token exchange rate-limited; retry allowed in %s", d.Truncate(time.Millisecond))
	}
	if tok, ok := a.tokenFresh(key); ok {
		return tok, nil
	}
	_, err, _ = a.refreshGroup.Do(key, func() (any, error) {
		// Double-check: a waiter that joined after the winner's refresh
		// completed must not exchange again while the token is FRESH.
		if tok, ok := a.tokenFresh(key); ok {
			return tok, nil
		}
		// A sibling exchange may have just been rate-limited between the
		// outer check and acquiring the singleflight slot.
		if d, active := a.cooldownRemaining(key); active {
			return nil, fmt.Errorf("vertex: ADC token exchange rate-limited; retry allowed in %s", d.Truncate(time.Millisecond))
		}
		if err := a.refreshToken(key, src); err != nil {
			return nil, err
		}
		return a.currentToken(key), nil
	})
	if err != nil {
		return "", err
	}
	return a.currentToken(key), nil
}

// source returns the adapter's ADC credential source. The chain is walked
// lazily on the first token request and a successful walk pins the source
// for the adapter's lifetime (Google SDK posture): after pinning, token
// requests perform no credential-file I/O, so a transient read failure or
// rotation race on the key file cannot fail a request that already holds a
// fresh token, and cache identities stay stable. A failed walk is NOT
// pinned — resolution errors are per-request fail-closed (packet negative:
// no fallback), and the chain is retried on the next request so a
// credential that appears later recovers without a restart. Concurrent
// first walks share one singleflight resolution.
func (a *vertexADC) source() (vertexTokenSource, error) {
	a.mu.Lock()
	if a.pinned {
		src := a.resolved
		a.mu.Unlock()
		return src, nil
	}
	a.mu.Unlock()
	_, err, _ := a.sourceGroup.Do("resolve", func() (any, error) {
		// Double-check: a waiter that joined after the winner's walk
		// completed must not re-walk a pinned chain.
		a.mu.Lock()
		if a.pinned {
			src := a.resolved
			a.mu.Unlock()
			return src, nil
		}
		a.mu.Unlock()
		src, err := a.resolveSource()
		if err != nil {
			return nil, err
		}
		a.bindEndpoints(src)
		a.mu.Lock()
		a.resolved = src
		a.pinned = true
		a.mu.Unlock()
		return src, nil
	})
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.resolved, nil
}

// bindEndpoints applies the ADC-level token-endpoint override to sources
// whose exchange endpoint is NOT carried by their credential file: the
// authorized_user (gcloud well-known) flow posts to the fixed Google
// endpoint by spec, so the only way to point it elsewhere (tests; a future
// sovereign-cloud endpoint override) is this ADC-level binding. Production
// is a no-op: oauthTokenURL equals the constant the source already carries.
// Service-account key files carry their own token_uri and are never
// rewritten here (Google SA semantics).
func (a *vertexADC) bindEndpoints(src vertexTokenSource) {
	if u, ok := src.(*vertexUserSource); ok {
		u.tokenURL = a.oauthTokenURL
	}
}

// resolveSource walks the ADC chain. See the file comment for the exact
// fail-closed rules; the ONLY non-terminal condition is the optional
// well-known file being absent.
func (a *vertexADC) resolveSource() (vertexTokenSource, error) {
	if path := osGetenv("GOOGLE_APPLICATION_CREDENTIALS"); path != "" {
		src, err := loadVertexKeyFile(path)
		if err != nil {
			return nil, fmt.Errorf("vertex: GOOGLE_APPLICATION_CREDENTIALS is set but unusable (no fallback): %w", err)
		}
		return src, nil
	}
	src, err := loadVertexWellKnownFile()
	switch {
	case err == nil:
		return src, nil
	case errors.Is(err, errVertexNoADCFile):
		// Optional file absent → metadata server is the credential.
		return &vertexMetadataSource{url: a.metadataURL}, nil
	default:
		return nil, fmt.Errorf("vertex: gcloud ADC well-known file is present but unusable (no fallback): %w", err)
	}
}

// refreshToken performs the exchange and records the token. Errors carry
// status codes only — never credential material (azure precedent).
func (a *vertexADC) refreshToken(key string, src vertexTokenSource) error {
	refreshCtx, cancel := context.WithTimeout(context.Background(), vertexTokenRefreshTimeout)
	defer cancel()
	accessToken, ttl, err := src.accessToken(refreshCtx, a.clientFor(src))
	if err != nil {
		var rle *vertexRateLimitError
		if errors.As(err, &rle) {
			cooldown := vertexRateLimitCooldownBase
			if rle.retryAfter > cooldown {
				cooldown = rle.retryAfter
			}
			if cooldown > vertexRateLimitCooldownMax {
				cooldown = vertexRateLimitCooldownMax
			}
			a.mu.Lock()
			a.cooldowns[key] = time.Now().Add(cooldown)
			a.mu.Unlock()
			return fmt.Errorf("vertex: ADC token exchange HTTP 429 (rate-limited, cooldown %s)", cooldown)
		}
		return err
	}
	if ttl <= 0 {
		ttl = vertexTokenDefaultTTL
	}
	a.mu.Lock()
	a.tokens[key] = vertexToken{accessToken: accessToken, tokenExp: time.Now().Add(ttl)}
	// A successful exchange clears any stale cooldown for the binding.
	delete(a.cooldowns, key)
	// Prune fully expired entries so a long-lived shared adapter does not
	// accumulate one slot per binding ever seen (azure precedent).
	now := time.Now()
	for k, t := range a.tokens {
		if now.After(t.tokenExp) {
			delete(a.tokens, k)
		}
	}
	a.mu.Unlock()
	return nil
}

// clientFor routes the metadata source to its short-timeout pinned client
// and everything else to the shared token client.
func (a *vertexADC) clientFor(src vertexTokenSource) *http.Client {
	if _, ok := src.(*vertexMetadataSource); ok {
		return a.metadataClient
	}
	return a.httpClient
}

func (a *vertexADC) cooldownRemaining(key string) (time.Duration, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
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

// tokenFresh reports the cached token when present and outside the refresh
// skew window.
func (a *vertexADC) tokenFresh(key string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	t, ok := a.tokens[key]
	if !ok || t.accessToken == "" || !time.Now().Before(t.tokenExp.Add(-vertexTokenSkew)) {
		return "", false
	}
	return t.accessToken, true
}

// currentToken returns the binding's cached token; callers must have run
// token() for the same binding first.
func (a *vertexADC) currentToken(key string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.tokens[key].accessToken
}

// vertexRateLimitError marks a 429 from a token endpoint; retryAfter is
// the Retry-After delta when the endpoint sent one (0 otherwise).
type vertexRateLimitError struct{ retryAfter time.Duration }

func (e *vertexRateLimitError) Error() string {
	return "vertex: ADC token endpoint rate-limited (HTTP 429)"
}

// loadVertexKeyFile parses a GOOGLE_APPLICATION_CREDENTIALS key file. Both
// documented ADC types are supported; the error text names fields only.
func loadVertexKeyFile(path string) (vertexTokenSource, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: operator-set GOOGLE_APPLICATION_CREDENTIALS path, never request input
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("key file does not exist: %w", errVertexNoADCFile)
		}
		return nil, fmt.Errorf("key file unreadable: %w", err)
	}
	return parseVertexKeyJSON(raw, "GOOGLE_APPLICATION_CREDENTIALS")
}

// loadVertexWellKnownFile resolves the gcloud ADC file. Absent →
// errVertexNoADCFile (chain continues); present-but-invalid → hard error.
func loadVertexWellKnownFile() (vertexTokenSource, error) {
	home, err := osUserHomeDir()
	if err != nil || home == "" {
		return nil, errVertexNoADCFile
	}
	path := filepath.Join(home, vertexWellKnownRelPath)
	raw, err := os.ReadFile(path) //nolint:gosec // G304: gcloud well-known path under the operator home, never request input
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errVertexNoADCFile
		}
		return nil, fmt.Errorf("well-known file unreadable: %w", err)
	}
	return parseVertexKeyJSON(raw, "gcloud ADC well-known file")
}

// parseVertexKeyJSON decodes either documented ADC file type. The second
// arg names the ORIGIN for error messages (field names only — never file
// contents).
func parseVertexKeyJSON(raw []byte, origin string) (vertexTokenSource, error) {
	var key struct {
		Type         string `json:"type"`
		ClientEmail  string `json:"client_email"`
		PrivateKey   string `json:"private_key"`
		TokenURI     string `json:"token_uri"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(raw, &key); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON", origin)
	}
	switch key.Type {
	case "service_account":
		switch {
		case key.ClientEmail == "":
			return nil, fmt.Errorf("%s: service_account key missing client_email", origin)
		case key.PrivateKey == "":
			return nil, fmt.Errorf("%s: service_account key missing private_key", origin)
		case key.TokenURI == "":
			return nil, fmt.Errorf("%s: service_account key missing token_uri", origin)
		}
		if !strings.HasPrefix(key.TokenURI, "https://") && !strings.HasPrefix(key.TokenURI, "http://") {
			return nil, fmt.Errorf("%s: token_uri must be an http(s) URL", origin)
		}
		return &vertexSASource{
			clientEmail: key.ClientEmail,
			privateKey:  []byte(key.PrivateKey),
			tokenURI:    key.TokenURI,
		}, nil
	case "authorized_user":
		switch {
		case key.ClientID == "":
			return nil, fmt.Errorf("%s: authorized_user key missing client_id", origin)
		case key.ClientSecret == "":
			return nil, fmt.Errorf("%s: authorized_user key missing client_secret", origin)
		case key.RefreshToken == "":
			return nil, fmt.Errorf("%s: authorized_user key missing refresh_token", origin)
		}
		return &vertexUserSource{
			clientID:     key.ClientID,
			clientSecret: key.ClientSecret,
			refreshToken: key.RefreshToken,
			tokenURL:     vertexOAuthTokenURL,
		}, nil
	case "":
		return nil, fmt.Errorf("%s: key file has no type field", origin)
	default:
		return nil, fmt.Errorf("%s: unsupported key file type (want service_account or authorized_user)", origin)
	}
}

// vertexSASource exchanges a signed JWT (RS256) for an access token at the
// key file's token_uri — the Google-documented service-account flow, stdlib
// crypto only.
type vertexSASource struct {
	clientEmail string
	privateKey  []byte // PEM PKCS#8 (or PKCS#1) RSA private key from the key file
	tokenURI    string
}

func (s *vertexSASource) identity() string {
	// Secret-free: the SA identity is its (public) principal email and the
	// exchange endpoint.
	return "sa|" + s.clientEmail + "|" + s.tokenURI
}

func (s *vertexSASource) accessToken(ctx context.Context, client *http.Client) (string, time.Duration, error) {
	assertion, err := s.signJWT(time.Now())
	if err != nil {
		return "", 0, fmt.Errorf("vertex: ADC service-account key unusable: %w", err)
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}
	return vertexPostTokenForm(ctx, client, s.tokenURI, form)
}

// signJWT builds and signs the JWT-bearer assertion. The aud claim is the
// token endpoint (Google SA flow); scope carries cloud-platform.
func (s *vertexSASource) signJWT(now time.Time) (string, error) {
	block, _ := pem.Decode(s.privateKey)
	if block == nil {
		return "", errors.New("private_key is not PEM-encoded")
	}
	var key any
	var err error
	if k, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes); parseErr == nil {
		key = k
	} else if k, parseErr := x509.ParsePKCS1PrivateKey(block.Bytes); parseErr == nil {
		key = k
	} else {
		return "", errors.New("private_key is neither PKCS#8 nor PKCS#1 RSA")
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return "", errors.New("private_key is not an RSA key")
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, err := json.Marshal(map[string]any{
		"iss":   s.clientEmail,
		"scope": vertexCloudPlatformScope,
		"aud":   s.tokenURI,
		"iat":   now.Unix(),
		"exp":   now.Add(vertexJWTTTL).Unix(),
	})
	if err != nil {
		return "", err
	}
	payload := header + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(payload))
	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return payload + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// vertexUserSource is the gcloud authorized_user (refresh-token) flow —
// the developer-workload ADC branch.
type vertexUserSource struct {
	clientID     string
	clientSecret string
	refreshToken string
	tokenURL     string
}

func (s *vertexUserSource) identity() string {
	// Secret-free: the OAuth client id is a public identifier.
	return "user|" + s.clientID
}

func (s *vertexUserSource) accessToken(ctx context.Context, client *http.Client) (string, time.Duration, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {s.refreshToken},
		"client_id":     {s.clientID},
		"client_secret": {s.clientSecret},
	}
	return vertexPostTokenForm(ctx, client, s.tokenURL, form)
}

// vertexMetadataSource is the GCP workload branch: the instance
// service-account token from the metadata server (literal address,
// Metadata-Flavor: Google).
type vertexMetadataSource struct {
	url string
}

func (*vertexMetadataSource) identity() string { return "metadata" }

func (s *vertexMetadataSource) accessToken(ctx context.Context, client *http.Client) (string, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		s.url+"/computeMetadata/v1/instance/service-accounts/default/token", nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("vertex: metadata server unreachable (not on GCP workload?): %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return "", 0, fmt.Errorf("vertex: metadata token request HTTP %d", resp.StatusCode)
	}
	return vertexDecodeTokenResponse(resp.Body)
}

// vertexPostTokenForm POSTs an OAuth token form and decodes the standard
// response. Error messages carry status codes only; 429 is surfaced as a
// typed error so the caller applies the bounded cooldown.
func vertexPostTokenForm(ctx context.Context, client *http.Client, tokenURL string, form url.Values) (string, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("vertex: token endpoint unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusTooManyRequests {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return "", 0, &vertexRateLimitError{retryAfter: vertexRetryAfterSeconds(resp.Header.Get("Retry-After"))}
	}
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return "", 0, fmt.Errorf("vertex: token exchange HTTP %d", resp.StatusCode)
	}
	return vertexDecodeTokenResponse(resp.Body)
}

// vertexDecodeTokenResponse parses {access_token, expires_in}. Limit 1 MiB
// like the azure exchange reader.
func vertexDecodeTokenResponse(r io.Reader) (string, time.Duration, error) {
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"` // seconds
	}
	if err := json.NewDecoder(io.LimitReader(r, 1<<20)).Decode(&tok); err != nil {
		return "", 0, fmt.Errorf("vertex: decode token response: %w", err)
	}
	if tok.AccessToken == "" {
		return "", 0, errors.New("vertex: empty access_token in token response")
	}
	return tok.AccessToken, time.Duration(tok.ExpiresIn) * time.Second, nil
}

// vertexRetryAfterSeconds parses a Retry-After delta-seconds header
// (azure precedent; unparsable/negative → 0 keeps the default cooldown).
func vertexRetryAfterSeconds(header string) time.Duration {
	// reuse the azure parser semantics via a local implementation to keep
	// vertex self-contained
	seconds := int64(0)
	header = strings.TrimSpace(header)
	if header == "" {
		return 0
	}
	for _, c := range header {
		if c < '0' || c > '9' {
			return 0
		}
		seconds = seconds*10 + int64(c-'0')
		if seconds > int64(vertexRateLimitCooldownMax/time.Second) {
			return vertexRateLimitCooldownMax
		}
	}
	if seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}
