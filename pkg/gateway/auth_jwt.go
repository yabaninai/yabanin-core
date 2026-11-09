package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	apierrors "github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/labels"
	"github.com/reireirei/yabanin/pkg/metrics"
)

// Authorization header carries a Bearer JWT (JWS compact form, kid header)
// is authenticated from the VERIFIED token claims alone: the mapped org_id
// claim becomes the request's org context (X-Org-Id) and the optional
// key-label claim becomes the locked "key" principal label source, narrowing
// the OP-8 policy-pipeline attachments (key_labels) exactly like an API
// key's labels do. No api_keys row, no static key: service-account auth.
//
// Security invariants:
//   - algorithm allow-list (RS256, ES256) enforced at parse time — "none"
//     and HMAC confusion are rejected before any key material is touched;
//   - keys are selected by kid from the org-configured JWKS only; a token
//     without kid never reaches a key (the format gate requires kid);
//   - multiple keys under one kid are all attempted (kid-collision safe);
//   - exp is REQUIRED; iss/aud are enforced when configured; 30s leeway;
//   - fail-closed: with an empty JWKS cache and an unreachable JWKS the
//     request gets 503; with a cached (possibly stale) set the cache serves
//     up to maxStale, then 503. Signature/claim failures are always 401.
//
// Format-collision note (deployment contract): recognition is by FORM —
// three base64url segments plus a kid JOSE header — and only while the
// feature is wired. A legacy API key that happens to have that shape would
// be routed to the JWT path and rejected; keys issued by this gateway
// (yag_/ypk_ + hex, session ybs_ + hex) never contain dots, so no real key
// collides. Operators must not mint 3-segment dotted API keys while the
// JWT path is enabled.

// JWTWiring carries the env-resolved JWT knobs from services/run into the
// gateway composition root (pkg/config is deliberately untouched). The zero
// value disables the JWT path — legacy API-key auth stays bit-for-bit.
type JWTWiring struct {
	// JWKSURL is the org-configured JWKS endpoint (YABANIN_JWT_JWKS_URL).
	// https required except loopback (the wiring in services/run enforces).
	JWKSURL string
	// Issuer is the required iss claim value (YABANIN_JWT_ISSUER). Empty
	// skips issuer validation.
	Issuer string
	// Audience is the required aud claim value (YABANIN_JWT_AUDIENCE).
	// Empty skips audience validation.
	Audience string
	// OrgClaim names the claim that maps the token to a gateway org
	// (YABANIN_JWT_ORG_CLAIM, default "org_id").
	OrgClaim string
	// KeyLabelClaim optionally names a claim whose value(s) become the
	// LOCKED key label source (YABANIN_JWT_KEY_LABEL_CLAIM). Accepted
	// shapes: string, array of strings, or object of string→string.
	KeyLabelClaim string
}

// Enabled reports whether the optional JWT auth path is configured.
func (w JWTWiring) Enabled() bool { return w.JWKSURL != "" }

// JWT auth error reasons (gateway_jwt_errors_total label values).
const (
	jwtReasonForm            = "form"
	jwtReasonAlg             = "alg"
	jwtReasonSignature       = "signature"
	jwtReasonUnknownKid      = "unknown_kid"
	jwtReasonIssuer          = "issuer"
	jwtReasonAudience        = "audience"
	jwtReasonExpired         = "expired"
	jwtReasonNotYetValid     = "not_yet_valid"
	jwtReasonMissingExp      = "missing_exp"
	jwtReasonOrgClaim        = "org_claim"
	jwtReasonJWKSUnavailable = "jwks_unavailable"
)

// jwtAllowedAlgorithms is the hard allow-list. Asymmetric signing only:
// "none" cannot appear, and an HMAC token (HS*) is rejected at parse time
// even if someone plants a symmetric key in the JWKS.
var jwtAllowedAlgorithms = []jose.SignatureAlgorithm{jose.RS256, jose.ES256}

// jwtClaimsLeeway is the clock-skew allowance for exp/nbf validation.
const jwtClaimsLeeway = 30 * time.Second

// jwtAuthError carries the fail-closed outcome to the middleware fork.
type jwtAuthError struct {
	status int    // 401 or 503
	reason string // gateway_jwt_errors_total label value
	msg    string // client-safe message
}

func (e *jwtAuthError) Error() string { return e.msg }

func jwtAuthErr(status int, reason, msg string) *jwtAuthError {
	return &jwtAuthError{status: status, reason: reason, msg: msg}
}

// JWTPrincipal is the verified token identity for one request.
type JWTPrincipal struct {
	// OrgID is the gateway org from the org claim; it flows downstream as
	// X-Org-Id (the same channel API-key auth uses).
	OrgID string
	// Subject is the token's sub claim (observability/logging only).
	Subject string
	// KeyLabels is the LOCKED key label set from the key-label claim; it
	// narrows policy-pipeline attachments like an API key's labels.
	KeyLabels labels.Set
}

// JWTAuthenticator validates gateway bearer JWTs against an org-configured
// JWKS endpoint. Constructed once at wiring (NewJWTAuthenticator); safe for
// concurrent use.
type JWTAuthenticator struct {
	wiring JWTWiring
	log    *slog.Logger
	cache  *jwksCache
}

// NewJWTAuthenticator builds the JWT path for the given wiring. Returns nil
// when the wiring is disabled, so the legacy API-key path stays untouched.
func NewJWTAuthenticator(wiring JWTWiring, l *slog.Logger) *JWTAuthenticator {
	if !wiring.Enabled() {
		return nil
	}
	if wiring.OrgClaim == "" {
		wiring.OrgClaim = "org_id"
	}
	if l == nil {
		l = slog.Default()
	}
	return &JWTAuthenticator{
		wiring: wiring,
		log:    l.With("component", "jwt-auth"),
		cache:  newJWKSCache(wiring.JWKSURL, l.With("component", "jwt-jwks")),
	}
}

// jwtHeader is the decoded JOSE header used by the format gate.
type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// decodeJWTHeader decodes the JWS compact header (first segment).
func decodeJWTHeader(token string) (jwtHeader, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return jwtHeader{}, false
	}
	for _, p := range parts {
		if p == "" {
			return jwtHeader{}, false
		}
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return jwtHeader{}, false
	}
	var h jwtHeader
	if err := json.Unmarshal(raw, &h); err != nil {
		return jwtHeader{}, false
	}
	if h.Kid == "" {
		return jwtHeader{}, false
	}
	return h, true
}

// tokenLooksLikeJWT is the form gate between the legacy API-key path and
// the JWT path. It only inspects the token shape (three base64url segments,
// a kid in the JOSE header); it verifies nothing.
func tokenLooksLikeJWT(token string) bool {
	_, ok := decodeJWTHeader(token)
	return ok
}

// Authenticate validates one bearer token and returns the mapped principal.
// Metrics are recorded here for every outcome.
func (a *JWTAuthenticator) Authenticate(ctx context.Context, token string) (*JWTPrincipal, error) {
	h, ok := decodeJWTHeader(token)
	if !ok {
		return nil, a.fail(jwtReasonForm, http.StatusUnauthorized,
			"malformed bearer token")
	}
	switch jose.SignatureAlgorithm(h.Alg) {
	case jose.RS256, jose.ES256:
	default:
		return nil, a.fail(jwtReasonAlg, http.StatusUnauthorized,
			"unsupported token algorithm")
	}

	keys, err := a.cache.keys(ctx, h.Kid)
	if err != nil {
		if errors.Is(err, errJWKSUnavailable) {
			return nil, a.fail(jwtReasonJWKSUnavailable, http.StatusServiceUnavailable,
				"authentication temporarily unavailable")
		}
		return nil, a.fail(jwtReasonUnknownKid, http.StatusUnauthorized,
			"unknown token key")
	}

	tok, err := jwt.ParseSigned(token, jwtAllowedAlgorithms)
	if err != nil {
		return nil, a.fail(jwtReasonSignature, http.StatusUnauthorized,
			"invalid bearer token")
	}

	var claims jwt.Claims
	extra := map[string]any{}
	verified := false
	for i := range keys {
		k := keys[i]
		if !keyMatchesAlg(&k, h.Alg) {
			continue
		}
		if tok.Claims(k.Key, &claims, &extra) == nil {
			verified = true
			break
		}
	}
	if !verified {
		return nil, a.fail(jwtReasonSignature, http.StatusUnauthorized,
			"invalid bearer token")
	}

	now := time.Now()
	if err := a.validateClaims(&claims, extra, now); err != nil {
		return nil, err
	}

	principal := &JWTPrincipal{
		OrgID:     claimsString(extra, a.wiring.OrgClaim),
		Subject:   claims.Subject,
		KeyLabels: claimsLabels(extra, a.wiring.KeyLabelClaim),
	}
	if principal.OrgID == "" {
		return nil, a.fail(jwtReasonOrgClaim, http.StatusUnauthorized,
			"invalid bearer token")
	}
	metrics.GatewayJWTValidationsTotal.WithLabelValues("ok").Inc()
	return principal, nil
}

// validateClaims enforces iss/aud/exp/nbf and the org-claim shape. exp is
// required (fail-closed); iss/aud are enforced only when configured.
func (a *JWTAuthenticator) validateClaims(claims *jwt.Claims, extra map[string]any, now time.Time) error {
	if claims.Expiry == nil {
		return a.fail(jwtReasonMissingExp, http.StatusUnauthorized, "invalid bearer token")
	}
	expected := jwt.Expected{Time: now}
	if a.wiring.Issuer != "" {
		expected.Issuer = a.wiring.Issuer
	}
	if a.wiring.Audience != "" {
		expected.AnyAudience = jwt.Audience{a.wiring.Audience}
	}
	switch err := claims.ValidateWithLeeway(expected, jwtClaimsLeeway); {
	case err == nil:
		return nil
	case errors.Is(err, jwt.ErrInvalidIssuer):
		return a.fail(jwtReasonIssuer, http.StatusUnauthorized, "invalid bearer token")
	case errors.Is(err, jwt.ErrInvalidAudience):
		return a.fail(jwtReasonAudience, http.StatusUnauthorized, "invalid bearer token")
	case errors.Is(err, jwt.ErrExpired):
		return a.fail(jwtReasonExpired, http.StatusUnauthorized, "invalid bearer token")
	case errors.Is(err, jwt.ErrNotValidYet):
		return a.fail(jwtReasonNotYetValid, http.StatusUnauthorized, "invalid bearer token")
	case errors.Is(err, jwt.ErrIssuedInTheFuture):
		return a.fail(jwtReasonNotYetValid, http.StatusUnauthorized, "invalid bearer token")
	default:
		return a.fail(jwtReasonExpired, http.StatusUnauthorized, "invalid bearer token")
	}
}

// fail records the rejection metric and returns the typed error.
func (a *JWTAuthenticator) fail(reason string, status int, msg string) error {
	metrics.GatewayJWTErrorsTotal.WithLabelValues(reason).Inc()
	return jwtAuthErr(status, reason, msg)
}

// keyMatchesAlg restricts JWKS keys to those compatible with the token's
// (already allow-listed) algorithm: an explicit key alg must match exactly;
// otherwise the key type must match (RSA→RS256, EC P-256→ES256). This keeps
// an RSA key from ever being offered to an ES256 signature and vice versa.
func keyMatchesAlg(k *jose.JSONWebKey, alg string) bool {
	if k.Use != "" && k.Use != "sig" {
		return false
	}
	if k.Algorithm != "" {
		return k.Algorithm == alg
	}
	switch key := k.Key.(type) {
	case *rsa.PublicKey:
		return alg == string(jose.RS256)
	case *ecdsa.PublicKey:
		return alg == string(jose.ES256) && key.Curve == elliptic.P256()
	default:
		return false
	}
}

// claimsString reads one string claim.
func claimsString(extra map[string]any, name string) string {
	if name == "" {
		return ""
	}
	if v, ok := extra[name].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// claimsLabels normalizes the optional key-label claim into a label set.
// Accepted shapes: string ("prod"), array of strings (["prod","team-a"]),
// object ({"env":"prod"}). Anything else is ignored — the label claim only
// NARROWS policy attachments; a malformed claim must not widen or fail auth.
func claimsLabels(extra map[string]any, name string) labels.Set {
	if name == "" {
		return nil
	}
	v, ok := extra[name]
	if !ok {
		return nil
	}
	out := labels.Set{}
	switch t := v.(type) {
	case string:
		if s := strings.TrimSpace(t); s != "" {
			out[s] = s
		}
	case []any:
		for _, item := range t {
			if s, ok := item.(string); ok {
				if s = strings.TrimSpace(s); s != "" {
					out[s] = s
				}
			}
		}
	case map[string]any:
		for k, val := range t {
			if s, ok := val.(string); ok {
				if s = strings.TrimSpace(s); s != "" {
					out[strings.TrimSpace(k)] = s
				}
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// serveJWT is the auth-middleware fork for recognized JWT tokens. The org
// flows downstream via X-Org-Id (the same channel as API-key auth); the
// key-label claim becomes the locked "key" principal label source.
func (a *AuthMiddleware) serveJWT(w http.ResponseWriter, r *http.Request, next http.Handler, token string) {
	principal, err := a.jwt.Authenticate(r.Context(), token)
	if err != nil {
		var ae *jwtAuthError
		if !errors.As(err, &ae) {
			ae = jwtAuthErr(http.StatusUnauthorized, jwtReasonSignature, "invalid bearer token")
		}
		apierrors.Write(w, ae.status, apierrors.ErrorCodeAuthentication, ae.msg)
		return
	}
	r.Header.Set("X-Org-Id", principal.OrgID)
	ctx := r.Context()
	if len(principal.KeyLabels) > 0 {
		ctx = withPrincipalLabelSources(ctx, []labels.Source{
			{Name: "key", Labels: principal.KeyLabels, Locked: true},
		})
	}
	next.ServeHTTP(w, r.WithContext(ctx))
}

// --- JWKS cache ---------------------------------------------------------------

const (
	// jwtJWKSFetchTimeout bounds one JWKS round trip (inline miss fetch and
	// background refresh). The fresh-cache hot path performs no network I/O.
	jwtJWKSFetchTimeout = 5 * time.Second
	// jwtJWKSTTL is the base freshness of a fetched key set before a
	// background refresh is scheduled. Jitter (fraction below) desynchronizes
	// replicas so they do not stampede the identity provider.
	jwtJWKSTTL = 10 * time.Minute
	// jwtJWKSJitterFrac is the fraction of the TTL added as random jitter.
	jwtJWKSJitterFrac = 0.1
	// jwtJWKSMaxStale bounds how long a cached set may keep serving while
	// the JWKS is unreachable. Beyond it the gateway fails closed (503) —
	// a revoked/rotated-away key must not authenticate forever.
	jwtJWKSMaxStale = time.Hour
	// jwtJWKSMaxBodyBytes caps the JWKS response size.
	jwtJWKSMaxBodyBytes = 1 << 20
)

var (
	// errJWKSUnavailable: the JWKS is unreachable and no cached set can
	// serve the request (empty cache or past max-stale) — fail closed 503.
	errJWKSUnavailable = errors.New("jwks unavailable")
	// errJWKSUnknownKey: the (possibly stale-cached) set has no key for the
	// token's kid — fail closed 401.
	errJWKSUnknownKey = errors.New("jwks has no key for kid")
)

// jwksCache caches the JWKS key set. Fresh-cache lookups take the RWMutex
// read lock only — never network I/O; fetches are single-flight under a
// separate fetchMu:
//   - a kid miss performs one bounded inline fetch (rotation acceptance) and
//     concurrent lookups with a cached kid are served while it runs;
//   - an aged set (past TTL + jitter) schedules ONE background refresh and
//     keeps serving stale keys so the hot path is never blocked on the
//     identity provider.
type jwksCache struct {
	url    string
	client *http.Client
	log    *slog.Logger
	now    func() time.Time
	// jitter returns [0,n); injected in tests. Deterministic in production
	// seeding terms — crypto randomness is not needed for de-sync.
	jitter func(n int) int

	ttl      time.Duration
	maxStale time.Duration

	// fetchMu serializes JWKS network fetches (inline miss + background
	// refresh). It is deliberately NOT c.mu: holding the cache lock during
	// a fetch would stall every request behind the identity provider.
	fetchMu sync.Mutex

	mu             sync.RWMutex
	set            *jose.JSONWebKeySet
	fetchedAt      time.Time
	refreshDue     time.Time // fetchedAt + ttl + jitter
	refreshRunning atomic.Bool
}

func newJWKSCache(url string, l *slog.Logger) *jwksCache {
	return &jwksCache{
		url:      url,
		client:   &http.Client{Timeout: jwtJWKSFetchTimeout},
		log:      l,
		now:      time.Now,
		jitter:   rand.IntN,
		ttl:      jwtJWKSTTL,
		maxStale: jwtJWKSMaxStale,
	}
}

// keys returns the JWKS keys for kid. See the type comment for the
// refresh policy. errJWKSUnavailable → 503, errJWKSUnknownKey → 401.
func (c *jwksCache) keys(ctx context.Context, kid string) ([]jose.JSONWebKey, error) {
	if ks, live := c.peekKeys(ctx, kid); live && len(ks) > 0 {
		return ks, nil
	}

	// Miss (no set, aged-out set, or unknown kid): one bounded inline fetch,
	// single-flight under fetchMu. fetchMu is not c.mu, so requests whose
	// kid is already cached keep being served while the fetch runs.
	c.fetchMu.Lock()
	defer c.fetchMu.Unlock()

	// Double-check: another fetcher may have refreshed while we waited.
	if ks, live := c.peekKeys(ctx, kid); live && len(ks) > 0 {
		return ks, nil
	}

	newSet, err := c.fetch(ctx)
	if err != nil {
		// The cache is the source of truth while it is within the
		// staleness bound: a kid it carries serves (stale), a kid it lacks
		// is unknown (401) — only a dead/empty cache fails closed (503).
		ks, live := c.peekKeys(ctx, kid)
		if !live {
			if c.log != nil {
				c.log.Warn("jwks unavailable", "error", err)
			}
			return nil, errJWKSUnavailable
		}
		if len(ks) > 0 && c.log != nil {
			c.log.Debug("jwks fetch failed; serving stale cache", "error", err)
		}
		if len(ks) > 0 {
			return ks, nil
		}
		return nil, errJWKSUnknownKey
	}
	c.store(newSet)
	ks := newSet.Key(kid)
	if len(ks) == 0 {
		return nil, errJWKSUnknownKey
	}
	return ks, nil
}

// peekKeys reads the cached key set under the read lock. It returns the keys
// for kid and whether the set is live (within max-stale): (ks, true) with
// len(ks)>0 is a hit; (nil, true) a live set without the kid; (nil, false)
// no live set (empty cache or past the staleness bound). A hit past the
// jittered TTL schedules one background refresh.
func (c *jwksCache) peekKeys(ctx context.Context, kid string) ([]jose.JSONWebKey, bool) {
	now := c.now()
	c.mu.RLock()
	var (
		set        = c.set
		live       = set != nil && now.Sub(c.fetchedAt) <= c.maxStale
		dueRefresh = live && now.After(c.refreshDue)
	)
	var ks []jose.JSONWebKey
	if live {
		ks = set.Key(kid)
	}
	c.mu.RUnlock()

	if len(ks) > 0 && dueRefresh {
		c.scheduleRefresh(ctx)
	}
	return ks, live
}

// store installs a freshly fetched key set and recomputes the jittered
// refresh deadline.
func (c *jwksCache) store(newSet *jose.JSONWebKeySet) {
	c.mu.Lock()
	c.set = newSet
	c.fetchedAt = c.now()
	c.refreshDue = c.nextRefresh(c.fetchedAt)
	c.mu.Unlock()
}

// nextRefresh computes fetchedAt + ttl + jitter so replicas de-synchronize.
func (c *jwksCache) nextRefresh(fetchedAt time.Time) time.Time {
	if c.jitter == nil || c.ttl <= 0 {
		return fetchedAt.Add(c.ttl)
	}
	n := int(float64(c.ttl) * jwtJWKSJitterFrac)
	if n <= 0 {
		return fetchedAt.Add(c.ttl)
	}
	return fetchedAt.Add(c.ttl + time.Duration(c.jitter(n)))
}

// refreshSync performs an immediate inline refresh of the key set. Not used
// on the request path (rotation acceptance uses the kid-miss inline fetch);
// tests use it to drive deterministic eviction of rotated-away keys.
func (c *jwksCache) refreshSync(ctx context.Context) error {
	c.fetchMu.Lock()
	defer c.fetchMu.Unlock()
	newSet, err := c.fetch(ctx)
	if err != nil {
		return err
	}
	c.store(newSet)
	return nil
}

// scheduleRefresh kicks off at most one background refresh. The cache keeps
// serving stale keys meanwhile — the request path never waits on it. The
// refresh context is detached from the triggering request (values inherited,
// cancellation dropped): a finished request must not abort the cache
// hygiene; the HTTP client timeout bounds the call.
func (c *jwksCache) scheduleRefresh(ctx context.Context) {
	if !c.refreshRunning.CompareAndSwap(false, true) {
		return
	}
	go func(ctx context.Context) {
		defer c.refreshRunning.Store(false)
		c.fetchMu.Lock()
		newSet, err := c.fetch(context.WithoutCancel(ctx))
		c.fetchMu.Unlock()
		if err != nil {
			if c.log != nil {
				c.log.Debug("background jwks refresh failed; keeping stale cache", "error", err)
			}
			return
		}
		c.store(newSet)
		if c.log != nil {
			c.log.Debug("background jwks refresh completed")
		}
	}(ctx)
}

// fetch performs one bounded JWKS GET. Caller must hold fetchMu (the cache
// read/write mutex stays free, so lookups of cached keys run during the
// fetch); fetch does not touch any other mutable state.
func (c *jwksCache) fetch(ctx context.Context) (*jose.JSONWebKeySet, error) {
	fetchCtx, cancel := context.WithTimeout(ctx, jwtJWKSFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, fmt.Errorf("jwks request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jwks fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks fetch: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, jwtJWKSMaxBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("jwks read: %w", err)
	}
	if len(body) > jwtJWKSMaxBodyBytes {
		return nil, errors.New("jwks response too large")
	}
	var keyset jose.JSONWebKeySet
	if err := json.Unmarshal(body, &keyset); err != nil {
		return nil, fmt.Errorf("jwks parse: %w", err)
	}
	if len(keyset.Keys) == 0 {
		return nil, errors.New("jwks has no keys")
	}
	return &keyset, nil
}
