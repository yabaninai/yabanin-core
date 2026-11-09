package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/circuit"
	"github.com/reireirei/yabanin/pkg/config"
	apierrors "github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/resolver"
)

// OrgKeyResolver is the request-path slice of the frozen W-BYOK-DB contract
// depends ONLY on ResolveKey: the request path never lists or mutates
// credentials, and the signature uses builtin types only, so the concrete
// *adminstore.Store (wired at the W-BYOK-DB merge) satisfies it structurally
// without a type-level coupling in either direction. Plaintext returned by
// ResolveKey is used for exactly one provider attempt and never cached or
// logged.
type OrgKeyResolver interface {
	ResolveKey(ctx context.Context, orgID, provider, baseURL string) (plaintext string, ok bool, err error)
}

// OrgCredsVersionStore is the org-credential cache-invalidation contract
// between the gateway (W-BYOK-CORE) and the admin API (W-BYOK-API):
//
//   - the admin API MUST call SetOrgCredsVersion(orgID, version) after every
//     credentials CRUD for that org. The recommended version value is
//     time.Now().UnixNano() — monotonic per org, no read-modify-write race
//     between concurrent admin mutations;
//   - the gateway probes GetOrgCredsVersion to drop its (secret-free)
//     "no matching credential" negative lookups the moment a credential is
//     added; without a reachable version store the negative entry expires at
//     orgCredsProbeTTL (30s) instead — the same bound the rulestore TTL gives
//     rule invalidation;
//     "orgcreds:ver:<orgID>" holding a decimal int64. SetOrgCredsVersion
//     refreshes a 7-day TTL so abandoned orgs do not accumulate keys.
type OrgCredsVersionStore interface {
	GetOrgCredsVersion(ctx context.Context, orgID string) (int64, error)
	SetOrgCredsVersion(ctx context.Context, orgID string, version int64) error
}

// orgCredsVersionKeyPrefix is the Redis key namespace of the version contract
// above. Both lanes must use the exact same prefix.
//
//nolint:gosec // false positive: this is a Redis key namespace (an invalidation version), not a credential
const orgCredsVersionKeyPrefix = "orgcreds:ver:"

// orgCredsVersionTTL bounds the Redis retention of one org's version key;
// every Set refreshes it. Expiry is harmless: a missing key reads as 0 and a
// 0 != cached-version comparison only forces a re-probe.
const orgCredsVersionTTL = 7 * 24 * time.Hour

// orgCredsProbeTTL is the hard staleness bound of the gateway's negative
// credential lookups when the version store is unavailable.
const orgCredsProbeTTL = 30 * time.Second

// OrgCredsRedis is the Redis surface the version store needs
// (*redis.Client satisfies it).
type OrgCredsRedis interface {
	Get(ctx context.Context, key string) *redis.StringCmd
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) *redis.StatusCmd
}

// redisOrgCredsVersions is the production OrgCredsVersionStore. Values are
// decimal int64 versions; a missing key reads as version 0 (no error) so a
// flushed Redis degrades to the TTL bound instead of failing requests.
type redisOrgCredsVersions struct {
	rdb OrgCredsRedis
	log *slog.Logger
}

// NewOrgCredsVersionStore builds the Redis-backed org-credential version
// the gateway probe; see the OrgCredsVersionStore contract.
func NewOrgCredsVersionStore(rdb OrgCredsRedis, l *slog.Logger) OrgCredsVersionStore {
	return &redisOrgCredsVersions{rdb: rdb, log: l}
}

func (s *redisOrgCredsVersions) key(orgID string) string {
	return orgCredsVersionKeyPrefix + orgID
}

// GetOrgCredsVersion reads the org's current credential version. A missing
// key is version 0, not an error (fresh org / expired key / flushed cache).
func (s *redisOrgCredsVersions) GetOrgCredsVersion(ctx context.Context, orgID string) (int64, error) {
	v, err := s.rdb.Get(ctx, s.key(orgID)).Result()
	if err == redis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read org creds version: %w", err)
	}
	version, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse org creds version %q: %w", v, err)
	}
	return version, nil
}

// SetOrgCredsVersion records a new credential version for the org. Called by
// the admin API after every credentials CRUD (contract above).
func (s *redisOrgCredsVersions) SetOrgCredsVersion(ctx context.Context, orgID string, version int64) error {
	if err := s.rdb.Set(ctx, s.key(orgID), strconv.FormatInt(version, 10), orgCredsVersionTTL).Err(); err != nil {
		return fmt.Errorf("write org creds version: %w", err)
	}
	return nil
}

// orgCredsProbe is the gateway-side cache over ONE boolean fact per
// (org, provider, base URL): does the org have a credential for this
// endpoint? It is the load guard that keeps non-BYOK traffic at zero extra
// upstream-store queries after the first probe per TTL. The cache stores no
// secret material — the boolean outcome only; the plaintext key is produced
// by ResolveKey per request (per-request decrypt, never cached) whenever the
// probe says the org plausibly holds a credential.
//
// Invalidation: an OrgCredsVersionStore version bump (W-BYOK-API CRUD hook)
// drops the affected org's entries immediately; when the version store is nil
// or unreachable the hard TTL (orgCredsProbeTTL) bounds staleness instead.
type orgCredsProbe struct {
	resolver OrgKeyResolver
	versions OrgCredsVersionStore // nil = TTL-only invalidation
	ttl      time.Duration
	now      func() time.Time
	log      *slog.Logger

	mu      sync.Mutex
	entries map[string]*orgCredsProbeEntry
}

type orgCredsProbeEntry struct {
	version  int64
	haveVer  bool
	ok       bool
	loadedAt time.Time
}

// orgCredsProbeMaxOrgs caps the per-org index; eviction is oldest-loaded.
// Keys are (org, provider, baseURL) triples, bounded in practice by the
// registry's endpoint set — the cap only closes the unbounded-growth corner.
const orgCredsProbeMaxOrgs = 4096

func newOrgCredsProbe(r OrgKeyResolver, versions OrgCredsVersionStore, ttl time.Duration, l *slog.Logger) *orgCredsProbe {
	if ttl <= 0 {
		ttl = orgCredsProbeTTL
	}
	return &orgCredsProbe{
		resolver: r,
		versions: versions,
		ttl:      ttl,
		now:      time.Now,
		log:      l,
		entries:  make(map[string]*orgCredsProbeEntry),
	}
}

// resolveUpstreamKey resolves the upstream credential for one provider
// attempt. Priority (W-BYOK-CORE, coordinated with W-PROV's resolver
// fail-closed policy):
//
//  1. request-scope key — RESERVED: no client-facing surface exists today,
//     that surface.
//     additive pool surface (gw.credPool): round-robin selection over the
//     rotation-eligible credentials (D-2), per-attempt plaintext of the
//     PINNED credential (D-3), masked credential ref for attribution (D-4).
//     Legacy path otherwise: OrgKeyResolver.ResolveKey(org, provider,
//     base_url), newest-first. Plaintext lives only in the attempt either
//     way.
//  3. per-model upstream_api_key (the W-PROV decrypted candidate key).
//  4. the global default (cfg.APIKey / cfg.FallbackKey).
//
// A probe/store/pool INFRASTRUCTURE error while the org plausibly holds a
// credential for this endpoint is fail-closed: silently sending the GLOBAL
// key to an org-registered endpoint is the exact credential-leak hazard the
// W-PROV resolver policy refuses for per-model keys. ok=false from the store
// (no matching credential) is a normal outcome — the caller falls through.
func (gw *gateway) resolveUpstreamKey(ctx context.Context, orgID string, mi resolver.ModelInfo) (key string, use orgCredentialUse, err error) {
	if gw.orgCreds != nil && orgID != "" && (gw.credPool != nil || gw.orgCredsProbe != nil) {
		endpoint := gw.upstreamURL(mi)
		// W-VER: try the exact upstream URL first, then its /v1-degenerate
		// form — org model rows conventionally append the OpenAI-compat /v1
		// suffix to the credential's registered base_url.
		candidates := []string{endpoint}
		if alt := adminstore.StripV1Suffix(endpoint); alt != "" && alt != endpoint {
			candidates = append(candidates, alt)
		}
		for _, candidate := range candidates {
			// feedback (recordOrgCredOutcome at the attempt call sites).
			if gw.credPool != nil {
				u, plain, ok, perr := gw.credPool.pickAndResolve(ctx, orgID, mi.Provider, candidate)
				if perr != nil {
					return "", u, fmt.Errorf("org credential pool: %w", perr)
				}
				if ok {
					return plain, u, nil
				}
				continue
			}
			// Legacy W-BYOK path: boolean probe gate + newest-first key.
			probe, verr := gw.orgCredsProbe.probe(ctx, orgID, mi.Provider, candidate)
			if verr != nil {
				return "", use, fmt.Errorf("org credential probe: %w", verr)
			}
			if !probe {
				continue
			}
			plain, ok, rerr := gw.orgCreds.ResolveKey(ctx, orgID, mi.Provider, candidate)
			if rerr != nil {
				return "", use, fmt.Errorf("org credential resolve: %w", rerr)
			}
			if ok && plain != "" {
				if gw.log != nil && gw.log.Enabled(ctx, slog.LevelDebug) {
					// No secret material in logs: credential ID and the
					// store-provided last-4 mask only.
					gw.log.Debug("org credential used for upstream key",
						"org_id", orgID, "provider", mi.Provider)
				}
				return plain, orgCredentialUse{used: true}, nil
			}
		}
	}
	if mi.UpstreamAPIKey != "" {
		return mi.UpstreamAPIKey, use, nil
	}
	return gw.getUpstreamAPIKey(), use, nil
}

// recordOrgCredOutcome feeds one provider attempt's upstream status back to
// authenticated the attempt until the end of the current UTC day, and the
// version bump drops every gateway's snapshot of the org. Quarantine is
// bookkeeping — it never fails the request, and in-flight attempts keep
// their already-resolved plaintext (per-request pinning: активные доживают).
func (gw *gateway) recordOrgCredOutcome(ctx context.Context, orgID, provider string, use orgCredentialUse, statusCode int) {
	gw.credPool.recordOutcome(ctx, orgID, provider, use, statusCode) // nil-safe
}

// probe reports whether the org plausibly holds a credential for
// (provider, baseURL), served from the version/TTL-bounded cache.
//
// Polarity policy: a stale POSITIVE entry (credential deleted without a
// version bump) is self-correcting — the per-request ResolveKey stays
// authoritative and a miss falls through to the per-model key. A stale
// NEGATIVE entry (credential added without a version bump) would silently
// keep the org key unused, so negatives never take the version fast path:
// they are re-probed at every TTL expiry. Positives reuse the cached outcome
// while the org's version is unchanged (the TTL lapse alone does not force a
// store round trip on active BYOK traffic).
func (p *orgCredsProbe) probe(ctx context.Context, orgID, providerName, baseURL string) (bool, error) {
	mapKey := orgID + "\x00" + providerName + "\x00" + baseURL
	now := p.now()

	p.mu.Lock()
	e, ok := p.entries[mapKey]
	if ok && now.Sub(e.loadedAt) < p.ttl {
		res := e.ok
		p.mu.Unlock()
		return res, nil
	}
	var prev orgCredsProbeEntry
	havePrev := false
	if e != nil {
		prev, havePrev = *e, true
	}
	p.mu.Unlock()

	res, entry, err := p.discover(ctx, orgID, providerName, baseURL, prev, havePrev)
	if err != nil {
		// Never cache failures: the next request retries the store.
		return false, err
	}

	p.mu.Lock()
	p.entries[mapKey] = &orgCredsProbeEntry{
		version:  entry.version,
		haveVer:  entry.haveVer,
		ok:       res,
		loadedAt: now,
	}
	p.evictLocked(now)
	p.mu.Unlock()
	return res, nil
}

// discover runs the authoritative probe against the credential store and
// returns the refreshed entry state for the caller to store.
func (p *orgCredsProbe) discover(ctx context.Context, orgID, providerName, baseURL string, entry orgCredsProbeEntry, haveEntry bool) (bool, orgCredsProbeEntry, error) {
	// Version fast path for positives only (see probe): an unchanged version
	// since the last authoritative probe keeps the positive outcome without a
	// store round trip.
	if haveEntry && entry.ok && p.versions != nil {
		v, err := p.versions.GetOrgCredsVersion(ctx, orgID)
		switch {
		case err == nil && entry.haveVer && v == entry.version:
			return true, entry, nil
		case err != nil && p.log != nil:
			p.log.Debug("org creds version probe failed; re-probing the store", "error", err)
		}
	}
	_, ok, err := p.resolver.ResolveKey(ctx, orgID, providerName, baseURL)
	if err != nil {
		return false, entry, err
	}
	if p.versions != nil {
		if v, verr := p.versions.GetOrgCredsVersion(ctx, orgID); verr == nil {
			entry.version, entry.haveVer = v, true
		}
	}
	entry.ok = ok
	return ok, entry, nil
}

// evictLocked drops expired entries first, then the oldest-loaded ones, while
// the index exceeds orgCredsProbeMaxOrgs. Caller holds p.mu.
func (p *orgCredsProbe) evictLocked(now time.Time) {
	if len(p.entries) <= orgCredsProbeMaxOrgs {
		return
	}
	for k, e := range p.entries {
		if now.Sub(e.loadedAt) >= p.ttl {
			delete(p.entries, k)
		}
	}
	for len(p.entries) > orgCredsProbeMaxOrgs {
		oldestKey := ""
		var oldest time.Time
		for k, e := range p.entries {
			if oldestKey == "" || e.loadedAt.Before(oldest) {
				oldestKey, oldest = k, e.loadedAt
			}
		}
		if oldestKey == "" {
			return
		}
		delete(p.entries, oldestKey)
	}
}

// resolveModelInfo returns the full ModelInfo (name, upstream_url, decrypted
// upstream_api_key) for a request model, resolved under the REQUEST context
// (RT-06): a cancelled/deadline-exceeded request or a registry DB failure
// returns an error instead of a synthetic fallback candidate. When a resolver
// is configured the registry is consulted; otherwise cfg.Provider +
// cfg.FallbackModel are used. The returned ModelInfo.UpstreamURL may be empty
// — callers must fall back to cfg.Provider when that happens.
//
// err != nil is terminal for the request: no routing continuation, no
// fallback, no provider call (see writeResolutionUnavailable).
func (gw *gateway) resolveModelInfo(ctx context.Context, name string) (resolver.ModelInfo, error) {
	if gw.res != nil {
		return gw.res.ResolveChecked(ctx, name)
	}
	return resolver.ModelInfo{
		ModelName:      ResolveModel(gw.cfg, name),
		UpstreamURL:    gw.cfg.Provider,
		UpstreamAPIKey: gw.getUpstreamAPIKey(),
		Enabled:        true,
	}, nil
}

// orgModelResolver is the org-scoped resolution surface of
// *resolver.Resolver (W-BYOK-CORE). A nil-able structural assertion keeps
// test stubs that only implement modelResolver working unchanged.
type orgModelResolver interface {
	ResolveOrgChecked(ctx context.Context, orgID, modelName string) (resolver.ModelInfo, error)
}

// resolveOrgModelInfo resolves a model through the org's custom-model table
// (global registry first, then org_custom_models). ok=false when the request
// cannot be served from the org table (no resolver, no org model).
func (gw *gateway) resolveOrgModelInfo(ctx context.Context, orgID, name string) (resolver.ModelInfo, bool, error) {
	if gw.res == nil || orgID == "" {
		return resolver.ModelInfo{}, false, nil
	}
	orr, ok := gw.res.(orgModelResolver)
	if !ok {
		return resolver.ModelInfo{}, false, nil
	}
	info, err := orr.ResolveOrgChecked(ctx, orgID, name)
	if err != nil {
		return resolver.ModelInfo{}, false, err
	}
	if info.Fallback || info.ModelName == "" {
		return resolver.ModelInfo{}, false, nil
	}
	return info, true, nil
}

// writeResolutionUnavailable emits the terminal 503 for a failed model
// resolution (registry outage or cancelled request context). Terminal by
// contract: the caller must not retry, fall back, or attempt a provider call.
func writeResolutionUnavailable(w http.ResponseWriter) {
	apierrors.Write(w, http.StatusServiceUnavailable, "model_registry_unavailable",
		"model registry temporarily unavailable")
}

func (gw *gateway) getUpstreamAPIKey() string {
	if gw.cfg.APIKey != "" {
		return gw.cfg.APIKey
	}
	return gw.cfg.FallbackKey
}

//
// Two scopes share one circuit.Map:
//
//     (checkBreaker) rejects everything when the single shared breaker is
//     open; the final success/failure of a request is recorded on that one
//     breaker (recordBreakerSuccess/recordBreakerFailure).
//   - per-endpoint (default, W-VER fix): the entry gate is inert; each
//     fallback hop gates itself on ITS endpoint breaker (allowEndpoint) and
//     records its own outcome (recordEndpointSuccess/recordEndpointFailure),
//     so a flapping provider opens only its own circuit and candidates on
//     other endpoints stay reachable. When every candidate's breaker is open
//     the chain exhausts and the request fails with 503 — the same terminal
//     envelope as before.

// checkBreaker gates the request entry. Global scope only: in per-endpoint
// scope no single breaker may reject the request before the chain has had
// the chance to route to a healthy endpoint.
func (gw *gateway) checkBreaker() error {
	if gw.circuits == nil || gw.circuitScope != circuit.ScopeGlobal {
		return nil
	}
	if err := gw.circuits.Allow(circuit.GlobalBreakerKey); err != nil {
		return fmt.Errorf("circuit breaker is %s", gw.circuits.State(circuit.GlobalBreakerKey))
	}
	return nil
}

func (gw *gateway) recordBreakerSuccess() {
	if gw.circuits != nil && gw.circuitScope == circuit.ScopeGlobal {
		gw.circuits.RecordSuccess(circuit.GlobalBreakerKey)
	}
}

func (gw *gateway) recordBreakerFailure() {
	if gw.circuits != nil && gw.circuitScope == circuit.ScopeGlobal {
		gw.circuits.RecordFailure(circuit.GlobalBreakerKey)
	}
}

// allowEndpoint gates one fallback hop on its endpoint breaker
// (normalized scheme://host key). Per-endpoint scope only. The returned
// error is a retryable upstream failure: the fallback chain advances to the
// next candidate instead of failing the request.
func (gw *gateway) allowEndpoint(rawURL string) error {
	if gw.circuits == nil || gw.circuitScope != circuit.ScopePerEndpoint {
		return nil
	}
	key := circuit.EndpointKey(rawURL)
	if err := gw.circuits.Allow(key); err != nil {
		return fmt.Errorf("circuit breaker open for endpoint %s: %w", key, err)
	}
	return nil
}

func (gw *gateway) recordEndpointSuccess(rawURL string) {
	if gw.circuits != nil && gw.circuitScope == circuit.ScopePerEndpoint {
		gw.circuits.RecordSuccess(circuit.EndpointKey(rawURL))
	}
}

func (gw *gateway) recordEndpointFailure(rawURL string) {
	if gw.circuits != nil && gw.circuitScope == circuit.ScopePerEndpoint {
		gw.circuits.RecordFailure(circuit.EndpointKey(rawURL))
	}
}

// ResolveModel resolves the model name from config and request.
func ResolveModel(cfg config.Gateway, model string) string {
	if model == "" || model == "auto" {
		return cfg.FallbackModel
	}
	return model
}

// callUpstreamSingle makes a single non-retry, non-fallback upstream request.
// Used by evalgate for premium model comparison sampling. This function has no
// request identity, so gating happens at the call site (RT-03): the evalgate
// caller runs gateAttemptCandidate on the resolved premium candidate before
// invoking this — a denied/unavailable premium target never reaches here.
func (gw *gateway) callUpstreamSingle(ctx context.Context, modelName string, body []byte) ([]byte, error) {
	info, err := gw.resolveModelInfo(ctx, modelName)
	if err != nil {
		return nil, fmt.Errorf("resolve model %q: %w", modelName, err)
	}
	if info.ModelName == "" {
		return nil, fmt.Errorf("unknown model: %s", modelName)
	}

	upstreamURL, apiKey, err := gw.lookupUpstream(info)
	if err != nil {
		return nil, err
	}

	client, err := gw.pool.Get(upstreamURL, info.Provider)
	if err != nil {
		return nil, fmt.Errorf("resolve upstream client for model %s: %w", modelName, err)
	}
	reqBody, _ := json.Marshal(map[string]interface{}{
		"model":    modelName,
		"messages": extractChatMessages(body),
	})

	resp, err := client.ForwardJSON(ctx, reqBody, modelName, apiKey)
	if err != nil {
		return nil, fmt.Errorf("upstream call failed: %w", err)
	}
	return resp, nil
}

// lookupUpstream returns the upstream URL and API key for a model info entry.
func (gw *gateway) lookupUpstream(info resolver.ModelInfo) (string, string, error) {
	if info.UpstreamURL == "" && info.Provider != zaiCodingProvider {
		return "", "", fmt.Errorf("no upstream configured for model %s", info.ModelName)
	}
	apiKey := info.UpstreamAPIKey
	if apiKey == "" {
		apiKey = gw.getUpstreamAPIKey()
	}
	return gw.upstreamURL(info), apiKey, nil
}
