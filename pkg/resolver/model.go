package resolver

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
)

// ModelInfo holds a resolved model entry from models_registry.
type ModelInfo struct {
	ModelName   string
	DisplayName string
	Tier        string
	UpstreamURL string
	// UpstreamAPIKey is the decrypted plaintext key for the upstream provider.
	// Empty when no per-model key is configured — caller falls back to a
	// global default.
	UpstreamAPIKey string
	// UpstreamTimeout, when non-zero, overrides the pool-wide default timeout
	// for this model. Wired in P3.12.
	UpstreamTimeout time.Duration
	// Provider selects the upstream adapter ("openai", "anthropic", ...).
	// Empty defaults to "openai" at the factory boundary.
	Provider string
	// FailoverModels is the ordered list of model names to try if this model
	// returns a retryable error. Consumed by the FallbackExecutor (P3.6).
	FailoverModels []string
	Enabled        bool
	// Alias is the client-supplied name when it matched model_aliases.
	// Empty when the client named the registry model directly.
	Alias string
	// Fallback is true only when the client named a concrete model that is
	// missing or disabled. Empty and "auto" resolve to the fallback model
	// without this flag.
	Fallback bool
	// Region is the upstream jurisdiction of this model (SG/IN/ID/EU/US/GLOBAL).
	// Populated from models_registry.region (PA.7 migration). Empty until the
	// migration is applied; the enforcer treats "" as GLOBAL (free-pass).
	Region string
}

// Decrypter decrypts per-model upstream_api_key values stored as AES-GCM
// ciphertext in models_registry. Implementations must be safe for concurrent
// use; *encryption.Encryptor satisfies this interface.
type Decrypter interface {
	Decrypt(ciphertext string) (string, error)
}

// ErrModelUnavailable reports a lookup-infrastructure failure: the registry
// could not be queried (DB error), the request context was cancelled before
// the answer arrived, or the row's encrypted upstream key is unusable under
// the fail-closed key policy (W-PROV). It is deliberately distinct from a
// genuine not-found — RT-06: an unavailable registry must never be treated
// as "model missing" (RM-09), must never continue routing, and must never be
// cached as either a success or a negative result.
var ErrModelUnavailable = errors.New("model registry unavailable")

// allowKeyFallback reports whether the dev-only escape hatch for the
// fail-closed encrypted-key policy is enabled. Default is OFF: a model whose
// own (encrypted) key cannot be produced must not be routed with the global
// key. YABANIN_ALLOW_KEY_FALLBACK={1,true,yes,on} restores the legacy
// degradation for development environments.
func allowKeyFallback() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("YABANIN_ALLOW_KEY_FALLBACK"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// Defaults for the AF-13 cache bounds and the shared loader. They can be
// narrowed in tests by setting the unexported fields directly (the package
// owns its tests); production wiring uses these defaults.
const (
	// af13MaxCacheEntries caps the model cache (positive AND negative
	// entries). Arbitrary unknown names — attacker-supplied garbage included
	// — therefore cannot grow the map without bound; eviction is LRU.
	af13MaxCacheEntries = 4096
	// af13NegativeTTL bounds how long a genuine not-found substitution (a
	// negative entry) stays cached. Negatives exist to absorb repeated
	// misses of well-known names, not to pin unknown names for the full TTL.
	af13NegativeTTL = 30 * time.Second
	// af13LoadTimeout bounds one shared miss load. The load runs detached
	// from any single caller (AF-03: one cancelled request must not abort
	// the load for everybody else), so an explicit timeout is what keeps a
	// hung registry DB from holding the flight forever.
	af13LoadTimeout = 30 * time.Second
	// af13LookupRounds bounds the invalidate-race retry loop of
	// resolveCachedChecked: a waiter that joined a flight which was
	// invalidated mid-flight retries on a fresh flight; beyond the bound it
	// performs an authoritative uncached lookup instead of serving or
	// caching anything unverified.
	af13LookupRounds = 4
)

// Resolver provides model name resolution with DB lookup, single-flight miss
// dedup and a bounded LRU cache.
type Resolver struct {
	mu    sync.Mutex
	cache map[string]*cacheSlot
	lru   list.List // front = most recent; element values are cache keys (string)
	// flights holds the in-flight miss loads keyed by model name. A flight
	// is created and observed only under mu; its result fields are written
	// once before close(done) and read after (happens-before via the channel).
	flights map[string]*flight
	// gen increments on Invalidate/InvalidateAll. A loader publishes its
	// result only when the generation it started under is still current, so
	// an invalidation can never be overwritten by a load that began before
	// it (AF-13: invalidate/TTL expiry must not publish stale results).
	gen      atomic.Uint64
	dbPool   pgxpool
	fallback string
	ttl      time.Duration
	// negativeTTL is the cache horizon for negative (Fallback=true) entries;
	// effective negative expiry = min(ttl, negativeTTL).
	negativeTTL time.Duration
	// maxEntries caps the cache; eviction is LRU.
	maxEntries int
	// loadTimeout bounds a detached shared miss load (af13LoadTimeout).
	loadTimeout time.Duration
	log         *slog.Logger
	enc         Decrypter
	aliases     *AliasBook
	// orgModels is the org_custom_models lookup pool (W-BYOK-CORE); nil
	// disables org-model resolution.
	orgModels orgModelPool
}

type cachedEntry struct {
	model   ModelInfo
	expires time.Time
}

// cacheSlot pairs the cached value with its LRU list element.
type cacheSlot struct {
	entry cachedEntry
	elem  *list.Element
}

// flight is one shared miss load (single-flight per model key).
type flight struct {
	done chan struct{}
	gen  uint64
	info ModelInfo
	err  error
}

// pgxpool is the DB interface used by Resolver.
type pgxpool interface {
	QueryRow(context.Context, string, ...interface{}) pgx.Row
	Close()
}

// NewResolver creates a model resolver with the given DB pool and config.
// fallback is used when the requested model is not found in the registry.
// Optional decrypters — at most one is honoured — enable per-model
// upstream_api_key decryption when supplied (P3.2). Passing nil keeps legacy
// behaviour where ModelInfo.UpstreamAPIKey is always empty.
func NewResolver(pool pgxpool, fallback string, ttl time.Duration, l *slog.Logger, decrypters ...Decrypter) *Resolver {
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	r := &Resolver{
		cache:       make(map[string]*cacheSlot),
		flights:     make(map[string]*flight),
		dbPool:      pool,
		fallback:    fallback,
		ttl:         ttl,
		negativeTTL: af13NegativeTTL,
		maxEntries:  af13MaxCacheEntries,
		loadTimeout: af13LoadTimeout,
		log:         l,
	}
	if len(decrypters) > 0 && decrypters[0] != nil {
		r.enc = decrypters[0]
	}
	return r
}

// Resolve is the legacy unchecked wrapper: it always returns a ModelInfo and
// never fails. Keep it for callers that cannot surface an error (the fallback
// chain builder synthesises candidates from names; request handlers use
// ResolveChecked instead). RT-06 contract: a registry outage, an alias-table
// outage, or a cancelled context degrades to the name-only fallback info
// WITHOUT caching it — a later request retries the lookup instead of serving
// the outage result from the cache until the TTL expires.
func (r *Resolver) Resolve(ctx context.Context, modelName string) ModelInfo {
	info, err := r.ResolveChecked(ctx, modelName)
	if err == nil {
		return info
	}
	if r.log != nil {
		r.log.Warn("model registry unavailable, degrading to fallback name (not cached)",
			"requested", modelName, "error", err)
	}
	if modelName == "" || modelName == "auto" {
		return ModelInfo{ModelName: r.fallback, Tier: "smart", Enabled: true}
	}
	return ModelInfo{ModelName: r.fallback, Tier: "smart", Enabled: true, Fallback: true}
}

// ResolveChecked resolves a model name with an explicit outcome:
//
//   - (info, nil): authoritative result. Either a registry hit, the resolved
//     default candidate for ""/"auto" (RT-06: resolved through the registry so
//     provider/region/URL data are consistent for the shared policy gate), or
//     a genuinely missing/disabled model substituted by the configured
//     fallback under the unknown-model policy (RM-09; Info.Fallback=true).
//     All of these are cached for the TTL.
//   - (zero info, err): the registry is unavailable (DB failure — wrapped in
//     ErrModelUnavailable), the alias table could not be consulted
//     (ErrAliasesUnavailable, also wrapping ErrModelUnavailable), the request
//     context was cancelled/expired, or the row's encrypted upstream key is
//     unusable under the fail-closed key policy (missing decrypter or failed
//     decrypt; nothing is cached and the caller must stop routing). AF-03: a
//     cold or outaged alias book is not an authoritative miss — falling
//     through to the registry lookup of the requested name would turn the
//     outage into a successful default-model call.
//
// Key policy (W-PROV): when a model owns an encrypted upstream_api_key but no
// plaintext can be produced (no decrypter configured, or decryption fails),
// routing is refused — silently sending the GLOBAL key to that model's
// upstream_url is a credential-leak hazard. The dev-only escape hatch
// YABANIN_ALLOW_KEY_FALLBACK=1 restores the legacy degradation to the global
// default key (empty UpstreamAPIKey), logged as a warning.
func (r *Resolver) ResolveChecked(ctx context.Context, modelName string) (ModelInfo, error) {
	if err := ctx.Err(); err != nil {
		return ModelInfo{}, fmt.Errorf("resolve %q: %w", modelName, err)
	}
	if modelName == "" || modelName == "auto" {
		return r.defaultCandidate(ctx)
	}
	requested := modelName
	if r.aliases != nil {
		target, err := r.aliases.Lookup(ctx, modelName)
		if err != nil {
			return ModelInfo{}, fmt.Errorf("resolve %q: %w", requested, err)
		}
		if target != "" {
			modelName = target
		}
	}
	info, err := r.resolveCachedChecked(ctx, modelName)
	if err != nil {
		return ModelInfo{}, err
	}
	if requested != modelName {
		info.Alias = requested
	}
	return info, nil
}

// defaultCandidate resolves the configured fallback model through the
// registry so the default candidate carries the same provider/region/URL data
// as every other candidate (the shared final-candidate gate needs provider
// and region to enforce ZAI/data-boundary and residency contracts). When the
// fallback itself has no registry row, the documented name-only shape is
// returned. Fallback stays false: this is the default, not an unknown-model
// substitution.
func (r *Resolver) defaultCandidate(ctx context.Context) (ModelInfo, error) {
	info, err := r.resolveCachedChecked(ctx, r.fallback)
	if err != nil {
		return ModelInfo{}, err
	}
	if info.Fallback {
		// The fallback name itself is not in the registry: legacy name-only
		// default shape. Fallback=false — the client did not name a model.
		return ModelInfo{ModelName: r.fallback, Tier: "smart", Enabled: true}, nil
	}
	return info, nil
}

// resolveCachedChecked serves modelName from the bounded TTL cache; on a
// miss it shares a single in-flight DB load per model key (AF-13 dedup) and
// caches only authoritative results (registry hit or genuine not-found
// fallback). Registry failures and cancelled contexts are never cached.
//
// Waiting is context-aware: every caller waits for the shared load within
// its own context, so one cancelled waiter gets its own context error while
// the load (and every other waiter) continues. The load itself is detached
// from the triggering request and bounded by loadTimeout — the AF-03
// policy: a cancelled caller must not abort the shared load, and no caller
// holds I/O or a lock while waiting.
//
// Invalidation: a load publishes (or its waiters accept) its result only
// while the generation it started under is current. Invalidate/InvalidateAll
// therefore can never be overwritten by a stale pre-invalidation load; a
// waiter whose flight was invalidated mid-flight retries on a fresh flight,
// and after a bounded number of rounds falls back to an authoritative
// uncached lookup.
func (r *Resolver) resolveCachedChecked(ctx context.Context, modelName string) (ModelInfo, error) {
	for range af13LookupRounds {
		r.mu.Lock()
		slot, ok := r.cache[modelName]
		if ok {
			if time.Now().Before(slot.entry.expires) {
				r.lru.MoveToFront(slot.elem)
				info := slot.entry.model
				r.mu.Unlock()
				return info, nil
			}
			// Expired: drop it now so unknown names do not linger past
			// their TTL even without LRU pressure.
			r.removeSlotLocked(modelName)
		}
		if f, joined := r.flights[modelName]; joined {
			r.mu.Unlock()
			info, ok, err := r.waitFlight(ctx, modelName, f)
			if !ok {
				continue // the flight was invalidated mid-load: retry fresh
			}
			return info, err
		}
		f := &flight{done: make(chan struct{}), gen: r.gen.Load()}
		r.flights[modelName] = f
		r.mu.Unlock()
		go r.runFlight(ctx, modelName, f)
		info, ok, err := r.waitFlight(ctx, modelName, f)
		if !ok {
			continue
		}
		return info, err
	}
	// Bounded fallback under invalidate churn: answer from the DB without
	// touching the cache — never a stale or unverified cached value.
	return r.lookupDBChecked(ctx, modelName)
}

// waitFlight waits for one shared load, bounded by the caller's context. The
// bool result reports whether the flight's generation is still current; a
// stale flight's result is discarded (never served, never trusted).
func (r *Resolver) waitFlight(ctx context.Context, modelName string, f *flight) (ModelInfo, bool, error) {
	select {
	case <-f.done:
	case <-ctx.Done():
		return ModelInfo{}, true, fmt.Errorf("resolve %q: %w", modelName, ctx.Err())
	}
	if f.gen != r.gen.Load() {
		return ModelInfo{}, false, nil
	}
	return f.info, true, f.err
}

// runFlight owns one shared miss load. It runs detached from the triggering
// request (context.WithoutCancel) so one cancelled caller cannot abort the
// load for the others, bounded by loadTimeout so a hung registry DB cannot
// hold the flight forever, and settles the flight exactly once. A result is
// published into the cache only when no invalidation happened mid-load and
// only on success: a DB error is an outage, not a not-found (RT-06/AF-03),
// and is never cached in either direction.
func (r *Resolver) runFlight(trigger context.Context, modelName string, f *flight) {
	loadCtx, cancel := context.WithTimeout(context.WithoutCancel(trigger), r.loadTimeout)
	defer cancel()

	info, err := r.lookupDBChecked(loadCtx, modelName)
	if err != nil && r.log != nil && errors.Is(loadCtx.Err(), context.DeadlineExceeded) {
		r.log.Warn("model registry load exceeded its bound", "model", modelName, "timeout", r.loadTimeout)
	}

	r.mu.Lock()
	if cur, ok := r.flights[modelName]; ok && cur == f {
		delete(r.flights, modelName)
	}
	if err == nil && f.gen == r.gen.Load() {
		r.setSlotLocked(modelName, info)
	}
	r.mu.Unlock()

	f.info, f.err = info, err
	close(f.done)
}

// setSlotLocked inserts (or refreshes) a cache entry and moves it to the LRU
// front. Negative entries (genuine not-found substitutions, Fallback=true)
// expire at min(ttl, negativeTTL); positives at ttl. Insertion evicts
// least-recently-used entries while the cache exceeds maxEntries, so
// arbitrary unknown names cannot grow the map without bound (AF-13).
func (r *Resolver) setSlotLocked(modelName string, info ModelInfo) {
	horizon := r.ttl
	if info.Fallback && r.negativeTTL < horizon {
		horizon = r.negativeTTL
	}
	if slot, ok := r.cache[modelName]; ok {
		slot.entry = cachedEntry{model: info, expires: time.Now().Add(horizon)}
		r.lru.MoveToFront(slot.elem)
		return
	}
	elem := r.lru.PushFront(modelName)
	r.cache[modelName] = &cacheSlot{
		entry: cachedEntry{model: info, expires: time.Now().Add(horizon)},
		elem:  elem,
	}
	for r.lru.Len() > r.maxEntries {
		oldest := r.lru.Back()
		if oldest == nil {
			break
		}
		r.lru.Remove(oldest)
		delete(r.cache, oldest.Value.(string))
	}
}

// removeSlotLocked drops a cache entry and its LRU element. No-op when absent.
func (r *Resolver) removeSlotLocked(modelName string) {
	if slot, ok := r.cache[modelName]; ok {
		r.lru.Remove(slot.elem)
		delete(r.cache, modelName)
	}
}

// Invalidate drops the cached entry (positive or negative) for modelName and
// bumps the generation, so any miss load that started before the
// invalidation can neither publish into the cache nor hand its stale result
// to fresh waiters. In-flight waiters that joined before the invalidation
// retry on a fresh load instead.
func (r *Resolver) Invalidate(modelName string) {
	r.gen.Add(1)
	r.mu.Lock()
	r.removeSlotLocked(modelName)
	r.mu.Unlock()
}

// InvalidateAll drops every cached entry and invalidates all in-flight
// loads, with the same generation guarantee as Invalidate.
func (r *Resolver) InvalidateAll() {
	r.gen.Add(1)
	r.mu.Lock()
	r.cache = make(map[string]*cacheSlot)
	r.lru.Init()
	r.mu.Unlock()
}

// lookupDBChecked performs the registry lookup with explicit outcome
// classification:
//   - row found → full ModelInfo;
//   - no row (missing or disabled) → configured fallback substitution with
//     Fallback=true (RM-09), cached as a genuine negative;
//   - any other DB error → ErrModelUnavailable, never cached;
//   - cancelled/expired context → the context error, never cached.
func (r *Resolver) lookupDBChecked(ctx context.Context, modelName string) (ModelInfo, error) {
	if err := ctx.Err(); err != nil {
		return ModelInfo{}, fmt.Errorf("resolve %q: %w", modelName, err)
	}

	var model, displayName, tier, provider string
	var upstreamURL, encryptedKey string
	var failoverModels []string
	var enabled bool
	var timeoutMs int64
	var region string

	err := r.dbPool.QueryRow(ctx, `
		SELECT model_name, display_name, tier,
		       COALESCE(upstream_url, ''), COALESCE(upstream_api_key, ''),
		       COALESCE(provider, ''), failover_models, enabled,
		       COALESCE(upstream_timeout_ms, 0),
		       COALESCE(region, 'GLOBAL')
		FROM models_registry
		WHERE model_name = $1 AND enabled = true
	`, modelName).Scan(&model, &displayName, &tier, &upstreamURL, &encryptedKey, &provider, &failoverModels, &enabled, &timeoutMs, &region)

	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !enabled) {
		if r.log != nil {
			r.log.Warn("model not found in registry or disabled, using fallback", "requested", modelName, "fallback", r.fallback)
		}
		return r.fallbackCandidate(ctx, modelName)
	}
	if err != nil {
		return ModelInfo{}, fmt.Errorf("%w: query model %q: %v", ErrModelUnavailable, modelName, err)
	}

	var apiKey string
	switch {
	case encryptedKey == "":
		// No per-model key: the caller falls back to the documented global
		// default key (RT-03).
	case r.enc == nil && !allowKeyFallback():
		// Fail closed (W-PROV): the model owns an (encrypted) key we cannot
		// decrypt. Silently routing the GLOBAL key to this model's
		// upstream_url would leak a shared credential to whatever endpoint
		// the row points at. Refuse the route instead.
		return ModelInfo{}, fmt.Errorf("%w: model %q has an encrypted upstream_api_key but no decrypter is configured; refusing to route the global key to %s (set YABANIN_ALLOW_KEY_FALLBACK=1 to allow this in dev)", ErrModelUnavailable, model, upstreamURL)
	case r.enc == nil:
		// Dev escape hatch explicitly enabled (YABANIN_ALLOW_KEY_FALLBACK):
		// degrade to the global key, loudly.
		if r.log != nil {
			r.log.Warn("encrypted upstream_api_key without decrypter, falling back to global key (YABANIN_ALLOW_KEY_FALLBACK)",
				"model", model)
		}
	default:
		plain, decErr := r.enc.Decrypt(encryptedKey)
		if decErr != nil {
			if !allowKeyFallback() {
				// Same hazard class as the missing decrypter: the model's
				// own key is unusable, so the global key would be sent to
				// its upstream_url instead. Fail closed.
				return ModelInfo{}, fmt.Errorf("%w: decrypt upstream_api_key for model %q: %v; refusing to route the global key (set YABANIN_ALLOW_KEY_FALLBACK=1 to allow this in dev)", ErrModelUnavailable, model, decErr)
			}
			if r.log != nil {
				r.log.Warn("decrypt upstream_api_key failed, falling back to global key (YABANIN_ALLOW_KEY_FALLBACK)",
					"model", model, "error", decErr)
			}
		} else {
			apiKey = plain
		}
	}

	return ModelInfo{
		ModelName:       model,
		DisplayName:     displayName,
		Tier:            tier,
		UpstreamURL:     upstreamURL,
		UpstreamAPIKey:  apiKey,
		UpstreamTimeout: time.Duration(timeoutMs) * time.Millisecond,
		Provider:        provider,
		FailoverModels:  failoverModels,
		Enabled:         enabled,
		Region:          region,
	}, nil
}

// fallbackCandidate substitutes the configured fallback model for a
// genuinely missing/disabled requested model. The fallback name is itself
// resolved through the registry so the substituted candidate keeps
// provider/region/URL data for the policy gate (RT-06); when the fallback has
// no registry row either, the legacy name-only shape is returned. A registry
// failure while resolving the fallback propagates as unavailable — an outage
// must not look like a successful fallback.
func (r *Resolver) fallbackCandidate(ctx context.Context, requested string) (ModelInfo, error) {
	if requested == r.fallback {
		// The requested name IS the fallback: no substitution possible.
		return ModelInfo{ModelName: r.fallback, Tier: "smart", Enabled: true, Fallback: true}, nil
	}
	if r.fallback == "" {
		// No fallback configured (a programmatic config may omit
		// FallbackModel). Substituting the empty name corrupted attribution
		// and forwarding — completed events carried model_requested="" while
		// stream turns carried the client's model (N07-P01-T06 defect 2,
		// 2026-11-03 acceptance record), and the upstream body rewrite
		// blanked the model field. Keep the requested name as the
		// name-only substituted candidate; Fallback stays true so the
		// unknown-model policy and the org-model seam still see the
		// substitution. This also avoids a pointless registry lookup of "".
		return ModelInfo{ModelName: requested, Tier: "smart", Enabled: true, Fallback: true}, nil
	}
	info, err := r.resolveCachedChecked(ctx, r.fallback)
	if err != nil {
		return ModelInfo{}, err
	}
	if info.Fallback {
		// Fallback name has no registry row of its own: legacy name-only shape.
		info = ModelInfo{ModelName: r.fallback, Tier: "smart", Enabled: true}
	}
	info.Fallback = true
	info.Alias = ""
	return info, nil
}

// orgModelPool is the DB surface for org_custom_models lookups
// (W-BYOK-CORE). *pgxpool.Pool satisfies it; the transaction is required so
// the org-isolation RLS GUC (app.current_org) is set in the same transaction
// that reads the row.
type orgModelPool interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// UseOrgModels attaches the org_custom_models lookup pool. Nil disables
// org-model resolution (the pre-BYOK behavior).
func (r *Resolver) UseOrgModels(pool orgModelPool) {
	if r == nil {
		return
	}
	r.orgModels = pool
}

// ResolveOrgChecked resolves a model for one org with the W-BYOK-CORE
// visibility contract: the org sees the GLOBAL registry (aliases first) plus
// its own org_custom_models entries.
//
//   - global hit (or any authoritative error) behaves exactly like
//     ResolveChecked — a global row always wins, and an outage of the global
//     registry or the alias book stays terminal (it must never degrade into
//     an authoritative-looking miss);
//   - on a genuine global miss (Fallback=true) the org table is consulted by
//     the requested name and, when different, the alias target;
//   - org rows are NEVER cached: a resolved org ModelInfo carries a
//     decrypted plaintext org credential, and BYOK keys are produced
//     per request (no plaintext cache) — the same reason the gateway calls
//     OrgKeyResolver.ResolveKey per request;
//   - the W-PROV fail-closed key policy applies unchanged to an org row's
//     encrypted upstream_api_key: no decrypter or a failed decrypt refuses
//     the route instead of leaking the global key to the row's upstream_url.
func (r *Resolver) ResolveOrgChecked(ctx context.Context, orgID, modelName string) (ModelInfo, error) {
	if err := ctx.Err(); err != nil {
		return ModelInfo{}, fmt.Errorf("resolve %q: %w", modelName, err)
	}
	info, err := r.ResolveChecked(ctx, modelName)
	if err != nil || orgID == "" || !info.Fallback {
		// Authoritative global outcome (hit) or terminal unavailability: no
		// org lookup may mask either.
		return info, err
	}
	if r.orgModels == nil {
		return info, nil
	}

	names := []string{modelName}
	if r.aliases != nil {
		if target, lerr := r.aliases.Lookup(ctx, modelName); lerr == nil && target != "" && target != modelName {
			names = append(names, target)
		}
	}
	for _, name := range names {
		orgInfo, err := r.lookupOrgModel(ctx, orgID, name)
		if err != nil {
			return ModelInfo{}, fmt.Errorf("resolve %q: %w", modelName, err)
		}
		if orgInfo.ModelName != "" {
			if modelName != name {
				orgInfo.Alias = modelName
			}
			return orgInfo, nil
		}
	}
	// The global fallback substitution stands.
	return info, nil
}

// orgModelSelect is the org_custom_models read used by lookupOrgModel. The
// row set mirrors models_registry's essential routing columns (migration
// 0003). Org scoping is enforced twice: the explicit org_id predicate (the
// primary layer, correct under any role) and the app.current_org RLS GUC set
// inside the transaction (defense in depth under the least-privilege role,
// which is NOBYPASSRLS in production).
const orgModelSelect = `
	SELECT model_name, display_name, tier,
	       COALESCE(upstream_url, ''), COALESCE(upstream_api_key, ''),
	       COALESCE(provider, ''), COALESCE(upstream_timeout_ms, 0),
	       COALESCE(region, 'GLOBAL')
	FROM org_custom_models
	WHERE org_id = $1::uuid AND model_name = $2 AND enabled = true`

// lookupOrgModel reads one enabled org model inside a transaction that pins
// the org-isolation GUC, then applies the W-PROV fail-closed key policy to
// the row's encrypted upstream_api_key. A missing row returns a zero
// ModelInfo (not found); any infrastructure failure wraps
// ErrModelUnavailable — an outage of the org table is never a not-found.
func (r *Resolver) lookupOrgModel(ctx context.Context, orgID, modelName string) (ModelInfo, error) {
	var info ModelInfo
	var encryptedKey, upstreamURL, providerName, region string
	var timeoutMs int64
	found := false

	err := pgx.BeginFunc(ctx, r.orgModels, func(tx pgx.Tx) error {
		// Org isolation: the RLS policy on org_custom_models compares
		// org_id against app.current_org for the transaction.
		if _, err := tx.Exec(ctx, "SELECT set_config('app.current_org', $1, true)", orgID); err != nil {
			return fmt.Errorf("set org isolation GUC: %w", err)
		}
		err := tx.QueryRow(ctx, orgModelSelect, orgID, modelName).
			Scan(&info.ModelName, &info.DisplayName, &info.Tier,
				&upstreamURL, &encryptedKey, &providerName, &timeoutMs, &region)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // genuine not-found for this org
		}
		if err != nil {
			return fmt.Errorf("query org_custom_models: %w", err)
		}
		found = true
		return nil
	})
	if err != nil || !found {
		if err != nil {
			return ModelInfo{}, fmt.Errorf("%w: org model %q: %v", ErrModelUnavailable, modelName, err)
		}
		return ModelInfo{}, nil
	}

	var apiKey string
	switch {
	case encryptedKey == "":
		// No per-model key on the org row: the gateway's credential chain
		// (org credential → per-model → global) decides downstream.
	case r.enc == nil && !allowKeyFallback():
		// Fail closed (W-PROV, mirrored for org models): an encrypted key we
		// cannot produce must not silently route the GLOBAL key to the row's
		// upstream_url.
		return ModelInfo{}, fmt.Errorf("%w: org model %q has an encrypted upstream_api_key but no decrypter is configured; refusing to route the global key to %s (set YABANIN_ALLOW_KEY_FALLBACK=1 to allow this in dev)", ErrModelUnavailable, modelName, upstreamURL)
	case r.enc == nil:
		if r.log != nil {
			r.log.Warn("org model encrypted upstream_api_key without decrypter, falling back to global key (YABANIN_ALLOW_KEY_FALLBACK)",
				"model", modelName, "org_id", orgID)
		}
	default:
		plain, decErr := r.enc.Decrypt(encryptedKey)
		if decErr != nil {
			if !allowKeyFallback() {
				return ModelInfo{}, fmt.Errorf("%w: decrypt upstream_api_key for org model %q: %v; refusing to route the global key (set YABANIN_ALLOW_KEY_FALLBACK=1 to allow this in dev)", ErrModelUnavailable, modelName, decErr)
			}
			if r.log != nil {
				r.log.Warn("org model upstream_api_key decrypt failed, falling back to global key (YABANIN_ALLOW_KEY_FALLBACK)",
					"model", modelName, "org_id", orgID, "error", decErr)
			}
		} else {
			apiKey = plain
		}
	}

	// Beta contract: org models never enter failover chains and are never
	// cached (plaintext org credential in ModelInfo; produced per request).
	info.UpstreamURL = upstreamURL
	info.UpstreamAPIKey = apiKey
	info.UpstreamTimeout = time.Duration(timeoutMs) * time.Millisecond
	info.Provider = providerName
	info.Region = region
	info.Enabled = true
	info.FailoverModels = nil
	return info, nil
}
