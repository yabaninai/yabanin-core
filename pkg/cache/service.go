// Package cache provides semantic cache storage with Redis and pgvector backends.
package cache

import (
	"container/list"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	pgxpool "github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/embeddings"
)

// PrivacyMode controls whether an organization's prompts are cached.
type PrivacyMode int

const (
	// PrivacyEnabled enables caching for the organization.
	PrivacyEnabled PrivacyMode = iota
	// PrivacyDisabled disables all cache operations for the organization.
	PrivacyDisabled
	// PrivacyReadCacheOnly allows lookups but prevents writes.
	PrivacyReadCacheOnly
)

func (m PrivacyMode) String() string {
	switch m {
	case PrivacyEnabled:
		return "enabled"
	case PrivacyDisabled:
		return "disabled"
	case PrivacyReadCacheOnly:
		return "read-only"
	default:
		return "unknown"
	}
}

// OrgPolicy holds per-organization cache configuration. A published policy is
// an immutable snapshot: the cache never mutates it after publication and Get
// returns a copy, so callers cannot corrupt shared state. Treat received
// values as read-only.
type OrgPolicy struct {
	Mode         PrivacyMode // enabled / disabled / read-only
	CacheMetrics bool        // whether to emit cache hit metrics for this org
	TTL          time.Duration
	Semantic     bool // enable semantic cache lookups
}

// OrgPolicyLoader is a function that loads per-org cache policy from the database.
type OrgPolicyLoader func(ctx context.Context, orgID string) (*OrgPolicy, error)

const (
	// policyLoadTimeout bounds one shared loader run: a hung DB limits the
	// flight's lifetime but never blocks other orgs' lookups.
	policyLoadTimeout = 10 * time.Second
	// maxPolicyLoadAttempts bounds the reload loop of a single Get when
	// invalidations keep racing loads; exhaustion fails closed for that
	// caller only.
	maxPolicyLoadAttempts = 4

	// maxPolicyCacheEntries bounds the PolicyCache (AF-16): org churn cannot
	// grow the policies/generations maps without bound. Eviction is safe for
	// security semantics by construction: a missing entry is a cache miss —
	// the next Get reloads from the loader, and a loader error fails closed
	// (PrivacyDisabled). Eviction never serves a stale permissive policy; only
	// the explicit Invalidate path changes when a live entry must not be used.
	maxPolicyCacheEntries = 4096
)

// policyEntry is a published immutable policy snapshot with its load time and
// the policy generation it was loaded under.
type policyEntry struct {
	policy   *OrgPolicy
	loadedAt time.Time
	gen      uint64
	elem     *list.Element // LRU node in PolicyCache.lru
}

// policyFlight is a single in-flight load for one org (single-flight). done
// is closed exactly once after the load outcome was applied.
type policyFlight struct {
	done chan struct{}
	gen  uint64 // generation the load was started under
}

// PolicyCache provides a thread-safe org-level cache policy with TTL expiry.
//
// Loader I/O never runs under a cache-wide lock: a slow loader of one org
// does not block policy lookups of other orgs. Concurrent misses of the same
// org share one load (single-flight per org). Invalidate bumps the org's
// generation, so a load that started before the invalidation never publishes
// its stale policy — its waiters reload under the new generation instead.
// Loader errors fail closed: a disabled policy is served and cached for the
// TTL window. Callers' contexts are independent: a cancelled caller gets a
// fail-closed answer immediately without affecting the shared load or other
// callers.
//
// The cache is LRU-bounded at maxPolicyCacheEntries orgs (AF-16). Evicting an
// org drops its cached snapshot and its generation guard entry; this is safe
// for revoke semantics: without an Invalidate there is no revocation to lose,
// and any Invalidate that races the eviction re-creates the generation entry
// with a fresh value, so a pre-invalidation flight still cannot publish.
type PolicyCache struct {
	mu          sync.Mutex
	policies    map[string]*policyEntry
	inflight    map[string]*policyFlight
	generations map[string]uint64
	lru         *list.List // front = most recently used org; shared with policies
	ttl         time.Duration
	maxEntries  int             // LRU cap; default maxPolicyCacheEntries (tests may shrink)
	loader      OrgPolicyLoader // DB-backed loader set via SetOrgPolicyLoader
}

// NewPolicyCache creates a policy cache with the given default TTL for stale entries.
func NewPolicyCache(ttl time.Duration) *PolicyCache {
	if ttl == 0 {
		ttl = 60 * time.Second
	}
	return &PolicyCache{
		policies:    make(map[string]*policyEntry),
		inflight:    make(map[string]*policyFlight),
		generations: make(map[string]uint64),
		lru:         list.New(),
		ttl:         ttl,
		maxEntries:  maxPolicyCacheEntries,
	}
}

// Get returns the policy for an org. If not found or expired, calls the
// loader and caches it. If both the per-call loader and the configured
// loader are nil, returns a default enabled policy.
func (pc *PolicyCache) Get(ctx context.Context, orgID string, loader func(ctx context.Context, orgID string) (*OrgPolicy, error)) *OrgPolicy {
	pc.mu.Lock()
	if e, ok := pc.policies[orgID]; ok && time.Since(e.loadedAt) < pc.ttl {
		pc.lru.MoveToFront(e.elem)
		pol := *e.policy
		pc.mu.Unlock()
		return &pol
	}
	fl := pc.inflight[orgID]
	if fl == nil {
		fl = pc.startFlightLocked(ctx, orgID, pc.effectiveLoaderLocked(loader))
	}
	pc.mu.Unlock()
	return pc.awaitPolicy(ctx, orgID, loader, fl)
}

// effectiveLoaderLocked resolves the loader for a new flight. Callers must
// hold pc.mu.
func (pc *PolicyCache) effectiveLoaderLocked(loader OrgPolicyLoader) OrgPolicyLoader {
	if loader != nil {
		return loader
	}
	if pc.loader != nil {
		return pc.loader
	}
	return func(context.Context, string) (*OrgPolicy, error) {
		return &OrgPolicy{Mode: PrivacyEnabled, Semantic: true}, nil
	}
}

// startFlightLocked registers a single-flight load for orgID and launches its
// executor goroutine. Callers must hold pc.mu.
func (pc *PolicyCache) startFlightLocked(ctx context.Context, orgID string, loader OrgPolicyLoader) *policyFlight {
	fl := &policyFlight{done: make(chan struct{}), gen: pc.generations[orgID]}
	pc.inflight[orgID] = fl
	go pc.runFlight(ctx, orgID, loader, fl)
	return fl
}

// runFlight executes the loader outside any cache lock and publishes the
// result only when the org's generation is unchanged: a load that started
// before an Invalidate never publishes its stale policy.
func (pc *PolicyCache) runFlight(ctx context.Context, orgID string, loader OrgPolicyLoader, fl *policyFlight) {
	// Detached bounded context: the shared load survives one caller's
	// cancellation, but a hung loader cannot outlive the deadline.
	loadCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), policyLoadTimeout)
	defer cancel()

	pol, err := loader(loadCtx, orgID)
	if err != nil {
		// Fail closed on loader error.
		pol = &OrgPolicy{Mode: PrivacyDisabled}
	}

	pc.mu.Lock()
	if pc.inflight[orgID] == fl {
		delete(pc.inflight, orgID)
	}
	if pc.generations[orgID] == fl.gen {
		pc.publishLocked(orgID, &policyEntry{policy: pol, loadedAt: time.Now(), gen: fl.gen})
	}
	pc.mu.Unlock()

	close(fl.done)
}

// publishLocked stores a freshly loaded policy and refreshes the LRU order,
// evicting the least-recently-used org when over the cap. Evicting org X
// removes its cached snapshot and its generation guard: safe because a
// missing generation reads as 0 and any later Invalidate re-creates the
// entry with an incremented value, so a flight started before the eviction
// (gen G) still publishes only while no invalidation happened — exactly the
// pre-eviction contract. Callers must hold pc.mu.
func (pc *PolicyCache) publishLocked(orgID string, e *policyEntry) {
	if old, ok := pc.policies[orgID]; ok {
		pc.lru.Remove(old.elem)
	}
	e.elem = pc.lru.PushFront(orgID)
	pc.policies[orgID] = e
	for pc.lru.Len() > pc.maxEntries {
		oldest := pc.lru.Back()
		if oldest == nil {
			break
		}
		evicted := oldest.Value.(string)
		pc.lru.Remove(oldest)
		delete(pc.policies, evicted)
		delete(pc.generations, evicted)
	}
}

// awaitPolicy waits for the flight result and serves it. When the flight was
// invalidated mid-load (or its caller's context is done) it fails closed for
// this caller only; the shared load and other callers are unaffected.
func (pc *PolicyCache) awaitPolicy(ctx context.Context, orgID string, loader OrgPolicyLoader, fl *policyFlight) *OrgPolicy {
	for attempt := 1; ; attempt++ {
		select {
		case <-fl.done:
		case <-ctx.Done():
			// This caller's context is independent of the shared load.
			return &OrgPolicy{Mode: PrivacyDisabled}
		}

		pc.mu.Lock()
		if e, ok := pc.policies[orgID]; ok && e.gen >= fl.gen && time.Since(e.loadedAt) < pc.ttl {
			pc.lru.MoveToFront(e.elem)
			pol := *e.policy
			pc.mu.Unlock()
			return &pol
		}
		// No fresh entry for this generation: the load was invalidated
		// mid-flight and its stale policy was never published — reload.
		var next *policyFlight
		if attempt < maxPolicyLoadAttempts {
			next = pc.inflight[orgID]
			if next == nil {
				next = pc.startFlightLocked(ctx, orgID, pc.effectiveLoaderLocked(loader))
			}
		}
		pc.mu.Unlock()

		if next == nil {
			return &OrgPolicy{Mode: PrivacyDisabled}
		}
		fl = next
	}
}

// Invalidate drops the cached privacy policy for an org, forcing a reload.
// It bumps the org's generation: in-flight loads that started before the
// invalidation do not publish their stale policy.
func (pc *PolicyCache) Invalidate(orgID string) {
	pc.mu.Lock()
	pc.generations[orgID]++
	if e, ok := pc.policies[orgID]; ok {
		pc.lru.Remove(e.elem)
		delete(pc.policies, orgID)
	}
	pc.mu.Unlock()
}

// setLoader stores the DB-backed policy loader. Safe against concurrent Get.
func (pc *PolicyCache) setLoader(loader OrgPolicyLoader) {
	pc.mu.Lock()
	pc.loader = loader
	pc.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Unified Cache Service — orchestrates all cache layers.
// ---------------------------------------------------------------------------

// BackendStore is the narrow pgvector surface CacheService uses. It is an
// interface so tests can count calls without a live Postgres.
type BackendStore interface {
	GetExact(ctx context.Context, orgID, modelTier, promptHash, modelVer string) (*Entry, error)
	PurgeExpired(ctx context.Context) (int, error)
	PurgeExpiredWithLock(ctx context.Context) (int, bool, error)
}

// CacheService is the top-level API for the semantic cache system.
type CacheService struct {
	exact    *RedisStore
	semantic *SemanticCache
	store    BackendStore
	writer   *Writer
	policy   *PolicyCache
	// regime resolves an org's tenant policy regime fingerprint
	// (N03-P02-T03, set via SetPolicyRegimeResolver). nil = binding
	// disarmed: the plain RT-05 route identity is used unchanged.
	regime   PolicyRegimeResolver
	embedder embeddings.Client
	// embedVer/thresholdVer are this service's current embedding-space and
	// similarity-admission identities (N03-P04-T02). The semantic path only
	// serves entries whose stamped versions match both; a config change
	// (embedder model/query prefix, admission rule) therefore invalidates
	// old semantic entries into self-healing misses instead of comparing
	// vectors across incompatible spaces.
	embedVer       string
	thresholdVer   string
	embedCache     *EmbedCache
	embedFlight    *embedFlights // stampede guard for lookup embeddings (N03-P05); nil = legacy direct calls
	expStore       *ExperimentStore
	log            *slog.Logger
	pgExactEnabled bool
	// partition coalesces identical lookups while the exact layer's Redis
	// is partitioned and bounds their upstream multiplication
	// (N03-P05-T04). nil = legacy unguarded behavior (partial test
	// constructions keep their pre-T04 semantics).
	partition *partitionFlights
	// redisDownUntil is the UnixNano deadline until which the exact layer
	// is presumed down after a classified partition error: lookups skip
	// the doomed Redis round-trip for partitionCooldown, then re-probe.
	redisDownUntil atomic.Int64
}

// NewCacheService creates a fully wired cache service. ctx bounds the async
// writer pool's lifetime (see Writer). pgExactEnabled toggles the pgvector
// exact-match lookup on Redis misses (disabled by default; see
// CachePGExactLookup in config).
func NewCacheService(
	ctx context.Context,
	pool *pgxpool.Pool,
	rdb *redis.Client,
	embedder embeddings.Client,
	log *slog.Logger,
	pgExactEnabled bool,
) *CacheService {
	return &CacheService{
		exact:          NewRedisStore(rdb, 24*time.Hour),
		semantic:       NewSemanticCache(pool, 0, 0),
		store:          NewStore(pool),
		writer:         NewWriter(ctx, pool, embedder, log),
		policy:         NewPolicyCache(60 * time.Second),
		embedder:       embedder,
		embedCache:     nil,
		embedFlight:    newEmbedFlights(maxEmbedFlights, embedFlightTimeout),
		embedVer:       embedderSpaceVersion(embedder),
		thresholdVer:   SemanticAdmissionVersion(),
		log:            log,
		pgExactEnabled: pgExactEnabled,
		partition:      newPartitionFlights(maxPartitionFlights, partitionLease, partitionFlightTTL),
	}
}

// SetOrgPolicyLoader sets the DB-backed policy loader used by Lookup and Write.
func (cs *CacheService) SetOrgPolicyLoader(loader OrgPolicyLoader) {
	cs.policy.setLoader(loader)
}

// SetEmbedCache configures an in-memory LRU cache for embedding vectors.
func (cs *CacheService) SetEmbedCache(ec *EmbedCache) {
	cs.embedCache = ec
}

// SetExperimentStore enables A/B experiment bucketing for the control arm.
func (cs *CacheService) SetExperimentStore(es *ExperimentStore) {
	cs.expStore = es
}

// CacheHit holds metadata returned alongside a cached response.
//
//nolint:revive // CacheHit is clearer than Hit in the cache package context
type CacheHit struct {
	Data       []byte
	SourceType string  // "exact" | "pg_exact" | "semantic"
	Similarity float32 // cosine similarity for semantic hits (0..1)
	// ModelUsed is the canonical model recorded in the entry's provenance —
	// the model that actually generated the cached response. It equals the
	// route model the lookup was performed with (verified), so callers can
	// attribute the response honestly.
	ModelUsed string
}

// normalizeForCache canonicalizes a prompt body once so the exact-match hash
// and the semantic embedding are always computed over identical bytes on both
// the lookup and the write path. Without this, a lookup embedding over RAW
// bytes could never match a write embedding over NORMALIZED bytes and the
// hit rate was systematically understated. An unparsable body is used as-is
// (mirroring Writer.write's fallback).
func normalizeForCache(promptJSON []byte) []byte {
	norm, err := NormalizeMessagesJSON(promptJSON)
	if err != nil {
		return promptJSON
	}
	return norm
}

// Lookup checks Redis exact cache first, then pgvector semantic search.
// Compatibility wrapper over LookupWithResult with the route identity
// (orgID, modelTier, default route namespace version).
func (cs *CacheService) Lookup(ctx context.Context, orgID, modelTier string, promptJSON []byte, modelVer ...string) ([]byte, error) {
	ri := RouteIdentity{OrgID: orgID, Model: modelTier}
	if len(modelVer) > 0 && modelVer[0] != "" {
		ri.Version = modelVer[0]
	}
	result, err := cs.LookupWithResult(ctx, ri, promptJSON)
	if err != nil || result == nil {
		return nil, err
	}
	return result.Data, nil
}

// LookupWithResult checks Redis exact cache first, then pgvector exact and
// semantic search. The lookup runs under the given route identity: an entry
// is only served when its stored provenance matches the identity (org, route
// model, namespace version, generation parameters). Legacy or foreign entries
// degrade to misses; a policy-disabled org is a miss, not an error. With the
// policy-regime binding armed, an org whose enforcement is off or
// unverifiable (N03-P02-T04) is a miss served without touching any cache
// layer — no reads, and Write stores nothing for the org.
func (cs *CacheService) LookupWithResult(ctx context.Context, ri RouteIdentity, promptJSON []byte) (*CacheHit, error) {
	ri = ri.Resolved()
	promptJSON = normalizeForCache(promptJSON)
	pol := cs.policy.Get(ctx, ri.OrgID, nil)

	if pol.Mode == PrivacyDisabled {
		RecordMiss()
		return nil, nil //nolint:nilnil // documented: privacy-disabled is a cache miss, not an error
	}

	// N03-P02-T03/T04: resolve the tenant policy regime once per operation.
	// A policy change (a tighten included) changes the fingerprint, so warm
	// entries stored under the earlier regime degrade to misses on every
	// layer below instead of replaying past the tightened policy. When
	// enforcement is off or unverifiable for this org (armed resolver, empty
	// fingerprint), the lookup is gated before any cache layer is touched:
	// enforcement-off is preserved without reads — not "read and filter".
	regimeRI, gated := cs.regimeResolve(ctx, ri)
	if gated {
		RecordMiss()
		return nil, nil //nolint:nilnil // documented: enforcement-off is a cache miss, not an error
	}
	ri = regimeRI

	// P4.14: Check A/B experiment assignments — control arm skips cache entirely.
	if cs.expStore != nil {
		experiments, err := cs.expStore.ListExperiments(ctx, ri.OrgID, true)
		if err == nil && len(experiments) > 0 {
			for _, exp := range experiments {
				assignment, assignErr := cs.expStore.AssignAssignment(ctx, exp.ID, ri.OrgID)
				if assignErr == nil {
					if assignment.Variant == exp.ControlVariant {
						RecordABArm("control", exp.ID)
						cs.log.Debug("a/b control arm — skip cache", "exp_id", exp.ID, "org_id", ri.OrgID)
						// Skip all cache lookups for control arm.
						return nil, nil //nolint:nilnil // sentinel ErrMiss would change signature contract
					}
					RecordABArm("treatment", exp.ID)
				}
			}
		}
	}

	// 1. Exact Redis lookup (fast path).
	start := time.Now()
	hash := ComputePromptHash(promptJSON)
	key := MakeKey(ri.OrgID, ri.Model, hash)

	// N03-P05-T04: inside the partition cooldown the exact layer is
	// presumed down — skip its round-trip (which would burn the Redis
	// timeout on every lookup) and go straight to the bounded fallback
	// below. The backend is re-probed when the cooldown expires.
	partitioned := cs.redisDown()
	data := []byte(nil)
	if !partitioned {
		var err error
		data, err = cs.exact.Get(ctx, ri.OrgID, ri.Model, hash)
		if err == nil && len(data) > 0 {
			// RT-05: verify the entry's provenance against the current route.
			// Legacy raw payloads, foreign orgs, other route models or
			// generation parameters are misses — never served.
			prov, unsealed, ok := OpenEntry(data)
			if ok && prov.Matches(ri) {
				cs.log.Debug("cache hit (redis exact)", "org_id", ri.OrgID, "model_used", prov.ModelUsed)
				RecordHit("exact")
				RecordLatency("exact", time.Since(start).Seconds())
				go RecordGlobalHit(ri.OrgID, ri.Model, "exact", 0)
				return &CacheHit{Data: unsealed, SourceType: "exact", Similarity: 1.0, ModelUsed: prov.ModelUsed}, nil
			}
			cs.log.Debug("stale exact entry ignored (provenance mismatch)", "org_id", ri.OrgID, "model", ri.Model)
		} else if redisUnavailable(ctx, err) {
			// N03-P05-T04: a non-miss error with a live caller means the
			// backend or the network to it is partitioned — including the
			// store's own dial/read timeouts. Classify once, arm the
			// cooldown and coalesce what follows instead of letting every
			// lookup degrade into an independent upstream call.
			cs.markRedisDown()
			partitioned = true
			cs.log.Warn("redis exact layer unavailable — partition mode engaged", "error", err)
		}
	}

	if partitioned {
		RecordRedisPartition()
		cs.log.Debug("redis partition: coalescing lookup",
			"org_id", ri.OrgID, "model", ri.Model, "hash", hash[:8])
		hit, proceed := cs.partitionLookup(ctx, key, ri)
		switch {
		case hit != nil:
			RecordLatency("exact", time.Since(start).Seconds())
			return hit, nil
		case proceed && ctx.Err() == nil:
			// Leadership mandate (creator or lease) or bounded fail-open:
			// continue into the remaining layers exactly as before the
			// guard existed — but bounded, since identical concurrent
			// callers are coalesced and further mandates are capped at
			// one per lease window.
		default:
			// The flight's payload was foreign to this identity, or the
			// caller's context ended: a miss, never an error.
			RecordMiss()
			go RecordGlobalMiss(ri.OrgID, ri.Model)
			return nil, nil //nolint:nilnil // documented miss contract
		}
	}

	// 2. pgvector exact lookup (disabled by default: Redis is the exact
	// layer, and the pg lookup only helps after Redis data loss, at the
	// cost of a Postgres round-trip on every miss).
	if cs.pgExactEnabled {
		entry, err := cs.store.GetExact(ctx, ri.OrgID, ri.Model, hash, ri.Version)
		if err != nil {
			return nil, err
		}
		if entry != nil {
			// RT-05: verify provenance before serving; a mismatch is a miss.
			prov, unsealed, ok := OpenEntry(entry.Response)
			if !ok || !prov.Matches(ri) {
				cs.log.Debug("stale pg exact entry ignored (provenance mismatch)", "org_id", ri.OrgID, "model", ri.Model)
			} else {
				cs.log.Debug("cache hit (pg exact)", "org_id", ri.OrgID)
				// Best-effort Redis warm-up under the same route identity:
				// the entry's provenance was just verified against it.
				if sealed, sealErr := SealEntry(unsealed, ri); sealErr == nil {
					// N03-P05-T04: partition waiters coalesced on this key
					// are served the payload immediately, without waiting
					// for the (possibly partitioned) Redis write.
					cs.partition.publish(key, sealed)
					go func() {
						if err := cs.exact.Put(ctx, ri.OrgID, ri.Model, hash, sealed); err != nil {
							cs.log.Warn("redis warm-up write failed", "error", err)
						}
					}()
				}
				RecordHit("exact")
				RecordLatency("exact", time.Since(start).Seconds())
				go RecordGlobalHit(ri.OrgID, ri.Model, "exact", 0)
				return &CacheHit{Data: unsealed, SourceType: "pg_exact", Similarity: 1.0, ModelUsed: prov.ModelUsed}, nil
			}
		}
	}

	// 3. Semantic lookup (only if enabled for this org).
	if !pol.Semantic {
		RecordMiss()
		go RecordGlobalMiss(ri.OrgID, ri.Model)
		return nil, nil //nolint:nilnil // documented: semantic disabled is a cache miss, not an error
	}

	// P4.15 + N03-P05: EmbedCache deduplicates SEQUENTIAL embedding repeats
	// via in-memory LRU; embedFlights additionally deduplicates CONCURRENT
	// identical misses (per-hash singleflight on a detached load context)
	// and bounds the total concurrent upstream embedding calls — beyond the
	// limit the lookup degrades to a cache miss without an upstream call.
	//
	// N03-P04-T03: the embedding input and the space identity carry the
	// per-input multilingual/domain qualifier tag derived from this
	// prompt's content (same derivation as the writer — see
	// qualifierSourceText/embedderInputTag). A near-duplicate in another
	// language — or any prompt under a different qualifier configuration —
	// resolves to a different space, so cache.Provenance.SpaceMatch
	// degrades the stale entry to a miss regardless of the reported cosine
	// similarity; a qualifier-blind embedder yields an empty tag and
	// reproduces the N03-P04-T02 behavior exactly.
	qualTag := embedderInputTag(cs.embedder, qualifierSourceText(promptJSON))
	embedInput := qualifiedEmbedInput(string(promptJSON), qualTag)
	lookupEmbedVer := embeddings.QualifiedSpaceVersion(cs.embedVer, qualTag)
	var vec []float32
	embedded := false
	if cs.embedCache != nil {
		if v, ok := cs.embedCache.Get(hash); ok && len(v) > 0 {
			cs.log.Debug("embedding cached (in-memory)", "org_id", ri.OrgID, "hash", hash[:8])
			vec, embedded = v, true
		}
	}
	if !embedded {
		v, embErr := cs.embedFlight.do(ctx, hash, func(loadCtx context.Context) ([]float32, error) {
			return cs.embedder.Embed(loadCtx, embedInput)
		})
		if cs.embedLookupError(embErr) {
			RecordMiss()
			go RecordGlobalMiss(ri.OrgID, ri.Model)
			return nil, nil //nolint:nilnil // follows existing LookupWithResult contract
		}
		if len(v) > 0 && cs.embedCache != nil {
			cs.embedCache.Set(hash, v)
		}
		vec = v
	}

	result, err := cs.semantic.Lookup(ctx, ri.OrgID, ri.Model, ri.Version, vec)
	if err != nil || result == nil {
		RecordMiss()
		go RecordGlobalMiss(ri.OrgID, ri.Model)
		//nolint:nilerr // cache miss is (nil,nil) by contract: a lookup failure degrades to a miss
		return nil, nil //nolint:nilnil // documented miss contract
	}

	// RT-05: a semantic hit is only served when its stored provenance still
	// matches the current route. The SQL filters org/model/version; the
	// generation parameters live inside the sealed payload.
	prov, unsealed, ok := OpenEntry(result.Entry.Response)
	if !ok || !prov.Matches(ri) {
		cs.log.Debug("stale semantic entry ignored (provenance mismatch)", "org_id", ri.OrgID, "model", ri.Model)
		RecordMiss()
		go RecordGlobalMiss(ri.OrgID, ri.Model)
		return nil, nil //nolint:nilnil // unverifiable provenance degrades to a miss
	}

	// N03-P04-T02 (+ N03-P04-T03): a semantic hit is only served when the
	// entry's stamped embedding-space and threshold-admission versions
	// match this service's current configuration; since T03 the space
	// version includes the per-input qualifier tag (lookupEmbedVer). Cosine
	// similarity between vectors from different spaces (embedder model or
	// query prefix changed, or the prompt's multilingual/domain qualifier
	// differs) is meaningless and produced false hits — "a similar question
	// gets someone else's answer". Such entries degrade to a miss (never an
	// error) and refill under the current versions; exact layers are
	// hash-keyed and intentionally not subject to this check.
	// A service with NO versions configured (zero-value struct, test-only
	// construction today; production always goes through NewCacheService)
	// cannot know its space and acts as a legacy reader: the check is
	// skipped, mirroring the entry-side legacy compatibility in SpaceMatch.
	if (cs.embedVer != "" || cs.thresholdVer != "") && !prov.SpaceMatch(lookupEmbedVer, cs.thresholdVer) {
		cs.log.Debug("stale semantic entry ignored (embedding/threshold version mismatch)",
			"org_id", ri.OrgID, "model", ri.Model,
			"entry_embed_ver", prov.EmbedVer, "current_embed_ver", lookupEmbedVer,
			"entry_threshold_ver", prov.ThresholdVer, "current_threshold_ver", cs.thresholdVer)
		RecordMiss()
		go RecordGlobalMiss(ri.OrgID, ri.Model)
		return nil, nil //nolint:nilnil // incompatible vector space or admission epoch degrades to a miss
	}

	// N03-P04-T05: decisive-content admission guard. Near-duplicate prompts
	// that differ only in a date, a number, an entity or an access level
	// score above the similarity threshold on real embedders — T04 measured
	// 10/14 such false hits on the holdout ("a similar question gets
	// someone else's answer"). The writer stamps a one-way fingerprint of
	// the entry prompt's decisive content into the provenance
	// (DecisiveContentStamp over the same normalized bytes); when it
	// disagrees with THIS prompt's stamp, the entry answers a different
	// question and degrades to a self-healing miss. Strict equality with
	// the empty string, mirroring SpaceMatch: a versioning service never
	// serves unstamped (legacy) entries, a version-blind service skips the
	// check, and the exact layers are hash-keyed and never consult it.
	if cs.embedVer != "" || cs.thresholdVer != "" {
		decVer, decFP := DecisiveContentStamp(promptJSON)
		if !prov.DecisiveMatch(decVer, decFP) {
			cs.log.Debug("stale semantic entry ignored (decisive-content mismatch)",
				"org_id", ri.OrgID, "model", ri.Model,
				"entry_decisive_ver", prov.DecisiveVer,
				"current_decisive_ver", decVer,
				"similarity", result.Similarity)
			RecordMiss()
			go RecordGlobalMiss(ri.OrgID, ri.Model)
			return nil, nil //nolint:nilnil // different decisive content degrades to a miss
		}
	}

	cs.log.Debug("cache hit (semantic)", "org_id", ri.OrgID, "similarity", result.Similarity)
	// best-effort semantic write under the verified route identity; a dropped
	// entry only costs a cache miss
	if sealed, sealErr := SealEntry(unsealed, ri); sealErr == nil {
		// N03-P05-T04: publish to partition waiters before the (possibly
		// partitioned) Redis write — during an outage the waiters are the
		// only consumers that can still be served.
		cs.partition.publish(key, sealed)
		_ = cs.exact.Put(ctx, ri.OrgID, ri.Model, hash, sealed)
	}
	RecordHit("semantic")
	RecordLatency("semantic", time.Since(start).Seconds())
	RecordSimilarity(result.Similarity)
	go RecordGlobalHit(ri.OrgID, ri.Model, "semantic", int(result.Similarity*1000))
	return &CacheHit{Data: unsealed, SourceType: "semantic", Similarity: result.Similarity, ModelUsed: prov.ModelUsed}, nil
}

// embedLookupError reports whether err ends the embedding stage of a lookup
// and logs it at the right level: the flight limit is an expected degradation
// (debug + busy counter), a caller's cancellation is normal (debug), and any
// other embedder failure keeps the existing warning.
func (cs *CacheService) embedLookupError(err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, ErrEmbedFlightBusy):
		RecordEmbedFlightBusy()
		cs.log.Debug("embedding flight limit reached — degrading to cache miss")
	case IsCancellation(err):
		cs.log.Debug("caller canceled during embedding lookup", "error", err)
	default:
		cs.log.Warn("embedding failed, skipping semantic", "error", err)
	}
	return true
}

// markRedisDown arms the partition cooldown: for the next partitionCooldown
// the exact layer is presumed unavailable and lookups skip its round-trip
// (N03-P05-T04). The backend is re-probed when the cooldown expires, so a
// recovered Redis is picked up with at most that much extra delay.
func (cs *CacheService) markRedisDown() {
	cs.redisDownUntil.Store(time.Now().Add(partitionCooldown).UnixNano())
}

// redisDown reports whether the exact layer is inside the partition cooldown.
func (cs *CacheService) redisDown() bool {
	return time.Now().UnixNano() < cs.redisDownUntil.Load()
}

// partitionLookup serves a lookup through the Redis-partition flight for key
// (N03-P05-T04). Outcomes:
//
//	(hit, false) — the flight published a payload whose provenance matched
//	    this caller's identity: serve it (hit metrics recorded here).
//	(nil, true) — the caller holds the leadership mandate (creator or
//	    lease), failed open (overflow, dissolved flight), its context ended
//	    (the caller re-checks ctx.Err() and turns that into a plain miss),
//	    or the flight's payload was foreign to this identity (fall through
//	    to the remaining layers, as it would on a healthy backend): the
//	    lookup continues below the exact layer, bounded by the guard.
func (cs *CacheService) partitionLookup(ctx context.Context, key string, ri RouteIdentity) (*CacheHit, bool) {
	sealed, published := cs.partition.await(ctx, key)
	if !published {
		return nil, true
	}
	// RT-05: the payload is only served after this caller's own provenance
	// verification — a flight shared by callers under different route
	// identities degrades the mismatched ones to fall-through.
	prov, unsealed, ok := OpenEntry(sealed)
	if !ok || !prov.Matches(ri) {
		cs.log.Debug("partition flight payload ignored (provenance mismatch)",
			"org_id", ri.OrgID, "model", ri.Model)
		return nil, true
	}
	cs.log.Debug("cache hit (partition flight)", "org_id", ri.OrgID, "model_used", prov.ModelUsed)
	RecordHit("exact")
	go RecordGlobalHit(ri.OrgID, ri.Model, "exact", 0)
	return &CacheHit{Data: unsealed, SourceType: "exact", Similarity: 1.0, ModelUsed: prov.ModelUsed}, false
}

// Write stores a response in both Redis and pgvector under the given route
// identity. The stored bytes carry the identity as provenance, so later
// lookups can verify model used, org, namespace version and generation
// parameters before serving the entry.
func (cs *CacheService) Write(ctx context.Context, ri RouteIdentity, promptJSON, response json.RawMessage, tokensIn, tokensOut int) error {
	ri = ri.Resolved()
	// Normalize once here so the synchronous Redis hash, the queued pgvector
	// job and the worker's embedding all key on the same canonical bytes the
	// lookup path computes (see normalizeForCache).
	promptJSON = normalizeForCache(promptJSON)
	pol := cs.policy.Get(ctx, ri.OrgID, nil)

	if pol.Mode == PrivacyDisabled || pol.Mode == PrivacyReadCacheOnly {
		return nil
	}

	// N03-P02-T03/T04: seal under the same regime-bound identity the lookup
	// path composes, so the exact layer, the queued pgvector job (whose
	// fields are taken from this identity) and every later lookup agree on
	// one identity for this response. While enforcement is off or
	// unverifiable for this org (armed resolver, empty fingerprint), nothing
	// is written to any layer or queue: an untagged entry stored while off
	// could otherwise be served by a later lookup whose regime resolution
	// transiently failed — a bypass past re-governance entirely.
	regimeRI, gated := cs.regimeResolve(ctx, ri)
	if gated {
		return nil
	}
	ri = regimeRI

	// RT-05: seal before enqueueing — a response that cannot carry a
	// verifiable provenance is never written, to either backend.
	sealed, err := SealEntry(response, ri)
	if err != nil {
		return err
	}

	// Enqueue for async write to pgvector. The worker re-seals from the job's
	// identity fields (defense in depth); the exact layer stores `sealed`.
	queued := cs.writer.Submit(writerJob{
		orgID:      ri.OrgID,
		modelTier:  ri.Model,
		modelVer:   ri.Version,
		genParams:  ri.GenParams,
		upstream:   ri.Upstream,
		promptJSON: promptJSON,
		response:   response,
		tokensIn:   tokensIn,
		tokensOut:  tokensOut,
	})
	// N2: at Submit time the job is only queued — the worker records the real
	// "written" outcome per job. Previously "written" was incremented here,
	// overstating actual writes.
	if !queued {
		RecordWrite("dropped")
	} else {
		RecordWrite("queued")
	}

	// Update queue size gauge.
	q, _, _ := cs.writer.Stats()
	RecordWriteQueueSize(q)

	// Write to Redis synchronously for fast exact lookups.
	hash := ComputePromptHash(promptJSON)
	// N03-P05-T04: publish to partition waiters BEFORE the Put — under a
	// Redis partition the Put fails, yet the coalesced waiters must still
	// receive the leader's response. On a healthy backend this is a no-op
	// (no active flight for the key).
	cs.partition.publish(MakeKey(ri.OrgID, ri.Model, hash), sealed)
	return cs.exact.Put(ctx, ri.OrgID, ri.Model, hash, sealed)
}

// Delete removes a cache entry from both backends. The prompt is normalized
// with the same canonical form Write and Lookup use, so deletion targets the
// keys those paths actually wrote.
func (cs *CacheService) Delete(ctx context.Context, orgID, modelTier string, promptJSON []byte) error {
	hash := ComputePromptHash(normalizeForCache(promptJSON))
	return cs.exact.Delete(ctx, orgID, modelTier, hash)
}

// PurgeExpired removes expired entries from both backends. Returns counts.
func (cs *CacheService) PurgeExpired(ctx context.Context) (int, int, error) {
	redisCount, err := cs.exact.PurgeExpired(ctx)
	if err != nil {
		cs.log.Warn("redis purge failed", "error", err)
	}

	pgCount, err := cs.store.PurgeExpired(ctx)
	if err != nil {
		cs.log.Warn("pgvector purge failed", "error", err)
	}

	return redisCount, pgCount, nil
}

// PurgeAllWithLock removes expired entries from both backends; pgvector side
// uses pg_try_advisory_xact_lock for multi-replica safety. Returns (redis_deleted, pg_deleted, lock_acquired).
func (cs *CacheService) PurgeAllWithLock(ctx context.Context) (int, int, bool, error) {
	redisCount, err := cs.exact.PurgeExpired(ctx)
	if err != nil {
		cs.log.Warn("redis purge failed", "error", err)
	}

	pgDeleted, gotLock, err := cs.store.PurgeExpiredWithLock(ctx)
	if err != nil {
		return 0, 0, false, fmt.Errorf("pgvector purge with lock: %w", err)
	}

	return redisCount, pgDeleted, gotLock, nil
}

// Stats returns cache namespace sizes.
func (cs *CacheService) Stats(ctx context.Context) (int64, int64, error) {
	redisCount, err := cs.exact.Stats(ctx)
	if err != nil {
		cs.log.Warn("redis stats failed", "error", err)
	}
	return redisCount, 0, nil
}

// WriterStats returns write pipeline metrics.
func (cs *CacheService) WriterStats() (queued, dropped, written int64) {
	return cs.writer.Stats()
}
