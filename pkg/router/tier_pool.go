package router

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"

	"github.com/reireirei/yabanin/pkg/classifier"
	"github.com/reireirei/yabanin/pkg/metrics"
	sovereign "github.com/reireirei/yabanin/pkg/sovereign"
)

// ModelInfo holds per-model routing metadata.
type ModelInfo struct {
	Name        string
	Tier        string   // cheap | smart | turbo
	TierPool    []string // ["easy"], ["medium"], ["hard"], or multiple
	Weight      int
	UpstreamURL string
	Enabled     bool

	// PB4: sovereignty metadata used by Policy.Allows() to filter models.
	Country         string // ISO-3166 vendor HQ (e.g. "CN", "US")
	VendorHQ        string // parent company jurisdiction
	SovereigntyTier string // TierForeign/TierChinaOffshore/TierChinaOnshore
	CNFlagged       bool   // model is flagged as Chinese-origin
}

// ToModelMeta converts ModelInfo to sovereign.ModelMeta for policy checks.
func (m ModelInfo) ToModelMeta() sovereign.ModelMeta {
	return sovereign.ModelMeta{
		ModelName:    m.Name,
		Country:      m.Country,
		Jurisdiction: m.Country,
		Tier:         sovereign.Tier(m.SovereigntyTier),
		VendorHQ:     m.VendorHQ,
		CNFlagged:    m.CNFlagged,
	}
}

// ModelLoader fetches model routing metadata from the database.
type ModelLoader interface {
	ListModels(ctx context.Context) ([]ModelInfo, error)
}

// TierRouter maps a classifier.Class to a concrete model with caching and load balancing.
type TierRouter struct {
	loader      ModelLoader
	rdb         redisClient // abstracted redis ops
	ttl         time.Duration
	mu          sync.RWMutex
	pools       map[classifier.Class][]ModelInfo
	loaded      time.Time
	policyStore *sovereign.PolicyStore // nil in single-region / no-policy deployments
	// feature is unwired and SelectModelForSession is exactly
	// SelectModelWithAffinity (zero-overhead path).
	canaries *CanaryRolloutCache
	// pins is the session→rollout-version stickiness bound (N09-P04-T03);
	// nil = layer off, resolution is the plain D2 hash (see
	// WithCanaryVersionPins).
	pins *CanaryVersionPins
}

// redisClient abstracts the subset of go-redis operations we need.
type redisClient interface {
	Incr(ctx context.Context, key string) *redis.IntCmd
	Expire(ctx context.Context, key string, expiration time.Duration) *redis.BoolCmd
}

// intResult extracts int64 from a *redis.IntCmd.
func intResult(cmd *redis.IntCmd) (int64, error) {
	if cmd == nil {
		return 0, redis.Nil
	}
	return cmd.Result()
}

// NewTierRouter creates a new tier router. Requires a ModelLoader; Redis client is optional.
func NewTierRouter(loader ModelLoader, rdb redisClient) *TierRouter {
	return &TierRouter{
		loader: loader,
		rdb:    rdb,
		ttl:    60 * time.Second,
		pools: map[classifier.Class][]ModelInfo{
			classifier.ClassEasy:   {},
			classifier.ClassMedium: {},
			classifier.ClassHard:   {},
		},
	}
}

// WithPolicyStore sets the sovereignty policy store on the tier router.
// When set, SelectModel filters candidate models through the org's policy.
func (tr *TierRouter) WithPolicyStore(ps *sovereign.PolicyStore) *TierRouter {
	tr.policyStore = ps
	return tr
}

// snapshotPools returns a private deep copy of a pools map so callers can
// select from it without holding tr.mu while a concurrent refresh swaps the
// map underneath.
func snapshotPools(src map[classifier.Class][]ModelInfo) map[classifier.Class][]ModelInfo {
	dst := make(map[classifier.Class][]ModelInfo, len(src))
	for cls, pool := range src {
		cp := make([]ModelInfo, len(pool))
		copy(cp, pool)
		dst[cls] = cp
	}
	return dst
}

// ensureLoaded populates pools from the ModelLoader if TTL has expired.
// It returns a snapshot of the pools that is safe to read without holding
// tr.mu, even while another goroutine triggers a refresh.
func (tr *TierRouter) ensureLoaded(ctx context.Context) (map[classifier.Class][]ModelInfo, error) {
	tr.mu.RLock()
	if tr.pools != nil && time.Since(tr.loaded) < tr.ttl {
		snapshot := snapshotPools(tr.pools)
		tr.mu.RUnlock()
		return snapshot, nil
	}
	tr.mu.RUnlock()

	tr.mu.Lock()
	defer tr.mu.Unlock()

	// Double-check after acquiring write lock.
	if tr.pools != nil && time.Since(tr.loaded) < tr.ttl {
		return snapshotPools(tr.pools), nil
	}

	models, err := tr.loader.ListModels(ctx)
	if err != nil {
		return nil, err
	}

	pools := map[classifier.Class][]ModelInfo{
		classifier.ClassEasy:   {},
		classifier.ClassMedium: {},
		classifier.ClassHard:   {},
	}
	for _, m := range models {
		if !m.Enabled {
			continue
		}
		// PB4.5: Pre-filter via default policy so per-org filtering is fast.
		// Models that fail the default policy are excluded from all pools.
		if tr.policyStore != nil && !sovereign.DefaultPolicy().Allows(m.ToModelMeta()) {
			continue
		}
		for _, p := range m.TierPool {
			switch p {
			case "easy":
				pools[classifier.ClassEasy] = append(pools[classifier.ClassEasy], m)
			case "medium":
				pools[classifier.ClassMedium] = append(pools[classifier.ClassMedium], m)
			case "hard":
				pools[classifier.ClassHard] = append(pools[classifier.ClassHard], m)
			}
		}
	}
	tr.pools = pools
	tr.loaded = time.Now()
	return snapshotPools(pools), nil
}

// SelectModel picks a concrete model from the pool for the given class.
// It delegates to SelectModelWithAffinity with no preferred model.
func (tr *TierRouter) SelectModel(ctx context.Context, cls classifier.Class, orgID string) (ModelInfo, error) {
	return tr.SelectModelWithAffinity(ctx, cls, orgID, "")
}

// SelectModelWithAffinity picks a concrete model from the pool for the given
// class. If the target pool is empty, it falls back to Medium → Easy → Hard.
// When a policy store is configured, models are filtered through the org's
// sovereignty policy after tier selection (PB4.5).
//
// When preferredModel is non-empty and present in the (already
// sovereignty-filtered) pool, it is returned directly — repeated prefixes on
// the same model are billed at the provider's cached-input rate. Otherwise the
// normal weighted selection runs. The affinity outcome is counted via
// metrics.SessionAffinityTotal (used|miss); an empty preferredModel skips the
// lookup and the counter entirely.
func (tr *TierRouter) SelectModelWithAffinity(ctx context.Context, cls classifier.Class, orgID, preferredModel string) (ModelInfo, error) {
	pool, err := tr.filteredPool(ctx, cls, orgID)
	if err != nil {
		return ModelInfo{}, err
	}
	return tr.pickWithAffinity(ctx, pool, orgID, preferredModel)
}

// filteredPool resolves the class pool (with the Medium→Easy→Hard fallback
// chain) and applies the per-org sovereignty filter (PB4.5). Every selection
// draws from this pool, so neither can widen what the policy allows. It
// have exactly one implementation.
func (tr *TierRouter) filteredPool(ctx context.Context, cls classifier.Class, orgID string) ([]ModelInfo, error) {
	pools, err := tr.ensureLoaded(ctx)
	if err != nil {
		return nil, err
	}
	return tr.resolvePolicyPool(ctx, pools, cls, orgID)
}

// resolvePolicyPool returns the candidate pool for cls after the historical
// empty-pool fallback chain (Medium → Easy → Hard) and the per-org
// quality selection (SelectModelWithQuality) resolve their pool here, so a
// quality ranking can never widen the candidate set the policy allows.
func (tr *TierRouter) resolvePolicyPool(ctx context.Context, pools map[classifier.Class][]ModelInfo, cls classifier.Class, orgID string) ([]ModelInfo, error) {
	pool := pools[cls]
	if len(pool) == 0 {
		// Fallback chain: try other tiers.
		for _, fb := range []classifier.Class{classifier.ClassMedium, classifier.ClassEasy, classifier.ClassHard} {
			if p := pools[fb]; len(p) > 0 {
				pool = p
				break
			}
		}
	}
	if len(pool) == 0 {
		return nil, errors.New("no models available for class " + string(cls))
	}

	// PB4.5: Apply per-org sovereignty policy filter.
	if tr.policyStore != nil && orgID != "" {
		policy := tr.policyStore.Get(ctx, orgID)
		filtered := make([]ModelInfo, 0, len(pool))
		for _, m := range pool {
			if policy.Allows(m.ToModelMeta()) {
				filtered = append(filtered, m)
			}
		}
		pool = filtered
		if len(pool) == 0 {
			return nil, sovereign.ErrNoSovereignModel{
				OrgID:        orgID,
				RequiredTier: policy.RequiredTier,
				Excluded:     policy.ExcludedCountries,
				// PoolSizeBefore is 0 here by construction (pool was just
				// reassigned to the empty filtered slice); the ensureLoaded
				// pre-filter logs the original pool size.
			}
		}
	}
	return pool, nil
}

// pickWithAffinity runs the KV-cache-aware stickiness lookup and the
// weighted selection over an already-filtered pool. Never bypasses the
// implementation for affinity, quality, and canary paths.)
func (tr *TierRouter) pickWithAffinity(ctx context.Context, pool []ModelInfo, orgID, preferredModel string) (ModelInfo, error) {
	if preferredModel != "" {
		for _, m := range pool {
			if m.Name == preferredModel {
				metrics.SessionAffinityTotal.WithLabelValues("used").Inc()
				return m, nil
			}
		}
		metrics.SessionAffinityTotal.WithLabelValues("miss").Inc()
	}
	return tr.selectByWeight(ctx, pool, orgID), nil
}

// selectByWeight performs weighted round-robin selection from a pool.
func (tr *TierRouter) selectByWeight(ctx context.Context, pool []ModelInfo, key string) ModelInfo {
	if len(pool) == 1 {
		return pool[0]
	}

	totalWeight := 0
	for _, m := range pool {
		totalWeight += m.Weight
	}
	if totalWeight <= 0 {
		return pool[0]
	}

	if tr.rdb != nil {
		counterKey := "lb:" + key
		idxCmd := tr.rdb.Incr(ctx, counterKey)
		if idx, err := intResult(idxCmd); err == nil {
			tr.rdb.Expire(ctx, counterKey, 24*time.Hour) // TTL expiry is best-effort
			target := int(idx % int64(totalWeight))
			cum := 0
			for _, m := range pool {
				cum += m.Weight
				if target < cum {
					return m
				}
			}
			return pool[len(pool)-1]
		}
	}

	// Fallback without Redis: walk the same cumulative-weight distribution
	// the Redis path uses, seeded by the clock for spread. A zero-weight
	// member (a canary candidate parked in the pool for the session-hash
	// swap) is never selected here — direct canary traffic would bypass the
	// rollout's percent split and its rollback governance.
	target := int(time.Now().UnixNano() % int64(totalWeight))
	cum := 0
	for _, m := range pool {
		cum += m.Weight
		if target < cum {
			return m
		}
	}
	return pool[len(pool)-1]
}

// dbModelLoader fetches models from the models_registry table.
type dbModelLoader struct {
	pool pgxPool
	log  *slog.Logger
}

// pgxPool abstracts the subset of pgxpool we need.
type pgxPool interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// NewDBModelLoader creates a ModelLoader backed by the models_registry table.
func NewDBModelLoader(pool pgxPool, l *slog.Logger) *dbModelLoader {
	return &dbModelLoader{pool: pool, log: l}
}

func (l *dbModelLoader) ListModels(ctx context.Context) ([]ModelInfo, error) {
	rows, err := l.pool.Query(ctx, `
		SELECT model_name, tier, tier_pool, COALESCE(weight,1), COALESCE(upstream_url,''), enabled,
		       COALESCE(country,''), COALESCE(vendor_hq,''),
		COALESCE(sovereignty_tier,''), cn_flagged
		FROM models_registry ORDER BY model_name
	`)
	if err != nil {
		return nil, fmt.Errorf("list models for tier routing: %w", err)
	}
	defer rows.Close()

	var result []ModelInfo
	for rows.Next() {
		var m ModelInfo
		var weight int
		var sovTier string
		if err := rows.Scan(&m.Name, &m.Tier, &m.TierPool, &weight, &m.UpstreamURL, &m.Enabled,
			&m.Country, &m.VendorHQ, &sovTier, &m.CNFlagged); err != nil {
			return nil, fmt.Errorf("scan model row: %w", err)
		}
		m.Weight = weight
		m.SovereigntyTier = sovTier
		result = append(result, m)
	}
	return result, rows.Err()
}

// stickiness + weighted selection; it delegates to pickWithAffinity so the
func (tr *TierRouter) selectPreferredOrWeighted(ctx context.Context, pool []ModelInfo, orgID, preferredModel string) ModelInfo {
	m, _ := tr.pickWithAffinity(ctx, pool, orgID, preferredModel)
	return m
}
