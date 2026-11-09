package classifier

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// classifierCacheKeyPrefix is the Redis key prefix for classifier results.
	classifierCacheKeyPrefix = "yabanin:classifier:"
	// classifierCacheTTL is how long to cache classification results in Redis.
	classifierCacheTTL = 1 * time.Hour
)

// CachedResult is the serializable form of a Result stored in Redis.
type CachedResult struct {
	Class      string  `json:"class"`
	Confidence float64 `json:"confidence"`
	Source     string  `json:"source"`
	Latency    int64   `json:"latency_ns"`
}

// cacheClient is the minimal Redis interface needed for classifier caching.
type cacheClient interface {
	Get(ctx context.Context, key string) *redis.StringCmd
	SetEx(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd
}

// RegistryWithCache wraps a Registry with Redis-backed classification caching.
type RegistryWithCache struct {
	inner      *Registry
	rdb        cacheClient
	log        *slog.Logger
	cacheTTL   time.Duration
	cacheKeyFn func(orgID, prompt string) string
}

// NewRegistryWithCache creates a classifier registry with Redis read-through cache.
// When enabled (rdb != nil), classification results are cached in Redis for 1 hour,
// keyed by org ID + prompt SHA-256 hash. Cache hits return Source="cache_hit".
func NewRegistryWithCache(reg *Registry, rdb cacheClient, log *slog.Logger) *RegistryWithCache {
	return &RegistryWithCache{
		inner:    reg,
		rdb:      rdb,
		log:      log,
		cacheTTL: classifierCacheTTL,
		cacheKeyFn: func(orgID, prompt string) string {
			h := sha256.Sum256([]byte(orgID + ":" + prompt))
			return classifierCacheKeyPrefix + fmt.Sprintf("%x", h)
		},
	}
}

// Classify checks the Redis cache first. On hit, returns the cached result.
// On miss, delegates to the inner Registry and caches the result.
func (r *RegistryWithCache) Classify(ctx context.Context, in Input) Result {
	start := time.Now()

	// Build cache key from org ID + prompt.
	cacheKey := r.cacheKeyFn(in.OrgID, in.Prompt)

	// Attempt cache lookup.
	if r.rdb != nil && in.OrgID != "" {
		data, err := r.rdb.Get(ctx, cacheKey).Bytes()
		if err == nil {
			var cached CachedResult
			if json.Unmarshal(data, &cached) == nil {
				r.log.Debug("classifier cache hit", "org_id", in.OrgID, "class", cached.Class)
				return Result{
					Class:      Class(cached.Class),
					Confidence: cached.Confidence,
					Source:     string(SourceCacheHit),
					Latency:    time.Since(start).Nanoseconds(),
				}
			}
			r.log.Warn("classifier cache decode failed")
		}
		// Cache miss or error — proceed to classifier.
		if err != nil && err != redis.Nil {
			r.log.Debug("classifier cache lookup failed, proceeding to classifier", "error", err)
		}
	}

	// Cache miss — delegate to inner registry.
	res := r.inner.Classify(ctx, in)

	// Write result to cache (best-effort).
	if r.rdb != nil && in.OrgID != "" && res.Source != string(SourceDefault) {
		cached := CachedResult{
			Class:      string(res.Class),
			Confidence: res.Confidence,
			Source:     res.Source,
			Latency:    res.Latency,
		}
		data, err := json.Marshal(cached)
		if err == nil {
			// Best-effort cache write — ignore errors.
			_ = r.rdb.SetEx(ctx, cacheKey, data, r.cacheTTL)
		}
	}

	return res
}

// NewRegistryWithCacheNoop creates a RegistryWithCache with nil Redis —
// acts as a pass-through to the inner registry without caching. Useful when
// gateway is initialized without Redis (e.g., tests, single-binary mode).
func NewRegistryWithCacheNoop(inner *Registry) *RegistryWithCache {
	return &RegistryWithCache{
		inner:    inner,
		rdb:      nil,
		log:      slog.Default(),
		cacheTTL: classifierCacheTTL,
		cacheKeyFn: func(orgID, prompt string) string {
			h := sha256.Sum256([]byte(orgID + ":" + prompt))
			return classifierCacheKeyPrefix + fmt.Sprintf("%x", h)
		},
	}
}

// Name returns a descriptive name for this cached registry.
func (r *RegistryWithCache) Name() string {
	return "registry_with_cache"
}
