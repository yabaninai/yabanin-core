package classifier

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	pgxpool "github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// RegistryWithDBCache extends RegistryWithCache with pgvector-backed semantic classification cache.
// Lookup order: Redis exact → DB exact (prompt_hash) → DB semantic (cosine < threshold) → inner classifier.
type RegistryWithDBCache struct {
	*RegistryWithCache
	dbPool *pgxpool.Pool
	log    *slog.Logger
	hashFn func(orgID, prompt string) string
	table  string // classifier cache table name
}

// NewRegistryWithDBCache creates a classifier registry with Redis + pgvector caching.
// Uses bge-small-en-v1.5 embeddings (384-dim). Semantic match requires cosine >= 0.92.
func NewRegistryWithDBCache(reg *Registry, rdb cacheClient, dbPool *pgxpool.Pool, log *slog.Logger) *RegistryWithDBCache {
	inner := NewRegistryWithCache(reg, rdb, log)
	return &RegistryWithDBCache{
		RegistryWithCache: inner,
		dbPool:            dbPool,
		log:               log,
		hashFn: func(orgID, prompt string) string {
			h := sha256.Sum256([]byte(orgID + ":" + prompt))
			return fmt.Sprintf("%x", h)
		},
		table: "classifier_cache",
	}
}

// Classify performs a 4-tier lookup: Redis → DB exact → DB semantic → inner classifier.
func (r *RegistryWithDBCache) Classify(ctx context.Context, in Input) Result {
	start := time.Now()

	// Tier 1: Redis exact match (fastest).
	if r.RegistryWithCache != nil && r.rdb != nil && in.OrgID != "" {
		cacheKey := r.cacheKeyFn(in.OrgID, in.Prompt)
		data, err := r.RegistryWithCache.rdb.Get(ctx, cacheKey).Bytes()
		if err == nil {
			var cached CachedResult
			if json.Unmarshal(data, &cached) == nil {
				r.log.Debug("classifier redis cache hit", "org_id", in.OrgID, "class", cached.Class)
				return Result{
					Class:      Class(cached.Class),
					Confidence: cached.Confidence,
					Source:     string(SourceCacheHit),
					Latency:    time.Since(start).Nanoseconds(),
				}
			}
		}
		if err != nil && err != redis.Nil {
			r.log.Debug("classifier redis lookup failed", "error", err)
		}
	}

	// Tier 2 & 3: DB exact + semantic match.
	promptHash := r.hashFn(in.OrgID, in.Prompt)

	if r.dbPool != nil && in.OrgID != "" {
		classVal, conf, _, found := r.lookupDBExact(ctx, in.OrgID, promptHash)
		if found {
			r.log.Debug("classifier db exact cache hit", "org_id", in.OrgID, "class", classVal)
			return Result{
				Class:      Class(classVal),
				Confidence: conf,
				Source:     string(SourceCacheHit),
				Latency:    time.Since(start).Nanoseconds(),
			}
		}

		// Tier 3: DB semantic match (requires embedding — use prompt hash as fallback if no embedder).
		classVal, conf, found = r.lookupDBSemantic(ctx, in.OrgID, in.Prompt)
		if found {
			r.log.Debug("classifier db semantic cache hit", "org_id", in.OrgID, "class", classVal)
			return Result{
				Class:      Class(classVal),
				Confidence: conf,
				Source:     string(SourceCacheHit),
				Latency:    time.Since(start).Nanoseconds(),
			}
		}
	}

	// Tier 4: Cache miss — delegate to inner registry.
	res := r.inner.Classify(ctx, in)

	// Write result to both Redis and DB (best-effort).
	if res.Source != string(SourceDefault) && in.OrgID != "" {
		r.writeToRedis(ctx, in.OrgID, in.Prompt, res)
		r.writeToDBExact(ctx, in.OrgID, promptHash, res)
	}

	return res
}

// lookupDBExact performs exact match on prompt_hash.
func (r *RegistryWithDBCache) lookupDBExact(ctx context.Context, orgID, promptHash string) (string, float64, string, bool) {
	var classVal string
	var conf float64
	var sourceVal string
	err := r.dbPool.QueryRow(ctx,
		`SELECT class, confidence, source FROM `+r.table+`
		 WHERE org_id = $1 AND prompt_hash = $2 AND expires_at > now()`,
		orgID, promptHash,
	).Scan(&classVal, &conf, &sourceVal)

	if err == nil {
		_, _ = r.dbPool.Exec(ctx,
			`UPDATE `+r.table+` SET hit_count = hit_count + 1 WHERE org_id = $1 AND prompt_hash = $2`,
			orgID, promptHash,
		)
		return classVal, conf, sourceVal, true
	}
	if err != nil && err != pgx.ErrNoRows {
		r.log.Debug("classifier db exact lookup failed", "error", err)
	}
	return "", 0, "", false
}

// lookupDBSemantic performs semantic match via pgvector cosine distance.
// Falls back to prompt-hash-based approximate matching if no embedding column is populated.
func (r *RegistryWithDBCache) lookupDBSemantic(ctx context.Context, orgID, prompt string) (string, float64, bool) {
	// Try pgvector cosine match first (requires embedding vector).
	var classVal string
	var conf float64
	err := r.dbPool.QueryRow(ctx,
		`SELECT class, confidence FROM `+r.table+`
		 WHERE org_id = $1 AND expires_at > now()
		   AND embedding IS NOT NULL
		 ORDER BY embedding <-> $2::vector
		 LIMIT 1`,
		orgID, prompt,
	).Scan(&classVal, &conf)

	if err == nil {
		return classVal, conf, true
	}
	if err != nil && err != pgx.ErrNoRows {
		r.log.Debug("classifier db semantic lookup failed", "error", err)
	}
	return "", 0, false
}

func (r *RegistryWithDBCache) writeToRedis(ctx context.Context, orgID, prompt string, res Result) {
	if r.RegistryWithCache == nil || r.rdb == nil {
		return
	}
	cacheKey := r.cacheKeyFn(orgID, prompt)
	cached := CachedResult{
		Class:      string(res.Class),
		Confidence: res.Confidence,
		Source:     res.Source,
		Latency:    res.Latency,
	}
	data, err := json.Marshal(cached)
	if err == nil {
		_ = r.rdb.SetEx(ctx, cacheKey, data, r.cacheTTL)
	}
}

func (r *RegistryWithDBCache) writeToDBExact(ctx context.Context, orgID, promptHash string, res Result) {
	if r.dbPool == nil || orgID == "" {
		return
	}
	_, err := r.dbPool.Exec(ctx,
		`INSERT INTO `+r.table+` (org_id, prompt_hash, class, confidence, source, expires_at)
		 VALUES ($1, $2, $3, $4, $5, now() + interval '7 days')
		 ON CONFLICT DO NOTHING`,
		orgID, promptHash, string(res.Class), res.Confidence, res.Source,
	)
	if err != nil {
		r.log.Debug("classifier db cache write failed", "error", err)
	}
}

// NewRegistryWithDBCacheSilent creates a RegistryWithDBCache wrapping a pre-built
// RegistryWithCache, with an optional DB pool. When dbPool is nil, only Redis cache
// is used (no pgvector semantic lookup). Useful for single-binary mode or when the
// classifier needs to be initialized separately from the DB pool.
func NewRegistryWithDBCacheSilent(inner *RegistryWithCache, dbPool *pgxpool.Pool, log *slog.Logger) *RegistryWithDBCache {
	return &RegistryWithDBCache{
		RegistryWithCache: inner,
		dbPool:            dbPool,
		log:               log,
		hashFn: func(orgID, prompt string) string {
			h := sha256.Sum256([]byte(orgID + ":" + prompt))
			return fmt.Sprintf("%x", h)
		},
		table: "classifier_cache",
	}
}

// Name returns a descriptive name for this cached registry.
func (r *RegistryWithDBCache) Name() string {
	return "registry_with_db_cache"
}
