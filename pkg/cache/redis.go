// Package cache provides semantic cache storage with Redis and pgvector backends.
package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// DefaultTTL is the default time-to-live for cache entries in Redis.
	DefaultTTL = 24 * time.Hour

	// keyPrefix is the Redis key namespace prefix.
	keyPrefix = "cache:"

	// keyVersionSegment scopes keys to the route-identity namespace (RT-05),
	// mirroring the affinity store's "v2" transition: keys written before the
	// segment existed simply age out — they are never read or deleted by new
	// code, and no flush touches another tenant's keys.
	keyVersionSegment = RouteVersion

	// statsScanBatch is the SCAN COUNT hint per iteration. Each batch is a
	// single O(batch) command, so no step blocks the Redis event loop the way
	// a full KEYSCAN/KEYS over the keyspace would (AF-16).
	statsScanBatch = 500

	// statsScanMaxBatches is the safety valve on one Stats call: at most
	// statsScanBatch×statsScanMaxBatches keys are visited before the count is
	// reported as partial. 40k batches × 500 ≈ a 20M-key budget — far above
	// any expected cache namespace, while bounding worst-case Stats work.
	statsScanMaxBatches = 40000

	// statsScanMaxDuration bounds one Stats call in wall-clock time; when
	// exceeded the partial count is returned with ErrStatsIncomplete.
	statsScanMaxDuration = 2 * time.Second
)

// ErrStatsIncomplete reports that the Stats scan hit its batch/time budget
// and the returned count covers only the portion of the keyspace visited so
// far (a lower bound, never an overcount of visited keys).
var ErrStatsIncomplete = errors.New("redis stats scan budget exhausted: count is partial")

// KeyPatternOrg returns the SCAN pattern that matches every cache key of one
// organization in the current route namespace.
func KeyPatternOrg(orgID string) string {
	return fmt.Sprintf("%s%s:%s:*", keyPrefix, keyVersionSegment, orgID)
}

// KeyPatternTier returns the SCAN pattern that matches every cache key of a
// model tier across organizations in the current route namespace.
func KeyPatternTier(modelTier string) string {
	return fmt.Sprintf("%s%s:*:%s:*", keyPrefix, keyVersionSegment, modelTier)
}

// MakeKey builds a Redis key from the route namespace segment, org_id,
// model_tier and prompt_hash.
func MakeKey(orgID, modelTier, promptHash string) string {
	return fmt.Sprintf("%s%s:%s:%s:%s", keyPrefix, keyVersionSegment, orgID, modelTier, promptHash)
}

// RedisStore provides fast exact-match caching backed by Redis.
type RedisStore struct {
	rdb *redis.Client
	ttl time.Duration

	// Stats scan budget (AF-16): batch size, max batches and wall-clock cap
	// of one Stats call. Defaults come from the statsScan* constants; tests
	// may shrink them to exercise the partial-count path.
	statsBatch       int64
	statsMaxBatches  int
	statsMaxDuration time.Duration
}

// NewRedisStore creates a new Redis-backed cache store with the given TTL.
func NewRedisStore(rdb *redis.Client, ttl time.Duration) *RedisStore {
	if ttl == 0 {
		ttl = DefaultTTL
	}
	return &RedisStore{
		rdb:              rdb,
		ttl:              ttl,
		statsBatch:       statsScanBatch,
		statsMaxBatches:  statsScanMaxBatches,
		statsMaxDuration: statsScanMaxDuration,
	}
}

// ComputePromptHash computes a SHA-256 hash of the normalized prompt JSON bytes.
func ComputePromptHash(promptJSON []byte) string {
	h := sha256.Sum256(promptJSON)
	return hex.EncodeToString(h[:])
}

// Has checks whether an exact cache entry exists for the given key.
// Returns true if the key is present in Redis (not expired).
func (r *RedisStore) Has(ctx context.Context, orgID, modelTier, promptHash string) (bool, error) {
	key := MakeKey(orgID, modelTier, promptHash)
	exists, err := r.rdb.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("redis has: %w", err)
	}
	return exists > 0, nil
}

// Get retrieves a cached response by org_id, model_tier and prompt_hash.
// Returns (nil, redis.Nil) on miss.
func (r *RedisStore) Get(ctx context.Context, orgID, modelTier, promptHash string) ([]byte, error) {
	key := MakeKey(orgID, modelTier, promptHash)
	data, err := r.rdb.Get(ctx, key).Bytes()
	if err != nil {
		return nil, fmt.Errorf("redis get: %w", err)
	}
	return data, nil
}

// Put stores a JSON response in Redis with the configured TTL.
func (r *RedisStore) Put(ctx context.Context, orgID, modelTier, promptHash string, data []byte) error {
	key := MakeKey(orgID, modelTier, promptHash)
	err := r.rdb.Set(ctx, key, data, r.ttl).Err()
	if err != nil {
		return fmt.Errorf("redis put: %w", err)
	}
	return nil
}

// Delete removes a cache entry by key.
func (r *RedisStore) Delete(ctx context.Context, orgID, modelTier, promptHash string) error {
	if r.rdb == nil {
		return nil
	}
	key := MakeKey(orgID, modelTier, promptHash)
	err := r.rdb.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("redis delete: %w", err)
	}
	return nil
}

// PurgeExpired scans the cache namespace and deletes only keys whose TTL has
// actually expired (PTTL == 0) or that vanished mid-scan (PTTL == -2; counting
// only what UNLINK really removed). Keys with PTTL == -1 are persistent — they
// have no expiry and must never be deleted by a TTL purge — and live keys
// (PTTL > 0) are left alone. PTTL (millisecond precision) is used instead of
// the second-granular TTL because TTL truncates a sub-second remainder to 0,
// which would make a still-live key look expired and delete it up to a second
// early. Deletion is batched per SCAN page through UNLINK, which frees the
// memory asynchronously without blocking the Redis event loop.
func (r *RedisStore) PurgeExpired(ctx context.Context) (int, error) {
	var deleted int
	cursor := uint64(0)
	for {
		keys, newCursor, err := r.rdb.Scan(ctx, cursor, keyPrefix+"*", 100).Result()
		if err != nil {
			return deleted, fmt.Errorf("redis purge scan: %w", err)
		}
		var expired []string
		for _, key := range keys {
			pttl, err := r.rdb.PTTL(ctx, key).Result()
			if err != nil {
				continue
			}
			switch {
			case pttl == -1: // persistent: no expiry, keep
				continue
			case pttl > 0: // still live (millisecond precision)
				continue
			case pttl == -2: // key gone between SCAN and PTTL: nothing to delete
				continue
			}
			expired = append(expired, key)
		}
		if len(expired) > 0 {
			n, err := r.rdb.Unlink(ctx, expired...).Result()
			if err != nil {
				return deleted, fmt.Errorf("redis purge unlink: %w", err)
			}
			deleted += int(n)
		}
		cursor = newCursor
		if cursor == 0 {
			break
		}
	}
	return deleted, nil
}

// Stats returns an approximate count of cache namespace keys.
//
// Implementation is an incremental bounded SCAN (AF-16): the cursor loop
// issues COUNT=statsScanBatch commands, so the Redis event loop is never
// blocked for the whole keyspace the way a single KEYS call would be, and
// the batch/time budget caps the total work of one call. When the budget is
// exhausted, the partial count is returned together with an error wrapping
// ErrStatsIncomplete.
//
// Concurrency honesty — this is NOT a consistent snapshot. Redis SCAN only
// guarantees that keys present for the entire iteration are returned; keys
// added or removed while the scan runs may or may not be included, and a
// hash-table rehash triggered by concurrent writes can visit a key more
// than once, so the count can slightly over- or under-count a live keyspace.
// Callers must treat the value as an operations-grade approximation, not an
// accounting figure.
func (r *RedisStore) Stats(ctx context.Context) (int64, error) {
	var (
		count    int64
		cursor   uint64
		batches  int
		deadline = time.Now().Add(r.statsMaxDuration)
	)
	for {
		if err := ctx.Err(); err != nil {
			return count, fmt.Errorf("redis stats scan: %w", err)
		}
		keys, next, err := r.rdb.Scan(ctx, cursor, keyPrefix+"*", r.statsBatch).Result()
		if err != nil {
			return count, fmt.Errorf("redis stats scan: %w", err)
		}
		count += int64(len(keys))
		cursor = next
		batches++
		if cursor == 0 {
			return count, nil
		}
		if batches >= r.statsMaxBatches || time.Now().After(deadline) {
			return count, fmt.Errorf("redis stats after %d batches: %w", batches, ErrStatsIncomplete)
		}
	}
}
