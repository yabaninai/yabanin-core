package router

import (
	"context"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

// ENT-04 (HA multi-replica): shared sticky-state.
//
// AffinityStore is the session-affinity surface the gateway uses: Record notes
// that a model just served a session with warm cache, and Preferred returns the
// sticky model for a session ("" = none). The in-memory SessionAffinity
// satisfies it (single replica); RedisSessionAffinity satisfies it with state in
// Redis so N gateway replicas share one stickiness table (a session that hops
// replicas does not lose its warm model). Losing the state only costs
// stickiness, never correctness, so the Redis backend is best-effort: a Redis
// error degrades to "no affinity" rather than failing the request.

// AffinityStore is the KV-cache-aware session stickiness surface. All
// operations are scoped by org: the same sessionID in two organizations is
// two independent stickiness entries. The request context flows through both
// operations (RT-06): a cancelled request can never block on or outlive its
// own affinity I/O; the Redis backend stays best-effort — any error (including
// cancellation) degrades to a miss/ignore, never an infinite wait and never
// another org's sticky model.
type AffinityStore interface {
	Record(ctx context.Context, orgID, sessionID, model string, cacheReadTokens int64)
	Preferred(ctx context.Context, orgID, sessionID string) string
}

// affinityRedis is the minimal Redis surface the shared affinity store needs.
// *redis.Client satisfies it; the test double is in-memory.
type affinityRedis interface {
	Get(ctx context.Context, key string) *redis.StringCmd
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd
	PExpire(ctx context.Context, key string, expiration time.Duration) *redis.BoolCmd
}

// affinityKeyPrefix is the org-scoped key layout
// ("yb:affinity:v2:<org>:<session>"). The v2 segment guarantees no collision
// with the pre-RT-01 unscoped layout ("yb:affinity:<session>"): entries
// written there are never read, because a sessionID is only meaningful within
// its org — unscoped stickiness could route one org's session to another
// org's sticky model.
const affinityKeyPrefix = "yb:affinity:v2:"

// affinityKey builds the Redis key for an org-scoped session entry.
func affinityKey(orgID, sessionID string) string {
	return affinityKeyPrefix + orgID + ":" + sessionID
}

// RedisSessionAffinity is the shared (multi-replica) session-affinity backend.
// One Redis key per org+session holds the sticky model with the session TTL.
type RedisSessionAffinity struct {
	rdb       affinityRedis
	ttl       time.Duration
	minTokens int64
	log       *slog.Logger
}

// NewRedisSessionAffinity applies the same defaults as the in-memory store for
// zero/negative values (ttl=10m, minTokens=512).
func NewRedisSessionAffinity(rdb affinityRedis, ttl time.Duration, minTokens int64, log *slog.Logger) *RedisSessionAffinity {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if minTokens <= 0 {
		minTokens = 512
	}
	if log == nil {
		log = slog.Default()
	}
	return &RedisSessionAffinity{rdb: rdb, ttl: ttl, minTokens: minTokens, log: log}
}

// Record implements AffinityStore. A cache-read hit at/above minTokens sets the
// sticky model (refreshing the TTL); a lower value still refreshes the TTL
// (session alive, model remembered) without overwriting it. Entries are keyed
// by org+session. Best-effort: errors (including a cancelled request context)
// are logged and ignored — affinity loss never fails a request.
func (a *RedisSessionAffinity) Record(ctx context.Context, orgID, sessionID, model string, cacheReadTokens int64) {
	if orgID == "" || sessionID == "" || model == "" {
		return
	}
	key := affinityKey(orgID, sessionID)
	if cacheReadTokens >= a.minTokens {
		if err := a.rdb.Set(ctx, key, model, a.ttl).Err(); err != nil {
			a.log.Debug("affinity SET failed", "error", err.Error())
			return
		}
		return
	}
	// Below threshold: refresh the TTL only (keep the existing model). A miss
	// (key absent) is a no-op — there is no model to remember yet.
	if err := a.rdb.PExpire(ctx, key, a.ttl).Err(); err != nil {
		a.log.Debug("affinity PEXPIRE failed", "error", err.Error())
	}
}

// Preferred implements AffinityStore: orgID's sticky model for the session, or
// "" when absent/expired — or when the org/session is empty: an empty org must
// never read another org's entry. The request context bounds the Redis call
// (RT-06): a cancelled or expired request degrades to "" immediately instead
// of waiting on the datastore; any other error also degrades to ""
// (best-effort stickiness).
func (a *RedisSessionAffinity) Preferred(ctx context.Context, orgID, sessionID string) string {
	if orgID == "" || sessionID == "" {
		return ""
	}
	val, err := a.rdb.Get(ctx, affinityKey(orgID, sessionID)).Result()
	if err != nil {
		if err != redis.Nil && ctx.Err() == nil {
			a.log.Debug("affinity GET failed", "error", err.Error())
		}
		return ""
	}
	return val
}

// Compile-time assertions: both backends satisfy the shared interface.
var (
	_ AffinityStore = (*SessionAffinity)(nil)
	_ AffinityStore = (*RedisSessionAffinity)(nil)
)
