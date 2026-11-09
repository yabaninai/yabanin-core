// Package regionrouter maps an org_id to its home region (Redis-cached,
// DB-backed) and decides failover when the local region is unhealthy.
package regionrouter

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/reireirei/yabanin/pkg/metrics"
)

// Assignment is the resolved region decision for an org.
type Assignment struct {
	HomeRegion      string
	ResidencyPinned bool
}

// orgStore is the DB read-contract (satisfied by *pgxpool.Pool via pgStore).
// Kept as an interface so the Router is unit-testable without Postgres.
type orgStore interface {
	// LookupRegion returns the org's home_region, residency_pinned flag.
	// errOrgNotFound signals "no row" (Router falls back to default).
	LookupRegion(ctx context.Context, orgID string) (region string, pinned bool, err error)
}

// kvStore is the minimal Redis contract. Wrapping *redis.Client satisfies it.
type kvStore interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	Del(ctx context.Context, key string) error
}

// errCacheMiss is the sentinel returned by kvStore.Get on a cache miss.
var errCacheMiss = errors.New("regionrouter: cache miss")

// DefaultRegion is the fail-open region for unknown orgs.
const DefaultRegion = "sg"

// Router maps org_id → home region. Redis-cached (60s TTL), DB-backed.
type Router struct {
	store    orgStore
	cache    kvStore
	ttl      time.Duration
	fallback Assignment
	log      *slog.Logger
}

// New builds a Router backed by an orgStore and a kvStore.
func New(store orgStore, cache kvStore) *Router {
	return &Router{
		store:    store,
		cache:    cache,
		ttl:      60 * time.Second,
		fallback: Assignment{HomeRegion: DefaultRegion, ResidencyPinned: false},
		log:      slog.Default(),
	}
}

// WithLogger returns the receiver for chaining; a nil logger is ignored.
func (r *Router) WithLogger(log *slog.Logger) *Router {
	if log != nil {
		r.log = log
	}
	return r
}

// NewWithRedis wires a *redis.Client as the kvStore. pool must satisfy
// orgStore — typically a *pgStore wrapping *pgxpool.Pool (see pgstore.go).
func NewWithRedis(store orgStore, rdb *redis.Client) *Router {
	return New(store, redisKV{rdb: rdb})
}

// Resolve returns the org's home region. Default "sg" when no mapping
// (fail-open to the deployment's primary region — never block unknown orgs).
func (r *Router) Resolve(ctx context.Context, orgID string) Assignment {
	if orgID == "" {
		return r.fallback
	}
	key := "org_region:" + orgID
	if v, err := r.cache.Get(ctx, key); err == nil && v != "" {
		return decode(v, r.fallback)
	}
	region, pinned, err := r.store.LookupRegion(ctx, orgID)
	if err != nil || region == "" {
		assign := r.fallback
		// Negative cache (shorter TTL) to avoid hammering DB for unknown orgs.
		r.cacheSet(ctx, orgID, assign, 15*time.Second)
		return assign
	}
	assign := Assignment{HomeRegion: region, ResidencyPinned: pinned}
	r.cacheSet(ctx, orgID, assign, r.ttl)
	return assign
}

// Invalidate clears the cached region for an org (call on admin update).
func (r *Router) Invalidate(ctx context.Context, orgID string) {
	if err := r.cache.Del(ctx, "org_region:"+orgID); err != nil {
		// mapping would keep serving until TTL. Count and warn.
		metrics.RegionCacheInvalidateFailedTotal.WithLabelValues("del").Inc()
		r.log.Warn("region cache invalidate failed", "org_id", orgID, "error", err.Error())
	}
}

// cacheSet writes the assignment to the cache, counting and warning on
// silently sends every request to the DB until it succeeds.
func (r *Router) cacheSet(ctx context.Context, orgID string, assign Assignment, ttl time.Duration) {
	if err := r.cache.Set(ctx, "org_region:"+orgID, encode(assign.HomeRegion, assign.ResidencyPinned), ttl); err != nil {
		metrics.RegionCacheInvalidateFailedTotal.WithLabelValues("set").Inc()
		r.log.Warn("region cache set failed",
			"org_id", orgID, "region", assign.HomeRegion, "ttl", ttl.String(), "error", err.Error())
	}
}

// SetAssignment upserts the org mapping in the store and invalidates cache.
// orgStore implementations should expose a writer; this delegates.
func (r *Router) SetAssignment(ctx context.Context, orgID, region string, pinned bool) error {
	w, ok := r.store.(orgWriter)
	if !ok {
		return errors.New("regionrouter: store is read-only")
	}
	if err := w.UpsertRegion(ctx, orgID, region, pinned); err != nil {
		return err
	}
	r.Invalidate(ctx, orgID)
	return nil
}

// orgWriter is implemented by stores that support writes.
type orgWriter interface {
	UpsertRegion(ctx context.Context, orgID, region string, pinned bool) error
}

// encode packs region+pinned into a cache string: "1sg" (pinned) / "0in" (not).
func encode(region string, pinned bool) string {
	if pinned {
		return "1" + region
	}
	return "0" + region
}

// decode reverses encode. Falls back to def on malformed input.
func decode(v string, def Assignment) Assignment {
	if len(v) < 2 {
		return def
	}
	pinned := v[0] == '1'
	region := v[1:]
	if region == "" {
		return def
	}
	return Assignment{HomeRegion: region, ResidencyPinned: pinned}
}

// PeerRedirect is returned by an edge decider when this instance is NOT the
// org's home region — caller must 307 to the peer gateway_url.
type PeerRedirect struct {
	TargetURL string
	Reason    string
}

func (e PeerRedirect) Error() string {
	return "redirect to " + e.TargetURL + ": " + e.Reason
}

// --- kvStore adapter for *redis.Client ---

type redisKV struct{ rdb *redis.Client }

func (k redisKV) Get(ctx context.Context, key string) (string, error) {
	s, err := k.rdb.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", errCacheMiss
	}
	return s, err
}

func (k redisKV) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	return k.rdb.Set(ctx, key, value, ttl).Err()
}

func (k redisKV) Del(ctx context.Context, key string) error {
	return k.rdb.Del(ctx, key).Err()
}
