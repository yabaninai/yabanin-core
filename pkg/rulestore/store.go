package rulestore

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"

	"github.com/reireirei/yabanin/pkg/auth"
	evaluator "github.com/reireirei/yabanin/pkg/rulesengine"
)

const (
	cacheKeyPrefix = "rules:org:"
	defaultTTL     = 5 * time.Minute
)

// dbConn abstracts pgxpool.Pool.Query for testability.
type dbConn interface {
	Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
}

// cacheOps abstracts redis.Client.Get/Set/Del for testability.
type cacheOps interface {
	Get(ctx context.Context, key string) *redis.StringCmd
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) *redis.StatusCmd
	Del(ctx context.Context, keys ...string) *redis.IntCmd
}

// Store reads routing rules from Postgres with a Redis cache layer.
type Store struct {
	pool   dbConn
	rdb    cacheOps
	ttl    time.Duration
	signer *auth.CacheSigner
	log    *slog.Logger
}

// New creates a new rule store. If pool is nil, only Redis cache is used (cache-only mode for testing).
// Pass signer as nil to skip HMAC verification on cache values.
func New(pool dbConn, rdb cacheOps, ttl time.Duration, signer *auth.CacheSigner, l *slog.Logger) *Store {
	if ttl == 0 {
		ttl = defaultTTL
	}
	return &Store{
		pool:   pool,
		rdb:    rdb,
		ttl:    ttl,
		signer: signer,
		log:    l,
	}
}

// GetByOrg returns rules for an org, using Redis cache when available.
//
// RT-06 caching contract:
//   - EMPTY rule sets are cached too ("[]" with the same TTL): an org without
//     rules no longer costs a DB query per request until the TTL expires;
//   - only authoritative results are cached — a DB error is returned to the
//     caller and never written as a negative (or positive) cache entry;
//   - invalidation is rulestore.Invalidate (a Redis DEL) and is the contract
//     for create/update/delete of an org's rules. The store itself keeps no
//     local state, so there is no local mutex to confuse with cross-replica
//     invalidation: the Redis layer is shared by all replicas. A load that
//     races an invalidate may repopulate the pre-mutation value; the chosen
//     contract bounds that staleness at the TTL.
func (s *Store) GetByOrg(ctx context.Context, orgID string) ([]evaluator.Rule, error) {
	cacheKey := cacheKeyPrefix + orgID

	if s.rdb != nil {
		signedData, err := s.rdb.Get(ctx, cacheKey).Result()
		if err == nil {
			var data []byte
			if s.signer != nil {
				verified, ok := s.signer.Verify(cacheKey, signedData)
				if !ok {
					s.log.Warn("rulestore cache HMAC verify failed, falling back to DB", "org_id", orgID)
				} else {
					data = []byte(verified)
				}
			} else {
				data = []byte(signedData)
			}
			if len(data) > 0 {
				s.log.Debug("rulestore cache hit", "org_id", orgID)
				var rules []evaluator.Rule
				decodeErr := unmarshalRules(data, &rules)
				if decodeErr == nil {
					return rules, nil
				}
				s.log.Warn("rulestore cache decode failed, falling back to DB", "error", decodeErr)
			}
		} else if err != redis.Nil {
			s.log.Warn("rulestore cache read failed", "error", err)
		}
	}

	if s.pool == nil {
		return nil, nil
	}

	rules, err := s.loadFromDB(ctx, orgID)
	if err != nil {
		// RT-06: a DB failure is never cached — neither as the empty set nor
		// as the previous value's refresh. The next request retries the DB.
		return nil, fmt.Errorf("load rules from db: %w", err)
	}

	if s.rdb != nil {
		data, marshalErr := marshalRules(rules)
		if marshalErr == nil {
			var cacheVal interface{} = data
			if s.signer != nil {
				cacheVal = s.signer.Sign(cacheKey, string(data))
			}
			if setErr := s.rdb.Set(ctx, cacheKey, cacheVal, s.ttl).Err(); setErr != nil {
				s.log.Warn("rulestore cache write failed", "error", setErr)
			}
		}
	}

	return rules, nil
}

// Invalidate removes the cached rules for an org. It is the invalidation
// half of the RT-06 contract: rule mutations (create/update/delete on the
// admin surface) call it so new rules become visible without waiting for the
// TTL. It only clears the shared Redis entry — replicas re-read the DB on
// their next request; no local state exists to clear here.
func (s *Store) Invalidate(ctx context.Context, orgID string) {
	if s.rdb == nil {
		return
	}
	key := cacheKeyPrefix + orgID
	if err := s.rdb.Del(ctx, key).Err(); err != nil && err != redis.Nil {
		s.log.Warn("rulestore cache invalidation failed", "error", err)
	}
}

func (s *Store) loadFromDB(ctx context.Context, orgID string) ([]evaluator.Rule, error) {
	query := `SELECT id::text, org_id::text, match_expr, target_model, priority, enabled
              FROM routing_rules
              WHERE org_id = $1 AND enabled = true
              ORDER BY priority DESC`

	rows, err := s.pool.Query(ctx, query, orgID)
	if err != nil {
		return nil, fmt.Errorf("query routing_rules: %w", err)
	}
	defer rows.Close()

	var rules []evaluator.Rule
	for rows.Next() {
		var r evaluator.Rule
		if err := rows.Scan(&r.ID, &r.OrgID, &r.MatchExpr, &r.TargetModel, &r.Priority, &r.Enabled); err != nil {
			return nil, fmt.Errorf("scan routing_rule: %w", err)
		}
		rules = append(rules, r)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate routing_rules: %w", err)
	}

	return rules, nil
}

// marshalRules serializes a rule slice to JSON bytes.
func marshalRules(rules []evaluator.Rule) ([]byte, error) {
	return json.Marshal(rules)
}

// unmarshalRules deserializes JSON bytes into a rule slice.
func unmarshalRules(data []byte, rules *[]evaluator.Rule) error {
	return json.Unmarshal(data, rules)
}
