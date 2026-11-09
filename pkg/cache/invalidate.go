// Package cache provides semantic cache storage with Redis and pgvector backends.
package cache

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/redis/go-redis/v9"
)

// ErrInvalidationIncomplete is wrapped by every *InvalidationError: it marks
// a flush that did NOT complete, so stale entries may remain. Callers check
// it with errors.Is to distinguish "nothing was cleaned" from "cleaned, but
// not fully" — both must be surfaced, neither may be reported as success.
var ErrInvalidationIncomplete = errors.New("cache invalidation incomplete")

// InvalidationError reports an incomplete cache invalidation together with
// the partial state an operator (or retry loop) needs.
type InvalidationError struct {
	// Backend names the failing backend: "redis" or "pgvector".
	Backend string
	// Deleted counts keys successfully deleted before the failure
	// (0 when none or unknown).
	Deleted int
	// Failed counts keys known to remain: attempted but not deleted.
	// 0 when unknown (e.g. SCAN died before enumerating them).
	Failed int
	// ScanIncomplete marks a SCAN that ended early: an unknown number of
	// matching keys was never enumerated, so Failed is a lower bound.
	ScanIncomplete bool
	// Err is the underlying cause (wrapped, so errors.Is still reaches
	// context.Canceled, net errors, etc.).
	Err error
}

func (e *InvalidationError) Error() string {
	msg := e.Backend + " cache invalidation incomplete"
	var parts []string
	if e.Deleted > 0 {
		parts = append(parts, fmt.Sprintf("%d keys deleted", e.Deleted))
	}
	if e.Failed > 0 {
		parts = append(parts, fmt.Sprintf("%d keys failed", e.Failed))
	}
	if e.ScanIncomplete {
		parts = append(parts, "scan ended early: unknown matching keys may remain")
	}
	if len(parts) > 0 {
		msg += " (" + strings.Join(parts, ", ") + ")"
	}
	return msg + ": " + e.Err.Error()
}

func (e *InvalidationError) Unwrap() error { return e.Err }

// Is marks every *InvalidationError with ErrInvalidationIncomplete while
// keeping errors.Is working for the wrapped cause via Unwrap.
func (e *InvalidationError) Is(target error) bool { return target == ErrInvalidationIncomplete }

// IsCancellation reports whether err was caused by a context being canceled
// or expired. This is an error-SHAPE predicate only: go-redis surfaces a
// store-side dial/read timeout as a context.DeadlineExceeded wrap even while
// the caller's own context is live (the T06 classification), so a true
// caller-abort verdict needs the caller's context — see IsRetryable.
// Such failures are never retried automatically on this predicate alone.
func IsCancellation(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// IsRetryable reports whether re-running the same invalidation can make
// progress, judged against the caller's own context (the same ctx the sweep
// ran under):
//
//   - err == nil: nothing to retry;
//   - caller gone (ctx.Err() != nil): only non-cancellation failures are
//     retryable — a cancellation-shaped error on a spent context is a
//     caller abort;
//   - caller live: a pure context.Canceled wrap stays non-retryable
//     (conservative: caller-initiated), while a DeadlineExceeded wrap is a
//     STORE-side timeout signal (go-redis wraps read timeouts this way) and
//     IS retryable — the caller's own deadline is not spent.
func IsRetryable(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	if ctx.Err() != nil {
		return !IsCancellation(err)
	}
	return !errors.Is(err, context.Canceled)
}

// Invalidator manages cache invalidation at various granularities.
type Invalidator struct {
	exact *RedisStore
	store *Store
	rdb   *redis.Client
}

// NewInvalidator creates a new invalidator backed by Redis and pgvector stores.
func NewInvalidator(exact *RedisStore, store *Store, rdb *redis.Client) *Invalidator {
	return &Invalidator{exact: exact, store: store, rdb: rdb}
}

// redisSweep scans pattern and deletes every matching key (FIX-04/CA-06).
//
// Failure semantics — none of these are silent:
//   - every SCAN/DEL error is returned, wrapped so errors.Is reaches the
//     cause and ErrInvalidationIncomplete / IsCancellation / IsRetryable
//     classify it;
//   - a SCAN that dies mid-page still deletes the keys enumerated so far
//     (less staleness is better than none) and reports ScanIncomplete with
//     the count deleted — the number of surviving keys is unknown;
//   - a caller cancellation stops the sweep immediately (further Redis
//     work would fail anyway) and returns the cancellation unwrapped-ish
//     for IsCancellation.
//
// Known inherent SCAN semantics (documented caveat, not a defect): keys
// written while the sweep runs may be missed by that pass and survive until
// their TTL or the next flush. Callers needing a stronger bound must repeat
// the sweep; an unbounded rescan-until-empty loop is not safe under
// sustained writes.
func (i *Invalidator) redisSweep(ctx context.Context, label, pattern string, pageSize int64) error {
	iter := i.rdb.Scan(ctx, 0, pattern, pageSize).Iterator()
	var keys []string
	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}
	scanErr := iter.Err()

	if scanErr != nil && IsCancellation(scanErr) && ctx.Err() != nil {
		// Caller aborted: don't spend more work, surface the class as-is.
		// A deadline-exceeded-shaped error with a LIVE caller ctx is a
		// store-side timeout (go-redis wraps read timeouts this way, T06
		// classification): fall through, delete the keys enumerated so far
		// and report the honest incomplete state instead.
		return fmt.Errorf("%s canceled: %w", label, scanErr)
	}

	deleted := 0
	var delErr error
	if len(keys) > 0 {
		n, err := i.rdb.Del(ctx, keys...).Result()
		if err != nil && !isRedisNil(err) {
			delErr = err
		}
		deleted = int(n)
	}

	switch {
	case delErr != nil && scanErr != nil:
		return &InvalidationError{
			Backend:        "redis",
			Deleted:        deleted,
			Failed:         len(keys) - deleted,
			ScanIncomplete: true,
			Err:            errors.Join(fmt.Errorf("scan: %w", scanErr), fmt.Errorf("del: %w", delErr)),
		}
	case delErr != nil:
		return &InvalidationError{
			Backend: "redis",
			Deleted: deleted,
			Failed:  len(keys) - deleted,
			Err:     fmt.Errorf("del: %w", delErr),
		}
	case scanErr != nil:
		return &InvalidationError{
			Backend:        "redis",
			Deleted:        deleted,
			ScanIncomplete: true,
			Err:            fmt.Errorf("scan: %w", scanErr),
		}
	}
	return nil
}

// InvalidateOrgAll removes all cache entries for an organization from both
// backends. Both backends are always attempted; a partial failure returns a
// joined error naming every backend that did not finish.
func (i *Invalidator) InvalidateOrgAll(ctx context.Context, orgID string) error {
	var errs []error

	// Redis: SCAN + DEL by pattern (current route namespace only — RT-05;
	// legacy pre-namespace keys are never read and expire through their TTL).
	if i.rdb != nil {
		if err := i.redisSweep(ctx, "redis invalidate org", KeyPatternOrg(orgID), 500); err != nil {
			errs = append(errs, err)
		}
	}

	// pgvector: delete by org_id.
	if i.store != nil && i.store.pool != nil {
		if _, err := i.store.pool.Exec(ctx, "DELETE FROM cache_entries WHERE org_id = $1", orgID); err != nil {
			errs = append(errs, &InvalidationError{
				Backend: "pgvector",
				Err:     fmt.Errorf("pgvector invalidate org: %w", err),
			})
		}
	}

	return errors.Join(errs...)
}

// InvalidateModelVersion removes all cache entries for a specific model tier
// and version. Used when a model's upstream_url or API key changes.
func (i *Invalidator) InvalidateModelVersion(ctx context.Context, modelTier, modelVer string) error {
	var errs []error

	if i.store != nil && i.store.pool != nil {
		if _, err := i.store.pool.Exec(ctx,
			"DELETE FROM cache_entries WHERE model_tier = $1 AND model_version = $2",
			modelTier, modelVer); err != nil {
			errs = append(errs, &InvalidationError{
				Backend: "pgvector",
				Err:     fmt.Errorf("invalidate model version: %w", err),
			})
		}
	}

	// Also remove from Redis by pattern (current route namespace only —
	// RT-05; Redis keys do not carry the pg model_version, so the tier-wide
	// namespace sweep is the closest safe scope).
	if i.rdb != nil {
		if err := i.redisSweep(ctx, "redis invalidate model version", KeyPatternTier(modelTier), 1000); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// InvalidateByPromptHash removes a single cache entry by org, tier and prompt hash.
func (i *Invalidator) InvalidateByPromptHash(ctx context.Context, orgID, modelTier, promptHash string) error {
	if i.exact != nil {
		if err := i.exact.Delete(ctx, orgID, modelTier, promptHash); err != nil && !isRedisNil(err) {
			return fmt.Errorf("redis invalidate by hash: %w", err)
		}
	}

	if i.store != nil && i.store.pool != nil {
		_, err := i.store.pool.Exec(ctx,
			"DELETE FROM cache_entries WHERE org_id = $1 AND model_tier = $2 AND prompt_hash = $3",
			orgID, modelTier, promptHash)
		if err != nil {
			return fmt.Errorf("pgvector invalidate by hash: %w", err)
		}
	}

	return nil
}

// InvalidateModelByTier removes all cache entries for a specific model tier (all versions).
// This is used when a model's upstream_url or API key changes.
func (i *Invalidator) InvalidateModelByTier(ctx context.Context, modelTier string) error {
	var errs []error

	if i.store != nil && i.store.pool != nil {
		if _, err := i.store.pool.Exec(ctx, "DELETE FROM cache_entries WHERE model_tier = $1", modelTier); err != nil {
			errs = append(errs, &InvalidationError{
				Backend: "pgvector",
				Err:     fmt.Errorf("invalidate model by tier: %w", err),
			})
		}
	}

	// Redis: SCAN + DEL for this tier in the current route namespace (RT-05).
	if i.rdb != nil {
		if err := i.redisSweep(ctx, "redis invalidate model tier", KeyPatternTier(modelTier), 1000); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

func isRedisNil(err error) bool {
	return err == redis.Nil
}
