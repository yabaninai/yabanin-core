package cache

// FIX-04 (CA-06): failure-path tests for the Redis invalidator.
//
// The pre-fix invalidator swallowed SCAN errors (all three sweep methods
// returned nil when the scan died) and DEL errors (tier/version sweeps
// discarded them), so a failing Redis produced a silent partial
// invalidation that callers reported as success. These tests pin the
// honest contract:
//
//   - every failure (canceled context, dial failure, mid-page SCAN death,
//     DEL failure) surfaces as a non-nil error;
//   - partial failures name the partial state (deleted N, failed M,
//     scan-incomplete);
//   - canceled-context and transport failures are distinguishable classes
//     (IsCancellation / IsRetryable);
//   - a sweep concurrent with writes never panics (inherent SCAN-race
//     semantics are documented, not panicked on).

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	pgxpool "github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// injectHook is a go-redis Hook that fails selected commands deterministically.
// It fails a command name at most `remaining[name]` times, and optionally every
// SCAN whose cursor is non-zero (i.e. after the first page) — reproducing a
// Redis dying mid-iteration.
type injectHook struct {
	mu                 sync.Mutex
	failRemaining      map[string]int
	failScanNonZeroCur bool
	failScanFromCall   int // fail every scan from the Nth call (1-based); 0 = disabled
	scanCalls          int
	injected           error
}

func newInjectHook(injected error) *injectHook {
	return &injectHook{failRemaining: map[string]int{}, injected: injected}
}

func (h *injectHook) check(cmd redis.Cmder) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	name := cmd.Name()
	if n, ok := h.failRemaining[name]; ok && n > 0 {
		h.failRemaining[name] = n - 1
		return h.injected
	}
	if name == "scan" {
		h.scanCalls++
		if h.failScanNonZeroCur && len(cmd.Args()) > 1 {
			if cursor, ok := cmd.Args()[1].(uint64); ok && cursor != 0 {
				return h.injected
			}
		}
		if h.failScanFromCall > 0 && h.scanCalls >= h.failScanFromCall {
			return h.injected
		}
	}
	return nil
}

func (h *injectHook) DialHook(next redis.DialHook) redis.DialHook { return next }

func (h *injectHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if err := h.check(cmd); err != nil {
			return err
		}
		return next(ctx, cmd)
	}
}

func (h *injectHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		for _, cmd := range cmds {
			if err := h.check(cmd); err != nil {
				return err
			}
		}
		return next(ctx, cmds)
	}
}

// seedKeys writes n org-scoped cache keys and returns them.
func seedKeys(t *testing.T, rdb *redis.Client, orgID, tier string, n int) []string {
	t.Helper()
	ctx := context.Background()
	keys := make([]string, 0, n)
	// Pipeline the writes: seeding thousands of keys one SET at a time is
	// needlessly slow.
	pipe := rdb.Pipeline()
	for i := 0; i < n; i++ {
		key := MakeKey(orgID, tier, fmt.Sprintf("%064x", i))
		pipe.Set(ctx, key, "v", time.Minute)
		keys = append(keys, key)
	}
	_, err := pipe.Exec(ctx)
	require.NoError(t, err)
	return keys
}

func countExisting(t *testing.T, rdb *redis.Client, keys []string) int64 {
	t.Helper()
	n, err := rdb.Exists(context.Background(), keys...).Result()
	require.NoError(t, err)
	return n
}

func deadRedisClient() *redis.Client {
	// Nothing listens on TCP port 1; with MaxRetries=0 and a short dial
	// timeout every command fails fast with a transport (dial) error.
	return redis.NewClient(&redis.Options{
		Addr:         "127.0.0.1:1",
		DialTimeout:  300 * time.Millisecond,
		ReadTimeout:  300 * time.Millisecond,
		WriteTimeout: 300 * time.Millisecond,
		MaxRetries:   0,
	})
}

// --- Normal path: real keys are actually cleared ---------------------------

func TestInvalidateOrgAll_ClearsRealKeys(t *testing.T) {
	rdb := redisContainer(t)
	org := "org-fix04-ok"
	keys := seedKeys(t, rdb, org, "smart", 3)
	inv := NewInvalidator(NewRedisStore(rdb, 0), nil, rdb)

	require.NoError(t, inv.InvalidateOrgAll(context.Background(), org))
	assert.Zero(t, countExisting(t, rdb, keys), "org keys must be gone after a successful flush")
}

func TestInvalidateModelVersion_ClearsRealKeys(t *testing.T) {
	rdb := redisContainer(t)
	keys := seedKeys(t, rdb, "org-fix04-ver", "smart", 3)
	inv := NewInvalidator(NewRedisStore(rdb, 0), nil, rdb)

	require.NoError(t, inv.InvalidateModelVersion(context.Background(), "smart", RouteVersion))
	assert.Zero(t, countExisting(t, rdb, keys), "tier keys must be gone after version invalidation")
}

func TestInvalidateModelByTier_ClearsRealKeys(t *testing.T) {
	rdb := redisContainer(t)
	keys := seedKeys(t, rdb, "org-fix04-tier", "smart", 3)
	inv := NewInvalidator(NewRedisStore(rdb, 0), nil, rdb)

	require.NoError(t, inv.InvalidateModelByTier(context.Background(), "smart"))
	assert.Zero(t, countExisting(t, rdb, keys), "tier keys must be gone after tier invalidation")
}

// --- Failure paths ----------------------------------------------------------

func TestInvalidateOrgAll_CanceledContextReturnsError(t *testing.T) {
	rdb := redisContainer(t)
	inv := NewInvalidator(NewRedisStore(rdb, 0), nil, rdb)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // caller aborted before the sweep started

	err := inv.InvalidateOrgAll(ctx, "org-fix04-cancel")
	require.Error(t, err, "a canceled context must never be reported as a successful invalidation")
	assert.True(t, IsCancellation(err), "canceled-context failure must classify as cancellation, got: %v", err)
	assert.False(t, IsRetryable(ctx, err), "cancellation must never classify as retryable")
	assert.ErrorIs(t, err, context.Canceled)
}

func TestInvalidateModelVersion_CanceledContextReturnsError(t *testing.T) {
	rdb := redisContainer(t)
	inv := NewInvalidator(NewRedisStore(rdb, 0), nil, rdb)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := inv.InvalidateModelVersion(ctx, "smart", RouteVersion)
	require.Error(t, err)
	assert.True(t, IsCancellation(err), "got: %v", err)
}

func TestInvalidateModelByTier_CanceledContextReturnsError(t *testing.T) {
	rdb := redisContainer(t)
	inv := NewInvalidator(NewRedisStore(rdb, 0), nil, rdb)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := inv.InvalidateModelByTier(ctx, "smart")
	require.Error(t, err)
	assert.True(t, IsCancellation(err), "got: %v", err)
}

func TestInvalidateOrgAll_RedisDownIsRetryableNotCanceled(t *testing.T) {
	rdb := deadRedisClient()
	t.Cleanup(func() { _ = rdb.Close() })
	inv := NewInvalidator(NewRedisStore(rdb, 0), nil, rdb)

	err := inv.InvalidateOrgAll(context.Background(), "org-fix04-down")
	require.Error(t, err, "dial failure must surface, not be swallowed")
	assert.False(t, IsCancellation(err), "dial failure is not a caller cancellation")
	assert.True(t, IsRetryable(context.Background(), err), "transport failure is retryable")
}

// TestInvalidateOrgAll_ScanDiesMidPage reproduces the audit's V2 scenario:
// Redis dies after the first SCAN page. The sweep must (a) return an error
// naming the incomplete scan and the partial state, and (b) still delete the
// keys it did manage to enumerate.
func TestInvalidateOrgAll_ScanDiesMidPage(t *testing.T) {
	rdb := redisContainer(t)
	org := "org-fix04-midpage"
	// InvalidateOrgAll scans with page size 500: 1200 keys force >= 3 SCAN
	// round-trips, so failing scans on a non-zero cursor kills the sweep
	// after the first page.
	keys := seedKeys(t, rdb, org, "smart", 1200)

	hook := newInjectHook(errors.New("injected: redis died mid-scan"))
	hook.failScanNonZeroCur = true
	rdb.AddHook(hook)

	inv := NewInvalidator(NewRedisStore(rdb, 0), nil, rdb)
	err := inv.InvalidateOrgAll(context.Background(), org)
	require.Error(t, err, "a scan that died mid-page must never return nil")
	require.ErrorIs(t, err, ErrInvalidationIncomplete, "got: %v", err)
	assert.Contains(t, err.Error(), "scan ended early", "error must name the scan-incomplete state: %v", err)

	var invErr *InvalidationError
	require.ErrorAs(t, err, &invErr, "failure must be an *InvalidationError")
	assert.True(t, invErr.ScanIncomplete)
	assert.Positive(t, invErr.Deleted, "keys enumerated before the death must have been deleted")
	// SCAN yields keys in keyspace order, not seed order: assert by totals.
	// Exactly the enumerated keys are gone; keys never enumerated remain —
	// that is the honest partial state the error reports.
	assert.Equal(t, int64(len(keys)-invErr.Deleted), countExisting(t, rdb, keys),
		"deleted count must account exactly for the surviving keys")
}

// TestInvalidateModelByTier_DelFailureReturnsError covers the discarded DEL
// error in the tier sweep (V1).
func TestInvalidateModelByTier_DelFailureReturnsError(t *testing.T) {
	rdb := redisContainer(t)
	keys := seedKeys(t, rdb, "org-fix04-deltier", "smart", 5)

	hook := newInjectHook(errors.New("injected: DEL rejected"))
	hook.failRemaining["del"] = 1
	rdb.AddHook(hook)

	inv := NewInvalidator(NewRedisStore(rdb, 0), nil, rdb)
	err := inv.InvalidateModelByTier(context.Background(), "smart")
	require.Error(t, err, "a failed DEL must never return nil")
	require.ErrorIs(t, err, ErrInvalidationIncomplete, "got: %v", err)

	var invErr *InvalidationError
	require.ErrorAs(t, err, &invErr)
	assert.Equal(t, 0, invErr.Deleted)
	assert.Equal(t, len(keys), invErr.Failed, "all attempted keys must be accounted as failed")
	assert.Equal(t, len(keys), countExistingInt(t, rdb, keys), "failed keys must still exist")
}

// TestInvalidateModelVersion_DelFailureReturnsError covers the discarded DEL
// error in the version sweep (V1).
func TestInvalidateModelVersion_DelFailureReturnsError(t *testing.T) {
	rdb := redisContainer(t)
	keys := seedKeys(t, rdb, "org-fix04-delver", "smart", 5)

	hook := newInjectHook(errors.New("injected: DEL rejected"))
	hook.failRemaining["del"] = 1
	rdb.AddHook(hook)

	inv := NewInvalidator(NewRedisStore(rdb, 0), nil, rdb)
	err := inv.InvalidateModelVersion(context.Background(), "smart", RouteVersion)
	require.Error(t, err, "a failed DEL must never return nil")
	require.ErrorIs(t, err, ErrInvalidationIncomplete, "got: %v", err)
	assert.Equal(t, len(keys), countExistingInt(t, rdb, keys), "failed keys must still exist")
}

func TestInvalidateOrgAll_DelFailureReturnsError(t *testing.T) {
	rdb := redisContainer(t)
	keys := seedKeys(t, rdb, "org-fix04-delorg", "smart", 5)

	hook := newInjectHook(errors.New("injected: DEL rejected"))
	hook.failRemaining["del"] = 1
	rdb.AddHook(hook)

	inv := NewInvalidator(NewRedisStore(rdb, 0), nil, rdb)
	err := inv.InvalidateOrgAll(context.Background(), "org-fix04-delorg")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidationIncomplete, "got: %v", err)
	assert.Equal(t, len(keys), countExistingInt(t, rdb, keys))
}

// TestInvalidateOrgAll_PartialAcrossBackends covers the acceptance case
// "Redis+Postgres partial failure": Redis cleanup succeeds, pgvector fails.
// The error must name the pg failure; the Redis keys must still be gone.
func TestInvalidateOrgAll_PartialAcrossBackends(t *testing.T) {
	rdb := redisContainer(t)
	org := "org-fix04-pgfail"
	keys := seedKeys(t, rdb, org, "smart", 3)

	// A pool pointed at a closed port: every Exec fails with a dial error
	// (pgxpool connects lazily, so construction alone is cheap).
	pool, err := pgxpool.New(context.Background(), "postgres://cache:cache@127.0.0.1:1/cache")
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	inv := NewInvalidator(NewRedisStore(rdb, 0), NewStore(pool), rdb)
	err = inv.InvalidateOrgAll(context.Background(), org)
	require.Error(t, err, "pgvector failure must surface even when Redis succeeded")
	assert.Contains(t, err.Error(), "pgvector", "error must name the failing backend: %v", err)
	assert.Zero(t, countExisting(t, rdb, keys), "redis keys must still be deleted when only pg failed")
}

// TestInvalidationErrorTaxonomy pins the error classes the callers rely on:
// Redis-down vs context-canceled must be distinguishable.
func TestInvalidationErrorTaxonomy(t *testing.T) {
	live := context.Background()
	assert.False(t, IsCancellation(nil))
	assert.False(t, IsRetryable(live, nil))

	assert.True(t, IsCancellation(fmt.Errorf("wrap: %w", context.Canceled)))
	assert.True(t, IsCancellation(fmt.Errorf("wrap: %w", context.DeadlineExceeded)))
	assert.False(t, IsRetryable(live, context.Canceled))

	dialErr := fmt.Errorf("redis invalidate org: %w", errors.New("dial tcp 127.0.0.1:1: connect: connection refused"))
	assert.False(t, IsCancellation(dialErr), "dial errors are not cancellations")
	assert.True(t, IsRetryable(live, dialErr), "dial errors are retryable")

	// Context-aware boundary (N03-P05-T07): a spent caller context turns
	// cancellation-shaped failures non-retryable, while a live caller with
	// a DeadlineExceeded wrap (store-side timeout, T06 classification) is
	// retryable. The pure Canceled wrap stays non-retryable either way.
	spent, spentCancel := context.WithCancel(context.Background())
	spentCancel()
	assert.False(t, IsRetryable(spent, fmt.Errorf("wrap: %w", context.Canceled)))
	assert.False(t, IsRetryable(spent, fmt.Errorf("wrap: %w", context.DeadlineExceeded)))
	assert.True(t, IsRetryable(live, fmt.Errorf("wrap: %w", context.DeadlineExceeded)),
		"store-side timeout with a live caller is retryable")
}

// TestInvalidateOrgAll_ConcurrentWritesNoPanic: a sweep racing with writers
// must never panic (inherent SCAN-race: keys written mid-scan may survive
// that pass — documented, not a crash).
func TestInvalidateOrgAll_ConcurrentWritesNoPanic(t *testing.T) {
	rdb := redisContainer(t)
	inv := NewInvalidator(NewRedisStore(rdb, 0), nil, rdb)
	ctx := context.Background()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			key := MakeKey("org-fix04-race", "smart", fmt.Sprintf("%064x", i))
			_ = rdb.Set(ctx, key, "v", time.Minute).Err()
			i++
		}
	}()

	var err error
	for round := 0; round < 5; round++ {
		err = inv.InvalidateOrgAll(ctx, "org-fix04-race")
		// Any outcome is fine (success or honest partial); what must hold
		// is: never a panic, and never a silent lie under a broken client.
		if err != nil {
			assert.True(t, errors.Is(err, ErrInvalidationIncomplete) || IsCancellation(err) || IsRetryable(ctx, err),
				"unexpected error shape: %v", err)
		}
	}
	close(stop)
	wg.Wait() // reaching here without panic/race is the assertion
}

// countExistingInt is countExisting for int-typed assertions.
func countExistingInt(t *testing.T, rdb *redis.Client, keys []string) int {
	t.Helper()
	return int(countExisting(t, rdb, keys))
}
