package cache

// N03-P05-T03: TTL eviction and distributed invalidation under concurrency.
//
// Pins the concurrency contracts the card asks to verify:
//   - expired pg entries are never served by either lookup path, even in the
//     lazy-expiry window before the cleaner purges them;
//   - a cancelled cleanup leaves no advisory lock behind (the card's negative
//     acceptance: cancelling one client must not leave the lock held);
//   - invalidate × write × lookup racing on pgvector has a defined winner:
//     no pre-invalidate write survives a completed InvalidateOrgAll, and
//     every entry served during the storm is unexpired;
//   - invalidation is distributed: an org flush done through one Redis client
//     (gateway instance) is observed by a second client on the same Redis;
//   - the policy-cache eviction × invalidation × in-flight-load corner: an
//     eviction that removes the generation guard while a post-invalidation
//     flight is pending must not publish that flight's result — the caller
//     converges to a fresh reload instead (pins the publishLocked safety
//     argument for the reachable state where the guard is evictable).

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	pgxpool "github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStore_ExpiredEntryNeverServed pins the lazy-expiry window: an entry
// past expires_at physically remains in cache_entries until the cleaner
// purges it, but neither pg lookup path may serve it.
func TestStore_ExpiredEntryNeverServed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testcontainers (Postgres) test in -short mode")
	}
	ctx := context.Background()
	pool := testdb.Postgres(t)
	store := NewStore(pool)

	org := "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a31"
	now := time.Now()
	sharedVec := makeTestEmbedding(384, 0.1)

	live := &Entry{
		OrgID: org, ModelTier: "smart", PromptHash: "hash-live",
		Embedding: sharedVec,
		Response:  json.RawMessage(`{"id":"live"}`),
		ModelVer:  "v1",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	expired := &Entry{
		OrgID: org, ModelTier: "smart", PromptHash: "hash-expired",
		// Same vector as the live entry: the semantic ranking would pick it
		// if the expiry filter were missing.
		Embedding: sharedVec,
		Response:  json.RawMessage(`{"id":"expired"}`),
		ModelVer:  "v1",
		CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour),
	}
	_, err := store.Put(ctx, live)
	require.NoError(t, err)
	_, err = store.Put(ctx, expired)
	require.NoError(t, err)

	// Premise: both rows are physically present — the miss below is caused
	// by the expiry filter, not by absence.
	var rows int
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT count(*) FROM cache_entries WHERE org_id = $1", org).Scan(&rows))
	require.Equal(t, 2, rows, "both entries must exist before the cleaner purges (lazy expiry window)")

	e, err := store.GetExact(ctx, org, "smart", "hash-expired", "v1")
	require.NoError(t, err)
	assert.Nil(t, e, "an expired entry must be an exact-lookup miss even before the cleaner runs")

	e, err = store.GetExact(ctx, org, "smart", "hash-live", "v1")
	require.NoError(t, err)
	require.NotNil(t, e, "the live entry must still be served")
	assert.Equal(t, "hash-live", e.PromptHash)

	e, err = store.GetSemantic(ctx, org, "smart", sharedVec, 0.5)
	require.NoError(t, err)
	if e != nil {
		assert.Equal(t, "hash-live", e.PromptHash,
			"semantic lookup served an entry past its expires_at")
	}
}

// requireNoPurgeAdvisoryLock asserts pg_locks holds no xact advisory lock on
// the shared purge lock id.
func requireNoPurgeAdvisoryLock(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	var held int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND objid = $1`,
		cachePurgeLockID).Scan(&held))
	assert.Equal(t, 0, held, "advisory purge lock leaked")
}

// TestStore_PurgeExpiredWithLock_CancelLeavesNoLock is the card's negative
// acceptance: a cancelled cleanup fails, and the xact advisory lock must be
// released with the rolled-back transaction — a fresh cleanup immediately
// acquires it.
func TestStore_PurgeExpiredWithLock_CancelLeavesNoLock(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testcontainers (Postgres) test in -short mode")
	}
	ctx := context.Background()
	pool := testdb.Postgres(t)
	store := NewStore(pool)

	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	_, gotLock, err := store.PurgeExpiredWithLock(cancelCtx)
	require.Error(t, err, "a cancelled cleanup must fail, not succeed silently")
	require.ErrorIs(t, err, context.Canceled, "failure must classify as cancellation")
	assert.False(t, gotLock)

	requireNoPurgeAdvisoryLock(t, ctx, pool)

	_, gotLock, err = store.PurgeExpiredWithLock(ctx)
	require.NoError(t, err)
	assert.True(t, gotLock, "a cancelled cleanup must not leave the advisory lock held")
}

// TestStore_PurgeExpiredWithLock_BusySkipThenAcquire pins the multi-replica
// contract: while another session holds the advisory lock the cleanup skips
// (gotLock=false, no error, no delete); once the holder releases, the next
// cleanup acquires.
func TestStore_PurgeExpiredWithLock_BusySkipThenAcquire(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testcontainers (Postgres) test in -short mode")
	}
	ctx := context.Background()
	pool := testdb.Postgres(t)
	store := NewStore(pool)

	conn, err := pool.Acquire(ctx)
	require.NoError(t, err)
	defer conn.Release()

	tx, err := conn.Begin(ctx)
	require.NoError(t, err)
	var held bool
	require.NoError(t, tx.QueryRow(ctx,
		"SELECT pg_try_advisory_xact_lock($1)", cachePurgeLockID).Scan(&held))
	require.True(t, held, "sanity: the holder session must own the lock")

	deleted, gotLock, err := store.PurgeExpiredWithLock(ctx)
	require.NoError(t, err)
	assert.False(t, gotLock, "a busy lock must be skipped, not waited on")
	assert.Equal(t, 0, deleted)

	require.NoError(t, tx.Rollback(ctx))

	_, gotLock, err = store.PurgeExpiredWithLock(ctx)
	require.NoError(t, err)
	assert.True(t, gotLock, "after the holder releases, the next cleanup must acquire")
}

// TestInvalidateOrgAll_ConcurrentWritesAndLookups races pg writers, readers
// and InvalidateOrgAll. Defined winner: a completed InvalidateOrgAll leaves
// zero rows for the org (no pre-invalidate write survives it), no lookup ever
// serves an expired entry, and nothing deadlocks or races.
func TestInvalidateOrgAll_ConcurrentWritesAndLookups(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testcontainers (Postgres) test in -short mode")
	}
	ctx := context.Background()
	pool := testdb.Postgres(t)
	store := NewStore(pool)
	inv := NewInvalidator(nil, store, nil) // pg-only: the Redis side is covered by its own tests

	org := "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a41"
	const writers = 4
	const perWriter = 25

	var writeWG sync.WaitGroup
	for w := 0; w < writers; w++ {
		writeWG.Add(1)
		go func(w int) {
			defer writeWG.Done()
			for i := 0; i < perWriter; i++ {
				_, err := store.Put(ctx, &Entry{
					OrgID: org, ModelTier: "smart",
					PromptHash: fmt.Sprintf("hash-%d-%d", w, i),
					Embedding:  makeTestEmbedding(384, 0.1),
					Response:   json.RawMessage(fmt.Sprintf(`{"id":"w%d-i%d"}`, w, i)),
					ModelVer:   "v1",
					CreatedAt:  time.Now(), ExpiresAt: time.Now().Add(time.Hour),
				})
				if err != nil {
					t.Errorf("write failed: %v", err)
					return
				}
			}
		}(w)
	}

	writersDone := make(chan struct{})
	go func() { writeWG.Wait(); close(writersDone) }()

	stopReads := make(chan struct{})
	var readWG sync.WaitGroup
	for r := 0; r < 2; r++ {
		readWG.Add(1)
		go func() {
			defer readWG.Done()
			for {
				select {
				case <-stopReads:
					return
				default:
				}
				e, err := store.GetExact(ctx, org, "smart", "hash-0-0", "v1")
				if err != nil {
					t.Errorf("lookup failed: %v", err)
					return
				}
				if e != nil && !e.ExpiresAt.After(time.Now()) {
					t.Errorf("lookup served an expired entry: %+v", e)
					return
				}
			}
		}()
	}

	// Invalidate in a loop while writes run, then one final invalidate after
	// writers stop: that final one must leave zero rows — every write that
	// finished before it is covered by it, and the readers never write.
	for {
		select {
		case <-writersDone:
			require.NoError(t, inv.InvalidateOrgAll(ctx, org),
				"final invalidate over a quiesced writer set must complete fully")
			close(stopReads)
			readWG.Wait()

			var n int
			require.NoError(t, pool.QueryRow(ctx,
				"SELECT count(*) FROM cache_entries WHERE org_id = $1", org).Scan(&n))
			assert.Equal(t, 0, n,
				"a completed InvalidateOrgAll must leave no rows for the org")
			return
		default:
			if err := inv.InvalidateOrgAll(ctx, org); err != nil {
				t.Errorf("concurrent invalidate failed: %v", err)
				return
			}
		}
	}
}

// TestRedisInvalidation_IsDistributedAcrossClients pins the distributed
// invalidation semantics of the Redis backend: a second gateway instance (its
// own client on the same Redis) sees an org flush issued through the first
// instance's client.
func TestRedisInvalidation_IsDistributedAcrossClients(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testcontainers (Redis) test in -short mode")
	}
	rdbA := redisContainer(t)
	rdbB := redis.NewClient(&redis.Options{Addr: rdbA.Options().Addr})
	t.Cleanup(func() { _ = rdbB.Close() })

	storeA := NewRedisStore(rdbA, time.Hour)
	storeB := NewRedisStore(rdbB, time.Hour)
	invB := NewInvalidator(storeB, nil, rdbB) // instance B's invalidator

	ctx := context.Background()
	require.NoError(t, storeA.Put(ctx, "org-dist", "smart", "hash-d", []byte(`{"id":"d"}`)))

	require.NoError(t, invB.InvalidateOrgAll(ctx, "org-dist"))

	_, err := storeA.Get(ctx, "org-dist", "smart", "hash-d")
	assert.ErrorIs(t, err, redis.Nil,
		"invalidation done by another instance must be visible to this instance")
}

// TestPolicyCache_EvictGuardWhileFlightPending pins the publishLocked safety
// argument for the one reachable state where a generation guard is evictable
// while a flight is in flight: the org was published under generation G, its
// entry expired, a reload flight (gen G) is pending, and churn evicts the org
// — deleting the guard. That flight must NOT publish (a missing guard reads
// as 0 ≠ G); its caller converges to a fresh reload instead of receiving the
// mid-flight result as if it were current.
func TestPolicyCache_EvictGuardWhileFlightPending(t *testing.T) {
	pc := NewPolicyCache(time.Minute)
	pc.maxEntries = 1
	pc.ttl = time.Millisecond // entries expire immediately: every Get after a publish reloads

	type result struct {
		p *OrgPolicy
	}
	release := make(chan struct{})
	var mu sync.Mutex
	calls := 0
	// Distinct (Mode, Semantic) pairs per call so the served value identifies
	// exactly which loader invocation produced it.
	loader := func(context.Context, string) (*OrgPolicy, error) {
		mu.Lock()
		n := calls
		calls++
		mu.Unlock()
		switch n {
		case 0: // seed publish: org-x in LRU at gen 0
			return &OrgPolicy{Mode: PrivacyEnabled, Semantic: false}, nil
		case 1: // reload after Invalidate: publishes at gen 1, then expires
			return &OrgPolicy{Mode: PrivacyEnabled, Semantic: true}, nil
		case 2: // the guarded flight: held open across the eviction
			<-release
			return &OrgPolicy{Mode: PrivacyReadCacheOnly, Semantic: false}, nil
		default: // the post-eviction reload (gen 0)
			return &OrgPolicy{Mode: PrivacyReadCacheOnly, Semantic: true}, nil
		}
	}

	// Seed: publish org-x (gen 0).
	require.NotNil(t, pc.Get(context.Background(), "org-x", loader))
	// Invalidate, then reload: the gen-1 entry is published and expires at
	// once (ttl 1ms) while staying in the LRU.
	pc.Invalidate("org-x")
	require.NotNil(t, pc.Get(context.Background(), "org-x", loader))
	time.Sleep(5 * time.Millisecond) // the 1ms entry is now expired

	// The guarded flight: registered while org-x's (expired) entry and its
	// gen-1 guard are both evictable.
	res := make(chan result, 1)
	go func() {
		pol := pc.Get(context.Background(), "org-x", loader)
		res <- result{p: pol}
	}()
	waitForFlight(t, pc, "org-x")

	// The 1ms ttl has served its purpose (the gen-1 entry expired before
	// the guarded flight registered). Freeze expiry for the convergence
	// phase: the entry published by the post-eviction reload must stay
	// fresh, so scheduler jitter between a publish and the waiting
	// reader's re-check cannot masquerade as expiry and force spurious
	// extra reloads (CI flake, seen once on a loaded self-hosted runner).
	pc.ttl = time.Minute

	// Churn evicts org-x: the LRU cap is 1, so publishing org-y removes
	// org-x's entry AND its generation guard while the flight is pending.
	require.NotNil(t, pc.Get(context.Background(), "org-y", func(context.Context, string) (*OrgPolicy, error) {
		return &OrgPolicy{Mode: PrivacyReadCacheOnly}, nil
	}))

	close(release) // the guarded load completes after its guard was evicted

	var got result
	select {
	case got = <-res:
	case <-time.After(2 * time.Second):
		t.Fatal("Get did not converge after the guard eviction raced the flight")
	}

	mu.Lock()
	total := calls
	mu.Unlock()

	// The flight's own result (call 2: ReadCacheOnly+false) must not be
	// served as if fresh: the missing guard suppresses its publish, so the
	// caller reloads (call 3) and receives that fresh value.
	require.NotNil(t, got.p)
	assert.True(t, got.p.Semantic,
		"the mid-flight result published after its generation guard was evicted (got the call-%d value)",
		total-1)
	assert.Equal(t, PrivacyReadCacheOnly, got.p.Mode)
	assert.Equal(t, 4, total,
		"want exactly 4 org-x loader calls: seed, gen-1 reload, guarded flight, post-eviction reload")

	// The converged state is cached: further lookups make no loader calls.
	final := pc.Get(context.Background(), "org-x", loader)
	require.NotNil(t, final)
	assert.True(t, final.Semantic, "post-eviction fresh policy stays cached")
	assert.Equal(t, PrivacyReadCacheOnly, final.Mode)
	mu.Lock()
	after := calls
	mu.Unlock()
	assert.Equal(t, total, after, "converged entry must serve from cache without reloading")
}
