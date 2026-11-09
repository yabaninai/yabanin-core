package cli

// regression corpus for the pool selector's boundaries, complementary to
// credpool_test.go (behavior battery), credpool_boundary_test.go (baseline:
// all-quarantined fail-close, eligibility edge, single-member pool, log
// redaction) and credpool_failure_test.go (E2E failure legs). Pins: the
// round-robin cursor arithmetic over a SHRUNK eligible set, the immediate
// fail-closed resolve-error path, the resolved-empty-plaintext observation,
// and the outcome-classification extremes at the integer boundaries.

import (
	"context"
	"errors"
	"math"
	"net/http"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCredPoolRegression_AdvanceLockedShrunkEligibleRotation pins the
// round-robin selection site over a snapshot whose eligible set is smaller
// than the entry list: the cursor is taken modulo the ELIGIBLE length (not
// the raw entry count), the sequence continues over survivors without
// skipping or doubling, and large cursors wrap the same way. Also pins the
// all-quarantined horizon (the earliest LIVE deadline across mixed rows) at
// the function boundary.
func TestCredPoolRegression_AdvanceLockedShrunkEligibleRotation(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	entry := func(id string, until time.Time) adminstore.OrgCredentialPoolEntry {
		e := adminstore.OrgCredentialPoolEntry{}
		e.ID = id
		e.QuarantinedUntil = until
		return e
	}
	entries := []adminstore.OrgCredentialPoolEntry{
		entry("c1", time.Time{}),
		entry("c2", now.Add(2*time.Hour)), // live quarantine: excluded
		entry("c3", time.Time{}),
		entry("c4", now.Add(5*time.Hour)), // live quarantine: excluded
		entry("c5", time.Time{}),
	}

	pool := newTestCredPool(newStubCredPoolStore(), nil, now)
	st := &orgCredsPoolState{entries: entries, loadedAt: now}
	pool.mu.Lock()
	defer pool.mu.Unlock()

	// cursor 0,1,2,3 over eligible=[c1,c3,c5]: exact sequence, no drift.
	for i, want := range []string{"c1", "c3", "c5", "c1"} {
		got, ok, err := pool.advanceLocked(st, now)
		require.NoError(t, err)
		require.True(t, ok)
		assert.Equal(t, want, got.ID, "pick %d over the shrunk eligible set", i+1)
		assert.Equal(t, i+1, st.cursor, "the cursor advances by exactly one per pick")
	}

	// A large cursor wraps modulo the eligible length the same way.
	wrapped := &orgCredsPoolState{entries: entries, loadedAt: now, cursor: 7}
	got, ok, err := pool.advanceLocked(wrapped, now)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "c3", got.ID, "cursor 7 over 3 eligible lands on index 1")
	assert.Equal(t, 8, wrapped.cursor)

	// Every entry live-quarantined with mixed horizons: fail-closed with the
	// earliest LIVE deadline surfaced, nothing picked, cursor untouched.
	held := &orgCredsPoolState{entries: []adminstore.OrgCredentialPoolEntry{
		entry("c1", now.Add(2*time.Hour)),
		entry("c2", now.Add(5*time.Hour)),
	}, cursor: 4}
	_, ok, err = pool.advanceLocked(held, now)
	require.ErrorIs(t, err, errOrgCredsAllQuarantined)
	assert.False(t, ok)
	assert.Equal(t, 4, held.cursor, "an exhausted pick consumes no cursor")
	require.ErrorContains(t, err, "earliest return 2026-10-16T14:00:00Z")
	assert.True(t, earliestQuarantineReturn(nil).IsZero(), "no entries: no horizon")
	assert.True(t, earliestQuarantineReturn(entries[:1]).IsZero(),
		"an unquarantined entry contributes no horizon")
	assert.Equal(t, now.Add(2*time.Hour), earliestQuarantineReturn(entries),
		"the horizon is the earliest LIVE deadline across the held entries")
}

// TestCredPoolRegression_ResolveErrorFailsClosedImmediately pins the resolve
// failure boundary: an infrastructure error from ResolveKeyEntry fails the
// attempt immediately — no second pickAndResolve attempt, no stale-pin
// retry, no fall-through to a non-org key — and the error wraps the store
// cause.
func TestCredPoolRegression_ResolveErrorFailsClosedImmediately(t *testing.T) {
	k1 := "11111111-aaaa-4aaa-8aaa-000000000001"
	k2 := "11111111-aaaa-4aaa-8aaa-000000000002"
	boom := errors.New("key store unavailable")
	store := newStubCredPoolStore(
		stubPoolCred{id: k1, last4: "0001", key: "sk-pool-key-00000001", enabled: true, version: 1},
		stubPoolCred{id: k2, last4: "0002", key: "sk-pool-key-00000002", enabled: true, version: 1},
	)
	store.resolveErr = boom
	pool := newTestCredPool(store, nil, time.Now())
	ctx := context.Background()

	_, _, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.ErrorIs(t, err, boom, "the store cause must surface through the wrap")
	require.ErrorContains(t, err, "resolve pinned org credential")
	assert.False(t, ok, "a resolve failure must never fall through to a non-org key")
	assert.Equal(t, 1, store.resolves(), "the resolve error must end the attempt loop immediately")

	// The next request still fails closed (snapshot alive, cursor moved on).
	_, _, ok, err = pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.ErrorIs(t, err, boom)
	assert.False(t, ok)
	assert.Equal(t, 2, store.resolves())
	assert.NotContains(t, err.Error(), "sk-pool-key", "no key material through the failure")

	// Recovery: clearing the injection restores serving.
	store.resolveErr = nil
	use, plain, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Contains(t, []string{k1, k2}, use.credID)
	recovered := map[string]string{k1: "sk-pool-key-00000001", k2: "sk-pool-key-00000002"}
	assert.Equal(t, recovered[use.credID], plain,
		"the recovered resolve serves the pinned credential's own plaintext")
}

// TestCredPoolRegression_EmptyPlaintextPinnedStarvesEndpoint pins OBSERVED
// BEHAVIOR (documented in the T07 record; no production change on this
// card): a pinned credential whose resolve returns ("", true, nil) — the
// stale-key signal — exhausts BOTH pickAndResolve attempts on itself,
// because the snapshot refresh resets the round-robin cursor to the store
// order head. Healthy siblings are never reached within the request, the
// outcome is indistinguishable from a routing miss (ok=false, nil error),
// and every later request repeats the same shape until the row is fixed
// store-side. The pool never self-quarantines on a resolve result: the
// empty key is the caller's signal, not the selector's.
func TestCredPoolRegression_EmptyPlaintextPinnedStarvesEndpoint(t *testing.T) {
	k1 := "11111111-aaaa-4aaa-8aaa-000000000001"
	k2 := "11111111-aaaa-4aaa-8aaa-000000000002"
	store := newStubCredPoolStore(
		stubPoolCred{id: k1, last4: "0001", key: "sk-pool-key-00000001", enabled: true, version: 1},
		stubPoolCred{id: k2, last4: "0002", key: "sk-pool-key-00000002", enabled: true, version: 1},
	)
	pool := newTestCredPool(store, nil, time.Now())
	ctx := context.Background()

	store.resolveEmpty[k1] = true
	for i := 0; i < 2; i++ {
		use, plain, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
		require.NoError(t, err, "the empty-key signal is not an infrastructure error")
		assert.False(t, ok, "request %d must not serve anything while the head resolves empty", i+1)
		assert.Empty(t, use)
		assert.Empty(t, plain)
		assert.Equal(t, 2*(i+1), store.resolves(),
			"both attempts resolve (the same head credential twice — the sibling is never reached)")
	}
	// The healthy sibling stayed healthy the whole time: clearing the bad
	// row immediately restores it (the store-order head now resolves).
	store.resolveEmpty = nil
	use, plain, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok, "the endpoint recovers as soon as the head row resolves")
	assert.Equal(t, k1, use.credID)
	assert.Equal(t, "sk-pool-key-00000001", plain)
}

// TestCredPoolRegression_RecordOutcomeStatusExtremes pins the outcome
// classification at the integer boundaries through the gateway path: only
// exactly 401 and 429 reach the store — every neighbor, out-of-range and
// negative/overflow status is a silent no-op (no quarantine write, no org
// version bump) — and feedback for an attempt that did not use an org
// credential, or through a nil pool, is a no-op too.
func TestCredPoolRegression_RecordOutcomeStatusExtremes(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	k1 := "11111111-aaaa-4aaa-8aaa-000000000001"
	k2 := "11111111-aaaa-4aaa-8aaa-000000000002"
	store := newStubCredPoolStore(
		stubPoolCred{id: k1, last4: "0001", key: "sk-pool-key-00000001", enabled: true, version: 1},
		stubPoolCred{id: k2, last4: "0002", key: "sk-pool-key-00000002", enabled: true, version: 1},
	)
	store.nowFn = func() time.Time { return now }
	versions := &stubOrgVersions{versions: map[string]int64{}}
	pool := newTestCredPool(store, versions, now)
	ctx := context.Background()

	use1, _, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, k1, use1.credID)

	for _, status := range []int{
		math.MinInt32, -1, 0, 1, 99, 100, 101, 199, 200, 201, 204,
		300, 301, 399, 400, 402, 403, 404, 405, 408, 418, 425, 499,
		500, 502, 503, 504, 511, 599, 600, 1000, math.MaxInt32,
	} {
		pool.recordOutcome(ctx, "org-a", "openai-compat", use1, status)
		assert.Empty(t, store.quarantineLog(), "status %d must not write a quarantine row", status)
		assert.Equal(t, int64(0), versions.versions["org-a"], "status %d must not bump the org version", status)
	}

	// Feedback for an attempt that used a per-model/global key: no-op.
	pool.recordOutcome(ctx, "org-a", "openai-compat", orgCredentialUse{}, http.StatusUnauthorized)
	assert.Empty(t, store.quarantineLog())

	// Nil pool: a wiring no-op, not a panic.
	var nilPool *orgCredsPool
	require.NotPanics(t, func() { nilPool.recordOutcome(ctx, "org-a", "openai-compat", use1, http.StatusUnauthorized) })

	// Positive control: the two exact statuses quarantine.
	pool.recordOutcome(ctx, "org-a", "openai-compat", use1, http.StatusUnauthorized)
	require.Len(t, store.quarantineLog(), 1)
	assert.Equal(t, k1, store.quarantineLog()[0].credID)
	assert.Positive(t, versions.versions["org-a"])
	use2, _, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, k2, use2.credID, "the quarantined credential must not serve new attempts")
}
