package cli

// N08-P05-T08 recovery corpus for the gateway credential pool selector:
// the fail-closed EXIT paths at the serving boundary. T00–T07 pinned the
// quarantine entry, the all-quarantined refusal and the single-member
// midnight edge; this file pins the recovery journey — a fully
// quarantined endpoint leaves fail-closed one credential at a time as
// deadlines lapse, on the HELD snapshot (no store round trip), with the
// exact round-robin continuation; and an in-flight use whose feedback
// arrives after its quarantine already lapsed re-quarantines on the
// report-time horizon (the new UTC day), with the operator reset as the
// immediate exit. Deterministic: one shared mutable clock for the pool
// and the store eligibility check, no real time, no goroutines.

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCredPoolRecovery_CooldownLapseExit_StagedFromFailClosed: three
// credentials hold live quarantine rows with staggered horizons (mirroring
// rows written by feedback on different days). The pool refuses
// fail-closed from the single held snapshot; as the clock crosses each
// deadline the credentials return one at a time — the lapse exit runs on
// the version fast path, so the whole journey costs exactly ONE store
// list — and the round-robin over the eligible subset continues exactly.
func TestCredPoolRecovery_CooldownLapseExit_StagedFromFailClosed(t *testing.T) {
	base := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	k1 := "11111111-aaaa-4aaa-8aaa-000000000001"
	k2 := "11111111-aaaa-4aaa-8aaa-000000000002"
	k3 := "11111111-aaaa-4aaa-8aaa-000000000003"
	store := newStubCredPoolStore(
		stubPoolCred{id: k1, last4: "0001", key: "sk-pool-key-00000001", enabled: true, version: 1},
		stubPoolCred{id: k2, last4: "0002", key: "sk-pool-key-00000002", enabled: true, version: 1},
		stubPoolCred{id: k3, last4: "0003", key: "sk-pool-key-00000003", enabled: true, version: 1},
	)
	clock := base
	store.nowFn = func() time.Time { return clock }
	versions := &stubOrgVersions{versions: map[string]int64{}}
	pool := &orgCredsPool{
		store:    store,
		versions: versions,
		ttl:      orgCredsPoolTTL,
		now:      func() time.Time { return clock },
		log:      testLogger(),
		states:   make(map[string]*orgCredsPoolState),
	}
	ctx := context.Background()

	// Staggered live rows (written by the store verb, version-scoped, as
	// feedback on earlier moments would have left them).
	require.NoError(t, store.QuarantineOrgCredential(ctx, "org-a", k1, base.Add(30*time.Minute)))
	require.NoError(t, store.QuarantineOrgCredential(ctx, "org-a", k2, base.Add(60*time.Minute)))
	require.NoError(t, store.QuarantineOrgCredential(ctx, "org-a", k3, base.Add(90*time.Minute)))
	lists0 := store.lists()

	// The fail-closed episode: every pick refuses with the sentinel and
	// the earliest live horizon, served from the ONE held snapshot — the
	// refusals resolve nothing and never re-list.
	for i := 0; i < 3; i++ {
		_, _, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
		require.Error(t, err)
		assert.False(t, ok)
		require.ErrorIs(t, err, errOrgCredsAllQuarantined)
		assert.Contains(t, err.Error(), "earliest return 2026-10-16T12:30:00Z",
			"the refusal names when traffic can return")
	}
	assert.Equal(t, lists0+1, store.lists(), "the held snapshot serves the whole episode")
	assert.Equal(t, 0, store.resolves(), "refusals never resolve key material")

	// 12:30 — k1's deadline passes (deadline == now is expired): the
	// recovered key serves from the SAME snapshot via the version fast
	// path — no re-list, one resolve.
	clock = base.Add(30 * time.Minute)
	use, plain, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, k1, use.credID)
	assert.Equal(t, "sk-pool-key-00000001", plain)
	assert.Equal(t, lists0+1, store.lists(), "the lapse exit needs no store round trip")
	assert.Equal(t, 1, store.resolves())

	// 13:00 — k2 rejoins: the pool serves the eligible pair in the exact
	// continuation order (k3 still out, never retried while quarantined).
	clock = base.Add(60 * time.Minute)
	for _, want := range []string{k2, k1} {
		use, _, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
		require.NoError(t, err)
		require.True(t, ok)
		assert.Equal(t, want, use.credID)
	}

	// 13:31 — the last deadline passes: the full fair rotation resumes.
	clock = base.Add(91 * time.Minute)
	for _, want := range []string{k1, k2, k3} {
		use, plain, ok, err := pool.pickAndResolve(ctx, "org-a", "openai-compat", "https://ep.test/v1")
		require.NoError(t, err)
		require.True(t, ok)
		assert.Equal(t, want, use.credID)
		switch use.credID {
		case k1:
			assert.Equal(t, "sk-pool-key-00000001", plain)
		case k2:
			assert.Equal(t, "sk-pool-key-00000002", plain)
		case k3:
			assert.Equal(t, "sk-pool-key-00000003", plain)
		}
	}

	// The whole staged recovery ran on one store list; every successful
	// pick resolved exactly once (6 picks, 6 resolves, no duplicates).
	assert.Equal(t, lists0+1, store.lists(), "the entire lapse exit is store-pressure-free")
	assert.Equal(t, 6, store.resolves())
}

// TestCredPoolRecovery_LateFeedbackAfterLapse_ReQuarantinesNextHorizon:
// an in-flight use quarantined by a 401, the cooldown lapsing at midnight
// (the key auto-recovers and serves again — the resume), and the LATE
// duplicated feedback for the old attempt landing after the recovery: the
// row must carry the report-time horizon — the end of the NEW day — never
// the already-expired deadline. The operator reset completes the journey.
func TestCredPoolRecovery_LateFeedbackAfterLapse_ReQuarantinesNextHorizon(t *testing.T) {
	base := time.Date(2026, 10, 16, 23, 0, 0, 0, time.UTC)
	k1 := "11111111-aaaa-4aaa-8aaa-000000000001"
	k2 := "11111111-aaaa-4aaa-8aaa-000000000002"
	store := newStubCredPoolStore(
		stubPoolCred{id: k1, last4: "0001", key: "sk-pool-key-00000001", enabled: true, version: 1},
		stubPoolCred{id: k2, last4: "0002", key: "sk-pool-key-00000002", enabled: true, version: 1},
	)
	clock := base
	store.nowFn = func() time.Time { return clock }
	versions := &stubOrgVersions{versions: map[string]int64{}}
	pool := &orgCredsPool{
		store:    store,
		versions: versions,
		ttl:      orgCredsPoolTTL,
		now:      func() time.Time { return clock },
		log:      testLogger(),
		states:   make(map[string]*orgCredsPoolState),
	}
	ctx := context.Background()
	const provider = "openai-compat"
	const endpoint = "https://ep.test/v1"

	// The attempt: k1 serves at 23:00 and its 401 quarantines it until
	// the next midnight; the version bumps for cross-instance invalidation.
	use1, _, ok, err := pool.pickAndResolve(ctx, "org-a", provider, endpoint)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, k1, use1.credID)
	pool.recordOutcome(ctx, "org-a", provider, use1, http.StatusUnauthorized)
	calls := store.quarantineLog()
	require.Len(t, calls, 1)
	assert.Equal(t, k1, calls[0].credID)
	assert.Equal(t, time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC), calls[0].until)
	v1 := versions.versions["org-a"]
	assert.NotZero(t, v1, "the quarantine write bumps the org version")

	// The feedback window: only k2 serves; k1 is not retried.
	for i := 0; i < 2; i++ {
		use, _, ok, err := pool.pickAndResolve(ctx, "org-a", provider, endpoint)
		require.NoError(t, err)
		require.True(t, ok)
		assert.Equal(t, k2, use.credID)
	}

	// Midnight passes; the cooldown lapses. The snapshot re-listed after
	// the 401 (quarantined-but-held, version-captured) is kept via the
	// version fast path — no store round trip — and eligibility is
	// re-evaluated at the new instant, so the FIRST pick serves the
	// recovered key: the resume needs no operator action.
	clock = time.Date(2026, 10, 17, 0, 5, 0, 0, time.UTC)
	listsBefore := store.lists()
	use, plain, ok, err := pool.pickAndResolve(ctx, "org-a", provider, endpoint)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, k1, use.credID, "the lapsed cooldown returns the key to rotation")
	assert.Equal(t, "sk-pool-key-00000001", plain, "the same credential resumes with its own key")
	assert.Equal(t, listsBefore, store.lists(), "the lapse exit needs no store round trip")
	use, _, ok, err = pool.pickAndResolve(ctx, "org-a", provider, endpoint)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, k2, use.credID, "the fair rotation over the eligible pair continues")

	// The late duplicated feedback for the OLD attempt lands after the
	// recovery: the row carries the report-time horizon — the end of the
	// NEW day (2026-10-18), never the expired 2026-10-17 deadline.
	pool.recordOutcome(ctx, "org-a", provider, use1, http.StatusUnauthorized)
	calls = store.quarantineLog()
	require.Len(t, calls, 2)
	assert.Equal(t, k1, calls[1].credID)
	assert.Equal(t, time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC), calls[1].until,
		"the re-quarantine horizon follows the report timeline")
	v2 := versions.versions["org-a"]
	assert.NotEqual(t, v1, v2, "the re-quarantine bumps the org version again")

	// The re-quarantined key is not retried; the sibling carries traffic.
	for i := 0; i < 2; i++ {
		use, _, ok, err := pool.pickAndResolve(ctx, "org-a", provider, endpoint)
		require.NoError(t, err)
		require.True(t, ok)
		assert.Equal(t, k2, use.credID)
	}

	// The operator reset lifts the quarantine ahead of the new horizon
	// (past-dated row through the frozen store verb, version bump, local
	// invalidation) and the key serves again. The clock moves first — the
	// operator acts later, and the fresh timestamp makes the bump
	// observable.
	clock = time.Date(2026, 10, 17, 0, 5, 10, 0, time.UTC)
	require.NoError(t, pool.ResetOrgCredential(ctx, "org-a", provider, endpoint, k1))
	calls = store.quarantineLog()
	require.Len(t, calls, 3)
	assert.Equal(t, k1, calls[2].credID)
	assert.Equal(t, clock.Add(-time.Second), calls[2].until, "the reset writes a past-dated row")
	v3 := versions.versions["org-a"]
	assert.NotEqual(t, v2, v3, "the reset bumps the org version")
	use, plain, ok, err = pool.pickAndResolve(ctx, "org-a", provider, endpoint)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, k1, use.credID, "the operator reset returns the key ahead of its horizon")
	assert.Equal(t, "sk-pool-key-00000001", plain)

	// Exact whole-journey accounting: one list per mutation-invalidated
	// reload (initial, post-401, post-late-401, post-reset), one resolve
	// per successful pick.
	assert.Equal(t, 4, store.lists())
	assert.Equal(t, 8, store.resolves())
}
