package upstream

// N08-P05-T08 recovery corpus: the fail-closed EXIT paths of the
// credential pool engine. T00–T07 pinned the entry into quarantine and
// single-member expiry; this file pins the recovery journey as a whole —
// a pool that is fully out of rotation (fail closed) must leave that state
// through the authorized lifts only (cooldown lapse, manual reset, key
// rotation), one member at a time, with the round-robin continuation and
// the attribution counters preserved exactly (recovery without duplicates
// and without losses: a recovered key is picked once per cycle, an
// exhausted verdict consumes no rotation budget, a source is resolved
// exactly once per completed pick).
//
// Everything here is deterministic (pinned clocks, fixed registration
// order) and shuffle/race safe (no shared state, no real time).

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCredentialPoolRecovery_FailClosedExitByCooldownLapse: the full
// fail-closed episode with staggered cooldowns. While every member is out
// of rotation the pool refuses with the typed exhausted error (earliest
// live horizon, no source fetch, no counter movement, no membership
// change), and as the clock crosses each deadline the members return one
// at a time. The round-robin cursor survives the whole episode untouched —
// once the last member recovers, the exact fair sequence continues from
// where serving stopped.
func TestCredentialPoolRecovery_FailClosedExitByCooldownLapse(t *testing.T) {
	base := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	p, clock := newClockedPool(t, credKey("org-1", "openai-compat", "https://u.local"), base)
	c1 := &countingSource{key: "key-c1"}
	c2 := &countingSource{key: "key-c2"}
	c3 := &countingSource{key: "key-c3"}
	require.NoError(t, p.Add(CredentialSpec{ID: "c1", Last4: "0001", KeyVersion: 1, Source: c1.source}))
	require.NoError(t, p.Add(CredentialSpec{ID: "c2", Last4: "0002", KeyVersion: 1, Source: c2.source}))
	require.NoError(t, p.Add(CredentialSpec{ID: "c3", Last4: "0003", KeyVersion: 1, Source: c3.source}))
	ctx := context.Background()

	// Baseline pick: c1 serves, the cursor rests on c2.
	l1, err := p.Acquire(ctx)
	require.NoError(t, err)
	require.Equal(t, "c1", l1.Ref().ID)
	assert.Equal(t, uint64(1), p.Snapshot().Acquires)

	// Staggered cooldowns: c3 recovers first (13:00), then c2 (14:00),
	// then c1 (15:00). Reasons are secret-free classification tags.
	*clock = base
	require.True(t, p.MarkUnavailable("c1", base.Add(3*time.Hour), "cooldown-c1"))
	require.True(t, p.MarkUnavailable("c2", base.Add(2*time.Hour), "cooldown-c2"))
	require.True(t, p.MarkUnavailable("c3", base.Add(1*time.Hour), "cooldown-c3"))

	// The fail-closed episode: every pick refuses with the typed error,
	// naming the earliest live horizon, and moves nothing — no counter,
	// no source fetch, no membership, no cursor (proven by the exact
	// continuation once serving resumes).
	snap := p.Snapshot()
	require.Len(t, snap.Members, 3)
	for i, m := range snap.Members {
		assert.False(t, m.InRotation, "member %d must be out of rotation", i)
		assert.NotEmpty(t, m.UnavailableReason)
	}
	for i := 0; i < 3; i++ {
		_, err := p.Acquire(ctx)
		require.Error(t, err)
		var pex *PoolExhaustedError
		require.ErrorAs(t, err, &pex)
		assert.Equal(t, base.Add(time.Hour), pex.EarliestRecovery,
			"the refusal must name the earliest live deadline (c3, 13:00)")
	}
	snap = p.Snapshot()
	assert.Equal(t, uint64(1), snap.Acquires, "exhausted verdicts consume no rotation budget")
	assert.Equal(t, uint64(1), snap.Members[0].Acquires)
	assert.Equal(t, 1, c1.calls+c2.calls+c3.calls,
		"exactly one source fetch happened (the baseline pick); exhausted verdicts never fetch")
	assert.Equal(t, 3, p.Len(), "recovery never re-inserts members")

	// 13:00 — c3's deadline passes (deadline == now is already lifted):
	// c3 is the only member in rotation and serves every pick until the
	// next deadline; the pool leaves fail-closed as soon as one member
	// recovers (no all-or-nothing gating on the staged exit).
	*clock = base.Add(time.Hour)
	got := acquireIDs(t, p, 2)
	assert.Equal(t, []string{"c3", "c3"}, got, "with c1/c2 still out, the sole recovered member serves alone")

	// 14:00 — c2 rejoins: the pool serves the c2/c3 pair in exact
	// alternation, c1 still excluded (never retried while out).
	*clock = base.Add(2 * time.Hour)
	got = acquireIDs(t, p, 3)
	assert.Equal(t, []string{"c2", "c3", "c2"}, got)

	// 15:00 — the last deadline passes: the full fair rotation resumes
	// exactly where the cursor stopped (before the episode it rested on
	// c2; the exhausted verdicts never advanced it).
	*clock = base.Add(3 * time.Hour)
	got = acquireIDs(t, p, 6)
	assert.Equal(t, []string{"c3", "c1", "c2", "c3", "c1", "c2"}, got,
		"the fair rotation continues from the preserved cursor position")

	// Loss-free accounting: every pick is attributed exactly once, every
	// completed pick resolved its source exactly once (no duplicate
	// plaintext fetches, no lost picks).
	snap = p.Snapshot()
	assert.Equal(t, uint64(12), snap.Acquires)
	var sum uint64
	for _, m := range snap.Members {
		require.True(t, m.InRotation, "member %s must be back in rotation", m.Ref.ID)
		sum += m.Acquires
	}
	assert.Equal(t, snap.Acquires, sum, "member attribution sums to the pool total")
	assert.Equal(t, 3, c1.calls)
	assert.Equal(t, 4, c2.calls)
	assert.Equal(t, 5, c3.calls)
	assert.Equal(t, 12, c1.calls+c2.calls+c3.calls,
		"source fetches == completed picks: no duplicates, no losses")
	// The lapse exit is passive: eligibility flips at pick time, while the
	// diagnostic fields keep the last incident (reason tag + the past
	// deadline) as the operator trail — only an explicit reset or rotation
	// rewrites them (pinned differentially in AuthorizedLiftPathsConverge).
	assert.Equal(t, []string{"cooldown-c1", "cooldown-c2", "cooldown-c3"},
		[]string{snap.Members[0].UnavailableReason, snap.Members[1].UnavailableReason, snap.Members[2].UnavailableReason})
	assert.Equal(t, []time.Time{base.Add(3 * time.Hour), base.Add(2 * time.Hour), base.Add(time.Hour)},
		[]time.Time{snap.Members[0].RecoversAt, snap.Members[1].RecoversAt, snap.Members[2].RecoversAt})
}

// TestCredentialPoolRecovery_LateOutcomeAfterLapse_ReQuarantinesNewHorizon:
// an interrupted attempt whose feedback arrives late. The lease was
// quarantined by its 401, the cooldown lapsed at midnight and the key was
// auto-recovered and served again — then the late (duplicated) outcome
// lands. The pool must apply the policy as of the report time: the
// re-quarantine horizon is the END OF THE NEW DAY, not the expired one,
// and the key is not retried while out. The operator reset remains the
// immediate exit.
func TestCredentialPoolRecovery_LateOutcomeAfterLapse_ReQuarantinesNewHorizon(t *testing.T) {
	base := time.Date(2026, 10, 29, 23, 0, 0, 0, time.UTC)
	p, clock := newClockedPool(t, credKey("org-1", "openai-compat", "https://u.local"), base)
	c1 := &countingSource{key: "key-c1"}
	c2 := &countingSource{key: "key-c2"}
	require.NoError(t, p.Add(CredentialSpec{ID: "c1", Last4: "0001", KeyVersion: 1, Source: c1.source}))
	require.NoError(t, p.Add(CredentialSpec{ID: "c2", Last4: "0002", KeyVersion: 1, Source: c2.source}))
	ctx := context.Background()

	// The attempt: c1 serves at 23:00 and its 401 quarantines it until
	// the next midnight (the day-scoped horizon).
	l1, err := p.Acquire(ctx)
	require.NoError(t, err)
	require.Equal(t, "c1", l1.Ref().ID)
	require.True(t, p.ReportOutcome(l1, 401))
	snap := p.Snapshot()
	assert.Equal(t, time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC), snap.Members[0].RecoversAt)
	assert.Equal(t, QuarantineReasonUnauthorized, snap.Members[0].UnavailableReason)

	// The feedback window: only c2 serves (the sibling, no infinite
	// retry of the rejected key); c1's source is never consulted.
	for i := 0; i < 10; i++ {
		l, err := p.Acquire(ctx)
		require.NoError(t, err)
		assert.Equal(t, "c2", l.Ref().ID)
	}
	assert.Equal(t, 1, c1.calls)

	// Midnight passes: the cooldown lapses and the key auto-recovers at
	// pick time — the resume needs no operator action and no
	// re-registration (membership stays 2).
	*clock = time.Date(2026, 10, 30, 0, 5, 0, 0, time.UTC)
	l2, err := p.Acquire(ctx)
	require.NoError(t, err)
	require.Equal(t, "c1", l2.Ref().ID, "the lapsed cooldown returns the key to rotation")
	assert.Equal(t, "key-c1", l2.Plaintext())
	assert.Equal(t, 2, p.Len())

	// The late duplicated outcome for the old attempt lands AFTER the
	// recovery: accepted (the lease stays pool-bound across recovery),
	// but the horizon is computed from the report-time clock — the end
	// of the NEW day, never the already-expired deadline.
	require.True(t, p.ReportOutcome(l2, 429))
	snap = p.Snapshot()
	require.Len(t, snap.Members, 2)
	assert.Equal(t, time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC), snap.Members[0].RecoversAt,
		"the re-quarantine horizon follows the report timeline (next UTC midnight)")
	assert.Equal(t, QuarantineReasonThrottled, snap.Members[0].UnavailableReason)
	assert.False(t, snap.Members[0].InRotation)

	// The re-quarantined key is not retried; the sibling carries traffic.
	for i := 0; i < 3; i++ {
		l, err := p.Acquire(ctx)
		require.NoError(t, err)
		assert.Equal(t, "c2", l.Ref().ID)
	}
	assert.Equal(t, 2, c1.calls, "no source fetch for the re-quarantined key")

	// The operator reset is the immediate exit ahead of the new horizon.
	require.True(t, p.MarkRecovered("c1"))
	l3, err := p.Acquire(ctx)
	require.NoError(t, err)
	assert.Equal(t, "c1", l3.Ref().ID)

	// Accounting stays loss-free across the whole journey; the explicit
	// reset (unlike the lapse exit) clears the incident diagnostics.
	snap = p.Snapshot()
	assert.Equal(t, uint64(16), snap.Acquires)
	assert.Equal(t, uint64(3), snap.Members[0].Acquires)
	assert.Equal(t, uint64(13), snap.Members[1].Acquires)
	assert.True(t, snap.Members[0].InRotation)
	assert.Empty(t, snap.Members[0].UnavailableReason, "the manual reset clears the incident tag")
	assert.True(t, snap.Members[0].RecoversAt.IsZero())
	assert.Equal(t, 3, c1.calls)
	assert.Equal(t, 13, c2.calls)
}

// TestCredentialPoolRecovery_AuthorizedLiftPathsConverge: exactly three
// lifts exist (cooldown lapse, manual reset, key-version rotation). One
// pool, three quarantined members, one lift per member — all paths must
// converge to the same healthy state: full fair rotation with the
// preserved cursor, fixed member positions, exact attribution, and the
// rotated member serving its NEW plaintext.
func TestCredentialPoolRecovery_AuthorizedLiftPathsConverge(t *testing.T) {
	base := time.Date(2026, 10, 29, 22, 0, 0, 0, time.UTC)
	p, clock := newClockedPool(t, credKey("org-1", "openai-compat", "https://u.local"), base)
	c1 := &countingSource{key: "key-c1"}
	c2 := &countingSource{key: "key-c2"}
	c3 := &countingSource{key: "key-c3"}
	require.NoError(t, p.Add(CredentialSpec{ID: "c1", Last4: "0001", KeyVersion: 1, Source: c1.source}))
	require.NoError(t, p.Add(CredentialSpec{ID: "c2", Last4: "0002", KeyVersion: 1, Source: c2.source}))
	require.NoError(t, p.Add(CredentialSpec{ID: "c3", Last4: "0003", KeyVersion: 1, Source: c3.source}))
	ctx := context.Background()

	// Baseline full cycle pins the registration order and the cursor.
	var leases []*Lease
	for i := 0; i < 3; i++ {
		l, err := p.Acquire(ctx)
		require.NoError(t, err)
		leases = append(leases, l)
	}
	assert.Equal(t, []string{"c1", "c2", "c3"}, leaseIDs(leases))

	// Quarantine all three by different verbs: c1 via its upstream 401
	// (the day-scoped report horizon — the earliest live deadline), c2
	// and c3 via custom cooldowns.
	require.True(t, p.ReportOutcome(leases[0], 401))
	require.True(t, p.MarkUnavailable("c2", base.Add(4*time.Hour), "cooldown-custom"))
	require.True(t, p.MarkUnavailable("c3", base.Add(6*time.Hour), "cooldown-custom"))

	_, err := p.Acquire(ctx)
	var pex *PoolExhaustedError
	require.Error(t, err)
	require.ErrorAs(t, err, &pex)
	assert.Equal(t, time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC), pex.EarliestRecovery,
		"the report-scoped horizon is the earliest live deadline")
	snap := p.Snapshot()
	assert.Equal(t, uint64(3), snap.Acquires, "the exhausted verdict moved nothing")
	assert.Equal(t, []string{QuarantineReasonUnauthorized, "cooldown-custom", "cooldown-custom"},
		[]string{snap.Members[0].UnavailableReason, snap.Members[1].UnavailableReason, snap.Members[2].UnavailableReason})

	// Lift 1 — cooldown lapse (c1's deadline passes).
	*clock = time.Date(2026, 10, 30, 0, 0, 30, 0, time.UTC)
	l, err := p.Acquire(ctx)
	require.NoError(t, err)
	assert.Equal(t, "c1", l.Ref().ID)

	// Lift 2 — manual reset (operator override ahead of c2's cooldown).
	require.True(t, p.MarkRecovered("c2"))
	l, err = p.Acquire(ctx)
	require.NoError(t, err)
	assert.Equal(t, "c2", l.Ref().ID)

	// Lift 3 — key-version rotation (a rotated key is a new key): the
	// member returns AND serves the new version's plaintext.
	c3v2 := &countingSource{key: "key-c3-v2"}
	require.NoError(t, p.UpsertCredential(CredentialSpec{ID: "c3", Last4: "0003", KeyVersion: 2, Source: c3v2.source}))
	l, err = p.Acquire(ctx)
	require.NoError(t, err)
	assert.Equal(t, "c3", l.Ref().ID)
	assert.Equal(t, "key-c3-v2", l.Plaintext())
	assert.Equal(t, 2, l.Ref().KeyVersion)

	// Convergence: the full fair rotation continues from the preserved
	// cursor with fixed member positions.
	got := acquireIDs(t, p, 3)
	assert.Equal(t, []string{"c1", "c2", "c3"}, got)

	snap = p.Snapshot()
	assert.Equal(t, 3, p.Len())
	assert.Equal(t, uint64(9), snap.Acquires)
	assert.Equal(t, []int{1, 1, 2},
		[]int{snap.Members[0].Ref.KeyVersion, snap.Members[1].Ref.KeyVersion, snap.Members[2].Ref.KeyVersion})
	// Differential diagnostics of the three lifts: the passive lapse keeps
	// the incident trail (reason tag + past deadline); the explicit reset
	// and the rotation clear it.
	assert.True(t, snap.Members[0].InRotation)
	assert.Equal(t, QuarantineReasonUnauthorized, snap.Members[0].UnavailableReason)
	assert.Equal(t, time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC), snap.Members[0].RecoversAt)
	assert.True(t, snap.Members[1].InRotation)
	assert.Empty(t, snap.Members[1].UnavailableReason)
	assert.True(t, snap.Members[1].RecoversAt.IsZero())
	assert.True(t, snap.Members[2].InRotation)
	assert.Empty(t, snap.Members[2].UnavailableReason)
	assert.True(t, snap.Members[2].RecoversAt.IsZero())
	assert.Equal(t, 3, c1.calls)
	assert.Equal(t, 3, c2.calls)
	assert.Equal(t, 1, c3.calls, "the v1 source is retired by the rotation")
	assert.Equal(t, 2, c3v2.calls, "the v2 source serves the lift pick and the final-cycle pick")
	for i := 0; i < 3; i++ {
		l, err := p.Acquire(ctx)
		require.NoError(t, err)
		if l.Ref().ID == "c3" {
			assert.Equal(t, "key-c3-v2", l.Plaintext(), "the rotated member keeps serving the new plaintext")
		}
	}
}

// acquireIDs performs n acquires and returns the served member ids —
// a compact exact-sequence helper for the recovery batteries.
func acquireIDs(t *testing.T, p *CredentialPool, n int) []string {
	t.Helper()
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		l, err := p.Acquire(context.Background())
		require.NoError(t, err)
		ids = append(ids, l.Ref().ID)
	}
	return ids
}

// leaseIDs maps leases to their member ids.
func leaseIDs(leases []*Lease) []string {
	ids := make([]string, 0, len(leases))
	for _, l := range leases {
		ids = append(ids, l.Ref().ID)
	}
	return ids
}
