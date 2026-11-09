package upstream

// boundary corpus for the pool's quarantine, rotation and fail-closed
// edges: the exact integer extremes of the outcome policy, horizon and
// reason rewriting on repeated outcomes, past-dated and zero deadlines,
// version-decrease and insert arms of the rotation upsert, the round-robin
// cursor arithmetic under removals, the earliest-recovery horizon ignoring
// expired deadlines, and the empty-plaintext resolve guard with exact
// pick accounting. Companion to credpool_test.go (behavior battery) and
// credpool_joint_test.go (user journey).

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCredentialPoolBoundary_StatusExtremes pins the outcome classification
// at the integer extremes: exactly 401 and 429 quarantine; every other
// machine-readable status — including neighbors, out-of-range and
// negative/overflow values — is a no-op for pool state.
func TestCredentialPoolBoundary_StatusExtremes(t *testing.T) {
	base := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	extremes := []int{
		math.MinInt32, -1, 0, 1, 99, 100, 101, 199, 200, 201, 204,
		300, 301, 399, 400, 402, 403, 404, 405, 408, 418, 425, 499,
		500, 502, 503, 504, 511, 599, 600, 1000, math.MaxInt32,
	}
	for _, status := range extremes {
		if QuarantinableStatus(status) {
			t.Errorf("QuarantinableStatus(%d) = true; only 401 and 429 quarantine", status)
		}
		if reason := QuarantineReason(status); reason != "" {
			t.Errorf("QuarantineReason(%d) = %q; non-quarantining statuses have no reason", status, reason)
		}
	}
	if !QuarantinableStatus(401) || !QuarantinableStatus(429) {
		t.Fatal("401 and 429 must quarantine")
	}

	// The same extremes fed through a live lease never mutate pool state.
	for _, status := range extremes {
		p, _ := newClockedPool(t, credKey("org-1", "openai-compat", "https://u.local"), base)
		require.NoError(t, p.Add(CredentialSpec{ID: "c1", Last4: "0001", KeyVersion: 1, Source: sourceFor("key-c1")}))
		lease, err := p.Acquire(context.Background())
		require.NoError(t, err)
		require.True(t, p.ReportOutcome(lease, status))

		m, ok := snapshotMemberByID(p, "c1")
		require.True(t, ok)
		assert.True(t, m.InRotation, "status %d must not take the credential out of rotation", status)
		assert.Empty(t, m.UnavailableReason, "status %d must not record a reason", status)
		assert.True(t, m.RecoversAt.IsZero(), "status %d must not set a horizon", status)
		assert.Equal(t, uint64(1), m.Acquires, "status %d must not disturb the pick counter", status)
	}
}

// mustPickC1 acquires until c1 is served (c1 must be in rotation — the
// sibling only absorbs the interim pick).
func mustPickC1(t *testing.T, p *CredentialPool) *Lease {
	t.Helper()
	for range 8 {
		lease, err := p.Acquire(context.Background())
		require.NoError(t, err)
		if lease.Ref().ID == "c1" {
			return lease
		}
	}
	t.Fatal("c1 was never picked")
	return nil
}

// quarantineC1 reports status for a fresh c1 lease.
func quarantineC1(t *testing.T, p *CredentialPool, status int) {
	t.Helper()
	require.True(t, p.ReportOutcome(mustPickC1(t, p), status))
}

// TestCredentialPoolBoundary_OutcomeRewriteHorizonAndReason pins the
// repeated-outcome boundary on a frozen clock: a 429 after a 401 keeps the
// same day-horizon (same UTC day) but rewrites the reason; a repeated 401
// rewrites the identical horizon; and an outcome arriving for an in-flight
// lease whose credential took a custom cooldown in between overwrites that
// custom horizon with the policy's day horizon — quarantine deadlines are
// day-scoped, never inherited.
func TestCredentialPoolBoundary_OutcomeRewriteHorizonAndReason(t *testing.T) {
	base := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	dayHorizon := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	p, _ := newClockedPool(t, credKey("org-1", "openai-compat", "https://u.local"), base)
	require.NoError(t, p.Add(CredentialSpec{ID: "c1", Last4: "0001", KeyVersion: 1, Source: sourceFor("key-c1")}))
	require.NoError(t, p.Add(CredentialSpec{ID: "c2", Last4: "0002", KeyVersion: 1, Source: sourceFor("key-c2")}))

	quarantineC1(t, p, 401)
	m, ok := snapshotMemberByID(p, "c1")
	require.True(t, ok)
	require.Equal(t, dayHorizon, m.RecoversAt)
	require.Equal(t, QuarantineReasonUnauthorized, m.UnavailableReason)

	// 429 after 401: same horizon (still the same UTC day), rewritten reason.
	require.True(t, p.MarkRecovered("c1"))
	quarantineC1(t, p, 429)
	m, ok = snapshotMemberByID(p, "c1")
	require.True(t, ok)
	assert.Equal(t, dayHorizon, m.RecoversAt, "the 429 of the same day keeps the day horizon")
	assert.Equal(t, QuarantineReasonThrottled, m.UnavailableReason, "the reason is rewritten to the new outcome")

	// Repeated 401: the identical horizon again — never shortened, never grown.
	require.True(t, p.MarkRecovered("c1"))
	quarantineC1(t, p, 401)
	m, ok = snapshotMemberByID(p, "c1")
	require.True(t, ok)
	assert.Equal(t, dayHorizon, m.RecoversAt, "a repeated 401 rewrites the identical horizon")
	assert.Equal(t, QuarantineReasonUnauthorized, m.UnavailableReason)

	// Custom cooldown landing between pick and report: the outcome's day
	// horizon overwrites the custom horizon (state writes converge on the
	// latest classification, the day scope wins).
	require.True(t, p.MarkRecovered("c1"))
	lease := mustPickC1(t, p)
	require.True(t, p.MarkUnavailable("c1", base.Add(240*time.Hour), "custom_cooldown"))
	require.True(t, p.ReportOutcome(lease, 429))
	m, ok = snapshotMemberByID(p, "c1")
	require.True(t, ok)
	assert.Equal(t, dayHorizon, m.RecoversAt, "the outcome policy horizon overwrites the custom cooldown")
	assert.Equal(t, QuarantineReasonThrottled, m.UnavailableReason)
}

// mustPickIDs drains n picks and returns the served member ids.
func mustPickIDs(t *testing.T, p *CredentialPool, n int) []string {
	t.Helper()
	ids := make([]string, 0, n)
	for range n {
		lease, err := p.Acquire(context.Background())
		require.NoError(t, err)
		ids = append(ids, lease.Ref().ID)
	}
	return ids
}

// TestCredentialPoolBoundary_PastAndZeroDeadlines pins the deadline
// arithmetic at the state-primitive level: a past-dated unavailability is
// already expired (the reset verb's past-dated-row foundation), a zero
// deadline is the no-quarantine sentinel, and both leave the member in
// rotation at pick time while keeping the recorded diagnostics.
func TestCredentialPoolBoundary_PastAndZeroDeadlines(t *testing.T) {
	base := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	p, clock := newClockedPool(t, credKey("org-1", "openai-compat", "https://u.local"), base)
	require.NoError(t, p.Add(CredentialSpec{ID: "c1", Last4: "0001", KeyVersion: 1, Source: sourceFor("key-c1")}))
	require.NoError(t, p.Add(CredentialSpec{ID: "c2", Last4: "0002", KeyVersion: 1, Source: sourceFor("key-c2")}))

	// A past-dated deadline never excludes the member.
	require.True(t, p.MarkUnavailable("c1", base.Add(-time.Hour), "stale_row"))
	m, ok := snapshotMemberByID(p, "c1")
	require.True(t, ok)
	assert.True(t, m.InRotation, "a past-dated deadline is already expired")
	assert.Equal(t, []string{"c1", "c2"}, mustPickIDs(t, p, 2),
		"members with expired rows serve new attempts in store order")

	// A live quarantine excludes; a past-dated overwrite lifts at pick time.
	require.True(t, p.MarkUnavailable("c1", base.Add(time.Hour), "cooldown_test"))
	assert.Equal(t, []string{"c2", "c2"}, mustPickIDs(t, p, 2), "the live quarantine excludes c1")
	require.True(t, p.MarkUnavailable("c1", base.Add(-time.Minute), "stale_row"))
	*clock = base.Add(time.Minute)
	assert.Equal(t, []string{"c1", "c2"}, mustPickIDs(t, p, 2),
		"the past-dated overwrite returns the member to rotation")

	// The zero deadline is the explicit no-quarantine sentinel.
	require.True(t, p.MarkUnavailable("c1", time.Time{}, "zeroed"))
	m, ok = snapshotMemberByID(p, "c1")
	require.True(t, ok)
	assert.True(t, m.InRotation)
	assert.True(t, m.RecoversAt.IsZero())
	assert.Equal(t, []string{"c1", "c2"}, mustPickIDs(t, p, 2),
		"a zero deadline never excludes the member")
	assert.Equal(t, 2, p.Len(), "deadline writes never change membership")
}

// TestCredentialPoolBoundary_UpsertVersionDecreaseAndSkipLift pins the
// rotation-lift boundary: ANY key-version change lifts a quarantine — a
// decrease (rotation rollback to a previous key) and a multi-version skip
// behave exactly like an increment, because the stored unavailability
// belongs to the OLD key version. Membership and the acquire counter
// survive every rotation.
func TestCredentialPoolBoundary_UpsertVersionDecreaseAndSkipLift(t *testing.T) {
	base := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	p, _ := newClockedPool(t, credKey("org-1", "openai-compat", "https://u.local"), base)
	require.NoError(t, p.Add(CredentialSpec{ID: "c1", Last4: "0002", KeyVersion: 2, Source: sourceFor("key-c1-v2")}))
	require.NoError(t, p.Add(CredentialSpec{ID: "c2", Last4: "2222", KeyVersion: 1, Source: sourceFor("key-c2-v1")}))

	lease, err := p.Acquire(context.Background())
	require.NoError(t, err)
	require.Equal(t, "c1", lease.Ref().ID)
	require.True(t, p.ReportOutcome(lease, 401))
	assert.Equal(t, []string{"c2", "c2"}, mustPickIDs(t, p, 2), "c1 is quarantined before the rollback")
	before, ok := snapshotMemberByID(p, "c1")
	require.True(t, ok)
	require.False(t, before.InRotation)

	// Version DECREASE (2 -> 1): the rolled-back key is a new key too.
	require.NoError(t, p.UpsertCredential(CredentialSpec{ID: "c1", Last4: "0001", KeyVersion: 1, Source: sourceFor("key-c1-v1")}))
	m, ok := snapshotMemberByID(p, "c1")
	require.True(t, ok)
	assert.True(t, m.InRotation, "the version decrease lifts the quarantine")
	assert.Empty(t, m.UnavailableReason)
	assert.True(t, m.RecoversAt.IsZero())
	assert.Equal(t, uint64(1), m.Acquires, "rotation preserves the acquire counter")
	rolled, err := p.Acquire(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "c1", rolled.Ref().ID)
	assert.Equal(t, "key-c1-v1", rolled.Plaintext(), "the rolled-back source serves its own plaintext")
	assert.Equal(t, 1, rolled.Ref().KeyVersion)
	assert.Equal(t, "0001", rolled.Ref().Last4, "the mask follows the rotation spec")

	// Multi-version skip (1 -> 5) lifts the same way.
	require.True(t, p.ReportOutcome(rolled, 429))
	assert.Equal(t, []string{"c2"}, mustPickIDs(t, p, 1), "c1 is quarantined again before the skip")
	require.NoError(t, p.UpsertCredential(CredentialSpec{ID: "c1", Last4: "5555", KeyVersion: 5, Source: sourceFor("key-c1-v5")}))
	m, ok = snapshotMemberByID(p, "c1")
	require.True(t, ok)
	assert.True(t, m.InRotation, "a multi-version skip lifts the quarantine")
	assert.Equal(t, []string{"c1"}, mustPickIDs(t, p, 1))
	assert.Equal(t, 2, p.Len(), "rotation never duplicates membership")
}

// TestCredentialPoolBoundary_UpsertInsertAfterRemove_TailPosition pins the
// insert arm of the upsert: re-registering a removed id appends it at the
// TAIL of the rotation order — a re-added credential rejoins after the
// members that stayed, and a never-seen id joins the same way.
func TestCredentialPoolBoundary_UpsertInsertAfterRemove_TailPosition(t *testing.T) {
	base := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	p, _ := newClockedPool(t, credKey("org-1", "openai-compat", "https://u.local"), base)
	for _, id := range []string{"c1", "c2", "c3"} {
		require.NoError(t, p.Add(CredentialSpec{ID: id, Last4: "0000", KeyVersion: 1, Source: sourceFor("key-" + id)}))
	}
	require.Equal(t, []string{"c1", "c2", "c3"}, mustPickIDs(t, p, 3), "baseline order")

	// Remove c1 (cursor adjusts), serve the remaining pair, then re-add c1:
	// it re-enters at the tail, after c2 and c3.
	require.True(t, p.Remove("c1"))
	require.Equal(t, 2, p.Len())
	require.Equal(t, []string{"c2", "c3"}, mustPickIDs(t, p, 2))
	require.NoError(t, p.UpsertCredential(CredentialSpec{ID: "c1", Last4: "0001", KeyVersion: 2, Source: sourceFor("key-c1-v2")}))
	require.Equal(t, 3, p.Len())
	require.Equal(t, []string{"c2", "c3", "c1"}, mustPickIDs(t, p, 3),
		"a re-added credential rejoins at the tail of the rotation order")

	// A never-seen id inserts through the same arm.
	require.NoError(t, p.UpsertCredential(CredentialSpec{ID: "c4", Last4: "4444", KeyVersion: 1, Source: sourceFor("key-c4")}))
	require.Equal(t, 4, p.Len())
	require.Equal(t, []string{"c2", "c3", "c1", "c4"}, mustPickIDs(t, p, 4),
		"a first-time upsert registers a new member at the tail")
}

// TestCredentialPoolBoundary_RemoveCursorArithmetic pins the round-robin
// cursor adjustment under removals: removing a member BEFORE the cursor
// decrements it, removing at or after it keeps it (with the wrap reset when
// the cursor would fall off the shortened list), and every case continues
// the rotation without skipping or double-picking a survivor (exact
// expected sequences).
func TestCredentialPoolBoundary_RemoveCursorArithmetic(t *testing.T) {
	specFor := func(id string) CredentialSpec {
		return CredentialSpec{ID: id, Last4: "0000", KeyVersion: 1, Source: sourceFor("key-" + id)}
	}
	for _, tc := range []struct {
		name      string
		ids       []string
		picks     int // picks before the removal (advancing the cursor)
		remove    string
		wantPicks []string // the exact continuation
	}{
		{"remove after the cursor keeps it", []string{"c1", "c2", "c3", "c4"}, 1, "c4", []string{"c2", "c3", "c1", "c2"}},
		{"remove before the cursor decrements it", []string{"c1", "c2", "c3", "c4"}, 2, "c1", []string{"c3", "c4", "c2", "c3"}},
		{"remove at the cursor keeps the position", []string{"c1", "c2", "c3", "c4"}, 2, "c3", []string{"c4", "c1", "c2", "c4"}},
		{"remove the wrapped cursor member resets it", []string{"c1", "c2", "c3"}, 2, "c3", []string{"c1", "c2", "c1", "c2"}},
		{"remove mid-cycle decrements once", []string{"c1", "c2", "c3", "c4"}, 3, "c2", []string{"c4", "c1", "c3", "c4"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := newClockedPool(t, credKey("org-1", "openai-compat", "https://u.local"), time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC))
			for _, id := range tc.ids {
				require.NoError(t, p.Add(specFor(id)))
			}
			require.Len(t, mustPickIDs(t, p, tc.picks), tc.picks)
			require.True(t, p.Remove(tc.remove), "the removed member must be registered")
			require.Equal(t, len(tc.ids)-1, p.Len())
			assert.Equal(t, tc.wantPicks, mustPickIDs(t, p, len(tc.wantPicks)),
				"the rotation must continue without skipping or doubling survivors")
		})
	}

	// Draining to zero members turns the pool into the empty routing miss.
	p := NewCredentialPool(credKey("org-1", "openai-compat", "https://u.local"))
	require.NoError(t, p.Add(specFor("c1")))
	require.NoError(t, p.Add(specFor("c2")))
	require.Equal(t, []string{"c1", "c2"}, mustPickIDs(t, p, 2))
	require.True(t, p.Remove("c1"))
	require.True(t, p.Remove("c2"))
	_, err := p.Acquire(context.Background())
	require.ErrorIs(t, err, ErrPoolEmpty, "a fully drained pool is the plain routing miss")
	assert.Equal(t, 0, p.Len())
}

// TestCredentialPoolBoundary_ExhaustedEarliestRecoveryLiveHorizons pins the
// fail-closed horizon boundary: a stale past-dated row keeps its member
// eligible, so the pool does NOT exhaust while such a member exists — the
// exhausted horizon is the earliest LIVE deadline across quarantined
// members, it moves to the next member when the earliest one recovers or is
// re-quarantined further out, and equal deadlines collapse onto that value.
func TestCredentialPoolBoundary_ExhaustedEarliestRecoveryLiveHorizons(t *testing.T) {
	base := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	p, _ := newClockedPool(t, credKey("org-1", "openai-compat", "https://u.local"), base)
	for _, id := range []string{"c1", "c2", "c3"} {
		require.NoError(t, p.Add(CredentialSpec{ID: id, Last4: "0000", KeyVersion: 1, Source: sourceFor("key-" + id)}))
	}
	require.True(t, p.MarkUnavailable("c1", base.Add(-time.Hour), "stale_row"))
	require.True(t, p.MarkUnavailable("c2", base.Add(7*time.Hour), "cooldown_test"))
	require.True(t, p.MarkUnavailable("c3", base.Add(5*time.Hour), "cooldown_test"))

	// The stale row is not exclusionary: c1 serves every pick and the pool
	// never reports exhaustion while it is eligible.
	assert.Equal(t, []string{"c1", "c1", "c1"}, mustPickIDs(t, p, 3),
		"a member with an expired row serves new attempts indefinitely")
	var exhausted *PoolExhaustedError

	// Live-quarantining the last eligible member exhausts the pool; the
	// horizon is the earliest LIVE deadline (c3 at +5h), not the stale row.
	require.True(t, p.MarkUnavailable("c1", base.Add(6*time.Hour), "cooldown_test"))
	lease, err := p.Acquire(context.Background())
	assert.Nil(t, lease)
	require.ErrorAs(t, err, &exhausted)
	require.Equal(t, base.Add(5*time.Hour), exhausted.EarliestRecovery)
	require.Equal(t, "credential pool org=org-1 provider=openai-compat base_url=https://u.local: all credentials are out of rotation; earliest recovery 2026-10-28T17:00:00Z",
		exhausted.Error())
	assert.NotContains(t, exhausted.Error(), "key-", "the horizon message carries no plaintext")

	// Recovering the horizon member returns the pool to serving; moving it
	// further out moves the horizon to the next earliest live deadline.
	require.True(t, p.MarkRecovered("c3"))
	got, err := p.Acquire(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "c3", got.Ref().ID)
	require.True(t, p.MarkUnavailable("c3", base.Add(8*time.Hour), "cooldown_test"))
	_, err = p.Acquire(context.Background())
	require.ErrorAs(t, err, &exhausted)
	assert.Equal(t, base.Add(6*time.Hour), exhausted.EarliestRecovery,
		"the horizon recomputes across the remaining live deadlines")
	assert.True(t, strings.HasSuffix(exhausted.Error(), "2026-10-28T18:00:00Z"))

	// Equal live deadlines collapse onto that one value.
	require.True(t, p.MarkUnavailable("c1", base.Add(3*time.Hour), "cooldown_test"))
	require.True(t, p.MarkUnavailable("c2", base.Add(3*time.Hour), "cooldown_test"))
	require.True(t, p.MarkUnavailable("c3", base.Add(3*time.Hour), "cooldown_test"))
	_, err = p.Acquire(context.Background())
	require.ErrorAs(t, err, &exhausted)
	assert.Equal(t, base.Add(3*time.Hour), exhausted.EarliestRecovery)
}

// TestCredentialPoolBoundary_EmptyPlaintextResolve pins the empty-key guard
// and the pick-accounting boundary: a source resolving ("", nil) fails the
// acquire with the typed empty-key error (masked ref, no lease), the pick
// still counts (selection completes before the resolve), pool state is
// untouched — an empty key is the caller's stale-key signal, not a
// quarantine — and the rotation continues on the sibling.
func TestCredentialPoolBoundary_EmptyPlaintextResolve(t *testing.T) {
	base := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	p, _ := newClockedPool(t, credKey("org-1", "openai-compat", "https://u.local"), base)
	require.NoError(t, p.Add(CredentialSpec{ID: "c1", Last4: "0001", KeyVersion: 1, Source: func(context.Context) (string, error) {
		return "", nil
	}}))
	require.NoError(t, p.Add(CredentialSpec{ID: "c2", Last4: "0002", KeyVersion: 1, Source: sourceFor("key-c2")}))

	lease, err := p.Acquire(context.Background())
	require.Error(t, err)
	assert.Nil(t, lease, "a failed resolve never yields a lease")
	require.ErrorContains(t, err, "resolved an empty key")
	require.ErrorContains(t, err, "cred=c1", "the failure surfaces the masked reference")
	assert.NotContains(t, err.Error(), "key-c2", "no sibling plaintext in the error")
	var exhausted *PoolExhaustedError
	require.NotErrorAs(t, err, &exhausted)
	require.NotErrorIs(t, err, ErrPoolEmpty)

	// Accounting: the pick counted at selection, not at resolve success.
	snap := p.Snapshot()
	assert.Equal(t, uint64(1), snap.Acquires)
	m, ok := snapshotMemberByID(p, "c1")
	require.True(t, ok)
	assert.Equal(t, uint64(1), m.Acquires)
	require.True(t, m.InRotation, "an empty-key resolve is not a quarantine signal")
	assert.Empty(t, m.UnavailableReason)
	assert.True(t, m.RecoversAt.IsZero())

	// The rotation continues on the sibling; c1 is served (and fails)
	// again — the caller decides via ReportOutcome, the pool never
	// self-quarantines on a resolve failure.
	got, err := p.Acquire(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "c2", got.Ref().ID)
	assert.Equal(t, "key-c2", got.Plaintext())
	_, err = p.Acquire(context.Background())
	require.ErrorContains(t, err, "resolved an empty key", "c1 is picked again and fails again")

	snap = p.Snapshot()
	assert.Equal(t, uint64(3), snap.Acquires, "picks: c1 fail, c2 ok, c1 fail")
	m, ok = snapshotMemberByID(p, "c1")
	require.True(t, ok)
	assert.Equal(t, uint64(2), m.Acquires)
	assert.Equal(t, 2, p.Len())
}
