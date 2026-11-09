package upstream

// N08-P05-T09 [compatibility] — the rotation engine against the OLD and the
// NEW configuration shapes, walked through the supported consumer contract,
// with the explicit rejection surface for unsupported inputs:
//
//   - Consumer contract walk (old single-credential shape and new
//     multi-credential shape): a consumer following the documented
//     selection-failure contract — Acquire → one upstream attempt →
//     ReportOutcome; ErrPoolEmpty = a routing miss (the caller may use its
//     own fallback); *PoolExhaustedError = typed fail-closed (no fallback
//     key to an org-registered endpoint) — behaves identically per shape
//     and returns the recovered key without a race: the invalid key serves
//     again exactly at its staged deadline, never inside the window.
//   - Rejection-surface shape-invariance: every unsupported input (invalid
//     spec, duplicate id, unknown id, foreign-pool lease, non-quarantinable
//     status, all-quarantined selection) is refused with the SAME typed
//     outcome on the old shape and the new shape.
//
// Pinned contracts this corpus re-applies but does not change (T07/T08):
// the report-time re-quarantine horizon, lapse-keeps-diagnostics vs
// reset/rotation-clear, the boundary instant (deadline == now is lifted).
// Companion surfaces: credpool_test.go (battery), credpool_boundary_test.go
// (T07), credpool_joint_test.go (T06), credpool_recovery_test.go (T08).
// Deterministic; exercised under -race -shuffle -count=2.

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// consultCountingSource wraps a fixture plaintext with a consult counter:
// how often the pool resolved the plaintext (the pool consults the source
// exactly once per completed pick and never for an out-of-rotation member).
func consultCountingSource(secret string, consults *atomic.Int64) CredentialSource {
	return func(context.Context) (string, error) {
		consults.Add(1)
		return secret, nil
	}
}

func TestCredentialPoolCompat_ConsumerContractAcrossShapes(t *testing.T) {
	const day1End = "2026-10-30T00:00:00Z" // the 401 horizon from the base day
	base := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	midnight1 := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	midnight2 := time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)
	require.Equal(t, day1End, midnight1.Format(time.RFC3339))

	t.Run("old_single_member", func(t *testing.T) {
		p, clock := newClockedPool(t, credKey("org-a", "openai-compat", "https://u.local/v1"), base)
		var consults atomic.Int64
		require.NoError(t, p.Add(CredentialSpec{
			ID: "c1", Last4: "0001", KeyVersion: 1,
			Source: consultCountingSource("sk-compat-old-1", &consults),
		}))

		// The supported consumer's walk: acquire → attempt → report.
		lease, err := p.Acquire(context.Background())
		require.NoError(t, err)
		require.Equal(t, "c1", lease.Ref().ID)
		require.Equal(t, "sk-compat-old-1", lease.Plaintext())
		require.Equal(t, int64(1), consults.Load())

		// 401 quarantines the sole credential to the next UTC midnight.
		require.True(t, p.ReportOutcome(lease, http.StatusUnauthorized))
		snap := p.Snapshot()
		require.False(t, snap.Members[0].InRotation)
		require.Equal(t, QuarantineReasonUnauthorized, snap.Members[0].UnavailableReason)
		require.Equal(t, midnight1, snap.Members[0].RecoversAt)
		require.Equal(t, 1, p.Len(), "recovery never re-inserts a member")

		// Typed fail-closed: exhausted is NOT the routing miss; the consumer
		// must refuse the attempt instead of using a fallback key.
		for range 5 {
			_, err = p.Acquire(context.Background())
			var exhausted *PoolExhaustedError
			require.ErrorAs(t, err, &exhausted)
			require.NotErrorIs(t, err, ErrPoolEmpty)
			require.Equal(t, midnight1, exhausted.EarliestRecovery)
		}
		require.Equal(t, int64(1), consults.Load(),
			"the invalid key is not repeated: no source consult while out of rotation")

		// The pool continues: the recovered key returns exactly at the
		// staged deadline (the boundary instant itself is lifted).
		*clock = midnight1
		lease2, err := p.Acquire(context.Background())
		require.NoError(t, err)
		require.Equal(t, "c1", lease2.Ref().ID)
		require.Equal(t, "sk-compat-old-1", lease2.Plaintext())
		require.Equal(t, int64(2), consults.Load())

		// The next negative re-quarantines on the report-time horizon
		// (the T08 pin, re-applied compat: same on the old shape).
		require.True(t, p.ReportOutcome(lease2, http.StatusUnauthorized))
		_, err = p.Acquire(context.Background())
		var exhausted *PoolExhaustedError
		require.ErrorAs(t, err, &exhausted)
		require.Equal(t, midnight2, exhausted.EarliestRecovery)

		// A non-quarantinable outcome neither quarantines nor lifts.
		snap = p.Snapshot()
		require.True(t, p.ReportOutcome(lease2, http.StatusBadRequest))
		require.True(t, p.ReportOutcome(lease2, http.StatusInternalServerError))
		require.Equal(t, snap, p.Snapshot())
	})

	t.Run("new_multi_member", func(t *testing.T) {
		p, clock := newClockedPool(t, credKey("org-a", "openai-compat", "https://u.local/v1"), base)
		consults := map[string]*atomic.Int64{
			"c1": {}, "c2": {}, "c3": {},
		}
		for _, id := range []string{"c1", "c2", "c3"} {
			require.NoError(t, p.Add(CredentialSpec{
				ID: id, Last4: "000" + id[1:], KeyVersion: 1,
				Source: consultCountingSource("sk-compat-new-"+id[1:], consults[id]),
			}))
		}

		next := func() *Lease {
			lease, err := p.Acquire(context.Background())
			require.NoError(t, err)
			return lease
		}
		pickID := func() string {
			return next().Ref().ID
		}

		// Fresh rotation serves in order; the 401 quarantines the invalid
		// key and the siblings carry the endpoint (fair, in order).
		l1, l2, l3 := next(), next(), next()
		require.Equal(t, []string{"c1", "c2", "c3"},
			[]string{l1.Ref().ID, l2.Ref().ID, l3.Ref().ID})
		require.True(t, p.ReportOutcome(l1, http.StatusUnauthorized))
		require.Equal(t, []string{"c2", "c3", "c2"},
			[]string{pickID(), pickID(), pickID()},
			"the invalid key is not repeated: strict sibling rotation")

		// The pool continues: the recovered key rejoins at its RR position
		// exactly at the staged deadline. The scan starts at the cursor the
		// sibling rotation left off (c2 was picked last → scan opens at
		// idx2), so the next full cycle is c3, then the recovered c1, then
		// c2 — full rotation restored, no pick lost or duplicated.
		*clock = midnight1
		require.Equal(t, []string{"c3", "c1", "c2"},
			[]string{pickID(), pickID(), pickID()})

		// Loss-free accounting: the pool counter is the sum of the members.
		snap := p.Snapshot()
		require.Equal(t, uint64(9), snap.Acquires)
		var memberTotal uint64
		for _, m := range snap.Members {
			memberTotal += m.Acquires
		}
		require.Equal(t, snap.Acquires, memberTotal)
		require.Equal(t, uint64(2), snap.Members[0].Acquires)
		require.Equal(t, uint64(4), snap.Members[1].Acquires)
		require.Equal(t, uint64(3), snap.Members[2].Acquires)
		require.Equal(t, int64(2), consults["c1"].Load())
		require.Equal(t, int64(4), consults["c2"].Load())
		require.Equal(t, int64(3), consults["c3"].Load())
		// Isolation (the negative's second clause): the same credential ids
		// of ANOTHER org live in their own pool — p1's quarantine never
		// touches them, and a foreign lease refused by p1 mutates nothing.
		before := p.Snapshot()
		other := NewCredentialPool(credKey("org-b", "openai-compat", "https://u.local/v1"))
		for _, id := range []string{"c1", "c2", "c3"} {
			require.NoError(t, other.Add(CredentialSpec{
				ID: id, Last4: "000" + id[1:], KeyVersion: 1,
				Source: sourceFor("sk-other-org-" + id),
			}))
		}
		foreignLease, err := other.Acquire(context.Background())
		require.NoError(t, err)
		require.Equal(t, "c1", foreignLease.Ref().ID, "org-b's pool is untouched by org-a's quarantine")
		require.False(t, p.ReportOutcome(foreignLease, http.StatusUnauthorized),
			"a lease binds its report to its own pool")
		require.Equal(t, before, p.Snapshot())

		// Race surface (bounded, deterministic accounting): concurrent
		// serve with 200 no-op reports — no exhausted, no double-pick, the
		// registry invariants hold under -race.
		const workers = 8
		const perWorker = 40
		var wg sync.WaitGroup
		concurrent := map[string]*atomic.Int64{"c1": {}, "c2": {}, "c3": {}}
		var failures atomic.Int64
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range perWorker {
					lease, err := p.Acquire(context.Background())
					if err != nil {
						failures.Add(1)
						continue
					}
					if !p.ReportOutcome(lease, http.StatusOK) {
						failures.Add(1)
					}
					concurrent[lease.Ref().ID].Add(1)
				}
			}()
		}
		wg.Wait()
		require.Zero(t, failures.Load(), "every concurrent acquire succeeds while all members rotate")
		snap = p.Snapshot()
		require.Equal(t, 3, p.Len())
		require.Equal(t, uint64(workers*perWorker), snap.Acquires-before.Acquires)
		for i, id := range []string{"c1", "c2", "c3"} {
			//nolint:gosec // G115: the atomic counter only ever holds a
			// non-negative acquire count (same-type assertion, 43e7223).
			require.Equal(t, before.Members[i].Acquires+uint64(concurrent[id].Load()),
				snap.Members[i].Acquires, "member %s: no lost or duplicated picks", id)
		}
	})
}

// TestCredentialPoolCompat_RejectionSurfaceShapeInvariant: every unsupported
// input is refused with the SAME typed outcome on the old configuration
// shape (a single held credential) and the new shape (several) — invalid
// specs, duplicate ids, unknown ids, foreign-pool leases, non-quarantinable
// statuses — and the two selection-failure surfaces stay distinct
// (ErrPoolEmpty routing miss vs typed *PoolExhaustedError fail-closed).
func TestCredentialPoolCompat_RejectionSurfaceShapeInvariant(t *testing.T) {
	for _, shape := range []struct {
		name string
		ids  []string
	}{
		{name: "old_single", ids: []string{"m1"}},
		{name: "new_multi", ids: []string{"m1", "m2", "m3"}},
	} {
		t.Run(shape.name, func(t *testing.T) {
			p := NewCredentialPool(credKey("org-a", "openai-compat", "https://u.local/v1"))
			for _, id := range shape.ids {
				require.NoError(t, p.Add(CredentialSpec{
					ID: id, Last4: "0042", KeyVersion: 1,
					Source: sourceFor("sk-shape-" + id),
				}))
			}
			spec := func(id string) CredentialSpec {
				return CredentialSpec{
					ID: id, Last4: "0042", KeyVersion: 1,
					Source: sourceFor("sk-shape-" + id),
				}
			}

			// Duplicate id.
			require.Len(t, shape.ids, p.Len())
			err := p.Add(spec(shape.ids[0]))
			require.ErrorIs(t, err, ErrDuplicateCredential)
			require.Len(t, shape.ids, p.Len(), "the refused spec leaves no member")

			// Invalid specs: no id, no source; upsert follows the same rule.
			require.ErrorIs(t, p.Add(CredentialSpec{Source: sourceFor("sk-noid")}), ErrInvalidCredential)
			require.ErrorIs(t, p.Add(CredentialSpec{ID: "m9"}), ErrInvalidCredential)
			require.ErrorIs(t, p.UpsertCredential(CredentialSpec{Source: sourceFor("sk-noid")}), ErrInvalidCredential)
			require.Len(t, shape.ids, p.Len())

			// Unknown ids: every mutation reports false, nothing changes.
			before := p.Snapshot()
			require.False(t, p.Remove("m9"))
			require.False(t, p.MarkUnavailable("m9", time.Now().Add(time.Hour), QuarantineReasonUnauthorized))
			require.False(t, p.MarkRecovered("m9"))
			require.Equal(t, before, p.Snapshot())

			// A lease binds its report to its own pool; nil is refused too.
			other := NewCredentialPool(credKey("org-b", "openai-compat", "https://u.local/v1"))
			require.NoError(t, other.Add(spec("m1")))
			foreign, ferr := other.Acquire(context.Background())
			require.NoError(t, ferr)
			require.False(t, p.ReportOutcome(foreign, http.StatusUnauthorized))
			require.False(t, p.ReportOutcome(nil, http.StatusUnauthorized))
			require.Equal(t, before, p.Snapshot())

			// Non-quarantinable statuses are recognized no-ops on a held
			// lease (true) and never lift or set a quarantine.
			lease, aerr := p.Acquire(context.Background())
			require.NoError(t, aerr)
			require.Equal(t, shape.ids[0], lease.Ref().ID)
			require.True(t, p.ReportOutcome(lease, http.StatusBadRequest))
			require.True(t, p.ReportOutcome(lease, http.StatusInternalServerError))
			snap := p.Snapshot()
			require.True(t, snap.Members[0].InRotation)
			require.Empty(t, snap.Members[0].UnavailableReason)

			// Quarantine every member (shape-invariant bounded loop), then
			// the selection refuses typed: exhausted, not the routing miss.
			for range shape.ids {
				l, aerr := p.Acquire(context.Background())
				require.NoError(t, aerr)
				require.True(t, p.ReportOutcome(l, http.StatusUnauthorized))
			}
			_, aerr = p.Acquire(context.Background())
			var exhausted *PoolExhaustedError
			require.ErrorAs(t, aerr, &exhausted)
			require.NotErrorIs(t, aerr, ErrPoolEmpty,
				"all-quarantined is fail-closed, not a routing miss")
			snap = p.Snapshot()
			for _, m := range snap.Members {
				require.False(t, m.InRotation)
				require.Equal(t, QuarantineReasonUnauthorized, m.UnavailableReason)
			}

			// The empty pool is the OTHER surface: a routing miss the
			// caller may fall through from — never the typed refusal.
			empty := NewCredentialPool(credKey("org-c", "openai-compat", "https://u.local/v1"))
			_, eerr := empty.Acquire(context.Background())
			require.ErrorIs(t, eerr, ErrPoolEmpty)
			require.NotErrorAs(t, eerr, &exhausted)
		})
	}
}
