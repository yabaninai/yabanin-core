package consumer

// N06-P04 T05 — negative settlement convergence for cancel-partial and
// errors, at the real SettlementWorker seam (fakes only at the tx
// boundary): a resale job whose settle transaction fails — a transient
// exec error on the settle mark, or a lost lease (the mark finds the job
// no longer 'processing') — commits NOTHING on the interrupted pass and
// converges on the retry to exactly ONE reserve release with its
// reconcile key; and the release is bounded by the reservation, so a
// cancel-partial whose delivered prefix priced ABOVE the admission bound
// releases exactly the bound, never overdrafting the reserve.
//
// Already pinned elsewhere (cited, not duplicated):
//   - the agent-spend interruption window (spend + settle in ONE
//     transaction, lease loss, rollback whole) →
//     TestSettlementInterruptionRetryIdempotency (n06p3_corpus_test.go);
//   - the committed-charge replay guard (payload reconcile key) and the
//     released-allowance ledger-only settle →
//     TestSettle_ResaleReplayIsNoOpWithoutDecrement,
//     TestSettle_ResaleReleasedAllowanceIsLedgerOnly;
//   - the real-DB crash window where the charge stays committed and the
//     replayed DeductMicro is an idempotent no-op →
//     TestImp99R1Live_ResaleCrashWindowAppliesMissedRelease;
//   - the remainder-of-bound return after settle → pkg/budget reconcile
//     and settlement-batch tests.

import (
	"context"
	"fmt"
	"testing"

	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// n06p4ResaleJob is one cancel-partial resale_deduction job with a wallet
// reserve link: the durable shape a priced failed/cancelled delivery
// leaves behind for the settlement worker.
func n06p4ResaleJob(id int64, requestID string, amount, bound int64) *settlementJob {
	return &settlementJob{
		ID: id, OrgID: "org-n06", RequestID: requestID,
		ChargeKind: ChargeKindResaleDeduction, AmountMicro: money.MicroUSD(amount),
		Payload:  []byte(fmt.Sprintf(`{"model":"stub-model","allowance_id":7,"bound_micro_usd":%d}`, bound)),
		Attempts: 1,
	}
}

// TestN06P4ResaleSettleFailureConvergesToSingleRelease — the resale
// interruption window. The wallet charge commits in its own DeductMicro
// transaction BEFORE the settle; the settle transaction (release + mark +
// key) must be all-or-nothing: any failure rolls it back whole, and the
// recovered job settles exactly once across the whole retry history.
func TestN06P4ResaleSettleFailureConvergesToSingleRelease(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name    string
		breakTx func() *fakeSettlementTx
	}{
		{
			name: "transient settle-mark exec failure rolls back whole",
			breakTx: func() *fakeSettlementTx {
				return &fakeSettlementTx{
					queryRowFn: allowanceAnswer("wallet", "org-n06", ""),
					failNext:   map[string]int{"status = 'settled'": 1},
				}
			},
		},
		{
			name: "lost lease (mark finds the job no longer processing) rolls back whole",
			breakTx: func() *fakeSettlementTx {
				return &fakeSettlementTx{
					queryRowFn: allowanceAnswer("wallet", "org-n06", ""),
					zeroRows:   map[string]int{"status = 'settled'": 1},
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			job := n06p4ResaleJob(31, "req-n06p4-conv", 12000, 12000)
			interrupted := tc.breakTx()
			retry := &fakeSettlementTx{queryRowFn: allowanceAnswer("wallet", "org-n06", "")}
			db := &seqBeginDB{txs: []*fakeSettlementTx{interrupted, retry}}
			w := NewSettlementWorker(db, nil, nil, silentLogger())

			// Pass 1: the charge is already committed by the execute pass;
			// the settle must not commit half of itself.
			w.settle(ctx, job)

			require.True(t, interrupted.rolledBack(), "the interrupted settle rolled back whole")
			assert.False(t, interrupted.committed,
				"no release, no settled mark, no reconcile key ever commits from the interrupted pass")
			require.Len(t, interrupted.execsByQuerySubstring("reserved_micro_usd = reserved_micro_usd -"), 1,
				"the interrupted attempt reached the release inside its transaction — and rolled it back with the failure")
			assert.Empty(t, db.execs,
				"settle never re-queues or parks the job itself — the lease owns the retry, the charge stays committed")

			// Pass 2 (after lease recovery): exactly one committed release.
			w.settle(ctx, job)

			require.True(t, retry.committed)
			decrements := retry.execsByQuerySubstring("reserved_micro_usd = reserved_micro_usd -")
			require.Len(t, decrements, 1, "exactly one reserve release commits across both passes")
			assert.Equal(t, int64(12000), decrements[0].args[len(decrements[0].args)-1])
			marks := retry.execsByQuerySubstring("status = 'settled'")
			require.Len(t, marks, 1)
			assert.Contains(t, marks[0].query, budget.ReconcileSettleKey)
			assert.Equal(t, int64(12000), marks[0].args[1],
				"the reconcile key lands atomically with the settled mark")
			assert.False(t, retry.rolledBack())
		})
	}
}

// TestN06P4ResaleSettleReleaseNeverExceedsReserveBound — a cancel-partial
// whose delivered prefix priced ABOVE the admission bound (the price book
// moved between reserve and settle): the settle releases exactly the
// bound, and the reconcile key carries the released amount, not the
// charge amount.
func TestN06P4ResaleSettleReleaseNeverExceedsReserveBound(t *testing.T) {
	ctx := context.Background()
	tx := &fakeSettlementTx{queryRowFn: allowanceAnswer("wallet", "org-n06", "")}
	w := NewSettlementWorker(&stubBeginDB{tx: tx}, nil, nil, silentLogger())

	w.settle(ctx, n06p4ResaleJob(32, "req-n06p4-over", 15000, 12000))

	decrements := tx.execsByQuerySubstring("reserved_micro_usd = reserved_micro_usd -")
	require.Len(t, decrements, 1, "the release happens exactly once")
	assert.Equal(t, int64(12000), decrements[0].args[len(decrements[0].args)-1],
		"the release is min(actual, bound) — the reserve never overdrafts")
	marks := tx.execsByQuerySubstring("status = 'settled'")
	require.Len(t, marks, 1)
	assert.Equal(t, int64(12000), marks[0].args[1],
		"the reconcile key records the released amount, not the charge amount")
	require.True(t, tx.committed)
	assert.False(t, tx.rolledBack())
	// The remainder (actual − bound) belongs to the wallet charge itself;
	// reconcile's return of any leftover bound is pkg/budget coverage
	// (reconcile and settlement-batch tests).
}
