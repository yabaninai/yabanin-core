package consumer

// N06-P04 T04 — the settlement-worker and delivery-boundary proofs for
// "settlement after cancel partial and errors". The packet's identity
// contract (pending_price is a separate never-claimable identity; a late
// priced event is its own resale_deduction intent) is pinned by
// n06p3_corpus_test.go, the delivery-layer failed-event wiring by
// n06p4_settlement_failed_pending_test.go, and the batch-side dispositions
// by the pkg/budget settlement batch tests (ReasonPoisonPayload,
// unknown-never-masked, cancel-partial settle-once). This file closes the
// three boundaries that had NO unit-level pin:
//
//  1. a per-job resale job that claims a positive quote but carries a
//     zero or refund-shaped (negative) amount — or no request identity —
//     parks as requires_attention/poison_payload on the FIRST attempt,
//     exactly like the batch executor's disposition; the retry budget is
//     never burned (closes the T03 handoff that suspected a per-job
//     retry loop: the ProcessDeduction contract guard precedes any store
//     call, and this test proves the classification, not just the error);
//  2. late usage arriving after a cancelled request, once the reconcile
//     safety window already returned the wallet reserve, settles the late
//     job ledger-only: no second reserve release, no reconcile key (the
//     exactly-once marker cannot be minted without a decrement);
//  3. a platform-absorbed upstream error produces ZERO settlement intents
//     in every reservations mode — the would-be charge is exported to
//     absorbed_upstream_error_micro_usd instead — while an absorbed
//     UNKNOWN cost still records its pending_price visibility row and
//     counts the bound: absorb never masks unknown as zero.

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExecuteJob_RefundShapedResaleJobIsPoisonNotRetry — the per-job
// disposition for a claimable wallet job that violates the charge contract
// matches the batch executor's poison_payload disposition on the first
// attempt. The worker is built with a configured (non-nil) store whose pool
// is nil: the poison must fire in ProcessDeduction's contract guard BEFORE
// any store call. If the guard regressed, DeductMicro would answer a plain
// "amount must be positive" error, classifyFailure would fall through to
// the default transient disposition, and the retry assertions below would
// fail — the test discriminates the guard, it does not merely observe an
// error.
func TestExecuteJob_RefundShapedResaleJobIsPoisonNotRetry(t *testing.T) {
	tests := []struct {
		name      string
		requestID string
		amount    money.MicroUSD
	}{
		{"zero amount", "req-poison-zero", 0},
		{"refund-shaped negative amount", "req-poison-negative", money.MicroUSD(-12000)},
		{"empty request identity", "", money.MicroUSD(12000)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := &fakeSettlementDB{}
			w := NewSettlementWorker(db, credits.NewStore(nil, silentLogger()), nil, silentLogger())

			job := &settlementJob{ID: 41, OrgID: "org", RequestID: tt.requestID,
				ChargeKind: ChargeKindResaleDeduction, AmountMicro: tt.amount,
				Payload: []byte(`{"model":"stub-model","tokens_in":50,"tokens_out":20}`)}

			beforeAttention := testutil.ToFloat64(metrics.SettlementJobsTotal.WithLabelValues(ChargeKindResaleDeduction, "requires_attention"))
			beforeRetry := testutil.ToFloat64(metrics.SettlementJobsTotal.WithLabelValues(ChargeKindResaleDeduction, "retry"))

			w.executeJob(context.Background(), job)

			parked := db.execsBySubstring("status = 'requires_attention'")
			require.Len(t, parked, 1, "a contract-violating wallet job parks as durable debt on the first attempt")
			require.Len(t, parked[0].args, 2)
			lastErr, ok := parked[0].args[1].(string)
			require.True(t, ok)
			require.Contains(t, lastErr, "invalid resale deduction charge",
				"the ProcessDeduction contract guard fired — not a misconfigured store, not a transient store error")
			assert.Empty(t, db.execsBySubstring("status = 'retry'"),
				"no retry marks: the poison never burns the retry budget")

			assert.InDelta(t, beforeAttention+1,
				testutil.ToFloat64(metrics.SettlementJobsTotal.WithLabelValues(ChargeKindResaleDeduction, "requires_attention")), 0.001)
			assert.InDelta(t, beforeRetry,
				testutil.ToFloat64(metrics.SettlementJobsTotal.WithLabelValues(ChargeKindResaleDeduction, "retry")), 0.001,
				"no retry is counted for a poison payload")
		})
	}
}

// TestSettle_ResaleReleasedAllowanceIsLedgerOnly — late usage after a
// cancelled request: the priced prefix job settles after the reconcile
// safety window already returned the wallet reserve. The settle is
// ledger-only — the charge itself committed through the usage ledger's
// (org, request) identity — with no second reserve release and no
// reconcile key: the key is minted atomically with a decrement, so its
// absence here can never make a replay look like a lost settle.
func TestSettle_ResaleReleasedAllowanceIsLedgerOnly(t *testing.T) {
	tx := &fakeSettlementTx{queryRowFn: func(query string) ([]any, error) {
		if strings.Contains(query, "FROM budget_allowances") {
			return []any{"wallet", "org", "", budget.AllowanceReleased}, nil
		}
		return nil, fmt.Errorf("unexpected QueryRow: %s", query)
	}}
	w := NewSettlementWorker(&stubBeginDB{tx: tx}, nil, nil, silentLogger())

	job := &settlementJob{ID: 42, OrgID: "org", RequestID: "req-late", ChargeKind: ChargeKindResaleDeduction,
		AmountMicro: money.MicroUSD(12000),
		Payload:     []byte(`{"model":"gpt-4","allowance_id":7,"bound_micro_usd":12000}`)}
	w.settle(context.Background(), job)

	assert.Empty(t, tx.execsByQuerySubstring("org_credits SET reserved_micro_usd"),
		"the reserve already went back with the reconcile — no second release")
	marks := tx.execsByQuerySubstring("status = 'settled'")
	require.Len(t, marks, 1, "the late job still settles — it must not retry forever")
	assert.Nil(t, marks[0].args[1], "no reconcile key without a decrement")
	assert.True(t, tx.committed)
}

// n06p4AbsorbedEvent is the request.failed shape of a request the platform
// served and absorbed: the provider failed mid-flight (upstream_error)
// with usage on the wire — the one termination whose cost the org never
// owes.
func n06p4AbsorbedEvent(requestID, priceQuote string) map[string]interface{} {
	fields := n06p4FailedEvent(requestID, priceQuote)
	fields["termination"] = "upstream_error"
	return fields
}

// n06p4ModeDB is n06p4CapturingDB with a parameterized reservations mode
// answer, for the absorbed-mode-independence proofs.
func n06p4ModeDB(t *testing.T, execs *[]execRecord, mode string) *mockDB {
	t.Helper()
	return &mockDB{
		ExecFn: func(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
			*execs = append(*execs, execRecord{query: query, args: args})
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
		QueryRowFn: func(_ context.Context, query string, _ ...any) pgx.Row {
			if strings.Contains(query, "FROM organizations") {
				return &fakeRow{vals: []any{mode}}
			}
			return &fakeRow{}
		},
	}
}

// TestUpstreamErrorAbsorbedIsNeverBilledAtDelivery — D3 at the delivery
// boundary: an absorbed upstream error emits no settlement statements in
// any reservations mode (the absorbed branch precedes the mode switch, so
// even an enforce org cannot be billed for platform-absorbed usage), while
// an absorbed UNKNOWN cost keeps its pending_price visibility row — absorb
// is never allowed to masquerade as a confirmed zero.
func TestUpstreamErrorAbsorbedIsNeverBilledAtDelivery(t *testing.T) {
	ctx := context.Background()

	t.Run("priced upstream error bills nothing in every reservations mode", func(t *testing.T) {
		for _, mode := range []string{modeEnforce, modeShadow, modeOff} {
			t.Run(mode, func(t *testing.T) {
				var execs []execRecord
				c := NewWithCreditStore(nil, n06p4ModeDB(t, &execs, mode), "", silentLogger(),
					credits.NewStore(nil, silentLogger()))
				msg := redis.XMessage{ID: "n06p4-absorbed-" + mode,
					Values: n06p4AbsorbedEvent("req-absorbed-"+mode, "0.12")}

				beforeAbsorbed := testutil.ToFloat64(metrics.AbsorbedUpstreamErrorMicroUSD.WithLabelValues("wallet"))
				beforeUnknown := testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("wallet"))
				require.NoError(t, c.handleRequestFailed(ctx, msg))

				require.Empty(t, n06p4ExecsByQuerySubstring(execs, "INSERT INTO settlement_jobs"),
					"platform-absorbed usage produces neither a wallet charge intent nor a visibility row in any mode")
				assert.InDelta(t, beforeAbsorbed+120000,
					testutil.ToFloat64(metrics.AbsorbedUpstreamErrorMicroUSD.WithLabelValues("wallet")), 0.001,
					"the would-be charge is exported to the absorbed metric, not dropped")
				assert.InDelta(t, beforeUnknown,
					testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("wallet")), 0.001,
					"a priced absorbed failure is not an unknown cost")
				require.Len(t, n06p4ExecsByQuerySubstring(execs, "INSERT INTO request_logs"), 1,
					"the analytics row still commits")
			})
		}
	})

	t.Run("absorbed upstream error with an unknown price still surfaces the pending record", func(t *testing.T) {
		var execs []execRecord
		c := NewWithCreditStore(nil, n06p4ModeDB(t, &execs, modeEnforce), "", silentLogger(),
			credits.NewStore(nil, silentLogger()))
		msg := redis.XMessage{ID: "n06p4-absorbed-unknown",
			Values: n06p4AbsorbedEvent("req-absorbed-unknown", "")}

		beforeUnknown := testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("wallet"))
		require.NoError(t, c.handleRequestFailed(ctx, msg))

		jobs := n06p4ExecsByQuerySubstring(execs, "INSERT INTO settlement_jobs")
		require.Len(t, jobs, 1, "absorb never masks an unknown cost — the visibility record still commits")
		require.Contains(t, jobs[0].query, "VALUES ($1, $2, $3, 0, 0, 'pending_price', $4)",
			"no amount literals: never billed, never a confirmed zero")
		require.Contains(t, jobs[0].query, "ON CONFLICT (org_id, request_id, charge_kind) DO NOTHING")
		require.Equal(t, ChargeKindPendingPrice, jobs[0].args[2])
		assert.Empty(t, n06p4ExecsByArgValue(execs, ChargeKindResaleDeduction),
			"an unknown price never produces a wallet charge intent, absorbed or not")
		assert.InDelta(t, beforeUnknown+120000,
			testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("wallet")), 0.001,
			"the uncharged reserve bound is counted, not masked as zero")
	})
}
