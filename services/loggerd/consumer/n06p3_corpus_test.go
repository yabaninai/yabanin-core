package consumer

// N06-P03 T08 — the settlement-interruption corpus: the pending_price
// visibility record under a mid-flight mode flip (never double-bills), the
// lease-loss interruption window of the settlement worker, and retry
// idempotency, all at the unit boundary (mock seams, no DB).
//
// Coverage cited instead of duplicated:
//   - live pending_price redelivery keeps exactly one row and the request
//     logged → TestR041Failure_PendingPriceInsertFailsNothingPartialAndRedeliveryLogs;
//   - live worker ticks leave a pending_price row pending (non-claimable)
//     and its expiry terminates it → TestR041Integration_* and
//     TestR041FailureCancel_* (r041_settlement_cancel_live_test.go);
//   - the resale replay guard (payload reconcile key → no second decrement)
//     → TestSettle_ResaleReplayIsNoOpWithoutDecrement;
//   - transient → retry, never a fake success → TestExecuteJob_TransientErrorIsRetryNotSuccess;
//   - crash/restart of the RESERVATION side (self-reap sweep, safety window)
//     → the live TestR042SelfReap_* suite in pkg/budget; the ledger-boundary
//     unit half lives in pkg/budget's N06-P03 corpus.

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ppCaptureTx records every statement an intent write binds (an InboxTx).
type ppCaptureTx struct {
	mu    sync.Mutex
	execs []execRecord
}

func (t *ppCaptureTx) Exec(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.execs = append(t.execs, execRecord{query: query, args: args})
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

func (t *ppCaptureTx) QueryRow(context.Context, string, ...any) pgx.Row {
	return &fakeTxRow{err: context.Canceled}
}
func (t *ppCaptureTx) Commit(context.Context) error   { return nil }
func (t *ppCaptureTx) Rollback(context.Context) error { return nil }

func (t *ppCaptureTx) recorded() []execRecord {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]execRecord(nil), t.execs...)
}

// ppConsumer is a bare consumer: the intent write paths touch only the
// logger — no DB pool, no Redis, and deliberately no org-mode cache exists
// on this path (settlement is a pure function of the event).
func ppConsumer() *StreamConsumer { return &StreamConsumer{logger: silentLogger()} }

// ppBillingConsumer adds a configured (nil-DB) credit store so the wallet
// intent gate passes — the insert itself never touches the store.
func ppBillingConsumer() *StreamConsumer {
	return &StreamConsumer{logger: silentLogger(), creditStore: credits.NewStore(nil, silentLogger())}
}

// ppReservedEvent parses one completed event whose usage arrived but whose
// price stayed unknown, carrying wallet (+optional team) reserve tuples —
// the shape a reserved request lands with when the price book misses.
func ppReservedEvent(t *testing.T, requestID string, withTeam bool) requestEvent {
	t.Helper()
	tuples := `[{"scope_kind":"wallet","scope_key":"org-n06","period":"","allowance_id":7,"bound_micro_usd":120000}`
	if withTeam {
		tuples += `,{"scope_kind":"team_month","scope_key":"team-n06","period":"2026-10","allowance_id":8,"bound_micro_usd":50000}`
	}
	tuples += `]`
	return parseRequestEvent(map[string]interface{}{
		"org_id":       "org-n06",
		"request_id":   requestID,
		"usage_source": "provider",
		"termination":  "completed",
		"reservations": tuples,
	})
}

// TestPendingPriceInterruptionCorpus — T08: the unknown-cost visibility
// record under interruption and mode flips. Never billed, never claimable,
// idempotent under redelivery, and invariant against an org's mode flip.
func TestPendingPriceInterruptionCorpus(t *testing.T) {
	ctx := context.Background()

	t.Run("unknown cost with a reserve records exactly one never-billed row", func(t *testing.T) {
		ev := ppReservedEvent(t, "req-pp-1", true)
		tx := &ppCaptureTx{}
		require.NoError(t, ppConsumer().insertPendingPriceIntent(ctx, tx, ev, money.QuoteUnknown))

		execs := tx.recorded()
		require.Len(t, execs, 1)
		e := execs[0]
		require.Contains(t, e.query, "INSERT INTO settlement_jobs")
		require.Contains(t, e.query, "VALUES ($1, $2, $3, 0, 0, 'pending_price', $4)",
			"the record carries no amount: never billed, never a confirmed zero")
		require.Contains(t, e.query, "ON CONFLICT (org_id, request_id, charge_kind) DO NOTHING",
			"the (org, request, kind) identity makes a redelivery re-insert nothing")
		require.Equal(t, "org-n06", e.args[0])
		require.Equal(t, "req-pp-1", e.args[1])
		require.Equal(t, ChargeKindPendingPrice, e.args[2])

		var payload struct {
			Termination  string `json:"termination"`
			Reservations []struct {
				ScopeKind     string `json:"scope_kind"`
				BoundMicroUSD int64  `json:"bound_micro_usd"`
			} `json:"reservations"`
		}
		require.NoError(t, json.Unmarshal(e.args[3].([]byte), &payload))
		assert.Equal(t, "completed", payload.Termination)
		require.Len(t, payload.Reservations, 2, "every reserved scope stays visible")
		assert.Equal(t, "wallet", payload.Reservations[0].ScopeKind)
		assert.Equal(t, int64(120000), payload.Reservations[0].BoundMicroUSD)
		assert.Equal(t, "team_month", payload.Reservations[1].ScopeKind)
	})

	t.Run("skip matrix: nothing at stake means no record", func(t *testing.T) {
		ev := ppReservedEvent(t, "req-pp-skip", true)
		for _, tc := range []struct {
			name        string
			state       money.QuoteState
			usageSource string
			reserved    bool
			org         string
			request     string
		}{
			{"price known — the charge intents govern, no visibility row", money.QuotePositive, "provider", true, "org-n06", "r"},
			{"price explicitly zero — billed as zero, no unknown at stake", money.QuoteZero, "provider", true, "org-n06", "r"},
			{"no usage — nothing can be unknown (policy_denied etc.)", money.QuoteUnknown, "none", true, "org-n06", "r"},
			{"no reserve (legacy org) — nothing was at stake", money.QuoteUnknown, "provider", false, "org-n06", "r"},
			{"no org identity", money.QuoteUnknown, "provider", true, "", "r"},
			{"no request identity", money.QuoteUnknown, "provider", true, "org-n06", ""},
		} {
			t.Run(tc.name, func(t *testing.T) {
				e := ev
				e.acct.usageSource = tc.usageSource
				if !tc.reserved {
					e.reservations = nil
				}
				e.orgID, e.requestID = tc.org, tc.request
				tx := &ppCaptureTx{}
				require.NoError(t, ppConsumer().insertPendingPriceIntent(ctx, tx, e, tc.state))
				assert.Empty(t, tx.recorded())
			})
		}
	})

	t.Run("mode flip invariance: settlement is a pure function of the event", func(t *testing.T) {
		// The consumer holds no reservations-mode state on the settle path:
		// a flip (enforce→shadow or back) between deliveries of the SAME
		// event cannot change any write — including the pending_price record
		// and the absent charge intent. A cold (restarted) consumer behaves
		// byte-identically to a warm one.
		ev := ppReservedEvent(t, "req-pp-flip", true)

		beforeFlip := &ppCaptureTx{}
		require.NoError(t, ppConsumer().insertPendingPriceIntent(ctx, beforeFlip, ev, money.QuoteUnknown))
		afterFlip := &ppCaptureTx{} // "after" — nothing consumer-side changed
		require.NoError(t, ppConsumer().insertPendingPriceIntent(ctx, afterFlip, ev, money.QuoteUnknown))
		restarted := &ppCaptureTx{} // a cold consumer after a restart
		require.NoError(t, ppConsumer().insertPendingPriceIntent(ctx, restarted, ev, money.QuoteUnknown))

		require.Equal(t, beforeFlip.recorded(), afterFlip.recorded())
		require.Equal(t, beforeFlip.recorded(), restarted.recorded())

		// The charge plan under an unknown price carries NO wallet charge in
		// any mode — the org flipping to enforce mid-flight cannot turn the
		// unknown cost into a bill, and the flip to shadow cannot erase the
		// reserve visibility (the pending row above).
		planUnknown := scopeChargePlan(ev, 0, money.QuoteUnknown)
		require.Len(t, planUnknown, 1, "only the zero-amount team count intent remains")
		assert.Equal(t, ChargeKindTeamSpend, planUnknown[0].kind)
		assert.Zero(t, int64(planUnknown[0].amount), "the budget area counts the request, never charges it")
		for _, sc := range planUnknown {
			assert.NotEqual(t, ChargeKindResaleDeduction, sc.kind,
				"an unknown price never bills the wallet, whatever the org mode says")
		}
	})

	t.Run("a later-known price bills exactly once; the pending row never becomes a charge", func(t *testing.T) {
		// The price book recovers and the event is redelivered priced: the
		// wallet intent appears — once, identity-guarded — while the existing
		// pending_price row is untouched by it (different identity) and only
		// ever expires to 'unknown', never converts to a charge.
		ev := ppReservedEvent(t, "req-pp-priced", false)
		plan := scopeChargePlan(ev, money.MicroUSD(120000), money.QuotePositive)
		require.Len(t, plan, 1)
		require.Equal(t, ChargeKindResaleDeduction, plan[0].kind)
		require.Equal(t, int64(7), plan[0].link.AllowanceID, "the reserve linkage rides the charge")

		tx := &ppCaptureTx{}
		require.NoError(t, ppBillingConsumer().insertScopeIntent(ctx, tx, "org-n06", ev.requestID,
			plan[0], 10, 20, 0.012, 0.012, "stub-model"))
		execs := tx.recorded()
		require.Len(t, execs, 1)
		require.Contains(t, execs[0].query, "ON CONFLICT (org_id, request_id, charge_kind) DO NOTHING")
		require.Equal(t, "org-n06", execs[0].args[0])
		require.Equal(t, ev.requestID, execs[0].args[1])
		require.Equal(t, ChargeKindResaleDeduction, execs[0].args[2])
		require.Equal(t, int64(12), execs[0].args[3], "exact cents projection")
		require.Equal(t, int64(120000), execs[0].args[4], "exact micro amount (AF-05)")

		// The pending_price insert statement cannot produce a charge (amount
		// literals 0,0) and the charge insert cannot land as pending_price
		// (status literal 'pending'): the two identities cannot merge.
		require.Contains(t, pendingPriceIntentQuery, "'pending_price'")
		require.NotContains(t, settlementIntentQuery, "pending_price")
	})

	t.Run("pending_price is non-claimable and expires to 'unknown', never to a charge", func(t *testing.T) {
		// Schema pins: the lease query must only ever claim executable
		// rows, and expiry must terminate pending_price alone — pinned as
		// string literals so a query rewrite cannot silently widen either
		// contract.
		require.Contains(t, claimReadyJobsQuery, "status IN ('pending', 'retry')",
			"the claim leases only executable work")
		require.NotContains(t, claimReadyJobsQuery, "pending_price",
			"an unknown-cost record is never claimable, so it can never bill")
		require.NotContains(t, claimReadyJobsQuery, "settled",
			"a settled job is terminal — a worker restart can never re-execute it")
		require.Contains(t, expirePendingPriceQuery, "SET")
		require.Contains(t, expirePendingPriceQuery, "status = 'unknown'")
		require.Contains(t, expirePendingPriceQuery, "WHERE status = 'pending_price'")

		// The expiry pass terminates ONLY pending_price rows, with the
		// never-billed diagnostic, and counts them.
		db := &fakeSettlementDB{tagRows: 2}
		w := newUnitWorker(db).WithConfig(SettlementConfig{PendingPriceExpiry: 2 * time.Second})
		before := testutil.ToFloat64(metrics.SettlementPendingPriceExpiredTotal)
		w.expirePendingPrice(ctx)

		execs := db.execsBySubstring("status = 'unknown'")
		require.Len(t, execs, 1)
		require.Len(t, execs[0].args, 2)
		assert.InDelta(t, float64(2), execs[0].args[0], 1e-9, "the configured pending deadline, in seconds")
		assert.Contains(t, execs[0].args[1], "never billed")
		assert.InDelta(t, before+2, testutil.ToFloat64(metrics.SettlementPendingPriceExpiredTotal), 0.001)
	})
}

// seqBeginDB serves prepared transactions in sequence (the interruption
// windows between two attempts of the same job) and records worker-level
// writes (retry/attention marks).
type seqBeginDB struct {
	mu    sync.Mutex
	txs   []*fakeSettlementTx
	i     int
	execs []execRecord
}

func (d *seqBeginDB) Begin(context.Context) (pgx.Tx, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.i++
	if d.i > len(d.txs) {
		return nil, context.Canceled
	}
	return d.txs[d.i-1], nil
}

func (d *seqBeginDB) Exec(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.execs = append(d.execs, execRecord{query: query, args: args})
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

func (d *seqBeginDB) QueryRow(context.Context, string, ...any) pgx.Row { return &fakeRow{} }
func (d *seqBeginDB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return &fakeRows{}, nil
}

func (d *seqBeginDB) execsBySubstring(sub string) []execRecord {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []execRecord
	for _, e := range d.execs {
		if strings.Contains(e.query, sub) {
			out = append(out, e)
		}
	}
	return out
}

func allowanceAnswer(scope, key, period string) func(string) ([]any, error) {
	return func(query string) ([]any, error) {
		if strings.Contains(query, "FROM budget_allowances") {
			return []any{scope, key, period, "active"}, nil
		}
		return nil, context.Canceled
	}
}

// TestSettlementInterruptionRetryIdempotency — T08: the lease-loss
// interruption window. A worker claims a job, executes the money side
// effect, and dies before the settle mark commits (or its lease is stolen by
// the expiry recovery): the half-done attempt must roll back whole, the
// job must come back as retry, and the re-owning attempt must apply the
// side effect exactly once.
func TestSettlementInterruptionRetryIdempotency(t *testing.T) {
	ctx := context.Background()
	payload := []byte(`{"agent_id":"agent-n06","tokens_in":10,"tokens_out":5,"allowance_id":77,"bound_micro_usd":12000}`)
	job := &settlementJob{
		ID: 101, OrgID: "org-n06", RequestID: "req-int-1", ChargeKind: ChargeKindAgentSpend,
		AmountMicro: money.MicroUSD(15000), Payload: payload, Attempts: 1,
	}

	// Attempt 1: the spend applies INSIDE the transaction, but the settle
	// mark finds the job no longer 'processing' — the lease was recovered by
	// another worker between claim and settle (W-LOGG). The whole
	// transaction rolls back: no spend, no settle mark, no reconcile key.
	lostLease := &fakeSettlementTx{
		queryRowFn: allowanceAnswer("agent_day", "agent-n06", "2026-10-02"),
		zeroRows:   map[string]int{"status = 'settled'": 1},
	}
	// Attempt 2: a clean transaction — the re-owned job executes fully.
	retryTx := &fakeSettlementTx{queryRowFn: allowanceAnswer("agent_day", "agent-n06", "2026-10-02")}
	spender := &recordingExactSpender{}
	db := &seqBeginDB{txs: []*fakeSettlementTx{lostLease, retryTx}}
	w := NewSettlementWorker(db, nil, spender, silentLogger()).
		WithConfig(SettlementConfig{BackoffBase: time.Millisecond, BackoffMax: 5 * time.Millisecond})

	w.executeJob(ctx, job) // interrupted attempt

	require.Len(t, db.execsBySubstring("status = 'retry'"), 1,
		"the interrupted attempt re-queues as retry (transient, not terminal)")
	require.Empty(t, db.execsBySubstring("status = 'requires_attention'"),
		"a lease loss is never a diagnostic debt")
	require.Len(t, lostLease.execsByQuerySubstring(budget.ReconcileSettleKey), 1,
		"the attempt bound its settle mark before the lease check refused it")
	require.True(t, lostLease.rolledBack(), "the half-done attempt rolled back whole")
	assert.False(t, lostLease.committed,
		"rolled back: no spend, no reserve release, no reconcile key ever committed")

	// The recovered job re-executes: spend + reserve release + settle mark
	// commit as ONE unit, exactly once.
	w.executeJob(ctx, job)

	require.True(t, retryTx.committed)
	decrements := retryTx.execsByQuerySubstring("reserved_micro_usd = reserved_micro_usd -")
	require.Len(t, decrements, 1)
	assert.Equal(t, int64(12000), decrements[0].args[len(decrements[0].args)-1],
		"min(actual 15000, bound 12000) leaves the scope reserve")
	marks := retryTx.execsByQuerySubstring("status = 'settled'")
	require.Len(t, marks, 1)
	assert.Contains(t, marks[0].query, budget.ReconcileSettleKey)
	assert.Equal(t, int64(12000), marks[0].args[1],
		"the reconcile key lands atomically with the committed settle")
	assert.False(t, retryTx.rolledBack())

	// Exactly-once: the durable money effect exists only in the committed
	// transaction. The interrupted attempt's spend was rolled back with it.
	require.Len(t, spender.calls, 2, "both attempts executed the spend inside their own transaction")
	assert.Equal(t, int64(15000), spender.calls[0].micro)
	assert.Equal(t, int64(15000), spender.calls[1].micro)
}
