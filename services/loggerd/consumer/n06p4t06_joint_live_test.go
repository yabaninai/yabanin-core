package consumer

// N06-P04 T06 — the joint user scenario of the settlement packet, on the
// real stand (disposable PG+Redis, the same live acceptance environment
// the existing cancel and settlement live tests use). Every fact below is
// produced by the real delivery transaction, the real settlement worker
// and the real budget reconcile worker against the real tables. The
// mock-seam boundaries
// of the same contract stay in n06p4_dup_delivery_test.go (T05 — the
// recovery-then-settle race at the store seams) and
// n06p4_settlement_cancel_late_test.go (T04 — per-job poison and absorbed
// upstream errors at unit level); this file never repeats those pins.
//
// Stories (cancel-partial × late-usage joint matrix):
//
//   - A priced: the cancel bills the consumed prefix exactly once (D1, no
//     refund) → a replay on a fresh stream entry is a silent no-op → the
//     reconcile releases every un-consumed bound past the §14 safety
//     window (§7.1.1) → the LATE corrected usage event converges into the
//     SAME operation: the first amounts stay authoritative, the
//     corrections are reported per kind, no second charge anywhere.
//   - B unknown: the cancel stays visible as ONE pending_price record (D2
//     — never billed, never a confirmed zero) → the worker never claims it
//     → the reconcile returns the stake → the late priced usage bills ONCE
//     as its own identity, ledger-only against the released reserve → the
//     pending record stays visible, untouched.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// n06p4t06LateUsageMsg is the late corrected usage event for a request that
// already terminated: the provider's final numbers (base cost 0.006, resale
// price 0.010) with the same reservation tuples the request held.
func n06p4t06LateUsageMsg(entryID, requestID, org string, fx n18dFixture) redis.XMessage {
	msg := n18dCompletedMsg(entryID, requestID, org, fx)
	msg.Values["usage_source"] = "provider"
	msg.Values["estimated_cost_usd"] = "0.006"
	msg.Values["resale_cost_usd"] = "0.010"
	return msg
}

// n06p4t06ReleaseStake lapses the org's leases past the §14 safety window
// (2h) and runs one real reconcile release pass.
func n06p4t06ReleaseStake(ctx context.Context, t *testing.T, pool *pgxpool.Pool, org string) {
	t.Helper()
	_, err := pool.Exec(ctx,
		`UPDATE budget_allowances SET lease_until = now() - interval '3 hours' WHERE org_id = $1`, org)
	require.NoError(t, err)
	_, err = budget.NewReconcileWorker(pool, silentLogger(), budget.DefaultReconcileConfig()).ReleasePass(ctx)
	require.NoError(t, err)
}

// Story A: priced cancel → settle once → replay no-op → reconcile release
// (no refund) → late corrected usage converges into the SAME operation.
func TestN06P4T06Live_CancelPartialReconcileAndLateUsageAreOneOperation(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrg, 1000)

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:n06p4t06", silentLogger())
	c.SetAgentSpender(budget.NewAgentEnforcer(pool, silentLogger()))
	c.creditStore = credits.NewStore(pool, silentLogger())
	w := NewSettlementWorker(pool, c.creditStore, budget.NewAgentEnforcer(pool, silentLogger()), silentLogger()).
		WithConfig(liveSettlementConfig())

	// 1) The priced client cancel (base 0.004, resale 0.008, bound 0.012
	//    per scope): four intents, the worker settles them once.
	require.NoError(t, c.processMessage(ctx, r041CancelMsg("n06p4t06-a1", "req-n06p4t06-a", n18dOrg, fx)))
	require.Equal(t, int64(4), n18dJobCount(ctx, t, pool, n18dOrg), "one intent per reserved scope")
	w.tick(ctx)

	walletReserved, teamReserved, teamSpend, agentReserved, agentCost, sessionReserved, sessionSpent, ledgerRows, ledgerMicro := n18dScopeStates(ctx, t, pool, n18dOrg)
	require.Equal(t, int64(1), ledgerRows, "one wallet usage row")
	require.Equal(t, int64(-8000), ledgerMicro, "the wallet billed the consumed prefix's resale price once")
	require.Equal(t, int64(4000), teamSpend, "team billed the prefix's base cost")
	require.Equal(t, int64(4000), agentCost, "agent billed the prefix's base cost")
	require.Equal(t, int64(4000), sessionSpent, "session billed the prefix's base cost")
	require.Equal(t, int64(4000), walletReserved, "the un-consumed wallet bound stays reserved for the reconcile")
	require.Equal(t, int64(8000), teamReserved)
	require.Equal(t, int64(8000), agentReserved)
	require.Equal(t, int64(8000), sessionReserved)
	balance, remainder := requireWalletState(ctx, t, pool, n18dOrg)
	require.Equal(t, int64(1000), balance)
	require.Equal(t, int64(8000), remainder,
		"the 8000µ prefix is sub-cent: it accumulates durably as the remainder, no cent is invented or lost")
	require.Equal(t, int64(9_992_000), balance*10_000-remainder,
		"the effective wallet dropped by exactly the charged prefix")

	// 2) A replay of the same cancel on a fresh stream entry: the delivery
	//    is refused by the settlement identities (same amounts — a silent
	//    no-op, not a disagreement), nothing anywhere.
	resaleConflicts := testutil.ToFloat64(metrics.SettlementIntentConflicts.WithLabelValues(ChargeKindResaleDeduction))
	require.NoError(t, c.processMessage(ctx, r041CancelMsg("n06p4t06-a2", "req-n06p4t06-a", n18dOrg, fx)))
	require.Equal(t, int64(4), n18dJobCount(ctx, t, pool, n18dOrg), "the replay adds no intents")
	w.tick(ctx)
	walletReserved, teamReserved, teamSpend, agentReserved, agentCost, sessionReserved, sessionSpent, ledgerRows, ledgerMicro = n18dScopeStates(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(1), ledgerRows, "no second wallet row")
	assert.Equal(t, int64(-8000), ledgerMicro, "no second wallet debit")
	assert.Equal(t, int64(4000), teamSpend)
	assert.Equal(t, int64(4000), agentCost)
	assert.Equal(t, int64(4000), sessionSpent)
	assert.Equal(t, int64(4000), walletReserved)
	assert.Equal(t, int64(8000), teamReserved)
	assert.Equal(t, int64(8000), agentReserved)
	assert.Equal(t, int64(8000), sessionReserved)
	assert.InDelta(t, resaleConflicts, testutil.ToFloat64(metrics.SettlementIntentConflicts.WithLabelValues(ChargeKindResaleDeduction)), 0.001,
		"an identical re-delivery is a silent no-op")

	// 3) The leases lapse past the §14 safety window: one reconcile release
	//    pass returns every un-consumed remainder — and refunds nothing.
	n06p4t06ReleaseStake(ctx, t, pool, n18dOrg)

	walletReserved, teamReserved, teamSpend, agentReserved, agentCost, sessionReserved, sessionSpent, ledgerRows, ledgerMicro = n18dScopeStates(ctx, t, pool, n18dOrg)
	assert.Zero(t, walletReserved+teamReserved+agentReserved+sessionReserved, "every scope's stake returned")
	assert.Equal(t, int64(1), ledgerRows, "the release is not a refund: the usage row stays")
	assert.Equal(t, int64(-8000), ledgerMicro)
	assert.Equal(t, int64(4000), teamSpend, "the settled prefix stays settled")
	assert.Equal(t, int64(4000), agentCost)
	assert.Equal(t, int64(4000), sessionSpent)
	balance, remainder = requireWalletState(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(1000), balance, "no refund on release")
	assert.Equal(t, int64(8000), remainder, "the charged residue stays charged")

	// 4) The late corrected usage event (fresh entry, same request): the
	//    final provider numbers (base 0.006, resale 0.010) disagree with
	//    the settled first amounts — every scope's identity refuses the
	//    second amount, the disagreement is reported, nothing is charged.
	lateConflicts := map[string]float64{
		ChargeKindResaleDeduction: testutil.ToFloat64(metrics.SettlementIntentConflicts.WithLabelValues(ChargeKindResaleDeduction)),
		ChargeKindTeamSpend:       testutil.ToFloat64(metrics.SettlementIntentConflicts.WithLabelValues(ChargeKindTeamSpend)),
		ChargeKindAgentSpend:      testutil.ToFloat64(metrics.SettlementIntentConflicts.WithLabelValues(ChargeKindAgentSpend)),
		ChargeKindSessionSpend:    testutil.ToFloat64(metrics.SettlementIntentConflicts.WithLabelValues(ChargeKindSessionSpend)),
	}
	require.NoError(t, c.processMessage(ctx, n06p4t06LateUsageMsg("n06p4t06-a3", "req-n06p4t06-a", n18dOrg, fx)))
	require.Equal(t, int64(4), n18dJobCount(ctx, t, pool, n18dOrg), "the correction creates no second identities")
	for _, kind := range []string{ChargeKindResaleDeduction, ChargeKindTeamSpend, ChargeKindAgentSpend, ChargeKindSessionSpend} {
		assert.InDelta(t, lateConflicts[kind]+1, testutil.ToFloat64(metrics.SettlementIntentConflicts.WithLabelValues(kind)), 0.001,
			"%s: the amount correction is reported, never silently ignored", kind)
	}
	w.tick(ctx)

	// Final convergence: ONE settled operation across cancel → reconcile →
	// late usage. One ledger debit, prefix-only spends, zero reserves, and
	// the settle keys pinning exactly what ever moved (§7.1.3).
	walletReserved, teamReserved, teamSpend, agentReserved, agentCost, sessionReserved, sessionSpent, ledgerRows, ledgerMicro = n18dScopeStates(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(1), ledgerRows)
	assert.Equal(t, int64(-8000), ledgerMicro, "the correction never charged again")
	assert.Equal(t, int64(4000), teamSpend)
	assert.Equal(t, int64(4000), agentCost)
	assert.Equal(t, int64(4000), sessionSpent)
	assert.Zero(t, walletReserved+teamReserved+agentReserved+sessionReserved)
	balance, remainder = requireWalletState(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(1000), balance, "the correction never charged again")
	assert.Equal(t, int64(8000), remainder)
	assert.Equal(t, int64(9_992_000), balance*10_000-remainder,
		"one operation total: the effective wallet moved by the prefix exactly once")
	var keyWallet, keyTeam, keyAgent, keySession int64
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT COALESCE(SUM(CASE WHEN a.scope_kind = 'wallet' THEN (j.payload->>'settle_decrement_micro_usd')::bigint END), 0),
		       COALESCE(SUM(CASE WHEN a.scope_kind = 'team_month' THEN (j.payload->>'settle_decrement_micro_usd')::bigint END), 0),
		       COALESCE(SUM(CASE WHEN a.scope_kind = 'agent_day' THEN (j.payload->>'settle_decrement_micro_usd')::bigint END), 0),
		       COALESCE(SUM(CASE WHEN a.scope_kind = 'session' THEN (j.payload->>'settle_decrement_micro_usd')::bigint END), 0)
		FROM settlement_jobs j
		LEFT JOIN budget_allowances a ON a.id = j.allowance_id
		WHERE j.org_id = $1 AND j.status = 'settled'`, n18dOrg).
		Scan(&keyWallet, &keyTeam, &keyAgent, &keySession))
	assert.Equal(t, int64(8000), keyWallet, "§7.1.3: the wallet settle key matches the billed prefix")
	assert.Equal(t, int64(4000), keyTeam, "§7.1.3: the team settle key matches the counted prefix")
	assert.Equal(t, int64(4000), keyAgent)
	assert.Equal(t, int64(4000), keySession)
}

// Story B: unknown cancel → visible pending_price, never billed → worker
// never claims it → reconcile returns the stake → the late priced usage
// bills ONCE as its own identity, ledger-only against the released reserve
// → the pending record stays visible, never masked, replay adds nothing.
func TestN06P4T06Live_UnknownCancelLatePricedUsageBillsOncePendingStaysVisible(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrg, 1000)

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:n06p4t06", silentLogger())
	c.SetAgentSpender(budget.NewAgentEnforcer(pool, silentLogger()))
	c.creditStore = credits.NewStore(pool, silentLogger())
	w := NewSettlementWorker(pool, c.creditStore, budget.NewAgentEnforcer(pool, silentLogger()), silentLogger()).
		WithConfig(liveSettlementConfig())

	// 1) The unknown-cost cancel: one pending_price visibility record plus
	//    the three zero-amount counting intents — no money anywhere.
	require.NoError(t, c.processMessage(ctx, r041UnknownCancelMsg("n06p4t06-b1", "req-n06p4t06-b", n18dOrg, fx)))
	byStatus := r041JobCountByStatus(ctx, t, pool, n18dOrg)
	require.Equal(t, int64(1), byStatus[ChargeKindPendingPrice], "the unknown stays durably visible")
	require.Equal(t, int64(3), byStatus["pending"], "the counting intents exist at zero amount")
	rows, micro := r041LedgerRows(ctx, t, pool, n18dOrg)
	require.Zero(t, rows, "an unknown quote never bills")
	require.Zero(t, micro)

	// 2) The worker runs: the zero counting intents settle, the pending
	//    record is not claimable and stays pending.
	w.tick(ctx)
	byStatus = r041JobCountByStatus(ctx, t, pool, n18dOrg)
	require.Equal(t, int64(1), byStatus[ChargeKindPendingPrice], "the worker never claims the visibility record")
	require.Equal(t, int64(3), byStatus["settled"], "the counting intents settled at zero")
	walletReserved, teamReserved, teamSpend, agentReserved, agentCost, sessionReserved, sessionSpent, ledgerRows, ledgerMicro := n18dScopeStates(ctx, t, pool, n18dOrg)
	assert.Zero(t, teamSpend)
	assert.Zero(t, agentCost)
	assert.Zero(t, sessionSpent)
	assert.Zero(t, ledgerRows, "still nothing billed")
	assert.Zero(t, ledgerMicro, "not a single µUSD moved")
	assert.Equal(t, int64(fx.bound), walletReserved, "the stake stays bound for the reconcile")
	assert.Equal(t, int64(fx.bound), teamReserved)
	assert.Equal(t, int64(fx.bound), agentReserved)
	assert.Equal(t, int64(fx.bound), sessionReserved)

	// 3) The safety window passes: the reconcile returns the whole stake;
	//    the visibility record survives untouched — a release never
	//    rewrites an unknown into a confirmed zero.
	n06p4t06ReleaseStake(ctx, t, pool, n18dOrg)
	walletReserved, teamReserved, teamSpend, agentReserved, agentCost, sessionReserved, sessionSpent, ledgerRows, ledgerMicro = n18dScopeStates(ctx, t, pool, n18dOrg)
	assert.Zero(t, walletReserved+teamReserved+agentReserved+sessionReserved, "the stake returned")
	assert.Zero(t, ledgerRows, "the release bills nothing")
	assert.Zero(t, ledgerMicro)
	assert.Zero(t, teamSpend+agentCost+sessionSpent, "the release never writes spends")
	byStatus = r041JobCountByStatus(ctx, t, pool, n18dOrg)
	require.Equal(t, int64(1), byStatus[ChargeKindPendingPrice], "the pending record survives the release")

	// 4) The late priced usage (final numbers: base 0.006, resale 0.010):
	//    exactly ONE new identity — the wallet resale — bills once,
	//    ledger-only against the released reserve.
	require.NoError(t, c.processMessage(ctx, n06p4t06LateUsageMsg("n06p4t06-b2", "req-n06p4t06-b", n18dOrg, fx)))
	require.Equal(t, int64(5), n18dJobCount(ctx, t, pool, n18dOrg),
		"one new wallet identity; the counting identities kept their first amounts")
	w.tick(ctx)

	rows, micro = r041LedgerRows(ctx, t, pool, n18dOrg)
	require.Equal(t, int64(1), rows, "the late price bills exactly once")
	require.Equal(t, int64(-10000), micro, "the resale price of the corrected prefix")
	balance, remainder := requireWalletState(ctx, t, pool, n18dOrg)
	require.Equal(t, int64(999), balance, "the wallet paid the corrected prefix once")
	require.Zero(t, remainder, "the exact 10000µ lands as one whole cent")
	walletReserved, teamReserved, teamSpend, agentReserved, agentCost, sessionReserved, sessionSpent, _, _ = n18dScopeStates(ctx, t, pool, n18dOrg)
	assert.Zero(t, walletReserved+teamReserved+agentReserved+sessionReserved,
		"the settle does not re-bind a released reserve")
	assert.Zero(t, teamSpend, "the counting identities stay at their first (zero) amounts")
	assert.Zero(t, agentCost)
	assert.Zero(t, sessionSpent)

	var lateJobID int64
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT id FROM settlement_jobs
		WHERE org_id = $1 AND request_id = $2 AND charge_kind = $3`,
		n18dOrg, "req-n06p4t06-b", ChargeKindResaleDeduction).Scan(&lateJobID))
	status, attempts, lastErr := jobStatus(ctx, t, pool, lateJobID)
	require.Equal(t, "settled", status, "attempts=%d last_err=%s", attempts, lastErr)
	assert.Nil(t, imp99r1SettleKey(ctx, t, pool, lateJobID),
		"a released allowance settles ledger-only — no reconcile key without a decrement")
	byStatus = r041JobCountByStatus(ctx, t, pool, n18dOrg)
	require.Equal(t, int64(1), byStatus[ChargeKindPendingPrice], "the priced completion never touches the pending record")

	// 5) The replay of the late usage: no second charge, nothing moves.
	require.NoError(t, c.processMessage(ctx, n06p4t06LateUsageMsg("n06p4t06-b3", "req-n06p4t06-b", n18dOrg, fx)))
	require.Equal(t, int64(5), n18dJobCount(ctx, t, pool, n18dOrg))
	w.tick(ctx)
	rows, micro = r041LedgerRows(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(1), rows, "still exactly one charge")
	assert.Equal(t, int64(-10000), micro)
	balance, _ = requireWalletState(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(999), balance, "the replay never charges again")
	byStatus = r041JobCountByStatus(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(1), byStatus[ChargeKindPendingPrice], "the unknown stays visible, never masked")
}
