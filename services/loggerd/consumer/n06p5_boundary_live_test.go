//go:build integration

// N06-P05-T07 boundary corpus at the consumer boundary (disposable PG+Redis,
// contract artifacts/internal-delivery-program/N06-P05/contract.md). The T05 consumer
// file covered recovery-vs-settle as adversarial races; this file freezes
// the SETTLEMENT-EDGE boundaries of the same §7.1 remainder formula without
// any racing: after a FULL settle the replica's leases are young but their
// remainders are exactly zero — recovery must then reap every row while
// returning nothing (no resurrection, no double count); after a PARTIAL
// settle a young lease freezes the live half of the escrow, and only the
// window lapse releases exactly that remainder — granted = returned +
// settled per scope, whatever the split between the settle path and the
// verdict. Shares the fixture's enforce-mode org (n18dOrgEnf):
// seedNext18dWorld resets that org's whole world on every call and these
// tests are sequential (no t.Parallel), so reuse is collision-free.
package consumer

import (
	"testing"

	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestN06P05BoundaryLiveConsumer_FullSettleYoungLeaseZeroRemainderClose:
// the replica settles its whole escrow normally and crashes AFTERWARD,
// before its young leases lapse. Every row's remainder is exactly zero
// (settled == granted), so the lost-replica verdict closes all four rows
// while returning nothing — the §7.1.2 "nothing left to protect" close on
// young leases — and no reserve, spend or ledger line moves a second time.
func TestN06P05BoundaryLiveConsumer_FullSettleYoungLeaseZeroRemainderClose(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrgEnf, 1000)

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:n06p5-boundary-full", silentLogger())
	c.SetAgentSpender(budget.NewAgentEnforcer(pool, silentLogger()))
	c.creditStore = credits.NewStore(pool, silentLogger())
	require.NoError(t, c.processMessage(ctx, n18dCompletedMsg("n06p5-bf-1", "req-n06p5-bf", n18dOrgEnf, fx)))
	require.Equal(t, int64(4), n18dJobCount(ctx, t, pool, n18dOrgEnf), "one intent per reserve scope")

	// The normal settle drains every reserve exactly — no crash shape, the
	// leases stay young (seeded +10 minutes).
	w := NewSettlementWorker(pool, c.creditStore, budget.NewAgentEnforcer(pool, silentLogger()), silentLogger()).WithConfig(liveSettlementConfig())
	w.tick(ctx)
	walletRes, teamRes, teamSpend, agentRes, agentCost, sessRes, sessSpent, ledgerRows, ledgerMicro := n18dScopeStates(ctx, t, pool, n18dOrgEnf)
	assert.Zero(t, walletRes, "the full settle drains every scope reserve")
	assert.Zero(t, teamRes)
	assert.Zero(t, agentRes)
	assert.Zero(t, sessRes)
	assert.Equal(t, int64(fx.bound), teamSpend)
	assert.Equal(t, int64(fx.bound), agentCost)
	assert.Equal(t, int64(fx.bound), sessSpent)
	assert.Equal(t, int64(1), ledgerRows)
	assert.Equal(t, -int64(fx.bound), ledgerMicro)

	// Recovery over the fully settled, still-young replica: the candidate
	// scan visits every row, each has remainder zero, and each closes with
	// nothing returned — the young zero-remainder reap, with no money
	// movement anywhere.
	store := budget.NewReservationStore(pool, silentLogger())
	sum, err := store.CloseAbandonedReplica(ctx, "replica-"+n18dOrgEnf, 0)
	require.NoError(t, err)
	require.Equal(t, int64(4), sum.Closed, "every zero-remainder row closes despite young leases")
	require.Zero(t, sum.ReturnedMicroUSD, "a zero remainder returns nothing — no money moves")
	require.Zero(t, sum.SkippedLive)
	require.Zero(t, sum.AlreadyReleased)

	walletRes, teamRes, teamSpend, agentRes, agentCost, sessRes, sessSpent, ledgerRows, ledgerMicro = n18dScopeStates(ctx, t, pool, n18dOrgEnf)
	assert.Zero(t, walletRes, "no reserve moves again")
	assert.Zero(t, teamRes)
	assert.Zero(t, agentRes)
	assert.Zero(t, sessRes)
	assert.Equal(t, int64(fx.bound), teamSpend, "spends are never recorded twice")
	assert.Equal(t, int64(fx.bound), agentCost)
	assert.Equal(t, int64(fx.bound), sessSpent)
	assert.Equal(t, int64(1), ledgerRows, "the ledger is never charged twice")
	assert.Equal(t, -int64(fx.bound), ledgerMicro)

	for _, scope := range []string{"wallet", "team_month", "agent_day", "session"} {
		granted, returned, status := n06p5AllowanceScope(ctx, t, pool, n18dOrgEnf, scope)
		assert.Equal(t, "released", status, "scope %s", scope)
		assert.Zero(t, returned, "scope %s: the reap adds nothing to the settle's decrement", scope)
		assert.Equal(t, int64(fx.bound), granted, "scope %s: granted untouched", scope)
	}

	// Idempotent tail: a second verdict only reports the losing side, and
	// the settled queue never re-bills.
	sum2, err := store.CloseAbandonedReplica(ctx, "replica-"+n18dOrgEnf, 0)
	require.NoError(t, err)
	require.Equal(t, int64(4), sum2.AlreadyReleased)
	require.Zero(t, sum2.Closed)
	require.Zero(t, sum2.ReturnedMicroUSD)
	w.tick(ctx)
	_, _, teamSpend2, _, agentCost2, _, sessSpent2, ledgerRows2, ledgerMicro2 := n18dScopeStates(ctx, t, pool, n18dOrgEnf)
	assert.Equal(t, teamSpend, teamSpend2)
	assert.Equal(t, agentCost, agentCost2)
	assert.Equal(t, sessSpent, sessSpent2)
	assert.Equal(t, ledgerRows, ledgerRows2)
	assert.Equal(t, ledgerMicro, ledgerMicro2)
}

// TestN06P05BoundaryLiveConsumer_PartialSettleSkipsThenReturnsExactRemainder:
// a second in-flight request doubles each escrow (granted and reserves 2×
// bound), the replica settles its first request, then dies with the second
// still reserved. The young leases freeze the live half (SkippedLive=4 —
// the T05 race file never pins the frozen side); after the window lapses
// recovery returns exactly the unsettled remainder per scope, and granted
// = returned + settled holds per scope across the two writers.
func TestN06P05BoundaryLiveConsumer_PartialSettleSkipsThenReturnsExactRemainder(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrgEnf, 1000)

	// The second concurrent in-flight request: granted and every reserve
	// double to 2 × bound (production adds to the same scope escrow).
	granted := 2 * int64(fx.bound) // 24_000
	_, err := pool.Exec(ctx,
		`UPDATE budget_allowances SET granted_micro_usd = $2 WHERE org_id = $1`, n18dOrgEnf, granted)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `UPDATE org_credits SET reserved_micro_usd = $2 WHERE org_id = $1`, n18dOrgEnf, granted)
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		`UPDATE team_spend_monthly SET reserved_micro_usd = $2 WHERE team_id = $1`, n18dTeam, granted)
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		`UPDATE agent_spend_daily SET reserved_micro_usd = $2 WHERE agent_id = $1`, n18dAgent, granted)
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		`UPDATE session_spend SET reserved_micro_usd = $2 WHERE session_key_id = $1`, n18dSession, granted)
	require.NoError(t, err)

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:n06p5-boundary-part", silentLogger())
	c.SetAgentSpender(budget.NewAgentEnforcer(pool, silentLogger()))
	c.creditStore = credits.NewStore(pool, silentLogger())
	require.NoError(t, c.processMessage(ctx, n18dCompletedMsg("n06p5-bp-1", "req-n06p5-bp", n18dOrgEnf, fx)))
	require.Equal(t, int64(4), n18dJobCount(ctx, t, pool, n18dOrgEnf))

	// The first request settles exactly one bound per scope; the second
	// stays reserved.
	w := NewSettlementWorker(pool, c.creditStore, budget.NewAgentEnforcer(pool, silentLogger()), silentLogger()).WithConfig(liveSettlementConfig())
	w.tick(ctx)
	walletRes, teamRes, teamSpend, agentRes, agentCost, sessRes, sessSpent, ledgerRows, ledgerMicro := n18dScopeStates(ctx, t, pool, n18dOrgEnf)
	assert.Equal(t, int64(fx.bound), walletRes, "exactly one bound of each escrow stays reserved")
	assert.Equal(t, int64(fx.bound), teamRes)
	assert.Equal(t, int64(fx.bound), agentRes)
	assert.Equal(t, int64(fx.bound), sessRes)
	assert.Equal(t, int64(fx.bound), teamSpend)
	assert.Equal(t, int64(fx.bound), agentCost)
	assert.Equal(t, int64(fx.bound), sessSpent)
	assert.Equal(t, int64(1), ledgerRows)
	assert.Equal(t, -int64(fx.bound), ledgerMicro)

	// Young leases + live remainders: the verdict freezes every row.
	store := budget.NewReservationStore(pool, silentLogger())
	sum, err := store.CloseAbandonedReplica(ctx, "replica-"+n18dOrgEnf, 0)
	require.NoError(t, err)
	require.Equal(t, int64(4), sum.SkippedLive, "every young row with a live remainder freezes")
	require.Zero(t, sum.Closed)
	require.Zero(t, sum.ReturnedMicroUSD)
	fzWalletRes, fzTeamRes, _, fzAgentRes, _, fzSessRes, _, _, _ := n18dScopeStates(ctx, t, pool, n18dOrgEnf)
	assert.Equal(t, int64(fx.bound), fzWalletRes, "frozen means frozen: no µUSD moved")
	assert.Equal(t, int64(fx.bound), fzTeamRes)
	assert.Equal(t, int64(fx.bound), fzAgentRes)
	assert.Equal(t, int64(fx.bound), fzSessRes)

	// The replica dies for good; the window lapses; recovery returns
	// exactly the unsettled half of every escrow.
	n06p5ForceCrashShape(ctx, t, pool, n18dOrgEnf)
	sum2, err := store.CloseAbandonedReplica(ctx, "replica-"+n18dOrgEnf, 0)
	require.NoError(t, err)
	require.Equal(t, int64(4), sum2.Closed)
	require.Equal(t, 4*int64(fx.bound), sum2.ReturnedMicroUSD, "4 × one bound — exactly the unsettled half")
	require.Zero(t, sum2.SkippedLive)
	require.Zero(t, sum2.AlreadyReleased)

	walletRes, teamRes, _, agentRes, _, sessRes, _, _, _ = n18dScopeStates(ctx, t, pool, n18dOrgEnf)
	assert.Zero(t, walletRes)
	assert.Zero(t, teamRes)
	assert.Zero(t, agentRes)
	assert.Zero(t, sessRes)

	// Per-scope conservation: granted = returned + settled exactly once,
	// whatever the split between the settle path and the verdict; recovery
	// never records spend and never charges the ledger.
	decs := n06p5KindDecrement(ctx, t, pool, n18dOrgEnf)
	for _, pair := range []struct{ scope, kind string }{
		{"wallet", ChargeKindResaleDeduction},
		{"team_month", ChargeKindTeamSpend},
		{"agent_day", ChargeKindAgentSpend},
		{"session", ChargeKindSessionSpend},
	} {
		_, returned, status := n06p5AllowanceScope(ctx, t, pool, n18dOrgEnf, pair.scope)
		assert.Equal(t, "released", status, "scope %s", pair.scope)
		assert.Equal(t, granted, returned+decs[pair.kind],
			"scope %s: granted = returned + settled exactly once", pair.scope)
	}
	_, _, teamSpend2, _, agentCost2, _, sessSpent2, ledgerRows2, ledgerMicro2 := n18dScopeStates(ctx, t, pool, n18dOrgEnf)
	assert.Equal(t, int64(fx.bound), teamSpend2, "recovery never records spend")
	assert.Equal(t, int64(fx.bound), agentCost2)
	assert.Equal(t, int64(fx.bound), sessSpent2)
	assert.Equal(t, int64(1), ledgerRows2, "recovery never charges the ledger")
	assert.Equal(t, -int64(fx.bound), ledgerMicro2)

	// Idempotent tail: the second verdict only reports the losing side.
	sum3, err := store.CloseAbandonedReplica(ctx, "replica-"+n18dOrgEnf, 0)
	require.NoError(t, err)
	require.Equal(t, int64(4), sum3.AlreadyReleased)
	require.Zero(t, sum3.Closed)
	require.Zero(t, sum3.ReturnedMicroUSD)
}
