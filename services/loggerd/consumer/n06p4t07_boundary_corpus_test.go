package consumer

// N06-P04 T07 — the boundary regression corpus of the settlement packet,
// on the real stand (disposable PG+Redis, the same live acceptance
// environment the T06 joint scenario uses). Every fact below is produced
// by the real delivery transaction, the real settlement worker and the
// real budget reconcile worker against the real tables; the mid-range
// behavior of the same paths is already pinned by
// n06p4t06_joint_live_test.go (T06), r041_settlement_cancel_live_test.go
// (D1–D3) and the T04/T05 mock-seam tests — this file never repeats those
// pins, it walks the EDGES:
//
//   - known-zero price: a valid "0.000000" quote is a proven zero, not an
//     unknown — counting intents at 0, no wallet charge, no pending_price
//     record, and NO uncharged_unknown counting (that metric is for
//     unknown price; a known zero used to inflate it — N06-P04-T07
//     defect, fixed in reportUnchargedUnknown);
//   - sub-µUSD round-up: a positive quote below half a micro-USD settles
//     as the 1 µUSD minimum (never an invisible zero);
//   - prefix == bound: the settle consumes the whole stake; the reconcile
//     release is a zero-remainder no-op, never a second return;
//   - prefix > bound: the wallet ledger bills the FULL resale (real usage
//     above the admission estimate is not clamped), the reserve release
//     is clamped to min(actual, bound) — the ledger/reserve asymmetry;
//   - §14 safety window: a lease lapsed 119 minutes past expiry releases
//     NOTHING, 121 minutes releases everything (the 2h window edge);
//   - pending_price 24h deadline: 23h stays visible, 24h+1min terminates
//     to 'unknown'; an absorbed-unknown upstream failure rides the same
//     lifecycle (pending row, never claimed, stake returned by reconcile);
//   - org identity: settlement identities are org-scoped, but the wallet
//     usage-ledger idempotency index is global on request_id — the same
//     request id in a second org settles its own budget-area stake while
//     its wallet resale parks as durable requires_attention debt
//     (request_identity_conflict), and neither org's settle moves the
//     other's money;

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

// n06p4t07CancelMsg clones the NEXT-18d completed-event fixture as a
// priced client cancel with explicit quote fields. Empty estimates are
// deleted (the unknown shape); unknownPrice publishes the producer's
// hidden-zero placeholder (estimated_cost_usd=0 + cost_status=
// unknown_price).
func n06p4t07CancelMsg(entryID, requestID, org string, fx n18dFixture, est, resale string, unknownPrice bool) redis.XMessage {
	msg := n18dCompletedMsg(entryID, requestID, org, fx)
	msg.Values["termination"] = "client_cancel"
	if est == "" {
		delete(msg.Values, "estimated_cost_usd")
	} else {
		msg.Values["estimated_cost_usd"] = est
	}
	if resale == "" {
		delete(msg.Values, "resale_cost_usd")
	} else {
		msg.Values["resale_cost_usd"] = resale
	}
	if unknownPrice {
		msg.Values["cost_status"] = "unknown_price"
	}
	return msg
}

// n06p4t07LapseAllowances lapses the org's allowance leases by the given
// PG interval text ("119 minutes", "3 hours", ...).
func n06p4t07LapseAllowances(ctx context.Context, t *testing.T, pool *pgxpool.Pool, org, interval string) {
	t.Helper()
	_, err := pool.Exec(ctx,
		`UPDATE budget_allowances SET lease_until = now() - $2::interval WHERE org_id = $1`, org, interval)
	require.NoError(t, err)
}

// n06p4t07ReleaseStake runs one real reconcile release pass after the §14
// safety window (2h) has fully lapsed.
func n06p4t07ReleaseStake(ctx context.Context, t *testing.T, pool *pgxpool.Pool, org string) budget.ReconcileSummary {
	t.Helper()
	n06p4t07LapseAllowances(ctx, t, pool, org, "3 hours")
	summary, err := budget.NewReconcileWorker(pool, silentLogger(), budget.DefaultReconcileConfig()).ReleasePass(ctx)
	require.NoError(t, err)
	return summary
}

// n06p4t07SettleKeys sums the §7.1.3 reconcile payload keys per scope —
// the µUSD every settled job of the org removed from its scope reserve.
func n06p4t07SettleKeys(ctx context.Context, t *testing.T, pool *pgxpool.Pool, org string) (wallet, team, agent, session int64) {
	t.Helper()
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT COALESCE(SUM(CASE WHEN a.scope_kind = 'wallet' THEN (j.payload->>'settle_decrement_micro_usd')::bigint END), 0),
		       COALESCE(SUM(CASE WHEN a.scope_kind = 'team_month' THEN (j.payload->>'settle_decrement_micro_usd')::bigint END), 0),
		       COALESCE(SUM(CASE WHEN a.scope_kind = 'agent_day' THEN (j.payload->>'settle_decrement_micro_usd')::bigint END), 0),
		       COALESCE(SUM(CASE WHEN a.scope_kind = 'session' THEN (j.payload->>'settle_decrement_micro_usd')::bigint END), 0)
		FROM settlement_jobs j
		LEFT JOIN budget_allowances a ON a.id = j.allowance_id
		WHERE j.org_id = $1 AND j.status = 'settled'`, org).
		Scan(&wallet, &team, &agent, &session))
	return
}

// n06p4t07AllowanceStatuses returns the release state of the org's four
// allowance rows per scope kind.
func n06p4t07AllowanceStatuses(ctx context.Context, t *testing.T, pool *pgxpool.Pool, org string) map[string]string {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT scope_kind, status FROM budget_allowances WHERE org_id = $1`, org)
	require.NoError(t, err)
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var scope, status string
		require.NoError(t, rows.Scan(&scope, &status))
		out[scope] = status
	}
	require.NoError(t, rows.Err())
	return out
}

// Boundary 1 — a valid zero quote is a KNOWN zero: counting intents at 0,
// no wallet charge, no pending_price record, and no uncharged_unknown
// counting. The unknown-price placeholder ("0.000000" + cost_status
// unknown_price) is the contrast: a pending record and the uncharged
// counting.
func TestN06P4T07Live_KnownZeroCancelIsZeroNotUnknown(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrg, 1000)

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:n06p4t07", silentLogger())
	c.SetAgentSpender(budget.NewAgentEnforcer(pool, silentLogger()))
	c.creditStore = credits.NewStore(pool, silentLogger())
	w := NewSettlementWorker(pool, c.creditStore, budget.NewAgentEnforcer(pool, silentLogger()), silentLogger()).
		WithConfig(liveSettlementConfig())

	unchargedBefore := map[string]float64{
		"wallet":     testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("wallet")),
		"team_month": testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("team_month")),
		"agent_day":  testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("agent_day")),
		"session":    testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("session")),
	}

	// 1) The zero-priced cancel (valid zeros, usage present): the cost is
	//    proven zero — three zero-amount counting intents, no wallet job,
	//    no pending_price record, no uncharged counting.
	require.NoError(t, c.processMessage(ctx, n06p4t07CancelMsg("n06p4t07-z1", "req-n06p4t07-zero", n18dOrg, fx, "0.000000", "0.000000", false)))
	require.Equal(t, int64(3), n18dJobCount(ctx, t, pool, n18dOrg), "the three budget areas count at zero; no wallet, no pending")
	byStatus := r041JobCountByStatus(ctx, t, pool, n18dOrg)
	require.Zero(t, byStatus[ChargeKindPendingPrice], "a known zero never pends — it is not an unknown price")
	for scope, before := range unchargedBefore {
		assert.InDelta(t, before, testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues(scope)), 0.001,
			"scope %s: a proven-zero cost is not uncharged-unknown", scope)
	}

	// 2) The worker settles the counting intents at zero: no money, no
	//    settle keys (nothing ever left the reserves), stakes intact.
	w.tick(ctx)
	byStatus = r041JobCountByStatus(ctx, t, pool, n18dOrg)
	require.Equal(t, int64(3), byStatus["settled"], "the counting intents settle at zero")
	walletReserved, teamReserved, teamSpend, agentReserved, agentCost, sessionReserved, sessionSpent, ledgerRows, ledgerMicro := n18dScopeStates(ctx, t, pool, n18dOrg)
	assert.Zero(t, teamSpend+agentCost+sessionSpent, "a zero cost bills zero")
	assert.Zero(t, ledgerRows)
	assert.Zero(t, ledgerMicro)
	assert.Equal(t, int64(fx.bound), walletReserved, "nothing was consumed from the stake")
	assert.Equal(t, int64(fx.bound), teamReserved)
	assert.Equal(t, int64(fx.bound), agentReserved)
	assert.Equal(t, int64(fx.bound), sessionReserved)
	keyWallet, keyTeam, keyAgent, keySession := n06p4t07SettleKeys(ctx, t, pool, n18dOrg)
	assert.Zero(t, keyWallet+keyTeam+keyAgent+keySession, "a zero settle never moves a reserve — no reconcile keys")

	// 3) Contrast: the unknown-price placeholder (estimated 0 + cost_status
	//    unknown_price) is a DIFFERENT boundary — one pending_price record
	//    and the full bound counted as uncharged-unknown per scope.
	require.NoError(t, c.processMessage(ctx, n06p4t07CancelMsg("n06p4t07-z2", "req-n06p4t07-hidzero", n18dOrg, fx, "0.000000", "0.000000", true)))
	byStatus = r041JobCountByStatus(ctx, t, pool, n18dOrg)
	require.Equal(t, int64(1), byStatus[ChargeKindPendingPrice], "the published placeholder zero is an unknown price — it pends")
	for scope, before := range unchargedBefore {
		assert.InDelta(t, before+float64(fx.bound), testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues(scope)), 0.001,
			"scope %s: an unknown price counts its bound", scope)
	}

	// 4) The release pass returns both stakes; the unknown stays visible;
	//    still no money anywhere.
	summary := n06p4t07ReleaseStake(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(4), summary.Released, "every scope's stake released")
	assert.Equal(t, int64(4*int64(fx.bound)), summary.ReturnedMicroUSD, "the untouched stakes returned in full")
	walletReserved, teamReserved, teamSpend, agentReserved, agentCost, sessionReserved, sessionSpent, ledgerRows, ledgerMicro = n18dScopeStates(ctx, t, pool, n18dOrg)
	assert.Zero(t, walletReserved+teamReserved+agentReserved+sessionReserved)
	assert.Zero(t, ledgerRows+ledgerMicro+teamSpend+agentCost+sessionSpent)
	byStatus = r041JobCountByStatus(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(1), byStatus[ChargeKindPendingPrice], "the unknown survives the release, never masked")
}

// Boundary 2 — sub-µUSD round-up: a positive quote below half a micro-USD
// collapses to QuoteZero at the parse boundary and rounds UP to the 1 µUSD
// minimum (owner decision: no invisible zeros) — the smallest billable
// cancel there is.
func TestN06P4T07Live_SubMicroPositiveQuoteRoundsUpToOneMicro(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrg, 1000)

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:n06p4t07", silentLogger())
	c.SetAgentSpender(budget.NewAgentEnforcer(pool, silentLogger()))
	c.creditStore = credits.NewStore(pool, silentLogger())
	w := NewSettlementWorker(pool, c.creditStore, budget.NewAgentEnforcer(pool, silentLogger()), silentLogger()).
		WithConfig(liveSettlementConfig())

	// The 0.4µ quotes (base and resale) settle as 1µ known billable prices:
	// four intents at 1µ — the wallet resale and the three budget areas.
	require.NoError(t, c.processMessage(ctx, n06p4t07CancelMsg("n06p4t07-s1", "req-n06p4t07-submicro", n18dOrg, fx, "0.0000004", "0.0000004", false)))
	require.Equal(t, int64(4), n18dJobCount(ctx, t, pool, n18dOrg), "a sub-µUSD positive quote is billable, never an invisible zero")
	var amounts []int64
	rows, err := pool.Query(ctx, `SELECT amount_micro_usd FROM settlement_jobs WHERE org_id = $1 ORDER BY charge_kind`, n18dOrg)
	require.NoError(t, err)
	for rows.Next() {
		var amt int64
		require.NoError(t, rows.Scan(&amt))
		amounts = append(amounts, amt)
	}
	require.NoError(t, rows.Err())
	require.Equal(t, []int64{1, 1, 1, 1}, amounts, "every intent carries the 1 µUSD minimum")

	w.tick(ctx)
	walletReserved, teamReserved, teamSpend, agentReserved, agentCost, sessionReserved, sessionSpent, ledgerRows, ledgerMicro := n18dScopeStates(ctx, t, pool, n18dOrg)
	require.Equal(t, int64(1), ledgerRows, "one wallet usage row")
	require.Equal(t, int64(-1), ledgerMicro, "the wallet billed the rounded-up resale minimum")
	assert.Equal(t, int64(1), teamSpend, "the budget areas billed the rounded-up base minimum")
	assert.Equal(t, int64(1), agentCost)
	assert.Equal(t, int64(1), sessionSpent)
	assert.Equal(t, int64(11999), walletReserved)
	assert.Equal(t, int64(11999), teamReserved)
	assert.Equal(t, int64(11999), agentReserved)
	assert.Equal(t, int64(11999), sessionReserved)
	keyWallet, keyTeam, keyAgent, keySession := n06p4t07SettleKeys(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(1), keyWallet, "§7.1.3: the settle key matches the rounded-up charge")
	assert.Equal(t, int64(1), keyTeam)
	assert.Equal(t, int64(1), keyAgent)
	assert.Equal(t, int64(1), keySession)
	balance, remainder := requireWalletState(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(1000), balance, "a 1 µUSD charge is sub-cent: the cent stays, the residue is durable")
	assert.Equal(t, int64(1), remainder)

	// The release returns the residual stakes — 11999µ per scope, exactly.
	summary := n06p4t07ReleaseStake(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(4), summary.Released)
	assert.Equal(t, int64(4*11999), summary.ReturnedMicroUSD, "every unconsumed µUSD returned")
	walletReserved, teamReserved, _, agentReserved, _, sessionReserved, _, ledgerRows, ledgerMicro = n18dScopeStates(ctx, t, pool, n18dOrg)
	assert.Zero(t, walletReserved+teamReserved+agentReserved+sessionReserved)
	assert.Equal(t, int64(1), ledgerRows, "the release is not a refund")
	assert.Equal(t, int64(-1), ledgerMicro)
}

// Boundary 3 — prefix exactly at the bound: the settle consumes the whole
// stake; the reconcile release finds a zero remainder and only flips the
// release state — never a second return; a second pass is a no-op.
func TestN06P4T07Live_PrefixAtBoundConsumesWholeStake(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrg, 1000)

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:n06p4t07", silentLogger())
	c.SetAgentSpender(budget.NewAgentEnforcer(pool, silentLogger()))
	c.creditStore = credits.NewStore(pool, silentLogger())
	w := NewSettlementWorker(pool, c.creditStore, budget.NewAgentEnforcer(pool, silentLogger()), silentLogger()).
		WithConfig(liveSettlementConfig())

	require.NoError(t, c.processMessage(ctx, n06p4t07CancelMsg("n06p4t07-b1", "req-n06p4t07-atbound", n18dOrg, fx, "0.012", "0.012", false)))
	require.Equal(t, int64(4), n18dJobCount(ctx, t, pool, n18dOrg))
	w.tick(ctx)

	walletReserved, teamReserved, teamSpend, agentReserved, agentCost, sessionReserved, sessionSpent, ledgerRows, ledgerMicro := n18dScopeStates(ctx, t, pool, n18dOrg)
	require.Equal(t, int64(1), ledgerRows)
	require.Equal(t, int64(-12000), ledgerMicro, "the wallet billed the prefix's full-bound resale once")
	assert.Equal(t, int64(12000), teamSpend)
	assert.Equal(t, int64(12000), agentCost)
	assert.Equal(t, int64(12000), sessionSpent)
	assert.Zero(t, walletReserved, "the at-bound settle consumes the whole wallet stake")
	assert.Zero(t, teamReserved)
	assert.Zero(t, agentReserved)
	assert.Zero(t, sessionReserved)
	keyWallet, keyTeam, keyAgent, keySession := n06p4t07SettleKeys(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(12000), keyWallet, "the settle key equals the bound")
	assert.Equal(t, int64(12000), keyTeam)
	assert.Equal(t, int64(12000), keyAgent)
	assert.Equal(t, int64(12000), keySession)
	balance, remainder := requireWalletState(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(999), balance)
	assert.Equal(t, int64(2000), remainder, "the 1.2-cent charge carries its 2000µ residue exactly")

	// The release pass: every lease lapses, every remainder is zero — the
	// scopes flip to released with NOTHING returned, and a second pass is
	// a no-op (never a double return).
	summary := n06p4t07ReleaseStake(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(4), summary.Released)
	assert.Zero(t, summary.ReturnedMicroUSD, "an at-bound settle leaves nothing for the reconcile to return")
	assert.Equal(t, int64(4), summary.ZeroRemainderReleased)
	statuses := n06p4t07AllowanceStatuses(ctx, t, pool, n18dOrg)
	for scope, status := range statuses {
		assert.Equal(t, "released", status, "scope %s", scope)
	}
	summary2, err := budget.NewReconcileWorker(pool, silentLogger(), budget.DefaultReconcileConfig()).ReleasePass(ctx)
	require.NoError(t, err)
	assert.Zero(t, summary2.Released, "the second pass re-releases nothing")
	walletReserved, teamReserved, teamSpend, agentReserved, agentCost, sessionReserved, sessionSpent, ledgerRows, ledgerMicro = n18dScopeStates(ctx, t, pool, n18dOrg)
	assert.Zero(t, walletReserved+teamReserved+agentReserved+sessionReserved)
	assert.Equal(t, int64(1), ledgerRows)
	assert.Equal(t, int64(-12000), ledgerMicro)
	assert.Equal(t, int64(12000), teamSpend, "the settled amounts stay settled")
	assert.Equal(t, int64(12000), agentCost)
	assert.Equal(t, int64(12000), sessionSpent)
}

// Boundary 4 — prefix above the bound: the wallet ledger bills the FULL
// resale (real usage above the admission estimate is never clamped), the
// budget areas record the full base spend, and the reserve release is
// clamped to min(actual, bound) — settle keys cap at the bound, nothing
// is left for the reconcile, and a replay adds no second charge.
func TestN06P4T07Live_PrefixAboveBoundLedgerUnclampedReserveClamped(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrg, 1000)

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:n06p4t07", silentLogger())
	c.SetAgentSpender(budget.NewAgentEnforcer(pool, silentLogger()))
	c.creditStore = credits.NewStore(pool, silentLogger())
	w := NewSettlementWorker(pool, c.creditStore, budget.NewAgentEnforcer(pool, silentLogger()), silentLogger()).
		WithConfig(liveSettlementConfig())

	// Base 0.02, resale 0.03 — both above the 0.012 admission bound.
	require.NoError(t, c.processMessage(ctx, n06p4t07CancelMsg("n06p4t07-a1", "req-n06p4t07-overbound", n18dOrg, fx, "0.02", "0.03", false)))
	require.Equal(t, int64(4), n18dJobCount(ctx, t, pool, n18dOrg))
	w.tick(ctx)

	walletReserved, teamReserved, teamSpend, agentReserved, agentCost, sessionReserved, sessionSpent, ledgerRows, ledgerMicro := n18dScopeStates(ctx, t, pool, n18dOrg)
	require.Equal(t, int64(1), ledgerRows)
	require.Equal(t, int64(-30000), ledgerMicro, "the wallet billed the FULL resale — real usage is not clamped to the estimate")
	assert.Equal(t, int64(20000), teamSpend, "the budget areas recorded the full base spend")
	assert.Equal(t, int64(20000), agentCost)
	assert.Equal(t, int64(20000), sessionSpent)
	assert.Zero(t, walletReserved, "the reserve release clamped at the bound: min(30000, 12000)")
	assert.Zero(t, teamReserved)
	assert.Zero(t, agentReserved)
	assert.Zero(t, sessionReserved)
	keyWallet, keyTeam, keyAgent, keySession := n06p4t07SettleKeys(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(12000), keyWallet, "the §7.1.3 settle key caps at the bound, not the billed amount")
	assert.Equal(t, int64(12000), keyTeam)
	assert.Equal(t, int64(12000), keyAgent)
	assert.Equal(t, int64(12000), keySession)
	balance, remainder := requireWalletState(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(997), balance, "the wallet really paid 3 cents for the over-bound prefix")
	assert.Zero(t, remainder)

	// The reconcile has nothing to return; the excess was billed, not
	// released.
	summary := n06p4t07ReleaseStake(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(4), summary.Released)
	assert.Zero(t, summary.ReturnedMicroUSD, "nothing to return: the settle consumed the whole clamped stake")
	assert.Equal(t, int64(4), summary.ZeroRemainderReleased)

	// The replay: the identity keeps its first (over-bound) amount — no
	// second charge of the excess, no new intents.
	require.NoError(t, c.processMessage(ctx, n06p4t07CancelMsg("n06p4t07-a2", "req-n06p4t07-overbound", n18dOrg, fx, "0.02", "0.03", false)))
	require.Equal(t, int64(4), n18dJobCount(ctx, t, pool, n18dOrg))
	w.tick(ctx)
	_, _, _, _, _, _, _, ledgerRows, ledgerMicro = n18dScopeStates(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(1), ledgerRows, "the replay adds no wallet row")
	assert.Equal(t, int64(-30000), ledgerMicro, "the over-bound excess is never charged twice")
}

// Boundary 5 — the §14 safety-window edge and org identity: a lease lapsed
// 119 minutes past expiry (inside the 2h window) releases NOTHING; at 121
// minutes everything is returned exactly. The same request_id in a second
// org: its budget areas settle their own per-org stake, its wallet resale
// parks as requires_attention (the usage-ledger idempotency index is
// global on request_id — uniq_credit_transactions_usage_request_id), and
// neither org's settle moves the other's money.
func TestN06P4T07Live_SafetyWindowTwoHourEdgesAndOrgIdentity(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrg, 1000)

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:n06p4t07", silentLogger())
	c.SetAgentSpender(budget.NewAgentEnforcer(pool, silentLogger()))
	c.creditStore = credits.NewStore(pool, silentLogger())
	w := NewSettlementWorker(pool, c.creditStore, budget.NewAgentEnforcer(pool, silentLogger()), silentLogger()).
		WithConfig(liveSettlementConfig())

	// The priced partial cancel (base 0.004 / resale 0.008 / bound 0.012):
	// after the settle, org1's wallet stake holds 4000µ.
	require.NoError(t, c.processMessage(ctx, r041CancelMsg("n06p4t07-w1", "req-n06p4t07-edge", n18dOrg, fx)))
	require.Equal(t, int64(4), n18dJobCount(ctx, t, pool, n18dOrg))
	w.tick(ctx)
	walletReserved, _, _, _, _, _, _, _, _ := n18dScopeStates(ctx, t, pool, n18dOrg)
	require.Equal(t, int64(4000), walletReserved, "the un-consumed wallet bound stays for the reconcile")

	// 119 minutes past lease expiry: INSIDE the 2h safety window — the
	// release pass must not free a single µUSD.
	n06p4t07LapseAllowances(ctx, t, pool, n18dOrg, "119 minutes")
	summary, err := budget.NewReconcileWorker(pool, silentLogger(), budget.DefaultReconcileConfig()).ReleasePass(ctx)
	require.NoError(t, err)
	assert.Zero(t, summary.Released, "a lease inside the safety window is never released")
	walletReserved, _, _, _, _, _, _, _, _ = n18dScopeStates(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(4000), walletReserved, "the stake stays frozen inside the window")
	statuses := n06p4t07AllowanceStatuses(ctx, t, pool, n18dOrg)
	for scope, status := range statuses {
		assert.NotEqual(t, "released", status, "scope %s: not releasable inside the window", scope)
	}

	// A second org, the SAME request_id: the settlement identities are
	// org-scoped (org2 gets its own four jobs), but the wallet usage
	// ledger's idempotency index is global on request_id — org2's wallet
	// resale parks as durable requires_attention debt instead of charging
	// an identity already billed under org1, while org2's budget areas
	// settle their own stake.
	fx2 := seedNext18dWorld(ctx, t, pool, n18dOrgShadow, 1000)
	require.NoError(t, c.processMessage(ctx, r041CancelMsg("n06p4t07-w2", "req-n06p4t07-edge", n18dOrgShadow, fx2)))
	require.Equal(t, int64(4), n18dJobCount(ctx, t, pool, n18dOrgShadow), "org2 gets its own settlement identities for the same request id")
	w.tick(ctx)
	org2ByStatus := r041JobCountByStatus(ctx, t, pool, n18dOrgShadow)
	assert.Equal(t, int64(3), org2ByStatus["settled"], "org2's budget areas settle their own stake")
	assert.Equal(t, int64(1), org2ByStatus["requires_attention"], "the wallet resale parks on the conflicting global identity")
	var parkedErr string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT COALESCE(last_error, '') FROM settlement_jobs
		WHERE org_id = $1 AND charge_kind = 'resale_deduction' AND request_id = $2`,
		n18dOrgShadow, "req-n06p4t07-edge").Scan(&parkedErr))
	assert.Equal(t, "request_identity_conflict", parkedErr,
		"the batch executor detects the cross-org usage identity before charging and records its disposition reason")
	_, _, org2TeamSpend, _, org2AgentCost, _, org2SessionSpent, org2Rows, org2Micro := n18dScopeStates(ctx, t, pool, n18dOrgShadow)
	assert.Equal(t, int64(4000), org2TeamSpend, "org2's budget areas billed their own prefix")
	assert.Equal(t, int64(4000), org2AgentCost)
	assert.Equal(t, int64(4000), org2SessionSpent)
	assert.Zero(t, org2Rows, "org2's wallet never charged — the global request identity belongs to org1")
	assert.Zero(t, org2Micro)
	walletReserved, _, _, _, _, _, _, org1Rows, org1Micro := n18dScopeStates(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(4000), walletReserved, "org2's settle never moved org1's money")
	assert.Equal(t, int64(1), org1Rows)
	assert.Equal(t, int64(-8000), org1Micro)

	// 121 minutes past expiry: OUTSIDE the 2h window — org1's whole
	// remainder (4000 wallet + 8000×3 budget areas) returns at once; org2
	// (young leases) stays untouched, its parked wallet job keeping the
	// FULL wallet stake frozen and visible.
	n06p4t07LapseAllowances(ctx, t, pool, n18dOrg, "121 minutes")
	summary, err = budget.NewReconcileWorker(pool, silentLogger(), budget.DefaultReconcileConfig()).ReleasePass(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(4), summary.Released, "every lapsed org1 scope released")
	assert.Equal(t, int64(28000), summary.ReturnedMicroUSD, "4000 + 3×8000 returned exactly")
	assert.Equal(t, int64(4), summary.ExpiredSafetyReleased, "the release reason is the lapsed safety window")
	walletReserved, _, _, _, _, _, _, _, _ = n18dScopeStates(ctx, t, pool, n18dOrg)
	assert.Zero(t, walletReserved, "org1's stake returned once past the window")
	// org2's wallet stake is org-scoped (org_credits) and stays fully
	// frozen behind the parked job. The team/agent/session reserved
	// COUNTERS are shared per scope key in this fixture (org1's release
	// drains the same row), so they are not org-attributable here — the
	// org-scoped release state lives on org2's allowance rows, asserted
	// below; the spend history is never rewritten by a release.
	org2Wallet, _, org2TeamSpend, _, org2AgentCost, _, org2SessionSpent, _, _ := n18dScopeStates(ctx, t, pool, n18dOrgShadow)
	assert.Equal(t, int64(fx2.bound), org2Wallet, "org2's parked wallet job keeps the full stake frozen")
	assert.Equal(t, int64(4000), org2TeamSpend, "org2's settled spend history survives org1's release")
	assert.Equal(t, int64(4000), org2AgentCost)
	assert.Equal(t, int64(4000), org2SessionSpent)
	statuses = n06p4t07AllowanceStatuses(ctx, t, pool, n18dOrgShadow)
	for scope, status := range statuses {
		assert.NotEqual(t, "released", status, "org2 scope %s stays reserved", scope)
	}
}

// Boundary 6 — the pending_price 24h deadline edges and the absorbed-
// unknown upstream failure: 23h stays visible, 24h+1min terminates to
// 'unknown' (never billed, row kept); the absorbed unknown (upstream_error,
// placeholder-zero publication) rides the same lifecycle — one pending
// record, no intents, stake returned by the reconcile, record never
// masked.
func TestN06P4T07Live_PendingPriceExpiryEdgesAndAbsorbedUnknown(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrg, 1000)

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:n06p4t07", silentLogger())
	c.SetAgentSpender(budget.NewAgentEnforcer(pool, silentLogger()))
	c.creditStore = credits.NewStore(pool, silentLogger())
	w := NewSettlementWorker(pool, c.creditStore, budget.NewAgentEnforcer(pool, silentLogger()), silentLogger()).
		WithConfig(liveSettlementConfig())

	unchargedBefore := map[string]float64{
		"wallet":     testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("wallet")),
		"team_month": testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("team_month")),
		"agent_day":  testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("agent_day")),
		"session":    testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("session")),
	}

	// A: the unknown-cost cancel (quotes stripped) — one pending record
	// plus three zero-amount counting intents.
	require.NoError(t, c.processMessage(ctx, r041UnknownCancelMsg("n06p4t07-p1", "req-n06p4t07-pend-a", n18dOrg, fx)))

	// B: the absorbed-unknown upstream failure — the provider consumed
	// tokens, the price stayed the published placeholder zero under
	// unknown_price: NO charge intents in any shape, one pending record.
	failed := n06p4t07CancelMsg("n06p4t07-p2", "req-n06p4t07-pend-b", n18dOrg, fx, "0.000000", "0.000000", true)
	failed.Values["event_type"] = "request.failed"
	failed.Values["termination"] = "upstream_error"
	failed.Values["usage_source"] = "provider"
	failed.Values["status_code"] = "502"
	failed.Values["error"] = "upstream disconnect before pricing"
	require.NoError(t, c.processMessage(ctx, failed))

	// C: the pre-call denial edge — usage_source none (e.g. policy_denied)
	// with reservations and an unknown quote: nothing is unknown about a
	// request that never reached the provider, so no pending record, no
	// intents, and no uncharged counting (the §6 metric is for consumed
	// usage whose price is unknown — not for denials).
	denied := n06p4t07CancelMsg("n06p4t07-p3", "req-n06p4t07-pend-c", n18dOrg, fx, "", "", false)
	denied.Values["event_type"] = "request.failed"
	denied.Values["termination"] = "upstream_error"
	denied.Values["usage_source"] = "none"
	denied.Values["status_code"] = "403"
	denied.Values["error"] = "policy denied before the provider call"
	require.NoError(t, c.processMessage(ctx, denied))

	require.Equal(t, int64(2), r041JobCountByStatus(ctx, t, pool, n18dOrg)[ChargeKindPendingPrice],
		"both unknown costs stay durably visible, neither can ever be claimed")
	require.Equal(t, int64(3), n18dJobCount(ctx, t, pool, n18dOrg)-2, "the absorbed failure and the denial created no charge intents")
	for scope, before := range unchargedBefore {
		assert.InDelta(t, before+2*float64(fx.bound), testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues(scope)), 0.001,
			"scope %s: both unknown costs counted their bound", scope)
	}

	// 23 hours: one minute inside the deadline — both records stay
	// pending_price.
	backdatePending := func(requestID, interval string) {
		t.Helper()
		_, err := pool.Exec(ctx, `
				UPDATE settlement_jobs SET created_at = now() - $4::interval
				WHERE org_id = $1 AND charge_kind = $2 AND request_id = $3`,
			n18dOrg, ChargeKindPendingPrice, requestID, interval)
		require.NoError(t, err)
	}
	backdatePending("req-n06p4t07-pend-a", "23 hours")
	w.tick(ctx)
	require.Equal(t, int64(2), r041JobCountByStatus(ctx, t, pool, n18dOrg)[ChargeKindPendingPrice],
		"23h is inside the 24h deadline: still pending, still visible")

	// 24h + 1 minute: A terminates to the durable 'unknown' end state; B
	// (young) stays pending_price. Nothing is billed and no row is
	// removed.
	backdatePending("req-n06p4t07-pend-a", "24 hours 1 minute")
	w.tick(ctx)
	byStatus := r041JobCountByStatus(ctx, t, pool, n18dOrg)
	require.Equal(t, int64(1), byStatus[ChargeKindPendingPrice], "the young record stays pending")
	require.Equal(t, int64(1), byStatus["unknown"], "the expired record terminated as 'unknown'")
	var lastErr string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT COALESCE(last_error, '') FROM settlement_jobs
		WHERE org_id = $1 AND charge_kind = $2 AND request_id = $3`,
		n18dOrg, ChargeKindPendingPrice, "req-n06p4t07-pend-a").Scan(&lastErr))
	assert.NotEmpty(t, lastErr, "the expiry records its reason on the row")
	rows, micro := r041LedgerRows(ctx, t, pool, n18dOrg)
	assert.Zero(t, rows, "neither the deadline nor anything else ever billed an unknown")
	assert.Zero(t, micro)

	// The reconcile returns both stakes; both records survive — a release
	// never rewrites an unknown into a confirmed zero and never removes
	// the visibility rows.
	summary := n06p4t07ReleaseStake(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(4), summary.Released)
	assert.Equal(t, int64(4*int64(fx.bound)), summary.ReturnedMicroUSD)
	walletReserved, _, _, _, _, _, _, ledgerRows, ledgerMicro := n18dScopeStates(ctx, t, pool, n18dOrg)
	assert.Zero(t, walletReserved)
	assert.Zero(t, ledgerRows+ledgerMicro)
	byStatus = r041JobCountByStatus(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(1), byStatus[ChargeKindPendingPrice], "the absorbed unknown stays pending after the release")
	assert.Equal(t, int64(1), byStatus["unknown"], "the expired unknown stays terminal")
}
