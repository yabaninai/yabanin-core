package consumer

import (
	"context"
	"encoding/json"
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

// 2026-10-18 ratified D1–D3), disposable PG+Redis, same stand contract as
// the NEXT-18d live tests:
//
//   - D1 (no refund): a priced cancel bills the consumed prefix exactly
//     once — never the un-consumed part of the bound, never a second time
//     on replay.
//   - D2 (pending_price): an unknown-cost cancel with a reserve is durably
//     visible as a non-claimable pending_price settlement row that expires
//     to terminal 'unknown' after the deadline; never billed, never a
//     confirmed zero, replay adds nothing.
//   - D3 (absorb): an upstream_error's priced partial usage creates no
//     charge intents in ANY mode (enforce included); the would-be cost is
//     exported to absorbed_upstream_error_micro_usd.

// r041CancelMsg clones the NEXT-18d completed-event fixture as a priced
// client cancel whose partial usage is known: base cost 0.004 (the consumed
// prefix), resale price 0.008, bound 0.012 per scope.
func r041CancelMsg(entryID, requestID, org string, fx n18dFixture) redis.XMessage {
	msg := n18dCompletedMsg(entryID, requestID, org, fx)
	msg.Values["termination"] = "client_cancel"
	msg.Values["estimated_cost_usd"] = "0.004"
	msg.Values["resale_cost_usd"] = "0.008"
	return msg
}

// r041UnknownCancelMsg strips every quote from the cancel event: the cost
// of the consumed prefix stayed unknown (cost_status=unknown_price).
func r041UnknownCancelMsg(entryID, requestID, org string, fx n18dFixture) redis.XMessage {
	msg := n18dCompletedMsg(entryID, requestID, org, fx)
	msg.Values["termination"] = "client_cancel"
	msg.Values["cost_status"] = "unknown_price"
	delete(msg.Values, "estimated_cost_usd")
	delete(msg.Values, "resale_cost_usd")
	return msg
}

// r041JobCountByStatus counts the org's settlement jobs per status.
func r041JobCountByStatus(ctx context.Context, t *testing.T, pool *pgxpool.Pool, org string) map[string]int64 {
	t.Helper()
	rows, err := pool.Query(ctx, `SELECT status, count(*) FROM settlement_jobs WHERE org_id = $1 GROUP BY status`, org)
	require.NoError(t, err)
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var status string
		var n int64
		require.NoError(t, rows.Scan(&status, &n))
		out[status] = n
	}
	require.NoError(t, rows.Err())
	return out
}

func r041LedgerRows(ctx context.Context, t *testing.T, pool *pgxpool.Pool, org string) (rows, micro int64) {
	t.Helper()
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*), COALESCE(SUM(amount_micro_usd),0) FROM credit_transactions WHERE org_id = $1 AND type = 'usage'`, org).
		Scan(&rows, &micro))
	return
}

// D1: a priced cancel bills the consumed prefix (resale for the wallet,
// base for the budget areas) exactly once; the un-consumed part of the
// bound stays reserved for the reconcile; a replay of the same request id
// adds no charge anywhere.
func TestR041Live_CancelPartialDeliveryBillsConsumedPrefixOnce(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrg, 1000)

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:r041", silentLogger())
	c.SetAgentSpender(budget.NewAgentEnforcer(pool, silentLogger()))
	c.creditStore = credits.NewStore(pool, silentLogger())
	require.NoError(t, c.processMessage(ctx, r041CancelMsg("r041-c1", "req-r041-cancel", n18dOrg, fx)))
	require.Equal(t, int64(4), n18dJobCount(ctx, t, pool, n18dOrg), "one intent per reserved scope")

	w := NewSettlementWorker(pool, c.creditStore, budget.NewAgentEnforcer(pool, silentLogger()), silentLogger()).WithConfig(liveSettlementConfig())
	w.tick(ctx)

	walletReserved, teamReserved, teamSpend, agentReserved, agentCost, sessionReserved, sessionSpent, ledgerRows, ledgerMicro := n18dScopeStates(ctx, t, pool, n18dOrg)
	// Consumed prefix only: wallet bills the resale price of the prefix
	// (0.008), the budget areas the base cost of the prefix (0.004) — the
	// bound's un-consumed remainder (12000 − min(actual,bound)) stays
	// reserved for the reconcile, never billed.
	assert.Equal(t, int64(1), ledgerRows, "exactly one wallet usage row")
	assert.Equal(t, int64(-8000), ledgerMicro, "wallet billed the consumed prefix's resale price once")
	assert.Equal(t, int64(4000), teamSpend, "team billed the prefix's base cost")
	assert.Equal(t, int64(4000), agentCost, "agent billed the prefix's base cost")
	assert.Equal(t, int64(4000), sessionSpent, "session billed the prefix's base cost")
	assert.Equal(t, int64(4000), walletReserved, "un-consumed wallet bound left for reconcile")
	assert.Equal(t, int64(8000), teamReserved, "un-consumed team bound left for reconcile")
	assert.Equal(t, int64(8000), agentReserved, "un-consumed agent bound left for reconcile")
	assert.Equal(t, int64(8000), sessionReserved, "un-consumed session bound left for reconcile")

	// Replay (fresh stream entry, same request id): one charge per scope,
	// D1 has no refund and no second debit.
	require.NoError(t, c.processMessage(ctx, r041CancelMsg("r041-c2", "req-r041-cancel", n18dOrg, fx)))
	require.Equal(t, int64(4), n18dJobCount(ctx, t, pool, n18dOrg), "replay adds no intents")
	w.tick(ctx)
	walletReserved2, teamReserved2, teamSpend2, agentReserved2, agentCost2, sessionReserved2, sessionSpent2, ledgerRows2, ledgerMicro2 := n18dScopeStates(ctx, t, pool, n18dOrg)
	assert.Equal(t, ledgerRows, ledgerRows2, "no second wallet row")
	assert.Equal(t, ledgerMicro, ledgerMicro2, "no second wallet debit")
	assert.Equal(t, teamSpend, teamSpend2)
	assert.Equal(t, agentCost, agentCost2)
	assert.Equal(t, sessionSpent, sessionSpent2)
	assert.Equal(t, walletReserved, walletReserved2)
	assert.Equal(t, teamReserved, teamReserved2)
	assert.Equal(t, agentReserved, agentReserved2)
	assert.Equal(t, sessionReserved, sessionReserved2)
}

// D2: an unknown-cost cancel is visible as a non-claimable pending_price
// record committed with the request log; the worker never bills it; past
// the deadline the record terminates as 'unknown' (never a confirmed
// zero); a replay changes nothing.
func TestR041Live_UnknownCostCancelPendingVisibleThenExpires(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrg, 1000)

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:r041", silentLogger())
	c.SetAgentSpender(budget.NewAgentEnforcer(pool, silentLogger()))
	c.creditStore = credits.NewStore(pool, silentLogger())
	require.NoError(t, c.processMessage(ctx, r041UnknownCancelMsg("r041-u1", "req-r041-unknown", n18dOrg, fx)))

	byStatus := r041JobCountByStatus(ctx, t, pool, n18dOrg)
	require.Equal(t, int64(1), byStatus["pending_price"], "the unknown cost is visible as exactly one pending_price record")
	require.Equal(t, int64(3), byStatus["pending"], "team/agent/session keep their zero-amount counting intents")

	// The visibility payload carries the termination and the reserve
	// bounds — the pending view shows what is at stake.
	var payload []byte
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT payload FROM settlement_jobs WHERE org_id = $1 AND charge_kind = $2`, n18dOrg, ChargeKindPendingPrice).Scan(&payload))
	var pl struct {
		Termination string `json:"termination"`
		Reserved    []struct {
			ScopeKind     string `json:"scope_kind"`
			BoundMicroUSD int64  `json:"bound_micro_usd"`
		} `json:"reservations"`
	}
	require.NoError(t, json.Unmarshal(payload, &pl))
	assert.Equal(t, "client_cancel", pl.Termination)
	require.Len(t, pl.Reserved, 4, "every reserved scope's bound is visible")
	for _, r := range pl.Reserved {
		assert.Equal(t, int64(fx.bound), r.BoundMicroUSD, "scope %s bound", r.ScopeKind)
	}

	// The worker runs and must NOT claim, bill or settle the record.
	w := NewSettlementWorker(pool, c.creditStore, budget.NewAgentEnforcer(pool, silentLogger()), silentLogger()).WithConfig(liveSettlementConfig())
	w.tick(ctx)
	byStatus = r041JobCountByStatus(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(1), byStatus["pending_price"], "a worker tick leaves the pending_price record pending")
	rows, micro := r041LedgerRows(ctx, t, pool, n18dOrg)
	assert.Zero(t, rows, "unknown cost never bills")
	assert.Zero(t, micro)

	// Deadline passes (created 25h ago > the 24h default expiry): the
	// record terminates as 'unknown' — the durable, never-billed end state.
	expiredBefore := testutil.ToFloat64(metrics.SettlementPendingPriceExpiredTotal)
	_, err := pool.Exec(ctx, `
		UPDATE settlement_jobs SET created_at = now() - interval '25 hours'
		WHERE org_id = $1 AND charge_kind = $2`, n18dOrg, ChargeKindPendingPrice)
	require.NoError(t, err)
	w.tick(ctx)
	byStatus = r041JobCountByStatus(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(1), byStatus["unknown"], "expired record is terminal 'unknown'")
	assert.NotContains(t, byStatus, "pending_price")
	assert.InDelta(t, expiredBefore+1, testutil.ToFloat64(metrics.SettlementPendingPriceExpiredTotal), 0.001)
	rows, micro = r041LedgerRows(ctx, t, pool, n18dOrg)
	assert.Zero(t, rows, "expiry still never bills")
	assert.Zero(t, micro, "never a confirmed zero")

	// Replay of the same request id: the identity is unique — no second
	// record, the terminal state stands.
	require.NoError(t, c.processMessage(ctx, r041UnknownCancelMsg("r041-u2", "req-r041-unknown", n18dOrg, fx)))
	w.tick(ctx)
	assert.Equal(t, int64(1), r041JobCountByStatus(ctx, t, pool, n18dOrg)["unknown"], "replay adds no record")
}

// D3: an upstream failure's priced partial usage is absorbed by the
// platform — zero charge intents even in enforce mode; the would-be cost
// lands in absorbed_upstream_error_micro_usd; the request log itself is
// preserved with its termination.
func TestR041Live_UpstreamErrorPartialUsageNotBilled(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrgEnf, 1000)

	msg := r041CancelMsg("r041-e1", "req-r041-upstream", n18dOrgEnf, fx)
	msg.Values["event_type"] = "request.failed"
	msg.Values["termination"] = "upstream_error"
	msg.Values["usage_source"] = "provider"
	msg.Values["status_code"] = "502"
	msg.Values["error"] = "upstream disconnect after first tokens"

	absorbedBefore := map[string]float64{
		"wallet":     testutil.ToFloat64(metrics.AbsorbedUpstreamErrorMicroUSD.WithLabelValues("wallet")),
		"team_month": testutil.ToFloat64(metrics.AbsorbedUpstreamErrorMicroUSD.WithLabelValues("team_month")),
		"agent_day":  testutil.ToFloat64(metrics.AbsorbedUpstreamErrorMicroUSD.WithLabelValues("agent_day")),
		"session":    testutil.ToFloat64(metrics.AbsorbedUpstreamErrorMicroUSD.WithLabelValues("session")),
	}

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:r041", silentLogger())
	c.SetAgentSpender(budget.NewAgentEnforcer(pool, silentLogger()))
	c.creditStore = credits.NewStore(pool, silentLogger())
	require.NoError(t, c.processMessage(ctx, msg))

	assert.Zero(t, n18dJobCount(ctx, t, pool, n18dOrgEnf), "enforce mode creates no charge intents for an upstream error")

	// The absorbed platform cost stays observable per scope: wallet would
	// have billed the resale price (0.008), the budget areas the base
	// prefix cost (0.004).
	assert.InDelta(t, absorbedBefore["wallet"]+8000,
		testutil.ToFloat64(metrics.AbsorbedUpstreamErrorMicroUSD.WithLabelValues("wallet")), 0.001)
	assert.InDelta(t, absorbedBefore["team_month"]+4000,
		testutil.ToFloat64(metrics.AbsorbedUpstreamErrorMicroUSD.WithLabelValues("team_month")), 0.001)
	assert.InDelta(t, absorbedBefore["agent_day"]+4000,
		testutil.ToFloat64(metrics.AbsorbedUpstreamErrorMicroUSD.WithLabelValues("agent_day")), 0.001)
	assert.InDelta(t, absorbedBefore["session"]+4000,
		testutil.ToFloat64(metrics.AbsorbedUpstreamErrorMicroUSD.WithLabelValues("session")), 0.001)

	// The failure itself is still logged with its termination.
	var logged int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM request_logs WHERE org_id = $1 AND request_id = $2`, n18dOrgEnf, "req-r041-upstream").Scan(&logged))
	assert.Equal(t, int64(1), logged, "the failed request log is preserved")

	// The worker has nothing to bill and the escrow stays frozen for the
	// reconcile (the platform absorbed the cost, the reserve returns via
	// the safety window).
	w := NewSettlementWorker(pool, c.creditStore, budget.NewAgentEnforcer(pool, silentLogger()), silentLogger()).WithConfig(liveSettlementConfig())
	w.tick(ctx)
	rows, micro := r041LedgerRows(ctx, t, pool, n18dOrgEnf)
	assert.Zero(t, rows, "no billing after the worker runs")
	assert.Zero(t, micro)
	walletReserved, teamReserved, teamSpend, agentReserved, agentCost, sessionReserved, sessionSpent, _, _ := n18dScopeStates(ctx, t, pool, n18dOrgEnf)
	assert.Equal(t, int64(fx.bound), walletReserved, "wallet escrow intact for reconcile")
	assert.Equal(t, int64(fx.bound), teamReserved)
	assert.Equal(t, int64(fx.bound), agentReserved)
	assert.Equal(t, int64(fx.bound), sessionReserved)
	assert.Zero(t, teamSpend)
	assert.Zero(t, agentCost)
	assert.Zero(t, sessionSpent)
}
