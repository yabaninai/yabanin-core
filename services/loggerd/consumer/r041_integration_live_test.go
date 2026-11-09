package consumer

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// D1–D3): the full cancel→pending→expiry→unknown lifecycle through the
// ACTUAL consumer entry point (processMessage — the Redis-stream
// delivery boundary the gateway events arrive on), executed end-to-end
// against the disposable PG+Redis stand with the real settlement worker
// and the real backlog gauges. Package criterion: debit exactly once;
// unknown cost visible as pending. Negative scenario legs (replay,
// late priced promotion) run through the same boundary.
func TestR041Integration_CancelPendingExpiryUnknownLifecycle(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrg, 1000)
	req := "req-r041-e2e"

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:r041i", silentLogger())
	c.SetAgentSpender(budget.NewAgentEnforcer(pool, silentLogger()))
	c.creditStore = credits.NewStore(pool, silentLogger())
	w := NewSettlementWorker(pool, c.creditStore, budget.NewAgentEnforcer(pool, silentLogger()), silentLogger()).WithConfig(liveSettlementConfig())

	// --- Cancel with unknown cost: pending, visible, unbilled.
	require.NoError(t, c.processMessage(ctx, r041UnknownCancelMsg("r041-e2e-1", req, n18dOrg, fx)))
	byStatus := r041JobCountByStatus(ctx, t, pool, n18dOrg)
	require.Equal(t, int64(1), byStatus["pending_price"], "the unknown cost is visible as pending")
	require.Equal(t, int64(3), byStatus["pending"])
	require.Equal(t, int64(1), r041Count(ctx, t, pool,
		`SELECT count(*) FROM request_logs WHERE org_id = $1 AND request_id = $2`, n18dOrg, req),
		"the request log is committed with the pending record")

	// Worker tick (drains the zero-amount counting intents; the
	// pending_price record is non-claimable): the pending view stays
	// pending, the wallet is untouched, the gauge carries the state.
	w.tick(ctx)
	byStatus = r041JobCountByStatus(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(1), byStatus["pending_price"], "a worker tick leaves the pending record pending")
	assert.InDelta(t, float64(1), testutil.ToFloat64(metrics.SettlementBacklog.WithLabelValues("pending_price")), 0.001,
		"the backlog gauge shows the pending_price record")
	rows, micro := r041LedgerRows(ctx, t, pool, n18dOrg)
	assert.Zero(t, rows, "unknown cost never bills")
	assert.Zero(t, micro)

	// --- Expiry: past the 24h deadline the record terminates as
	// terminal 'unknown' — never billed, never a confirmed zero.
	expiredBefore := testutil.ToFloat64(metrics.SettlementPendingPriceExpiredTotal)
	_, err := pool.Exec(ctx, `
		UPDATE settlement_jobs SET created_at = now() - interval '25 hours'
		WHERE org_id = $1 AND request_id = $2 AND charge_kind = $3`, n18dOrg, req, ChargeKindPendingPrice)
	require.NoError(t, err)
	w.tick(ctx)
	byStatus = r041JobCountByStatus(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(1), byStatus["unknown"], "terminal 'unknown' after the deadline")
	assert.InDelta(t, float64(0), testutil.ToFloat64(metrics.SettlementBacklog.WithLabelValues("pending_price")), 0.001,
		"the pending view drained")
	assert.InDelta(t, float64(1), testutil.ToFloat64(metrics.SettlementBacklog.WithLabelValues("unknown")), 0.001,
		"the unknown state is durably visible in the backlog")
	assert.InDelta(t, expiredBefore+1, testutil.ToFloat64(metrics.SettlementPendingPriceExpiredTotal), 0.001)
	rows, micro = r041LedgerRows(ctx, t, pool, n18dOrg)
	assert.Zero(t, rows)
	assert.Zero(t, micro)

	// --- Replay (событие повторено): the same event redelivered adds no
	// record and no charge; the terminal state stands.
	require.NoError(t, c.processMessage(ctx, r041UnknownCancelMsg("r041-e2e-2", req, n18dOrg, fx)))
	w.tick(ctx)
	assert.Equal(t, int64(1), r041JobCountByStatus(ctx, t, pool, n18dOrg)["unknown"], "replay adds nothing")

	// --- Late priced promotion (usage поздний): the price resolved
	// AFTER expiry arrives as its own priced event and settles under its
	// own identity — the wallet debits exactly once (D1), the terminal
	// 'unknown' record is never re-opened, never billed.
	require.NoError(t, c.processMessage(ctx, r041CancelMsg("r041-e2e-3", req, n18dOrg, fx)))
	drainR041RequestJobs(ctx, t, w, pool, n18dOrg, req)
	byStatus = r041JobCountByStatus(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(1), byStatus["unknown"], "the unknown record keeps its terminal state")
	assert.Equal(t, int64(4), byStatus["settled"], "the priced event settled its identities")
	assert.Equal(t, int64(0), byStatus["requires_attention"])
	rows, micro = r041LedgerRows(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(1), rows, "the wallet debited exactly once — for the priced event only")
	assert.Equal(t, int64(-8000), micro, "the consumed prefix's resale price, exactly once")

	// --- Second full pass is a no-op (idempotence at the boundary).
	w.tick(ctx)
	rows2, micro2 := r041LedgerRows(ctx, t, pool, n18dOrg)
	assert.Equal(t, rows, rows2)
	assert.Equal(t, micro, micro2)
	assert.Equal(t, byStatus, r041JobCountByStatus(ctx, t, pool, n18dOrg))
}
