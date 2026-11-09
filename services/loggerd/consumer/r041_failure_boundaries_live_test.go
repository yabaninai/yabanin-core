package consumer

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Failure-boundary tests cover the negative scenario «клиент ушёл, usage поздний, событие
// live tests:
//
//   - pending_price insert failure: the visibility record commits in the
//     SAME delivery transaction as the request log, so a failed insert is
//     a failed delivery — nothing partial (no log, no intents, not even
//     the inbox claim), the error is the diagnosable cause, and the
//     redelivery still logs the request WITH the pending record.
//   - expiry race with late promotion: the 24h expiry pass racing a
//     late-arriving priced event for the same request id — the priced
//     event settles exactly once under its own identity, the pending
//     record terminates as 'unknown' exactly once, nothing is billed
//     twice, no state is lost.
//   - upstream_error absorb parity: priced partial usage on an upstream
//     failure creates no charge intents in ANY mode (off, shadow,
//     enforce); shadow does not even count it as "would bill" — the
//     platform cost is exported to absorbed_upstream_error instead.

// pendingPriceFailingDB fails the first N pending_price intent inserts
// else goes to the real pool.
type pendingPriceFailingDB struct {
	inner DBOps
	fail  atomic.Int32
}

func (w *pendingPriceFailingDB) Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	return w.inner.Exec(ctx, query, args...)
}

func (w *pendingPriceFailingDB) QueryRow(ctx context.Context, query string, args ...any) pgx.Row {
	return w.inner.QueryRow(ctx, query, args...)
}

func (w *pendingPriceFailingDB) BeginTx(ctx context.Context) (InboxTx, error) {
	tx, err := w.inner.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	return &pendingPriceFailingTx{InboxTx: tx, w: w}, nil
}

type pendingPriceFailingTx struct {
	InboxTx
	w *pendingPriceFailingDB
}

func (t *pendingPriceFailingTx) Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	if t.w.fail.Load() > 0 && strings.Contains(query, ChargeKindPendingPrice) && strings.Contains(query, "INSERT INTO settlement_jobs") && t.w.fail.Add(-1) >= 0 {
		return pgconn.CommandTag{}, errors.New("transient settlement_jobs outage")
	}
	return t.InboxTx.Exec(ctx, query, args...)
}

func r041Count(ctx context.Context, t *testing.T, pool *pgxpool.Pool, query string, args ...any) int64 {
	t.Helper()
	var n int64
	require.NoError(t, pool.QueryRow(ctx, query, args...).Scan(&n))
	return n
}

// drainR041RequestJobs ticks the worker until every non-pending_price job
// of the request reached a terminal state. Bounded past the claim lease
// (2s): a racer that lost a claimed job mid-execution leaves it
// 'processing' until recoverExpiredLeases re-queues it after the lease
// expires — the drain must outlive that window instead of failing.
func drainR041RequestJobs(ctx context.Context, t *testing.T, w *SettlementWorker, pool *pgxpool.Pool, org, requestID string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		w.tick(ctx)
		live := r041Count(ctx, t, pool, `
			SELECT count(*) FROM settlement_jobs
			WHERE org_id = $1 AND request_id = $2
			  AND status IN ('pending','retry','processing')`, org, requestID)
		if live == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	rows, err := pool.Query(ctx, `
		SELECT charge_kind, status, attempts, coalesce(last_error,'') FROM settlement_jobs
		WHERE org_id = $1 AND request_id = $2`, org, requestID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var kind, status, lastErr string
			var attempts int64
			_ = rows.Scan(&kind, &status, &attempts, &lastErr)
			t.Logf("stuck job: kind=%s status=%s attempts=%d err=%s", kind, status, attempts, lastErr)
		}
	}
	t.Fatalf("settlement jobs of request %s did not reach a terminal state", requestID)
}

// Boundary: the pending_price insert failing must never commit a partial
// delivery — no request log without the visibility record, no intents,
// no inbox claim (so the redelivery re-claims cleanly). The request is
// still logged: the SAME event, redelivered after the transient fault
// clears, commits log + pending record together, exactly once.
func TestR041Failure_PendingPriceInsertFailsNothingPartialAndRedeliveryLogs(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrg, 1000)

	failing := &pendingPriceFailingDB{inner: NewDBOps(pool)}
	failing.fail.Store(1)
	c := New(NewRedisOps(rdb), failing, "events:r041f", silentLogger())
	c.SetAgentSpender(budget.NewAgentEnforcer(pool, silentLogger()))
	c.creditStore = credits.NewStore(pool, silentLogger())

	// The insert fails inside the delivery transaction: the delivery is an
	// ERROR, never a partial success.
	err := c.processMessage(ctx, r041UnknownCancelMsg("r041-f1", "req-r041-fail1", n18dOrg, fx))
	require.Error(t, err, "the failed pending_price insert fails the delivery (diagnosable cause)")
	assert.Contains(t, err.Error(), "pending_price", "the error names the failed boundary")

	// Nothing partial committed: no log, no settlement rows, and — the
	// precondition for a clean redelivery — no durable inbox claim.
	req := "req-r041-fail1"
	require.Zero(t, r041Count(ctx, t, pool,
		`SELECT count(*) FROM request_logs WHERE org_id = $1 AND request_id = $2`, n18dOrg, req), "no request log committed")
	require.Zero(t, r041Count(ctx, t, pool,
		`SELECT count(*) FROM settlement_jobs WHERE org_id = $1`, n18dOrg), "no settlement rows committed")
	require.Zero(t, r041Count(ctx, t, pool,
		`SELECT count(*) FROM event_inbox WHERE source = $1 AND event_id = $2`, "events:r041f", "r041-f1"),
		"the inbox claim rolled back — the redelivery re-claims")

	// Redelivery of the SAME event (fault cleared): request log and
	// pending_price record commit together — the request is still logged.
	require.NoError(t, c.processMessage(ctx, r041UnknownCancelMsg("r041-f1", req, n18dOrg, fx)))
	byStatus := r041JobCountByStatus(ctx, t, pool, n18dOrg)
	require.Equal(t, int64(1), byStatus["pending_price"], "the pending_price record exists")
	require.Equal(t, int64(3), byStatus["pending"], "the zero-amount counting intents exist")
	require.Equal(t, int64(1), r041Count(ctx, t, pool,
		`SELECT count(*) FROM request_logs WHERE org_id = $1 AND request_id = $2`, n18dOrg, req), "the request is logged")

	// A third delivery of the same entry id is an inbox no-op.
	require.NoError(t, c.processMessage(ctx, r041UnknownCancelMsg("r041-f1", req, n18dOrg, fx)))
	require.Equal(t, int64(4), n18dJobCount(ctx, t, pool, n18dOrg), "duplicate delivery adds nothing")
	require.Equal(t, int64(1), r041Count(ctx, t, pool,
		`SELECT count(*) FROM event_inbox WHERE source = $1 AND event_id = $2`, "events:r041f", "r041-f1"))
}

// Boundary: the 24h expiry pass racing a late-arriving priced event for
// the same request id. Whatever the interleaving, the priced event
// settles exactly once (its own charge kinds), the pending record
// terminates as 'unknown' exactly once, and no money moves twice.
func TestR041Failure_ExpiryRaceWithLatePricedPromotion(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:r041r", silentLogger())
	c.SetAgentSpender(budget.NewAgentEnforcer(pool, silentLogger()))
	c.creditStore = credits.NewStore(pool, silentLogger())
	w := NewSettlementWorker(pool, c.creditStore, budget.NewAgentEnforcer(pool, silentLogger()), silentLogger()).WithConfig(liveSettlementConfig())

	const iterations = 15
	var totalRows, totalMicro int64
	for i := 0; i < iterations; i++ {
		// Fresh reservation world per request: each request owns its full
		// bound in every scope (the shared-fixture shape the NEXT-18d
		// harness defines — one in-flight request per seeded bound).
		fx := seedNext18dWorld(ctx, t, pool, n18dOrg, 1000)
		req := fmt.Sprintf("req-r041-race-%d", i)

		// The unknown-cost cancel already visible as pending, past its
		// deadline (created 25h ago — the expiry pass is due NOW).
		require.NoError(t, c.processMessage(ctx, r041UnknownCancelMsg(fmt.Sprintf("r041-race-u-%d", i), req, n18dOrg, fx)))
		_, err := pool.Exec(ctx,
			`UPDATE settlement_jobs SET created_at = now() - interval '25 hours'
			 WHERE org_id = $1 AND request_id = $2 AND charge_kind = $3`, n18dOrg, req, ChargeKindPendingPrice)
		require.NoError(t, err)

		// The race: the worker tick (expiry + claim + settle) runs while
		// the priced event for the SAME request id is delivered — the
		// price resolved late and arrives as its own priced event (D2).
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); w.tick(ctx) }()
		go func() {
			defer wg.Done()
			_ = c.processMessage(ctx, r041CancelMsg(fmt.Sprintf("r041-race-p-%d", i), req, n18dOrg, fx))
		}()
		wg.Wait()
		// Deterministic settle: a racer may have parked a job in retry
		// with backoff — drain to terminal state so the exactly-once
		// outcome does not depend on which racer won the interleaving.
		drainR041RequestJobs(ctx, t, w, pool, n18dOrg, req)

		// The pending record terminated exactly once, is never billed and
		// never re-created by the priced delivery.
		var pendingRows, pendingUnknown, pendingBilled int64
		require.NoError(t, pool.QueryRow(ctx, `
			SELECT count(*),
			       count(*) FILTER (WHERE status = 'unknown'),
			       count(*) FILTER (WHERE amount_micro_usd <> 0 OR amount_cents <> 0)
			FROM settlement_jobs WHERE org_id = $1 AND request_id = $2 AND charge_kind = $3`,
			n18dOrg, req, ChargeKindPendingPrice).Scan(&pendingRows, &pendingUnknown, &pendingBilled))
		assert.Equal(t, int64(1), pendingRows, "iteration %d: exactly one pending_price row", i)
		assert.Equal(t, int64(1), pendingUnknown, "iteration %d: the record is terminal 'unknown'", i)
		assert.Zero(t, pendingBilled, "iteration %d: the unknown cost never bills", i)

		// The priced event settled exactly once under its own identities.
		var settled, attention int64
		require.NoError(t, pool.QueryRow(ctx, `
			SELECT count(*) FILTER (WHERE status = 'settled'),
			       count(*) FILTER (WHERE status = 'requires_attention')
			FROM settlement_jobs
			WHERE org_id = $1 AND request_id = $2
			  AND charge_kind IN ('resale_deduction','team_spend','agent_spend','session_spend')`, n18dOrg, req).Scan(&settled, &attention))
		assert.Equal(t, int64(4), settled, "iteration %d: every priced intent settled", i)
		assert.Zero(t, attention, "iteration %d: no durable debt out of the race", i)
		var usage int64
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM credit_transactions WHERE request_id = $1 AND type = 'usage'`, req).Scan(&usage))
		assert.Equal(t, int64(1), usage, "iteration %d: the wallet debited exactly once", i)

		// Accumulate before the next iteration re-seeds the org (the
		// harness wipe deletes the ledger rows of the previous request).
		rows, micro := r041LedgerRows(ctx, t, pool, n18dOrg)
		totalRows += rows
		totalMicro += micro
	}

	// Aggregate across every interleaving: the wallet billed the resale
	// prefix once per request — never twice, never for the unknown one.
	assert.Equal(t, int64(iterations), totalRows)
	assert.Equal(t, int64(-8000*iterations), totalMicro)
}

// Boundary: an upstream failure's priced partial usage is absorbed in
// EVERY reservations mode — enforce creates no intents (D3), shadow does
// not even count it as would-bill (absorb wins over observation), off
// stays the legacy no-intents behavior. The platform cost stays
// observable per scope in absorbed_upstream_error_micro_usd.
func TestR041Failure_UpstreamErrorAbsorbedInEveryMode(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)

	for _, tc := range []struct{ org, mode string }{
		{n18dOrg, "off"}, {n18dOrgShadow, "shadow"}, {n18dOrgEnf, "enforce"},
	} {
		fx := seedNext18dWorld(ctx, t, pool, tc.org, 1000)
		msg := r041CancelMsg("r041-m-"+tc.mode, "req-r041-up-"+tc.mode, tc.org, fx)
		msg.Values["event_type"] = "request.failed"
		msg.Values["termination"] = "upstream_error"
		msg.Values["usage_source"] = "provider"
		msg.Values["status_code"] = "502"
		msg.Values["error"] = "upstream disconnect after first tokens"

		absorbed := map[string]float64{
			"wallet":     testutil.ToFloat64(metrics.AbsorbedUpstreamErrorMicroUSD.WithLabelValues("wallet")),
			"team_month": testutil.ToFloat64(metrics.AbsorbedUpstreamErrorMicroUSD.WithLabelValues("team_month")),
			"agent_day":  testutil.ToFloat64(metrics.AbsorbedUpstreamErrorMicroUSD.WithLabelValues("agent_day")),
			"session":    testutil.ToFloat64(metrics.AbsorbedUpstreamErrorMicroUSD.WithLabelValues("session")),
		}
		wouldBill := map[string]float64{
			"wallet":     testutil.ToFloat64(metrics.WouldBillPartialMicroUSD.WithLabelValues("wallet")),
			"team_month": testutil.ToFloat64(metrics.WouldBillPartialMicroUSD.WithLabelValues("team_month")),
			"agent_day":  testutil.ToFloat64(metrics.WouldBillPartialMicroUSD.WithLabelValues("agent_day")),
			"session":    testutil.ToFloat64(metrics.WouldBillPartialMicroUSD.WithLabelValues("session")),
		}

		c := New(NewRedisOps(rdb), NewDBOps(pool), "events:r041m", silentLogger())
		c.SetAgentSpender(budget.NewAgentEnforcer(pool, silentLogger()))
		c.creditStore = credits.NewStore(pool, silentLogger())
		require.NoError(t, c.processMessage(ctx, msg))

		assert.Zero(t, n18dJobCount(ctx, t, pool, tc.org), "mode %s: no charge intents for an upstream error", tc.mode)
		assert.InDelta(t, absorbed["wallet"]+8000,
			testutil.ToFloat64(metrics.AbsorbedUpstreamErrorMicroUSD.WithLabelValues("wallet")), 0.001, "mode %s", tc.mode)
		assert.InDelta(t, absorbed["team_month"]+4000,
			testutil.ToFloat64(metrics.AbsorbedUpstreamErrorMicroUSD.WithLabelValues("team_month")), 0.001, "mode %s", tc.mode)
		assert.InDelta(t, absorbed["agent_day"]+4000,
			testutil.ToFloat64(metrics.AbsorbedUpstreamErrorMicroUSD.WithLabelValues("agent_day")), 0.001, "mode %s", tc.mode)
		assert.InDelta(t, absorbed["session"]+4000,
			testutil.ToFloat64(metrics.AbsorbedUpstreamErrorMicroUSD.WithLabelValues("session")), 0.001, "mode %s", tc.mode)
		for scope, before := range wouldBill {
			assert.InDelta(t, before, testutil.ToFloat64(metrics.WouldBillPartialMicroUSD.WithLabelValues(scope)), 0.001,
				"mode %s scope %s: an absorbed failure is never counted as would-bill", tc.mode, scope)
		}

		// The worker has nothing to bill; the escrow stays frozen for the
		// reconcile (D3) and the failure log is preserved.
		w := NewSettlementWorker(pool, c.creditStore, budget.NewAgentEnforcer(pool, silentLogger()), silentLogger()).WithConfig(liveSettlementConfig())
		w.tick(ctx)
		rows, micro := r041LedgerRows(ctx, t, pool, tc.org)
		assert.Zero(t, rows, "mode %s: nothing billed", tc.mode)
		assert.Zero(t, micro, "mode %s", tc.mode)
		require.Equal(t, int64(1), r041Count(ctx, t, pool,
			`SELECT count(*) FROM request_logs WHERE org_id = $1 AND request_id = $2`,
			tc.org, "req-r041-up-"+tc.mode), "mode %s: the failure log is preserved", tc.mode)
		walletReserved, teamReserved, teamSpend, agentReserved, agentCost, sessionReserved, sessionSpent, _, _ :=
			n18dScopeStates(ctx, t, pool, tc.org)
		assert.Equal(t, int64(fx.bound), walletReserved, "mode %s: escrow intact", tc.mode)
		assert.Equal(t, int64(fx.bound), teamReserved, "mode %s", tc.mode)
		assert.Equal(t, int64(fx.bound), agentReserved, "mode %s", tc.mode)
		assert.Equal(t, int64(fx.bound), sessionReserved, "mode %s", tc.mode)
		assert.Zero(t, teamSpend)
		assert.Zero(t, agentCost)
		assert.Zero(t, sessionSpent)
	}
}
