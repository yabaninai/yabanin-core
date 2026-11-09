package consumer

// N06-P04 T09 — consumer-compatibility pins for settlement after cancel
// and partial failure (card action: "Пройти старую и новую конфигурацию и
// реальные поддержанные consumers; явный отказ для неподдержанного").
// Runs on disposable PG+Redis fixtures; the environment helpers are the
// ones in next18d_live_test.go and r041_settlement_cancel_live_test.go.
// The matrix walks OLD configuration × OLD event shape, OLD
// configuration × NEW event shape, NEW configuration × NEW event shape,
// and the schema-level explicit refusal of an unsupported mode value:
//
//   - a legacy event (no reservations/termination fields) keeps the exact
//     legacy semantics under every reservations mode: failed requests
//     never bill (the failed path charges only reservation tuples), the
//     legacy completed event still bills through the attribution fallback
//     (wallet + team + agent, never session), and reserves are untouched;
//   - an old (off-mode) org receiving a NEW reservation-backed priced
//     cancel is explicitly refused: no durable settlement work, while the
//     reserve bounds stay visible in the uncharged metric — never a
//     silent zero — and a redelivery does not re-count them (T08's
//     exactly-once counting, proven on the real DB);
//   - a NEW-mode (enforce) org settles a priced cancel once per scope,
//     and the late request.completed usage of the same request claims
//     nothing: cancel + late usage converge to exactly one committed
//     operation per scope (the card's acceptance sentence);
//   - an unsupported reservations_mode value cannot exist: the schema
//     refuses it outright (CHECK organizations_reservations_mode_check),
//     and the consumer's mode-probe switch keeps its unreachable
//     default→off branch as defense-in-depth (a probe failure degrades
//     fail-closed to off — pinned at unit level by T05's
//     TestN06P4PricedRedeliveryNeverBillsTwiceAtModeBoundaries probe-error
//     case; a live missing-org delivery cannot exist because
//     request_logs.org_id carries an FK to organizations).
//
// Already pinned elsewhere (cited, not duplicated):
//   - enforce/shadow/off failed-event matrix incl. unknown costs, the
//     shadow WouldBillPartial observation and the visible uncharged bounds
//     → TestN06P4PricedRedeliveryNeverBillsTwiceAtModeBoundaries,
//     TestUpstreamErrorAbsorbedIsNeverBilledAtDelivery (mock pool);
//   - live D1/D2/D3 cancel semantics on the enforce/off boundary →
//     r041_settlement_cancel_live_test.go;
//   - known-zero / sub-micro / bound-edge / pending-expiry boundaries →
//     n06p4t07_boundary_corpus_test.go;
//   - crash-recovery resume → n06p4t08_recovery_resume_test.go.

import (
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// n06p4t09LegacyFailedMsg is the pre-reservation request.failed shape: no
// reservations tuples, no termination field, no usage_source (the gateway
// only started attaching those with the §5 events). The prefix cost is
// priced on the wire — the old shape carried it as plain analytics.
func n06p4t09LegacyFailedMsg(entryID, requestID, org string) redis.XMessage {
	return redis.XMessage{ID: entryID, Values: map[string]interface{}{
		"event_type": "request.failed", "source": "gateway",
		"request_id": requestID, "org_id": org,
		"model_requested": "gpt-4", "model_used": "gpt-4",
		"status_code": "499", "tokens_in": "100", "tokens_out": "20",
		"estimated_cost_usd": "0.004", "resale_cost_usd": "0.008",
		"team_id": n18dTeam, "agent_id": n18dAgent, "session_key_id": n18dSession,
	}}
}

// n06p4t09LegacyCompletedMsg is the pre-reservation request.completed
// shape: attribution came from team/agent ids alone, no tuples, no
// termination. The wallet bills the estimated price.
func n06p4t09LegacyCompletedMsg(entryID, requestID, org string) redis.XMessage {
	return redis.XMessage{ID: entryID, Values: map[string]interface{}{
		"event_type": "request.completed", "source": "gateway",
		"request_id": requestID, "org_id": org,
		"model_requested": "gpt-4", "model_used": "gpt-4",
		"status_code": "200", "tokens_in": "100", "tokens_out": "20",
		"estimated_cost_usd": "0.012",
		"team_id":            n18dTeam, "agent_id": n18dAgent, "session_key_id": n18dSession,
	}}
}

// TestN06P4T09Live_LegacyEventsKeepLegacySemanticsAtEveryMode — the OLD
// event shape under the NEW pipeline. The legacy completed request keeps
// the attribution-fallback billing result on the old-configuration (off)
// org: wallet + team + agent (session requires a reserve tuple), no
// reserve decrements. The legacy FAILED request follows the reservations
// mode exactly as its reservation-backed sibling does (the plan builder is
// shared — D5/I2): enforce bills the known prefix via the attribution
// fallback, shadow only observes the would-bill, off refuses durably. A
// legacy unknown-price failed request grows nothing anywhere: without
// tuples there is no reserve at stake, so neither a pending_price row nor
// an uncharged bound may appear.
func TestN06P4T09Live_LegacyEventsKeepLegacySemanticsAtEveryMode(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrg, 1000)

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:n06p4t09-legacy", silentLogger())
	c.SetAgentSpender(budget.NewAgentEnforcer(pool, silentLogger()))
	c.creditStore = credits.NewStore(pool, silentLogger())

	// Legacy completed request on the old-configuration org: billed through
	// the attribution fallback and settled once — exactly the pre-
	// reservation contract, preserved.
	require.NoError(t, c.processMessage(ctx, n06p4t09LegacyCompletedMsg("t09-legacy-c", "req-t09-legacy-c", n18dOrg)))
	require.Equal(t, int64(3), n18dJobCount(ctx, t, pool, n18dOrg),
		"exactly three fallback intents: wallet, team, agent — no session without a tuple")

	w := NewSettlementWorker(pool, c.creditStore, budget.NewAgentEnforcer(pool, silentLogger()), silentLogger()).WithConfig(liveSettlementConfig())
	w.tick(ctx)

	walletReserved, teamReserved, teamSpend, agentReserved, agentCost, sessionReserved, sessionSpent, ledgerRows, ledgerMicro := n18dScopeStates(ctx, t, pool, n18dOrg)
	assert.Equal(t, int64(fx.bound), walletReserved, "the legacy settle never decrements the wallet reserve")
	assert.Equal(t, int64(fx.bound), teamReserved, "the legacy settle never decrements the team reserve")
	assert.Equal(t, int64(fx.bound), agentReserved, "the legacy settle never decrements the agent reserve")
	assert.Equal(t, int64(fx.bound), sessionReserved, "the legacy settle never decrements the session reserve")
	assert.Equal(t, int64(12000), teamSpend, "team billed the estimated base cost once")
	assert.Equal(t, int64(12000), agentCost, "agent billed the estimated base cost once")
	assert.Equal(t, int64(0), sessionSpent, "session is tuple-only: a legacy event never spends it")
	assert.Equal(t, int64(1), ledgerRows, "one wallet usage row")
	assert.Equal(t, int64(-12000), ledgerMicro, "wallet billed the estimated price once")

	// The legacy replay claims nothing: one operation per identity.
	require.NoError(t, c.processMessage(ctx, n06p4t09LegacyCompletedMsg("t09-legacy-c2", "req-t09-legacy-c", n18dOrg)))
	assert.Equal(t, int64(3), n18dJobCount(ctx, t, pool, n18dOrg), "the replay adds no intents")
	w.tick(ctx)
	_, _, teamSpend2, _, agentCost2, _, sessionSpent2, ledgerRows2, ledgerMicro2 := n18dScopeStates(ctx, t, pool, n18dOrg)
	assert.Equal(t, teamSpend, teamSpend2)
	assert.Equal(t, agentCost, agentCost2)
	assert.Equal(t, sessionSpent, sessionSpent2)
	assert.Equal(t, ledgerRows, ledgerRows2, "no second wallet row")
	assert.Equal(t, ledgerMicro, ledgerMicro2, "no second wallet debit")

	// The legacy failed request across the mode boundary.
	for _, org := range []string{n18dOrgEnf, n18dOrgShadow, n18dOrg} {
		beforeWouldWallet := testutil.ToFloat64(metrics.WouldBillPartialMicroUSD.WithLabelValues("wallet"))
		beforeWouldTeam := testutil.ToFloat64(metrics.WouldBillPartialMicroUSD.WithLabelValues("team_month"))
		beforeUnknown := testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("wallet"))

		// Legacy priced failed request: delivered and logged in every mode.
		jobsBeforeFailed := n18dJobCount(ctx, t, pool, org)
		require.NoError(t, c.processMessage(ctx, n06p4t09LegacyFailedMsg("t09-legacy-f-"+org[34:], "req-t09-legacy-f", org)),
			"the legacy shape still delivers")
		switch org {
		case n18dOrgEnf:
			assert.Equal(t, jobsBeforeFailed+3, n18dJobCount(ctx, t, pool, org),
				"enforce bills the known prefix through the attribution fallback: wallet, team, agent — no session without a tuple")
		default:
			assert.Equal(t, jobsBeforeFailed, n18dJobCount(ctx, t, pool, org),
				"no durable settlement work outside enforce — off is the legacy behavior, shadow only observes")
		}
		assert.InDelta(t, beforeUnknown, testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("wallet")), 0.001,
			"no uncharged-unknown signal without a reserve")
		if org == n18dOrgShadow {
			assert.InDelta(t, beforeWouldWallet+8000, testutil.ToFloat64(metrics.WouldBillPartialMicroUSD.WithLabelValues("wallet")), 0.001,
				"shadow observes the would-bill resale of the prefix")
			assert.InDelta(t, beforeWouldTeam+4000, testutil.ToFloat64(metrics.WouldBillPartialMicroUSD.WithLabelValues("team_month")), 0.001,
				"shadow observes the would-bill base cost of the prefix")
		} else {
			assert.InDelta(t, beforeWouldWallet, testutil.ToFloat64(metrics.WouldBillPartialMicroUSD.WithLabelValues("wallet")), 0.001,
				"the would-bill metric is shadow-only")
		}

		// The same-entry replay claims nothing further.
		jobsBeforeReplay := n18dJobCount(ctx, t, pool, org)
		require.NoError(t, c.processMessage(ctx, n06p4t09LegacyFailedMsg("t09-legacy-f-"+org[34:], "req-t09-legacy-f-replay", org)))
		assert.Equal(t, jobsBeforeReplay, n18dJobCount(ctx, t, pool, org),
			"the replay adds no intents")
		// Legacy unknown-price failed request: without tuples there is no
		// reserve at stake — no pending_price row, no uncharged bound, and
		// no charge (a known price is required for a failed-prefix charge).
		legacyUnknown := n06p4t09LegacyFailedMsg("t09-legacy-u-"+org[34:], "req-t09-legacy-u", org)
		legacyUnknown.Values["cost_status"] = "unknown_price"
		delete(legacyUnknown.Values, "estimated_cost_usd")
		delete(legacyUnknown.Values, "resale_cost_usd")
		require.NoError(t, c.processMessage(ctx, legacyUnknown))
		assert.Equal(t, jobsBeforeReplay, n18dJobCount(ctx, t, pool, org),
			"no pending_price and no charge for a legacy unknown-price event — nothing was reserved")
		assert.InDelta(t, beforeUnknown, testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("wallet")), 0.001,
			"the uncharged metric counts reservation bounds only")
	}
}

// TestN06P4T09Live_OldModeRefusesNewShapeChargesButKeepsBoundsVisible —
// OLD configuration × NEW event shape. An off-mode org receiving a
// reservation-backed priced request.failed is explicitly refused: no
// durable settlement work and no would-bill, while every reserve bound
// stays visible in the uncharged metric — the prefix is never masked as a
// confirmed zero and never dropped. A replayed event (same stream entry
// id) claims and re-counts nothing; the same identity under a NEW entry id
// is a new committed delivery by contract — its own analytics row and
// uncharged increment, still zero durable settlement work (T05/T08). The
// request.completed cancel shape is NOT gated by the mode: the completed
// path settles in every mode (r041_settlement_cancel_live_test.go test D1
// drives a request.completed cancel against an off-mode org and it
// settles); the mode boundary governs the failed path only.
func TestN06P4T09Live_OldModeRefusesNewShapeChargesButKeepsBoundsVisible(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrg, 1000)

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:n06p4t09-off", silentLogger())
	c.SetAgentSpender(budget.NewAgentEnforcer(pool, silentLogger()))
	c.creditStore = credits.NewStore(pool, silentLogger())

	failed := r041CancelMsg("t09-off-1", "req-t09-off", n18dOrg, fx)
	failed.Values["event_type"] = "request.failed"

	beforeWould := testutil.ToFloat64(metrics.WouldBillPartialMicroUSD.WithLabelValues("wallet"))
	beforeUnknown := map[string]float64{}
	for _, scope := range []string{"wallet", "team_month", "agent_day", "session"} {
		beforeUnknown[scope] = testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues(scope))
	}

	require.NoError(t, c.processMessage(ctx, failed))

	assert.Equal(t, int64(0), n18dJobCount(ctx, t, pool, n18dOrg),
		"off mode refuses the new shape: no durable settlement work")
	assert.InDelta(t, beforeWould, testutil.ToFloat64(metrics.WouldBillPartialMicroUSD.WithLabelValues("wallet")), 0.001,
		"off mode never counts a would-bill")
	for _, scope := range []string{"wallet", "team_month", "agent_day", "session"} {
		assert.InDelta(t, beforeUnknown[scope]+float64(fx.bound),
			testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues(scope)), 0.001,
			"the refused prefix's bound stays visible per scope, never masked as a zero")
	}
	var logRows int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM request_logs WHERE org_id = $1 AND request_id = $2`, n18dOrg, "req-t09-off").Scan(&logRows))
	assert.Equal(t, int64(1), logRows, "the refusal still delivers the analytics row")

	// The repeated event (same stream entry id redelivered) claims nothing,
	// re-counts nothing and writes no second analytics row — the card's
	// negative scenario on the real DB.
	require.NoError(t, c.processMessage(ctx, failed))
	assert.Equal(t, int64(0), n18dJobCount(ctx, t, pool, n18dOrg))
	for _, scope := range []string{"wallet", "team_month", "agent_day", "session"} {
		assert.InDelta(t, beforeUnknown[scope]+float64(fx.bound),
			testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues(scope)), 0.001,
			"the replay does not re-inflate the uncharged bound")
	}
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM request_logs WHERE org_id = $1 AND request_id = $2`, n18dOrg, "req-t09-off").Scan(&logRows))
	assert.Equal(t, int64(1), logRows, "the refused replay writes no second analytics row")

	// The same identity re-emitted under a NEW stream entry id is a new
	// committed delivery by contract (N06-P04-T05/T08: only the settlement
	// identity dedupes; every committed delivery keeps its own analytics
	// row and its own uncharged increment). The refusal itself still holds:
	// the durable settlement work stays empty.
	replayed := r041CancelMsg("t09-off-3", "req-t09-off", n18dOrg, fx)
	replayed.Values["event_type"] = "request.failed"
	require.NoError(t, c.processMessage(ctx, replayed))
	assert.Equal(t, int64(0), n18dJobCount(ctx, t, pool, n18dOrg),
		"a new entry id changes nothing about the off-mode refusal")
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM request_logs WHERE org_id = $1 AND request_id = $2`, n18dOrg, "req-t09-off").Scan(&logRows))
	assert.Equal(t, int64(2), logRows,
		"each committed delivery keeps its own analytics row (only the settlement identity dedupes)")
	for _, scope := range []string{"wallet", "team_month", "agent_day", "session"} {
		assert.InDelta(t, beforeUnknown[scope]+2*float64(fx.bound),
			testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues(scope)), 0.001,
			"the uncharged bound is counted once per committed delivery (stream.go's post-commit contract)")
	}
}

// TestN06P4T09Live_NewConfigCancelSettlesOnceAndLateUsageClaimsNothing —
// NEW configuration × NEW event shape, the card's acceptance sentence:
// cancel and late usage complete ONE operation. The priced cancel settles
// the consumed prefix once per scope; the late request.completed usage of
// the same request (full completed quotes, same identities) claims nothing
// anywhere — the settlement identities the cancel created refuse it, and
// no uncharged bound is re-counted by the billed plan.
func TestN06P4T09Live_NewConfigCancelSettlesOnceAndLateUsageClaimsNothing(t *testing.T) {
	ctx, pool, rdb := newNext18dEnv(t)
	fx := seedNext18dWorld(ctx, t, pool, n18dOrgEnf, 1000)

	c := New(NewRedisOps(rdb), NewDBOps(pool), "events:n06p4t09-enf", silentLogger())
	c.SetAgentSpender(budget.NewAgentEnforcer(pool, silentLogger()))
	c.creditStore = credits.NewStore(pool, silentLogger())

	// The priced cancel: one intent per reserved scope.
	require.NoError(t, c.processMessage(ctx, r041CancelMsg("t09-enf-1", "req-t09-enf", n18dOrgEnf, fx)))
	require.Equal(t, int64(4), n18dJobCount(ctx, t, pool, n18dOrgEnf), "one intent per reserved scope")

	w := NewSettlementWorker(pool, c.creditStore, budget.NewAgentEnforcer(pool, silentLogger()), silentLogger()).WithConfig(liveSettlementConfig())
	w.tick(ctx)

	walletReserved, teamReserved, teamSpend, agentReserved, agentCost, sessionReserved, sessionSpent, ledgerRows, ledgerMicro := n18dScopeStates(ctx, t, pool, n18dOrgEnf)
	assert.Equal(t, int64(1), ledgerRows)
	assert.Equal(t, int64(-8000), ledgerMicro, "the cancel settled the prefix's resale price once")
	assert.Equal(t, int64(4000), teamSpend)
	assert.Equal(t, int64(4000), agentCost)
	assert.Equal(t, int64(4000), sessionSpent)
	assert.Equal(t, int64(4000), walletReserved, "the un-consumed bound stays reserved for the reconcile")
	assert.Equal(t, int64(8000), teamReserved)
	assert.Equal(t, int64(8000), agentReserved)
	assert.Equal(t, int64(8000), sessionReserved)

	beforeUnknown := testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("wallet"))

	// The late usage: the completed event of the same request, full
	// completed quotes — it must claim nothing (every scope identity is
	// taken by the cancel) and count nothing as uncharged (its plan is
	// priced and therefore not an unknown cost).
	require.NoError(t, c.processMessage(ctx, n18dCompletedMsg("t09-enf-2", "req-t09-enf", n18dOrgEnf, fx)))
	assert.Equal(t, int64(4), n18dJobCount(ctx, t, pool, n18dOrgEnf),
		"the late usage adds no intents — the cancel's identities refuse it")
	assert.InDelta(t, beforeUnknown, testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("wallet")), 0.001,
		"the late priced plan is not counted as uncharged")

	// One worker pass later: still exactly the cancel's single operation.
	w.tick(ctx)
	walletReserved2, teamReserved2, teamSpend2, agentReserved2, agentCost2, sessionReserved2, sessionSpent2, ledgerRows2, ledgerMicro2 := n18dScopeStates(ctx, t, pool, n18dOrgEnf)
	assert.Equal(t, walletReserved, walletReserved2)
	assert.Equal(t, teamReserved, teamReserved2)
	assert.Equal(t, agentReserved, agentReserved2)
	assert.Equal(t, sessionReserved, sessionReserved2, "the late usage releases no reserve")
	assert.Equal(t, teamSpend, teamSpend2)
	assert.Equal(t, agentCost, agentCost2)
	assert.Equal(t, sessionSpent, sessionSpent2)
	assert.Equal(t, ledgerRows, ledgerRows2, "no second wallet row from the late usage")
	assert.Equal(t, ledgerMicro, ledgerMicro2, "no second wallet debit from the late usage")
}

// TestN06P4T09Live_UnsupportedModeValueIsRefusedBySchema — the explicit
// refusal for the unsupported: organizations.reservations_mode carries a
// CHECK restricting it to the supported set, so a bogus mode cannot exist
// for the consumer's mode probe to misread. The probe's default→off
// branch stays as defense-in-depth behind this schema guarantee (its
// error branch is unit-pinned by T05).
func TestN06P4T09Live_UnsupportedModeValueIsRefusedBySchema(t *testing.T) {
	ctx, pool, _ := newNext18dEnv(t)

	_, err := pool.Exec(ctx, `
		INSERT INTO organizations (id, name, slug, reservations_mode)
		VALUES ('181d0909-0000-4000-8000-00000000000a', 'n06p4t09-bogus', 'n06p4t09-bogus', 'bogus')`)
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr, "an unsupported reservations_mode value must be refused")
	assert.Equal(t, "23514", pgErr.Code, "the refusal is the CHECK constraint, not an accident")
}
