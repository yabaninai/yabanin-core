package consumer

import (
	"fmt"
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AF-05 live acceptance (disposable PG+Redis): the full consumer path bills
// 1000 individual $0.004 requests as exactly $4.00, across consumer/credits
// restarts, and replaying delivered messages never double-charges. The
// pre-AF-05 projection rounded every event to 0 cents — the audited loss.
// Since AF-06 the delivery path only commits the durable intents (exact µ);
// a settlement-worker pass executes them, adding one more restart boundary.
func TestAF05Live_ThousandSubCentRequestsAcrossRestarts(t *testing.T) {
	ctx, pool, rdb := newInboxLiveEnv(t)

	const orgID = "af05e111-0000-4000-8000-000000000001"
	_, err := pool.Exec(ctx, `
		INSERT INTO organizations (id, name, slug)
		VALUES ($1, 'af05-live-org', 'af05-live')
		ON CONFLICT (id) DO NOTHING`, orgID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO org_credits (org_id, balance_cents, remainder_micro_usd)
		VALUES ($1, 0, 0)
		ON CONFLICT (org_id) DO UPDATE SET balance_cents = 0, remainder_micro_usd = 0`, orgID)
	require.NoError(t, err)
	// A05 ownership model: destructive credit suites no longer reset the
	// shared public credit tables (that was the audited defect), so this
	// scenario clears ITS OWN org-scoped ledger rows instead of leaning on
	// a teardown neighbor's DROP. Without this, -count=2 round 2 idempotently
	// skips every deduction against round 1's surviving usage rows and the
	// wallet never moves — the suite's hidden dependency on the drops.
	_, err = pool.Exec(ctx, `DELETE FROM credit_transactions WHERE org_id = $1`, orgID)
	require.NoError(t, err)

	newConsumer := func() *StreamConsumer {
		// A fresh credits.Store per batch = a restarted billing process.
		// Deep grace: the scenario is pure accumulation, admission must not
		// stop it at the default −$1 overdraft floor.
		wallet := credits.NewStoreWithConfig(pool, silentLogger(), credits.Config{GracePeriodCents: -1_000_000})
		return NewWithCreditStore(NewRedisOps(rdb), NewDBOps(pool), "events:af05-live", silentLogger(), wallet)
	}

	price := "0.004"
	const total = 1000
	const batch = 100

	c := newConsumer()
	for i := 0; i < total; i++ {
		if i > 0 && i%batch == 0 {
			// Restart: fresh consumer + fresh credits store.
			c = newConsumer()
		}
		msg := redis.XMessage{ID: fmt.Sprintf("%d-0", 5000+i), Values: map[string]interface{}{
			"event_type":      "request.completed",
			"source":          "gateway-live",
			"request_id":      fmt.Sprintf("req-af05-%04d", i),
			"org_id":          orgID,
			"session_id":      "ses_live_af05",
			"model_requested": "gpt-4",
			"model_used":      "gpt-4-turbo",
			"status_code":     "200",
			"duration_ms":     "42",
			"tokens_in":       "10",
			"tokens_out":      "20",
			"method":          "POST",
			"resale_cost_usd": price,
		}}
		require.NoError(t, c.processMessage(ctx, msg), "delivery %d", i)
	}

	// Durable intents: one per request, exact micro, rounded compat cents.
	var jobs int64
	var jobMicro, jobCents int64
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*), COALESCE(SUM(amount_micro_usd), 0), COALESCE(SUM(amount_cents), 0)
		FROM settlement_jobs WHERE org_id = $1 AND charge_kind = $2`, orgID, ChargeKindResaleDeduction,
	).Scan(&jobs, &jobMicro, &jobCents))
	assert.Equal(t, int64(total), jobs, "every sub-cent request produced a charge intent")
	assert.Equal(t, int64(4_000_000), jobMicro, "intents sum to exactly $4.00 in µUSD")
	assert.Equal(t, int64(0), jobCents, "compat cents projection of sub-cent charges")

	// AF-06: a settlement-worker pass executes the intents (one more restart
	// boundary between the deliveries and the money moving). 1000 intents
	// exceed one bounded tick (10×25), so the queue is drained fully.
	worker := NewSettlementWorker(pool, credits.NewStoreWithConfig(pool, silentLogger(), credits.Config{GracePeriodCents: -1_000_000}), nil, silentLogger()).WithConfig(liveSettlementConfig())
	drainSettlementQueue(ctx, t, worker, pool, orgID, ChargeKindResaleDeduction)

	var unsettled int64
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM settlement_jobs
		WHERE org_id = $1 AND charge_kind = $2 AND status <> 'settled'`, orgID, ChargeKindResaleDeduction,
	).Scan(&unsettled))
	assert.Zero(t, unsettled, "every intent settled exactly once")

	// Exact totals in the wallet: 1000 × 4000µ = $4.00 — no residue, no drift.
	var balanceCents, remainder int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT balance_cents, remainder_micro_usd FROM org_credits WHERE org_id = $1`, orgID,
	).Scan(&balanceCents, &remainder))
	assert.Equal(t, int64(-400), balanceCents, "1000 × $0.004 = exactly −$4.00")
	assert.Equal(t, int64(0), remainder)

	// Ledger reconciliation: cents sum == wallet; exact micro recorded.
	var ledgerCents, ledgerMicro int64
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT COALESCE(SUM(amount_cents), 0), COALESCE(SUM(amount_micro_usd), 0)
		FROM credit_transactions WHERE org_id = $1`, orgID,
	).Scan(&ledgerCents, &ledgerMicro))
	assert.Equal(t, int64(-400), ledgerCents)
	assert.Equal(t, int64(-4_000_000), ledgerMicro, "ledger carries the exact µUSD total")

	// Replay across a restart with every Redis marker gone: the durable
	// inbox dedups and the wallet does not move.
	require.NoError(t, rdb.FlushDB(ctx).Err())
	replayed := newConsumer()
	for i := 0; i < 5; i++ {
		msg := redis.XMessage{ID: fmt.Sprintf("%d-0", 5000+i), Values: map[string]interface{}{
			"event_type":      "request.completed",
			"source":          "gateway-live",
			"request_id":      fmt.Sprintf("req-af05-%04d", i),
			"org_id":          orgID,
			"session_id":      "ses_live_af05",
			"model_requested": "gpt-4",
			"model_used":      "gpt-4-turbo",
			"status_code":     "200",
			"tokens_in":       "10",
			"tokens_out":      "20",
			"resale_cost_usd": price,
		}}
		require.NoError(t, replayed.processMessage(ctx, msg), "replay %d must succeed (already delivered)", i)
	}
	// A worker pass over the replays: settled identities settle nothing new.
	replayedWorker := NewSettlementWorker(pool, credits.NewStoreWithConfig(pool, silentLogger(), credits.Config{GracePeriodCents: -1_000_000}), nil, silentLogger()).WithConfig(liveSettlementConfig())
	drainSettlementQueue(ctx, t, replayedWorker, pool, orgID, ChargeKindResaleDeduction)
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT balance_cents, remainder_micro_usd FROM org_credits WHERE org_id = $1`, orgID,
	).Scan(&balanceCents, &remainder))
	assert.Equal(t, int64(-400), balanceCents, "replay must not double-charge")
	assert.Equal(t, int64(0), remainder)
}

// An event with an unknown price (missing and unparseable quotes) persists
// its log, creates no charge intent and never bills — observably distinct
// from a genuine zero quote, which skips as zero without charging too but is
// classified separately in metrics (unit-covered) and intents (none in both).
func TestAF05Live_UnknownPricePersistsWithoutCharge(t *testing.T) {
	ctx, pool, rdb := newInboxLiveEnv(t)
	setupCreditTables(ctx, t, pool)

	const orgID = "af05e222-0000-4000-8000-000000000002"
	_, err := pool.Exec(ctx, `
		INSERT INTO organizations (id, name, slug)
		VALUES ($1, 'af05-unknown-org', 'af05-unknown')
		ON CONFLICT (id) DO NOTHING`, orgID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO org_credits (org_id, balance_cents, remainder_micro_usd)
		VALUES ($1, 100, 0)
		ON CONFLICT (org_id) DO UPDATE SET balance_cents = 100, remainder_micro_usd = 0`, orgID)
	require.NoError(t, err)

	c := NewWithCreditStore(NewRedisOps(rdb), NewDBOps(pool), "events:af05-live", silentLogger(), credits.NewStore(pool, silentLogger()))

	msg := redis.XMessage{ID: "9000-0", Values: map[string]interface{}{
		"event_type":      "request.completed",
		"source":          "gateway-live",
		"request_id":      "req-af05-unknown",
		"org_id":          orgID,
		"session_id":      "ses_live_af05u",
		"model_requested": "gpt-4",
		"model_used":      "gpt-4-turbo",
		"status_code":     "200",
		"tokens_in":       "10",
		"tokens_out":      "20",
		"resale_cost_usd": "not-a-number",
	}}
	require.NoError(t, c.processMessage(ctx, msg))

	requireRowCount(t, ctx, pool, `SELECT count(*) FROM request_logs WHERE request_id='req-af05-unknown'`, 1,
		"unknown-price event still persists its log")
	requireRowCount(t, ctx, pool, `SELECT count(*) FROM settlement_jobs WHERE org_id='af05e222-0000-4000-8000-000000000002'`, 0,
		"unknown price creates no charge intent")

	var balanceCents, remainder int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT balance_cents, remainder_micro_usd FROM org_credits WHERE org_id = $1`, orgID,
	).Scan(&balanceCents, &remainder))
	assert.Equal(t, int64(100), balanceCents, "unknown price never bills")
	assert.Equal(t, int64(0), remainder)

	// A genuine zero quote behaves identically at the ledger (no charge) but
	// is a distinct classification in metrics/quote state (unit-covered).
	msg.Values["request_id"] = "req-af05-zeroquote"
	msg.Values["resale_cost_usd"] = "0"
	msg.ID = "9001-0"
	require.NoError(t, c.processMessage(ctx, msg))
	requireRowCount(t, ctx, pool, `SELECT count(*) FROM settlement_jobs WHERE org_id='af05e222-0000-4000-8000-000000000002'`, 0,
		"zero quote creates no charge intent either")
}

// pricing examples drive the REAL consumer entry point — published Redis
// events through processMessage, the durable settlement intents, a
// settlement-worker pass and the exact wallet — never the boundary helpers
// alone. One wallet, five events, one boundary:
//   - E1 float-drift reproducibility: the drift marker 0.007500000000000001
//     settles as exactly 7500 µUSD, byte-identical to the clean 0.0075 form.
//   - E2 hidden zero: an unknown_price event publishing estimated_cost_usd=0
//     settles QuoteUnknown — no wallet intent, no ledger row, never a
//     genuine zero; its request log keeps cost_status verbatim for analytics.
//   - E3 small price (owner decision 2026-10-12): a positive sub-µUSD quote
//     rounds UP to the 1 µUSD billable minimum — no invisible zeros.
//   - E5 large token counts: the 9e18-token quote ($2.25e13) never bills.
//     The money boundary would refuse it (out of µUSD range → QuoteUnknown,
//     parse-level lock in af05_money_test.go), and the delivery layer fails
//     earlier still: request_logs.cost_in_usd is numeric(12,6), so the
//     verbatim producer estimate overflows the insert (pre-existing at the
//     recorded here as the standing observable, DECISION-GATED: delivery
//     durability for absurd quotes needs an owner decision). The failure is
//     loud — a delivery error, no intents, no ledger row — never a silent
//     zero or a charge.
//   - Partial state: an unknown upstream cost does not suppress a known
//     resale price (resale wins, exact amount).
func TestR038Live_QuoteStatesThroughConsumerSettlementBoundary(t *testing.T) {
	ctx, pool, rdb := newInboxLiveEnv(t)
	setupCreditTables(ctx, t, pool)

	const orgID = "af05e111-0000-4000-8000-000000000003"
	const seedCents = int64(100_000)
	_, err := pool.Exec(ctx, `
		INSERT INTO organizations (id, name, slug)
		VALUES ($1, 'r038-live-org', 'r038-live')
		ON CONFLICT (id) DO NOTHING`, orgID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO org_credits (org_id, balance_cents, remainder_micro_usd)
		VALUES ($1, $2, 0)
		ON CONFLICT (org_id) DO UPDATE SET balance_cents = $2, remainder_micro_usd = 0`, orgID, seedCents)
	require.NoError(t, err)
	// A05 ownership model: clear THIS org's ledger rows so -count=2 rounds
	// are independent — the uniq_credit_transactions_usage_request_id index
	// dedups ledger rows by request_id, so round 1's surviving usage rows
	// would otherwise idempotently skip round 2's settlement charges (the
	// destructive drops this suite previously leaned on are gone by design).
	_, err = pool.Exec(ctx, `DELETE FROM credit_transactions WHERE org_id = $1`, orgID)
	require.NoError(t, err)

	wallet := credits.NewStoreWithConfig(pool, silentLogger(), credits.Config{GracePeriodCents: -1_000_000})
	c := NewWithCreditStore(NewRedisOps(rdb), NewDBOps(pool), "events:af05-live", silentLogger(), wallet)

	type example struct {
		id         string
		costStatus string
		resale     string
		estimated  string
	}
	examples := []example{
		{id: "req-r038-e1-drift", costStatus: "priced", resale: "0.007500000000000001", estimated: "0.007500000000000001"},
		{id: "req-r038-e2-unknown", costStatus: "unknown_price", resale: "", estimated: "0"},
		{id: "req-r038-e3-submicro", costStatus: "priced", resale: "4.5e-07", estimated: "4.5e-07"},
		{id: "req-r038-e5-huge", costStatus: "priced", resale: "", estimated: "22500000000000"},
		{id: "req-r038-resale-wins", costStatus: "unknown_price", resale: "0.01", estimated: "0"},
	}
	for i, ex := range examples {
		values := map[string]interface{}{
			"event_type":      "request.completed",
			"source":          "gateway-live",
			"request_id":      ex.id,
			"org_id":          orgID,
			"session_id":      "ses_live_r038",
			"model_requested": "gpt-4",
			"model_used":      "gpt-4-turbo",
			"status_code":     "200",
			"duration_ms":     "42",
			"tokens_in":       "10",
			"tokens_out":      "20",
			"method":          "POST",
			"cost_status":     ex.costStatus,
		}
		if ex.resale != "" {
			values["resale_cost_usd"] = ex.resale
		}
		if ex.estimated != "" {
			values["estimated_cost_usd"] = ex.estimated
		}
		msg := redis.XMessage{ID: fmt.Sprintf("%d-0", 7000+i), Values: values}
		if ex.id == "req-r038-e5-huge" {
			// DECISION-GATED observable (see header): the verbatim
			// $2.25e13 estimate overflows the numeric(12,6) cost column —
			// the delivery errors loudly, nothing money-shaped persists.
			require.Error(t, c.processMessage(ctx, msg), ex.id)
			continue
		}
		require.NoError(t, c.processMessage(ctx, msg), ex.id)
	}

	// Wallet intents exist for exactly the three positive-state requests,
	// each at the exact boundary µUSD amount.
	wantIntents := map[string]int64{
		"req-r038-e1-drift":    7500,
		"req-r038-e3-submicro": 1,
		"req-r038-resale-wins": 10000,
	}
	intentRows, err := pool.Query(ctx, `
		SELECT request_id, amount_micro_usd FROM settlement_jobs
		WHERE org_id = $1 AND charge_kind = $2`, orgID, ChargeKindResaleDeduction)
	require.NoError(t, err)
	gotIntents := map[string]int64{}
	for intentRows.Next() {
		var reqID string
		var micro int64
		require.NoError(t, intentRows.Scan(&reqID, &micro))
		gotIntents[reqID] = micro
	}
	require.NoError(t, intentRows.Err())
	assert.Equal(t, wantIntents, gotIntents, "wallet intents: exactly the positive-state examples at exact µUSD")

	// E2/E5 never produce a wallet intent — unknown is not a hidden zero.
	requireRowCount(t, ctx, pool, fmt.Sprintf(`
		SELECT count(*) FROM settlement_jobs
		WHERE org_id = '%s' AND charge_kind = '%s'
		  AND request_id IN ('req-r038-e2-unknown', 'req-r038-e5-huge')`,
		orgID, ChargeKindResaleDeduction), 0, "unknown-price and out-of-range quotes create no charge intent")

	// E5 observable, continued: the overflow aborted the whole delivery —
	// no request log row either (nothing silently zeroed or stored).
	requireRowCount(t, ctx, pool, `SELECT count(*) FROM request_logs WHERE request_id = 'req-r038-e5-huge'`, 0,
		"the overflowing E5 estimate leaves no request log row")

	// The request log keeps cost_status verbatim — the analytics/UI
	// contract is unchanged by the money gate (compat, card step 3).
	var e2Status string
	var e2Cost float64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT cost_status, cost_in_usd FROM request_logs WHERE request_id = 'req-r038-e2-unknown'`,
	).Scan(&e2Status, &e2Cost))
	assert.Equal(t, "unknown_price", e2Status, "request log preserves the producer cost_status")
	assert.InDelta(t, float64(0), e2Cost, 0, "unknown-price event stores the published placeholder, not the unknown state")

	// AF-06: the settlement worker executes the three intents exactly once.
	worker := NewSettlementWorker(pool, credits.NewStoreWithConfig(pool, silentLogger(), credits.Config{GracePeriodCents: -1_000_000}), nil, silentLogger()).WithConfig(liveSettlementConfig())
	drainSettlementQueue(ctx, t, worker, pool, orgID, ChargeKindResaleDeduction)

	// The wallet moved by exactly 17501 µUSD: 1 whole cent plus the 7501 µ
	// durable remainder — no residue lost, no rounding drift.
	var balanceCents, remainder int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT balance_cents, remainder_micro_usd FROM org_credits WHERE org_id = $1`, orgID,
	).Scan(&balanceCents, &remainder))
	assert.Equal(t, seedCents-1, balanceCents, "17501 µUSD = exactly 1 cent charged")
	assert.Equal(t, int64(7501), remainder, "the sub-cent residue is carried exactly")

	// The ledger carries the exact micro total and only the billed requests.
	var ledgerRows, ledgerMicro, ledgerCents int64
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*), COALESCE(SUM(amount_micro_usd), 0), COALESCE(SUM(amount_cents), 0)
		FROM credit_transactions WHERE org_id = $1 AND type = 'usage'`, orgID,
	).Scan(&ledgerRows, &ledgerMicro, &ledgerCents))
	assert.Equal(t, int64(3), ledgerRows)
	assert.Equal(t, int64(-17_501), ledgerMicro, "ledger carries the exact µUSD total")
	assert.Equal(t, int64(-1), ledgerCents, "whole-cent share matches the wallet decrement")
	requireRowCount(t, ctx, pool, fmt.Sprintf(`
		SELECT count(*) FROM credit_transactions
		WHERE org_id = '%s' AND type = 'usage'
		  AND request_id IN ('req-r038-e2-unknown', 'req-r038-e5-huge')`,
		orgID), 0, "unknown-price and out-of-range requests never reach the ledger")
}
