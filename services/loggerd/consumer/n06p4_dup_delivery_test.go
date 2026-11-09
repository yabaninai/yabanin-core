package consumer

// N06-P04 T05 — negative delivery-boundary pins for settlement after
// cancel and partial failure, at the real StreamConsumer seam (mockDB only
// at the pool boundary, mirroring the T02/T04 files):
//
//   - a priced cancel-partial redelivered under the SAME stream entry id
//     can never produce a second durable charge at ANY reservations-mode
//     boundary (enforce / shadow / off);
//   - the same settlement identity arriving under a NEW stream entry id
//     with a DIFFERENT amount charges only the first amount and reports
//     the conflict (diagnostic, never an error, never a second charge);
//   - an error-then-success delivery pair converges to exactly one
//     committed operation: the aborted attempt consumed nothing, the
//     retry re-claims and commits once, and the identity then refuses
//     everything further;
//   - a reservations-mode probe failure degrades fail-closed to off —
//     no charge anywhere, and the not-billed prefix stays visible as an
//     uncharged bound instead of a silent zero;
//   - an unknown price stays visible as unknown through the cancel path
//     (pending_price payload carries the termination and the reserve
//     bounds) and through late usage (duplicate unknown never upgrades
//     into a charge; the late known price bills once as its own identity
//     and never touches the pending visibility row).
//
// Already pinned elsewhere (cited, not duplicated):
//   - the unknown failed event's row shape + same-msg redelivery refusal →
//     TestFailedDeliverySettlementBoundary (n06p4_settlement_failed_pending_test.go);
//   - statement-level identity/conflict clauses, pending_price literals,
//     non-claimable claim query, expiry to 'unknown' →
//     TestPendingPriceInterruptionCorpus (n06p3_corpus_test.go);
//   - absorbed upstream errors never bill in any mode →
//     TestUpstreamErrorAbsorbedIsNeverBilledAtDelivery (n06p4_settlement_cancel_late_test.go);
//   - real-DB redelivery/exactly-once billing → inbox_live_test.go,
//     r041_settlement_cancel_live_test.go.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// n06p4ScanRow answers one QueryRow with typed values (int64 amounts for
// the duplicate-identity amount read) or a canned error (the mode-probe
// failure).
type n06p4ScanRow struct {
	vals []any
	err  error
}

func (r *n06p4ScanRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	for i, d := range dest {
		if i >= len(r.vals) {
			break
		}
		switch v := d.(type) {
		case *int64:
			*v = r.vals[i].(int64)
		case *string:
			*v = r.vals[i].(string)
		case *any:
			*v = r.vals[i]
		}
	}
	return nil
}

// n06p4CompletedEvent is one request.completed carrying only the wallet
// reservation tuple: the late-usage shape for a request that already
// terminated (cancel/failure) and delivered a billable prefix.
func n06p4CompletedEvent(requestID, priceQuote string) map[string]interface{} {
	return map[string]interface{}{
		"event_type": "request.completed", "source": "gateway",
		"org_id": "org-n06p4", "request_id": requestID,
		"model_requested": "stub-model", "model_used": "stub-model",
		"status_code": "200", "tokens_in": "50", "tokens_out": "20",
		"estimated_cost_usd": priceQuote,
		"usage_source":       "provider",
		"termination":        "completed",
		"reservations":       `[{"scope_kind":"wallet","scope_key":"org-n06p4","period":"","allowance_id":7,"bound_micro_usd":120000}]`,
	}
}

// TestN06P4PricedRedeliveryNeverBillsTwiceAtModeBoundaries — the priced
// cancel-partial replay matrix. The unknown-cost redelivery refusal is
// pinned by T02; the priced shape additionally exercises the mode probe
// and the wallet intent insert, so a wiring regression in either would
// pass T02. At every boundary the replay claims nothing and writes
// nothing durable.
func TestN06P4PricedRedeliveryNeverBillsTwiceAtModeBoundaries(t *testing.T) {
	ctx := context.Background()

	t.Run("enforce: one intent; the replay claims nothing and writes nothing", func(t *testing.T) {
		var execs []execRecord
		c := NewWithCreditStore(nil, n06p4CapturingDB(t, &execs), "", silentLogger(),
			credits.NewStore(nil, silentLogger()))
		msg := redis.XMessage{ID: "n06p4-dup-enforce", Values: n06p4FailedEvent("req-n06p4-dup-e", "0.12")}

		require.NoError(t, c.handleRequestFailed(ctx, msg))
		intents := n06p4ExecsByArgValue(execs, ChargeKindResaleDeduction)
		require.Len(t, intents, 1, "the priced prefix is billable exactly once")
		first := append([]execRecord(nil), execs...)

		require.NoError(t, c.handleRequestFailed(ctx, msg),
			"a redelivery reports success — the delivery is done, not failed")
		require.Len(t, execs, len(first),
			"the durable inbox refuses the replay: no second intent, no second log")
		for i := range first {
			require.Equal(t, first[i].query, execs[i].query)
		}
	})

	t.Run("shadow: durable writes stay empty; the replay adds nothing durable", func(t *testing.T) {
		var execs []execRecord
		c := NewWithCreditStore(nil, n06p4ModeDB(t, &execs, "shadow"), "", silentLogger(),
			credits.NewStore(nil, silentLogger()))
		msg := redis.XMessage{ID: "n06p4-dup-shadow", Values: n06p4FailedEvent("req-n06p4-dup-s", "0.12")}

		beforeWould := testutil.ToFloat64(metrics.WouldBillPartialMicroUSD.WithLabelValues("wallet"))
		beforeUnknown := testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("wallet"))
		require.NoError(t, c.handleRequestFailed(ctx, msg))

		assert.InDelta(t, beforeWould+120000,
			testutil.ToFloat64(metrics.WouldBillPartialMicroUSD.WithLabelValues("wallet")), 0.001,
			"shadow observes what enforce would bill")
		assert.InDelta(t, beforeUnknown+120000,
			testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("wallet")), 0.001,
			"the prefix genuinely stays uncharged in shadow — the bound stays visible, never a silent zero")
		require.Empty(t, n06p4ExecsByQuerySubstring(execs, "INSERT INTO settlement_jobs"),
			"shadow never creates a durable charge")
		first := append([]execRecord(nil), execs...)

		require.NoError(t, c.handleRequestFailed(ctx, msg))
		require.Len(t, execs, len(first),
			"the shadow replay writes nothing durable (N06-P04-T08: the uncharged-unknown counter counts exactly once per committed delivery — a replay that claims nothing must not re-inflate it)")
	})

	t.Run("off: nothing durable; the priced prefix stays visible as uncharged; the replay adds nothing", func(t *testing.T) {
		var execs []execRecord
		c := NewWithCreditStore(nil, n06p4ModeDB(t, &execs, "off"), "", silentLogger(),
			credits.NewStore(nil, silentLogger()))
		msg := redis.XMessage{ID: "n06p4-dup-off", Values: n06p4FailedEvent("req-n06p4-dup-o", "0.12")}

		beforeWould := testutil.ToFloat64(metrics.WouldBillPartialMicroUSD.WithLabelValues("wallet"))
		beforeUnknown := testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("wallet"))
		require.NoError(t, c.handleRequestFailed(ctx, msg))

		assert.InDelta(t, beforeWould,
			testutil.ToFloat64(metrics.WouldBillPartialMicroUSD.WithLabelValues("wallet")), 0.001,
			"off mode never counts a would-bill")
		assert.InDelta(t, beforeUnknown+120000,
			testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("wallet")), 0.001,
			"the org was not billed for the delivered prefix — the bound stays visible, never dropped as a zero")
		require.Empty(t, n06p4ExecsByQuerySubstring(execs, "INSERT INTO settlement_jobs"),
			"off mode is legacy: failed requests produce no durable settlement work")
		first := append([]execRecord(nil), execs...)

		require.NoError(t, c.handleRequestFailed(ctx, msg))
		require.Len(t, execs, len(first))
	})
}

// TestN06P4SameIdentityNewMessageChargesFirstAmountOnly — the identity
// conflict edge: the same (org, request, kind) re-emitted under a NEW
// stream entry id with a DIFFERENT amount. The first amount stays
// authoritative, the second affects zero rows, the conflict is reported —
// and the delivery still succeeds (a diagnostic must never wedge the
// stream).
func TestN06P4SameIdentityNewMessageChargesFirstAmountOnly(t *testing.T) {
	ctx := context.Background()
	identities := map[string]bool{}
	var execs []execRecord
	identityReads := 0
	db := &mockDB{
		ExecFn: func(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
			tag := "INSERT 0 1"
			if strings.Contains(query, "INSERT INTO settlement_jobs") {
				key := fmt.Sprintf("%v|%v|%v", args[0], args[1], args[2])
				if identities[key] {
					tag = "INSERT 0 0" // the unique identity conflict: first amount stays
				} else {
					identities[key] = true
				}
			}
			execs = append(execs, execRecord{query: query, args: args})
			return pgconn.NewCommandTag(tag), nil
		},
		QueryRowFn: func(_ context.Context, query string, _ ...any) pgx.Row {
			if strings.Contains(query, "FROM organizations") {
				return &fakeRow{vals: []any{"enforce"}}
			}
			if strings.Contains(query, "FROM settlement_jobs") {
				identityReads++
				return &n06p4ScanRow{vals: []any{int64(120000)}}
			}
			return &fakeRow{}
		},
	}
	c := NewWithCreditStore(nil, db, "", silentLogger(), credits.NewStore(nil, silentLogger()))
	msgFirst := redis.XMessage{ID: "n06p4-id-1", Values: n06p4FailedEvent("req-n06p4-idem", "0.12")}
	msgConflicting := redis.XMessage{ID: "n06p4-id-2", Values: n06p4FailedEvent("req-n06p4-idem", "0.25")}

	before := testutil.ToFloat64(metrics.SettlementIntentConflicts.WithLabelValues("resale_deduction"))
	require.NoError(t, c.handleRequestFailed(ctx, msgFirst))
	require.NoError(t, c.handleRequestFailed(ctx, msgConflicting),
		"the identity conflict is a diagnostic, never a delivery error")

	assert.InDelta(t, before+1,
		testutil.ToFloat64(metrics.SettlementIntentConflicts.WithLabelValues("resale_deduction")), 0.001,
		"the conflicting second amount is reported, not silently ignored")
	intents := n06p4ExecsByArgValue(execs, ChargeKindResaleDeduction)
	require.Len(t, intents, 2, "both deliveries attempted the identity-guarded insert")
	assert.Equal(t, int64(120000), intents[0].args[4], "the first amount landed as the authoritative job")
	assert.Equal(t, int64(250000), intents[1].args[4],
		"the second amount executed but affected zero rows — it can never become a second charge")
	assert.Equal(t, 1, identityReads,
		"the conflict diagnostic read the known authoritative amount")
	require.Len(t, n06p4ExecsByQuerySubstring(execs, "INSERT INTO request_logs"), 2,
		"each distinct delivery keeps its own analytics row (only the settlement identity dedupes)")

	require.NoError(t, c.handleRequestFailed(ctx, msgFirst))
	first := append([]execRecord(nil), execs...)
	require.NoError(t, c.handleRequestFailed(ctx, msgFirst))
	require.Len(t, execs, len(first), "a replay of an already-committed entry id is refused whole")
}

// TestN06P4DeliveryErrorThenSuccessConvergesToOneOperation — the
// error-then-success sequencing edge: the first delivery attempt fails
// transiently mid-transaction. The rollback discards the inbox claim with
// the writes, so the retry re-claims and converges to exactly one
// committed operation, and the consumed identity then refuses everything
// further.
func TestN06P4DeliveryErrorThenSuccessConvergesToOneOperation(t *testing.T) {
	ctx := context.Background()
	var execs []execRecord
	requestLogFails := 1 // the first attempt's request_log insert fails transiently
	db := &mockDB{
		ExecFn: func(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
			if strings.Contains(query, "INSERT INTO request_logs") && requestLogFails > 0 {
				requestLogFails--
				return pgconn.CommandTag{}, errors.New("server closed the connection unexpectedly")
			}
			execs = append(execs, execRecord{query: query, args: args})
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
		QueryRowFn: func(_ context.Context, query string, _ ...any) pgx.Row {
			if strings.Contains(query, "FROM organizations") {
				return &fakeRow{vals: []any{"enforce"}}
			}
			return &fakeRow{}
		},
	}
	c := NewWithCreditStore(nil, db, "", silentLogger(), credits.NewStore(nil, silentLogger()))
	msg := redis.XMessage{ID: "n06p4-ets", Values: n06p4FailedEvent("req-n06p4-ets", "0.12")}

	err := c.handleRequestFailed(ctx, msg)
	require.Error(t, err, "the transient failure surfaces so the message is retried")
	require.Empty(t, n06p4ExecsByQuerySubstring(execs, "INSERT INTO settlement_jobs"),
		"the aborted attempt produced no durable work item (the claim rolled back with it)")

	require.NoError(t, c.handleRequestFailed(ctx, msg),
		"the retried delivery re-claims the rolled-back inbox identity and commits")

	intents := n06p4ExecsByArgValue(execs, ChargeKindResaleDeduction)
	require.Len(t, intents, 1, "exactly one charge intent exists across the error-then-success pair")
	require.Len(t, n06p4ExecsByQuerySubstring(execs, "INSERT INTO request_logs"), 1,
		"exactly one committed analytics row")
	assert.Equal(t, int64(120000), intents[0].args[4], "the committed intent bills the delivered prefix once")

	committed := append([]execRecord(nil), execs...)
	require.NoError(t, c.handleRequestFailed(ctx, msg))
	require.Len(t, execs, len(committed),
		"the consumed identity refuses any further delivery — one operation, once")
}

// TestN06P4ModeProbeFailureDegradesToNoCharge — a reservations-mode read
// failure on a PRICED cancel-partial must fail closed to off: no charge,
// no pending_price row — and the not-billed prefix must stay visible as
// an uncharged bound instead of silently disappearing.
func TestN06P4ModeProbeFailureDegradesToNoCharge(t *testing.T) {
	ctx := context.Background()
	var execs []execRecord
	db := &mockDB{
		ExecFn: func(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
			execs = append(execs, execRecord{query: query, args: args})
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
		QueryRowFn: func(_ context.Context, query string, _ ...any) pgx.Row {
			if strings.Contains(query, "FROM organizations") {
				return &n06p4ScanRow{err: errors.New("org mode probe failed (transient)")}
			}
			return &fakeRow{}
		},
	}
	c := NewWithCreditStore(nil, db, "", silentLogger(), credits.NewStore(nil, silentLogger()))
	msg := redis.XMessage{ID: "n06p4-modefail", Values: n06p4FailedEvent("req-n06p4-modefail", "0.12")}

	beforeUnknown := testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("wallet"))
	beforeWould := testutil.ToFloat64(metrics.WouldBillPartialMicroUSD.WithLabelValues("wallet"))
	require.NoError(t, c.handleRequestFailed(ctx, msg),
		"a mode read failure degrades the delivery to the legacy path, never an error loop")

	require.Empty(t, n06p4ExecsByQuerySubstring(execs, "INSERT INTO settlement_jobs"),
		"an unreadable mode fails closed to off: neither a charge intent nor a visibility row")
	require.Len(t, n06p4ExecsByQuerySubstring(execs, "INSERT INTO request_logs"), 1,
		"the analytics row still commits")
	assert.InDelta(t, beforeWould,
		testutil.ToFloat64(metrics.WouldBillPartialMicroUSD.WithLabelValues("wallet")), 0.001,
		"a failed probe never counts a would-bill")
	assert.InDelta(t, beforeUnknown+120000,
		testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("wallet")), 0.001,
		"the priced prefix the org was not billed for stays visible as an uncharged bound — never a silent zero")
}

// TestN06P4UnknownStaysVisibleThroughCancelAndLateUsage — the unknown-
// price visibility edge across the full cancel/late-usage sequence: the
// cancel's pending_price row carries the termination and the reserve
// bounds (the stake stays auditable), a duplicate unknown event can never
// upgrade into a charge, and the late known price bills once as its own
// identity without touching the pending visibility rows.
func TestN06P4UnknownStaysVisibleThroughCancelAndLateUsage(t *testing.T) {
	ctx := context.Background()
	var execs []execRecord
	c := NewWithCreditStore(nil, n06p4CapturingDB(t, &execs), "", silentLogger(),
		credits.NewStore(nil, silentLogger()))

	// 1) The cancel with an unknown price: exactly one never-billed row,
	//    carrying what was at stake.
	require.NoError(t, c.handleRequestFailed(ctx,
		redis.XMessage{ID: "n06p4-vis-1", Values: n06p4FailedEvent("req-n06p4-vis", "")}))
	pending := n06p4ExecsByArgValue(execs, ChargeKindPendingPrice)
	require.Len(t, pending, 1)
	var payload struct {
		Termination  string           `json:"termination"`
		Reservations []map[string]any `json:"reservations"`
	}
	require.NoError(t, json.Unmarshal(pending[0].args[3].([]byte), &payload),
		"the pending row's payload must stay parseable — it is the audit trail")
	assert.Equal(t, "client_cancel", payload.Termination,
		"the row records HOW the request terminated, not just that it did")
	require.Len(t, payload.Reservations, 1)
	assert.Equal(t, "wallet", payload.Reservations[0]["scope_kind"])
	assert.EqualValues(t, 120000, payload.Reservations[0]["bound_micro_usd"],
		"the row records the reserve bound at stake while the price is unknown")
	require.Empty(t, n06p4ExecsByArgValue(execs, ChargeKindResaleDeduction),
		"an unknown price never produces a charge intent")

	// 2) A duplicate unknown event for the same request under a new entry
	//    id: still only the never-billed identity — a duplicate unknown can
	//    never upgrade into a charge (the DB ON CONFLICT collapses the row;
	//    statement pins live in the corpus test).
	require.NoError(t, c.handleRequestFailed(ctx,
		redis.XMessage{ID: "n06p4-vis-2", Values: n06p4FailedEvent("req-n06p4-vis", "")}))
	pending = n06p4ExecsByArgValue(execs, ChargeKindPendingPrice)
	require.Len(t, pending, 2)
	for _, p := range pending {
		require.Contains(t, p.query, "0, 0, 'pending_price'",
			"amount literals stay 0,0 — never billed, never a confirmed zero")
		require.Contains(t, p.query, "ON CONFLICT (org_id, request_id, charge_kind) DO NOTHING",
			"the duplicate lands on the same identity, not a second row")
	}
	require.Empty(t, n06p4ExecsByArgValue(execs, ChargeKindResaleDeduction),
		"no amount of repeated unknown events ever creates a charge")

	// 3) The late PRICED completion for the same request: the wallet intent
	//    appears once, as its own identity; the pending rows stay untouched.
	require.NoError(t, c.handleRequestComplete(ctx,
		redis.XMessage{ID: "n06p4-vis-3", Values: n06p4CompletedEvent("req-n06p4-vis", "0.12")}))
	intents := n06p4ExecsByArgValue(execs, ChargeKindResaleDeduction)
	require.Len(t, intents, 1, "the late known price bills exactly once")
	assert.Equal(t, int64(120000), intents[0].args[4])
	require.Len(t, n06p4ExecsByArgValue(execs, ChargeKindPendingPrice), 2,
		"the priced completion never touches the pending visibility rows")
	for _, e := range execs {
		require.NotContains(t, e.query, "UPDATE settlement_jobs",
			"nothing rewrites a settlement row on the delivery path — terminal states belong to the worker")
	}
}
