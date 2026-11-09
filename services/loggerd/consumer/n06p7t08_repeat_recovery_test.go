package consumer

// N06-P07 T08 — repeat and recovery on the durable settlement paths of
// non-chat and agent workload events, at the real StreamConsumer seam
// (mockDB at the pool boundary, mirroring the N06-P04 files):
//
//   - a unit-priced interactive leg (images.generation, usage_source none)
//     that fails mid-delivery converges on retry to exactly one durable
//     charge intent and one analytics row, and a replay of the committed
//     entry id is refused whole — no duplicate, no loss;
//   - two judge hops of ONE request (the normal multi-hop agent shape,
//     one request.completed event per hop) arrive as separate events
//     sharing the parent request id: the first hop's amount lands as the
//     authoritative intent, the second hop's delivery succeeds but its
//     identity conflicts — the conflicting hop amount is reported as a
//     diagnostic, never a second charge, and each hop keeps its own
//     analytics row.
//
// Already pinned elsewhere (cited, not duplicated): chat failed/completed
// redelivery + same-identity-new-message first-amount-wins →
// n06p4_dup_delivery_test.go; live-PG interruption/resume corpus →
// n06p4t08_recovery_resume_test.go; the in-process cap and hop retry arcs
// → pkg/budget (agent_test.go, n06p7t08_repeat_recovery_test.go).

import (
	"context"
	"errors"
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

// n06p7t08UnitPricedEvent is one request.completed for a unit-priced
// interactive leg: the provider reports no token usage (usage_source
// none), the unit tariff prices the call directly (cost_status priced),
// and the quote is positive.
func n06p7t08UnitPricedEvent(requestID string) map[string]interface{} {
	return map[string]interface{}{
		"event_type": "request.completed", "source": "gateway",
		"org_id": "org-n06p7t08", "request_id": requestID,
		"model_requested": "stub-image", "model_used": "stub-image",
		"endpoint":           "images.generation",
		"status_code":        "200",
		"estimated_cost_usd": "0.5",
		"usage_source":       "none",
		"cost_status":        "priced",
		"termination":        "completed",
	}
}

// n06p7t08JudgeHopEvent is one policy_judge hop settlement event: the
// request id is the PARENT request's (every hop of one external request
// shares it), the endpoint is the hop-dedicated one, and the event bills
// the hop's exact upstream usage.
func n06p7t08JudgeHopEvent(requestID, priceQuote string) map[string]interface{} {
	return map[string]interface{}{
		"event_type": "request.completed", "source": "gateway",
		"org_id": "org-n06p7t08", "request_id": requestID,
		"model_requested": "stub-judge", "model_used": "stub-judge",
		"endpoint":    "policy_judge",
		"status_code": "200",
		"tokens_in":   "800", "tokens_out": "120",
		"estimated_cost_usd": priceQuote,
		"usage_source":       "provider",
		"cost_status":        "priced",
		"termination":        "completed",
	}
}

// TestN06P7T08UnitPricedRetryConvergesToExactlyOnce — the interrupted
// delivery of a unit-priced interactive leg recovers without duplicates
// and without loss: the aborted attempt commits nothing, the retry claims
// the rolled-back inbox identity and commits exactly one charge intent and
// one analytics row, and any further replay of the consumed entry id
// changes nothing.
func TestN06P7T08UnitPricedRetryConvergesToExactlyOnce(t *testing.T) {
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
	msg := redis.XMessage{ID: "n06p7t08-img-1",
		Values: n06p7t08UnitPricedEvent("req-n06p7t08-img")}

	err := c.handleRequestComplete(ctx, msg)
	require.Error(t, err, "the transient failure surfaces so the message is retried")
	require.Empty(t, n06p4ExecsByQuerySubstring(execs, "INSERT INTO settlement_jobs"),
		"the aborted attempt produced no durable work item (the claim rolled back with it)")

	require.NoError(t, c.handleRequestComplete(ctx, msg),
		"the retried delivery re-claims the rolled-back inbox identity and commits")

	intents := n06p4ExecsByArgValue(execs, ChargeKindResaleDeduction)
	require.Len(t, intents, 1, "exactly one charge intent across the error-then-success pair")
	assert.Equal(t, int64(500000), intents[0].args[4],
		"the unit-priced leg bills its delivered quote exactly once")
	require.Len(t, n06p4ExecsByQuerySubstring(execs, "INSERT INTO request_logs"), 1,
		"exactly one committed analytics row")

	committed := append([]execRecord(nil), execs...)
	require.NoError(t, c.handleRequestComplete(ctx, msg))
	require.Len(t, execs, len(committed),
		"the consumed identity refuses any further delivery — one operation, once")
}

// TestN06P7T08JudgeHopRepeatChargesFirstAmountOnly — the multi-hop agent
// shape under repeat: two hops of one request settle as two events with
// the SAME (org, request) settlement identity and different amounts. The
// identity keeps the first amount authoritative, the second hop's amount
// conflicts and is reported (diagnostic, never an error, never a second
// charge), and each hop keeps its own analytics row. This pins the
// consumer-side contract exactly; the T08 record documents the corollary —
// hops 2..N of one request can never durably bill — with the producer-side
// handoff (no per-hop identity field exists on the hop event).
func TestN06P7T08JudgeHopRepeatChargesFirstAmountOnly(t *testing.T) {
	ctx := context.Background()
	identities := map[string]bool{}
	var execs []execRecord
	db := &mockDB{
		ExecFn: func(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
			tag := "INSERT 0 1"
			if strings.Contains(query, "INSERT INTO settlement_jobs") {
				key := strings.Join([]string{args[0].(string), args[1].(string), args[2].(string)}, "|")
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
				return &fakeRow{vals: []any{int64(100000)}}
			}
			return &fakeRow{}
		},
	}
	c := NewWithCreditStore(nil, db, "", silentLogger(), credits.NewStore(nil, silentLogger()))
	hop1 := redis.XMessage{ID: "n06p7t08-hop-1",
		Values: n06p7t08JudgeHopEvent("req-n06p7t08-hop", "0.10")}
	hop2 := redis.XMessage{ID: "n06p7t08-hop-2",
		Values: n06p7t08JudgeHopEvent("req-n06p7t08-hop", "0.15")}

	before := testutil.ToFloat64(metrics.SettlementIntentConflicts.WithLabelValues("resale_deduction"))
	require.NoError(t, c.handleRequestComplete(ctx, hop1))
	require.NoError(t, c.handleRequestComplete(ctx, hop2),
		"the identity conflict is a diagnostic, never a delivery error")

	assert.InDelta(t, before+1,
		testutil.ToFloat64(metrics.SettlementIntentConflicts.WithLabelValues("resale_deduction")), 0.001,
		"the second hop's conflicting amount is reported, not silently ignored")
	intents := n06p4ExecsByArgValue(execs, ChargeKindResaleDeduction)
	require.Len(t, intents, 2, "both hops attempted the identity-guarded insert")
	assert.Equal(t, int64(100000), intents[0].args[4], "hop 1's amount landed as the authoritative job")
	assert.Equal(t, int64(150000), intents[1].args[4],
		"hop 2's amount executed but affected zero rows — it can never become a second charge")
	require.Len(t, n06p4ExecsByQuerySubstring(execs, "INSERT INTO request_logs"), 2,
		"each hop keeps its own analytics row (only the settlement identity dedupes)")

	committed := append([]execRecord(nil), execs...)
	require.NoError(t, c.handleRequestComplete(ctx, hop1))
	require.Len(t, execs, len(committed), "a replay of an already-committed entry id is refused whole")
}
