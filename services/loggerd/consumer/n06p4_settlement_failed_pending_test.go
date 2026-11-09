package consumer

// N06-P04 T02 — the delivery-layer negative boundary for settlement after
// cancel and partial failure: an enforce-mode request.failed that reached
// the provider with a wallet reserve but an unknown price records exactly
// one never-billed pending_price visibility row, charges nothing, and
// counts the uncharged bound instead of masking it as zero; the priced
// counterpart bills the delivered prefix through exactly one identity-
// guarded wallet intent; and a redelivery of the same stream message
// claims nothing and writes nothing — the replay cannot charge twice.
//
// Coverage cited instead of duplicated:
//   - statement-level pending_price pins (0,0 literals, identity conflict,
//     non-claimable claim query, expiry to 'unknown')
//     → TestPendingPriceInterruptionCorpus (n06p3_corpus_test.go);
//   - live wallet-ledger outcomes (no refund on priced cancel, pending_price
//     expiry to terminal 'unknown', absorbed priced upstream_error)
//     → r041_settlement_cancel_live_test.go, r041_failure_boundaries_live_test.go;
//   - the batch/per-job settle parity → pkg/budget settlement batch tests.
//
// This file pins the handleRequestFailed WIRING itself — which durable
// statements the failed-delivery transaction emits per contract — which
// previously existed only under Docker live coverage.

import (
	"context"
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

// n06p4FailedEvent is one request.failed that reached the provider
// (usage_source provider) carrying a wallet reserve tuple — the shape a
// reserved request lands with after a mid-flight failure or client cancel.
// The optional price quote decides the quote state the handler must see.
func n06p4FailedEvent(requestID string, priceQuote string) map[string]interface{} {
	fields := map[string]interface{}{
		"event_type":   "request.failed",
		"source":       "gateway",
		"org_id":       "org-n06p4",
		"request_id":   requestID,
		"model_used":   "stub-model",
		"status_code":  "503",
		"tokens_in":    "50",
		"tokens_out":   "20",
		"method":       "POST",
		"error":        "upstream timeout",
		"usage_source": "provider",
		"termination":  "client_cancel",
		"reservations": `[{"scope_kind":"wallet","scope_key":"org-n06p4","period":"","allowance_id":7,"bound_micro_usd":120000}]`,
	}
	if priceQuote != "" {
		fields["estimated_cost_usd"] = priceQuote
	}
	return fields
}

// n06p4CapturingDB builds the mock pool: every non-inbox statement is
// captured in order, and the org reservations-mode probe answers enforce.
func n06p4CapturingDB(t *testing.T, execs *[]execRecord) *mockDB {
	t.Helper()
	return &mockDB{
		ExecFn: func(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
			*execs = append(*execs, execRecord{query: query, args: args})
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
		QueryRowFn: func(_ context.Context, query string, _ ...any) pgx.Row {
			if strings.Contains(query, "FROM organizations") {
				return &fakeRow{vals: []any{"enforce"}}
			}
			return &fakeRow{}
		},
	}
}

func n06p4ExecsByQuerySubstring(execs []execRecord, sub string) []execRecord {
	var out []execRecord
	for _, e := range execs {
		if strings.Contains(e.query, sub) {
			out = append(out, e)
		}
	}
	return out
}

func n06p4ExecsByArgValue(execs []execRecord, want any) []execRecord {
	var out []execRecord
	for _, e := range execs {
		for _, a := range e.args {
			if a == want {
				out = append(out, e)
				break
			}
		}
	}
	return out
}

// TestFailedDeliverySettlementBoundary — N06-P04 T02 at the delivery layer:
// the failed event's transaction emits the contract's exact statement set.
func TestFailedDeliverySettlementBoundary(t *testing.T) {
	ctx := context.Background()

	t.Run("unknown cost with a reserve: one never-billed pending_price row, no charge, bound counted", func(t *testing.T) {
		var execs []execRecord
		c := NewWithCreditStore(nil, n06p4CapturingDB(t, &execs), "", silentLogger(),
			credits.NewStore(nil, silentLogger()))
		msg := redis.XMessage{ID: "n06p4-unknown", Values: n06p4FailedEvent("req-n06p4-unknown", "")}

		before := testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("wallet"))
		require.NoError(t, c.handleRequestFailed(ctx, msg))

		jobs := n06p4ExecsByQuerySubstring(execs, "INSERT INTO settlement_jobs")
		require.Len(t, jobs, 1, "exactly one durable work item: the visibility record")
		require.Contains(t, jobs[0].query, "VALUES ($1, $2, $3, 0, 0, 'pending_price', $4)",
			"no amount literals: never billed, never a confirmed zero")
		require.Contains(t, jobs[0].query, "ON CONFLICT (org_id, request_id, charge_kind) DO NOTHING",
			"the (org, request, kind) identity makes a redelivery re-insert nothing")
		require.Equal(t, "org-n06p4", jobs[0].args[0])
		require.Equal(t, "req-n06p4-unknown", jobs[0].args[1])
		require.Equal(t, ChargeKindPendingPrice, jobs[0].args[2])

		require.Empty(t, n06p4ExecsByArgValue(execs, ChargeKindResaleDeduction),
			"an unknown price never produces a wallet charge intent")

		assert.InDelta(t, before+120000, testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("wallet")), 0.001,
			"the uncharged reserve bound is counted, not masked as zero")

		require.Len(t, n06p4ExecsByQuerySubstring(execs, "INSERT INTO request_logs"), 1,
			"the analytics row still commits with the visibility record")
	})

	t.Run("priced failure bills the delivered prefix once through one wallet intent", func(t *testing.T) {
		var execs []execRecord
		c := NewWithCreditStore(nil, n06p4CapturingDB(t, &execs), "", silentLogger(),
			credits.NewStore(nil, silentLogger()))
		msg := redis.XMessage{ID: "n06p4-priced", Values: n06p4FailedEvent("req-n06p4-priced", "0.12")}

		before := testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("wallet"))
		require.NoError(t, c.handleRequestFailed(ctx, msg))

		charges := n06p4ExecsByArgValue(execs, ChargeKindResaleDeduction)
		require.Len(t, charges, 1, "the priced prefix is billable exactly once")
		require.Contains(t, charges[0].query, "ON CONFLICT (org_id, request_id, charge_kind) DO NOTHING")
		require.Equal(t, int64(12), charges[0].args[3], "exact cents projection")
		require.Equal(t, int64(120000), charges[0].args[4], "exact micro amount (AF-05)")

		require.Empty(t, n06p4ExecsByQuerySubstring(execs, "'pending_price'"),
			"a priced failure is not an unknown cost — no visibility row")
		assert.InDelta(t, before, testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("wallet")), 0.001,
			"a billed scope is never also counted as uncharged unknown")
	})

	t.Run("redelivery of the same message claims nothing and writes nothing", func(t *testing.T) {
		var execs []execRecord
		c := NewWithCreditStore(nil, n06p4CapturingDB(t, &execs), "", silentLogger(),
			credits.NewStore(nil, silentLogger()))
		msg := redis.XMessage{ID: "n06p4-replay", Values: n06p4FailedEvent("req-n06p4-replay", "")}

		require.NoError(t, c.handleRequestFailed(ctx, msg))
		first := append([]execRecord(nil), execs...)
		require.NotEmpty(t, first)

		require.NoError(t, c.handleRequestFailed(ctx, msg))
		require.Len(t, execs, len(first),
			"the durable inbox claim refuses the replay: no second write, no second charge")
		for i := range first {
			require.Equal(t, first[i].query, execs[i].query)
		}
	})
}
