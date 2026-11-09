package consumer

// N06-P07 T09 — consumer-compatibility pins for the non-chat and agent
// workload cost accounting (card action: "Пройти старую и новую
// конфигурацию и реальные поддержанные consumers; явный отказ для
// неподдержанного"). Hermetic: mockDB at the pool boundary, mirroring the
// N06-P04 and N06-P07-T08 files; every delivery goes through the real
// handleRequestComplete seam (no endpoint- or money-shaped stubs in
// between).
//
// The matrix walks OLD configuration × OLD event shape, OLD configuration
// × NEW endpoint shape, NEW configuration × NEW event shape, and the
// explicit refusals of unsupported inputs:
//
//   - every supported endpoint value settles through the SAME consumer
//     path (the card's acceptance sentence, consumer half): the request
//     row keeps endpoint/usage_source/cost_status verbatim, the priced
//     quote bills once at the wallet, team_month and agent_day receive
//     their exact base-cost intents with reserve links, workload labels
//     persist — chat, completions, messages, responses, embeddings,
//     rerank, moderations, images, transcriptions, speech, realtime and
//     judge hops are indistinguishable at this seam;
//   - a batch line (chat.completions + a workload label) has no bypass:
//     it settles exactly like the chat baseline through the same intent
//     path;
//   - a legacy event (no endpoint/usage_source/cost_status/reservations
//     fields) keeps the exact legacy semantics: the defaults persist
//     verbatim, the wallet bills the resale price, budget areas bill the
//     base cost through the old attribution fallback, the session area
//     stays untouched;
//   - an OLD-configuration non-chat event (unknown_price, reservations
//     off) stays visible without billing: no wallet intent, a zero-amount
//     team counting entry, no pending_price record (no reserve at stake);
//   - a NEW-configuration event whose model is unpriced is explicitly
//     refused at the wallet: no charge, the reserve bounds stay visible
//     (pending_price payload + uncharged-unknown metric — never a silent
//     zero), budget areas keep their zero-amount counting entries;
//   - an unknown scope kind inside the reservations array is refused
//     individually: delivery continues, the supported scopes settle;
//   - an unknown charge kind cannot become an intent at all:
//     insertScopeIntent's default branch refuses it (defense-in-depth at
//     the intent seam), and agent_day participation is config-gated (nil
//     spender — agent budgets off — skips the intent);
//   - concurrent deliveries of two unit-priced non-chat events settle
//     each exactly once (race-safe at the mockDB inbox, the same
//     exactly-once contract the real unique index provides).
//
// Already pinned elsewhere (cited, not duplicated):
//   - tuple-field parse validation (unknown kind / empty key / non-positive
//     allowance / negative bound dropped per entry) and the plan-level
//     unknown-price wallet refusal → next18d_event_test.go;
//   - legacy failed/completed semantics on the enforce/off boundary LIVE →
//     n06p4t09_consumer_compat_live_test.go (schema-level refusal of an
//     unsupported reservations mode included);
//   - pending_price insert shape + mid-flight mode-flip visibility →
//     n06p3_corpus_test.go;
//   - exactly-once redelivery/convergence for unit-priced non-chat legs
//     and judge-hop repeat conflicts → n06p7t08_repeat_recovery_test.go;
//   - the admission half of the acceptance sentence (every supported
//     endpoint participates in admissionCore) → the N06-P07-T01 endpoint
//     inventory and T07's saturation pre-wire corpus in pkg/gateway.

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Attribution UUIDs for the legacy-shape deliveries (the pre-reservation
// attribution came from bare ids; uuidField validates the format).
const (
	n06p7t09TeamID  = "9c0f1a10-1111-4111-8111-111111111111"
	n06p7t09AgentID = "9c0f1a20-2222-4222-8222-222222222222"
	n06p7t09SessKey = "9c0f1a30-3333-4333-8333-333333333333"
)

// n06p7t09TuplesFmt is the NEW-configuration reservations payload of a
// budgeted request: team_month and agent_day tuples with reserve links.
// The agent_day allowance id is per-case so the corpus proves the link
// rides each delivery verbatim.
const n06p7t09TuplesFmt = `[{"scope_kind":"team_month","scope_key":"team-n06p7t09","period":"2026-10","allowance_id":41,"bound_micro_usd":900000},` +
	`{"scope_kind":"agent_day","scope_key":"agent-n06p7t09","period":"2026-10-29","allowance_id":%d,"bound_micro_usd":250000}]`

// n06p7t09PricedEvent is one NEW-configuration request.completed for a
// unit- or token-priced leg: the quote is positive and priced, the usage
// source names where the usage came from (provider tokens or none for
// unit-priced calls), and the termination is the normal completion.
func n06p7t09PricedEvent(requestID, endpoint, usageSource, model, quote string) map[string]interface{} {
	return map[string]interface{}{
		"event_type": "request.completed", "source": "gateway",
		"org_id": "org-n06p7t09", "request_id": requestID,
		"model_requested": model, "model_used": model,
		"endpoint": endpoint, "status_code": "200",
		"estimated_cost_usd": quote,
		"usage_source":       usageSource,
		"cost_status":        "priced",
		"termination":        "completed",
	}
}

// n06p7t09Intents filters the durable settlement_jobs writes of one kind.
func n06p7t09Intents(execs []execRecord, kind string) []execRecord {
	var out []execRecord
	for _, e := range execs {
		if strings.Contains(e.query, "INSERT INTO settlement_jobs") && len(e.args) >= 3 && e.args[2] == kind {
			out = append(out, e)
		}
	}
	return out
}

// n06p7t09RequestLog returns the single request_logs insert.
func n06p7t09RequestLog(t *testing.T, execs []execRecord) execRecord {
	t.Helper()
	logs := n06p4ExecsByQuerySubstring(execs, "INSERT INTO request_logs")
	require.Len(t, logs, 1)
	return logs[0]
}

// n06p7t09RowObjects decodes every JSON-object []byte argument of the
// request_logs row (the labels column is the only one this corpus binds).
func n06p7t09RowObjects(t *testing.T, args []any) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, a := range args {
		b, ok := a.([]byte)
		if !ok || len(b) == 0 || b[0] != '{' {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			continue
		}
		out = append(out, m)
	}
	return out
}

// n06p7t09IntentPayload decodes one settlement intent's payload argument.
func n06p7t09IntentPayload(t *testing.T, arg any) map[string]any {
	t.Helper()
	b, ok := arg.([]byte)
	require.True(t, ok, "intent payload must bind as JSON bytes")
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	return m
}

// TestN06P7T09SupportedEndpointsSettleThroughOnePath — the consumer half
// of the acceptance sentence: every supported endpoint value walks the
// identical settle path. Whatever the endpoint, the outcome shape is the
// same: verbatim analytics row, one exact wallet charge, exact base-cost
// budget intents carrying their reserve links, workload labels persisted,
// and never a pending_price record for a priced quote.
func TestN06P7T09SupportedEndpointsSettleThroughOnePath(t *testing.T) {
	cases := []struct {
		name      string
		endpoint  string
		usage     string
		model     string
		quote     string
		micro     int64
		allowance int64
	}{
		{"chat baseline", "chat.completions", "provider", "gpt-4", "0.04", 40000, 61},
		{"legacy completions", "completions", "provider", "gpt-4", "0.031", 31000, 62},
		{"messages native", "messages.native", "provider", "stub-sonnet", "0.07", 70000, 63},
		{"responses native", "responses.native", "provider", "stub-codex", "0.09", 90000, 64},
		{"embeddings", "embeddings", "provider", "text-embedding-3-small", "0.0002", 200, 65},
		{"rerank", "rerank", "provider", "stub-rerank", "0.001", 1000, 66},
		{"moderations", "moderations", "provider", "stub-moderation", "0.008", 8000, 67},
		{"images unit-priced", "images.generation", "none", "stub-image", "0.5", 500000, 68},
		{"transcriptions duration-priced", "audio.transcriptions", "provider", "stub-stt", "0.015", 15000, 69},
		{"speech unit-priced", "audio.speech", "none", "stub-tts", "0.02", 20000, 70},
		{"realtime", "realtime", "provider", "stub-realtime", "0.12", 120000, 71},
		{"judge hop", "policy_judge", "provider", "stub-judge", "0.10", 100000, 72},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			var execs []execRecord
			db := &mockDB{
				ExecFn: func(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
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
			c.SetAgentSpender(&fakeAgentSpender{})

			values := n06p7t09PricedEvent(fmt.Sprintf("req-n06p7t09-%d", i), tc.endpoint, tc.usage, tc.model, tc.quote)
			values["labels"] = `{"workload":"task:n06p7t09"}`
			values["reservations"] = fmt.Sprintf(n06p7t09TuplesFmt, tc.allowance)
			msg := redis.XMessage{ID: fmt.Sprintf("n06p7t09-corp-%d", i), Values: values}

			require.NoError(t, c.handleRequestComplete(ctx, msg))

			// The analytics row keeps the endpoint accounting verbatim and
			// carries the workload label.
			row := n06p7t09RequestLog(t, execs)
			assert.Contains(t, row.args, tc.endpoint)
			assert.Contains(t, row.args, tc.usage)
			assert.Contains(t, row.args, "priced")
			require.Len(t, n06p7t09RowObjects(t, row.args), 1)
			assert.Equal(t, map[string]any{"workload": "task:n06p7t09"},
				n06p7t09RowObjects(t, row.args)[0])

			// Wallet: the delivered quote bills once, exact micro amount.
			wallet := n06p7t09Intents(execs, ChargeKindResaleDeduction)
			require.Len(t, wallet, 1)
			assert.Equal(t, tc.micro, wallet[0].args[4])

			// team_month: exact base-cost intent with the reserve link and
			// the tuple's key and period.
			team := n06p7t09Intents(execs, ChargeKindTeamSpend)
			require.Len(t, team, 1)
			assert.Equal(t, tc.micro, team[0].args[4])
			assert.Contains(t, team[0].query, "allowance_id")
			assert.Equal(t, int64(41), team[0].args[6])
			teamPayload := n06p7t09IntentPayload(t, team[0].args[5])
			assert.Equal(t, "team-n06p7t09", teamPayload["team_id"])
			assert.Equal(t, "2026-10", teamPayload["period"])
			assert.InDelta(t, float64(900000), teamPayload["bound_micro_usd"], 0.0)

			// agent_day: exact base-cost intent, per-case allowance link.
			agents := n06p7t09Intents(execs, ChargeKindAgentSpend)
			require.Len(t, agents, 1)
			assert.Equal(t, tc.micro, agents[0].args[4])
			assert.Equal(t, tc.allowance, agents[0].args[6])
			agentPayload := n06p7t09IntentPayload(t, agents[0].args[5])
			assert.Equal(t, "agent-n06p7t09", agentPayload["agent_id"])

			// A priced quote never writes the pending_price record, and no
			// other settlement kind leaks into the delivery.
			assert.Empty(t, n06p7t09Intents(execs, ChargeKindPendingPrice))
			assert.Len(t, n06p4ExecsByQuerySubstring(execs, "INSERT INTO settlement_jobs"), 3)
		})
	}
}

// TestN06P7T09LegacyEventsKeepLegacySemantics — OLD configuration × OLD
// shape, then OLD configuration × NEW endpoint shape. The legacy event has
// no endpoint/usage_source/cost_status/reservations/labels fields at all:
// the mapper defaults persist verbatim, the wallet bills the resale price,
// budget areas bill the base cost through the attribution fallback (the
// producer ts buckets the team period), and the session area stays
// untouched. The old-configuration non-chat event (unknown_price, no
// unit pricing, reservations off) stays visible without billing: no wallet
// intent, a zero-amount team counting entry, no pending_price record —
// with no reserve held there is nothing at stake to record.
func TestN06P7T09LegacyEventsKeepLegacySemantics(t *testing.T) {
	ctx := context.Background()
	var execs []execRecord
	db := &mockDB{
		ExecFn: func(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
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
	c.SetAgentSpender(&fakeAgentSpender{})

	// OLD × OLD: the pre-reservation completed shape.
	legacy := map[string]interface{}{
		"event_type": "request.completed", "source": "gateway",
		"org_id": "org-n06p7t09", "request_id": "req-n06p7t09-legacy",
		"model_requested": "gpt-4", "model_used": "gpt-4",
		"status_code": "200", "tokens_in": "100", "tokens_out": "20",
		"estimated_cost_usd": "0.004", "resale_cost_usd": "0.008",
		"team_id": n06p7t09TeamID, "agent_id": n06p7t09AgentID, "session_key_id": n06p7t09SessKey,
		"ts": strconv.FormatInt(time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC).UnixMilli(), 10),
	}
	require.NoError(t, c.handleRequestComplete(ctx, redis.XMessage{ID: "n06p7t09-legacy", Values: legacy}))

	rows := n06p4ExecsByQuerySubstring(execs, "INSERT INTO request_logs")
	require.Len(t, rows, 1)
	row := rows[0]
	assert.Contains(t, row.args, "chat.completions", "the mapper default endpoint persists verbatim")
	assert.Contains(t, row.args, "provider", "the mapper default usage source persists verbatim")
	assert.Contains(t, row.args, "legacy", "the mapper default cost status persists verbatim")
	require.Len(t, n06p7t09RowObjects(t, row.args), 1)
	assert.Empty(t, n06p7t09RowObjects(t, row.args)[0], "absent labels persist as an empty object")

	wallet := n06p7t09Intents(execs, ChargeKindResaleDeduction)
	require.Len(t, wallet, 1)
	assert.Equal(t, int64(8000), wallet[0].args[4], "the wallet bills the resale price")
	assert.NotContains(t, wallet[0].query, "allowance_id", "a legacy event has no reserve link")

	team := n06p7t09Intents(execs, ChargeKindTeamSpend)
	require.Len(t, team, 1)
	assert.Equal(t, int64(4000), team[0].args[4], "budget areas bill the BASE cost (ADR I4)")
	teamPayload := n06p7t09IntentPayload(t, team[0].args[5])
	assert.Equal(t, n06p7t09TeamID, teamPayload["team_id"])
	assert.Equal(t, "2026-10", teamPayload["period"], "the period derives from the producer ts, not the delivery moment")

	agents := n06p7t09Intents(execs, ChargeKindAgentSpend)
	require.Len(t, agents, 1)
	assert.Equal(t, int64(4000), agents[0].args[4])
	assert.Empty(t, n06p7t09Intents(execs, ChargeKindSessionSpend),
		"the session area exists only for capped keys — the legacy attribution never bills it")
	assert.Empty(t, n06p7t09Intents(execs, ChargeKindPendingPrice))

	// OLD × NEW endpoint shape: an old configuration (no unit pricing,
	// reservations off) receives a non-chat event — unknown_price with the
	// zero placeholder and plain token usage.
	oldSTT := map[string]interface{}{
		"event_type": "request.completed", "source": "gateway",
		"org_id": "org-n06p7t09", "request_id": "req-n06p7t09-oldstt",
		"model_requested": "gpt-4o-transcribe", "model_used": "gpt-4o-transcribe",
		"endpoint": "audio.transcriptions", "status_code": "200",
		"tokens_in": "60", "tokens_out": "0",
		"estimated_cost_usd": "0", "cost_status": "unknown_price",
		"team_id": n06p7t09TeamID,
		"ts":      strconv.FormatInt(time.Date(2026, 10, 15, 13, 0, 0, 0, time.UTC).UnixMilli(), 10),
	}
	require.NoError(t, c.handleRequestComplete(ctx, redis.XMessage{ID: "n06p7t09-oldstt", Values: oldSTT}))

	rows = n06p4ExecsByQuerySubstring(execs, "INSERT INTO request_logs")
	require.Len(t, rows, 2)
	row = rows[1]
	assert.Contains(t, row.args, "audio.transcriptions")
	assert.Contains(t, row.args, "unknown_price")

	require.Len(t, n06p7t09Intents(execs, ChargeKindResaleDeduction), 1,
		"an unknown price never gains a wallet intent — the legacy one stays alone")
	team = n06p7t09Intents(execs, ChargeKindTeamSpend)
	require.Len(t, team, 2)
	assert.Equal(t, int64(0), team[1].args[4],
		"the old-configuration non-chat event keeps its zero-amount counting entry")
	assert.Empty(t, n06p7t09Intents(execs, ChargeKindPendingPrice),
		"no reserve was held — nothing is at stake, no pending_price record")
}

// TestN06P7T09UnknownPriceUnderNewConfigStaysVisibleUnbilled — the
// NEW-configuration explicit refusal: a budgeted request (reserve tuples,
// workload label) whose model turned out unpriced publishes the zero
// placeholder under cost_status=unknown_price. The wallet refuses to bill,
// the bounds stay visible in the pending_price payload and the
// uncharged-unknown metric (never a silent zero), and the budget areas
// keep their zero-amount counting entries so the scopes stay queryable.
func TestN06P7T09UnknownPriceUnderNewConfigStaysVisibleUnbilled(t *testing.T) {
	ctx := context.Background()
	var execs []execRecord
	db := &mockDB{
		ExecFn: func(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
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
	c.SetAgentSpender(&fakeAgentSpender{})

	walletBefore := testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("wallet"))
	teamBefore := testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("team_month"))

	values := n06p7t09PricedEvent("req-n06p7t09-unpriced", "audio.transcriptions", "provider", "new-unpriced-model", "0")
	values["cost_status"] = "unknown_price"
	values["tokens_in"] = "60"
	values["labels"] = `{"workload":"task:n06p7t09"}`
	values["reservations"] = `[{"scope_kind":"wallet","scope_key":"org-n06p7t09","period":"","allowance_id":81,"bound_micro_usd":12000},` +
		`{"scope_kind":"team_month","scope_key":"team-n06p7t09","period":"2026-10","allowance_id":82,"bound_micro_usd":500}]`
	msg := redis.XMessage{ID: "n06p7t09-unpriced", Values: values}

	require.NoError(t, c.handleRequestComplete(ctx, msg))

	row := n06p7t09RequestLog(t, execs)
	assert.Contains(t, row.args, "audio.transcriptions")
	assert.Contains(t, row.args, "unknown_price")

	assert.Empty(t, n06p7t09Intents(execs, ChargeKindResaleDeduction),
		"an unknown price is never billed")
	team := n06p7t09Intents(execs, ChargeKindTeamSpend)
	require.Len(t, team, 1)
	assert.Equal(t, int64(0), team[0].args[4], "the budget area keeps its zero-amount counting entry")

	pending := n06p7t09Intents(execs, ChargeKindPendingPrice)
	require.Len(t, pending, 1, "a held reserve with an unknown price keeps its visibility record")
	assert.Equal(t, "org-n06p7t09", pending[0].args[0])
	assert.Equal(t, "req-n06p7t09-unpriced", pending[0].args[1])
	payload := n06p7t09IntentPayload(t, pending[0].args[3])
	assert.Equal(t, map[string]any{
		"termination": "completed",
		"reservations": []any{
			map[string]any{"scope_kind": "wallet", "bound_micro_usd": float64(12000)},
			map[string]any{"scope_kind": "team_month", "bound_micro_usd": float64(500)},
		},
	}, payload, "the reserve bounds stay visible — never a silent zero")

	assert.InDelta(t, walletBefore+12000,
		testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("wallet")), 0.001)
	assert.InDelta(t, teamBefore+500,
		testutil.ToFloat64(metrics.UnchargedUnknownTotal.WithLabelValues("team_month")), 0.001,
		"every unbilled bound counts exactly once per committed delivery")
}

// TestN06P7T09UnsupportedInputsRefusedPerEntry — the explicit refusals of
// unsupported inputs never wedge a delivery: an unknown scope kind inside
// the reservations array is dropped individually while the supported
// scopes settle with their links, and a malformed labels payload degrades
// to an empty object without touching the settlement.
func TestN06P7T09UnsupportedInputsRefusedPerEntry(t *testing.T) {
	ctx := context.Background()
	var execs []execRecord
	db := &mockDB{
		ExecFn: func(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
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
	c.SetAgentSpender(&fakeAgentSpender{})

	values := n06p7t09PricedEvent("req-n06p7t09-refuse", "chat.completions", "provider", "gpt-4", "0.05")
	values["labels"] = `{"workload": ` // malformed — a bad producer must not break the delivery
	values["reservations"] = `[{"scope_kind":"team_month","scope_key":"team-n06p7t09","period":"2026-10","allowance_id":41,"bound_micro_usd":900000},` +
		`{"scope_kind":"wallet","scope_key":"org-n06p7t09","period":"","allowance_id":72,"bound_micro_usd":12000},` +
		`{"scope_kind":"quantum_flux","scope_key":"x","allowance_id":73,"bound_micro_usd":9000},` +
		`{"scope_kind":"agent_day","scope_key":"agent-n06p7t09","period":"2026-10-29","allowance_id":74,"bound_micro_usd":250000}]`
	msg := redis.XMessage{ID: "n06p7t09-refuse", Values: values}

	require.NoError(t, c.handleRequestComplete(ctx, msg),
		"an unsupported tuple entry is refused individually, never a failed delivery")

	row := n06p7t09RequestLog(t, execs)
	objects := n06p7t09RowObjects(t, row.args)
	require.Len(t, objects, 1)
	assert.Empty(t, objects[0], "malformed labels degrade to an empty object")

	intents := n06p4ExecsByQuerySubstring(execs, "INSERT INTO settlement_jobs")
	require.Len(t, intents, 3, "exactly the supported scopes settle — nothing else leaks in")
	assert.Equal(t, int64(50000), n06p7t09Intents(execs, ChargeKindResaleDeduction)[0].args[4])
	assert.Equal(t, int64(72), n06p7t09Intents(execs, ChargeKindResaleDeduction)[0].args[6])
	assert.Equal(t, int64(41), n06p7t09Intents(execs, ChargeKindTeamSpend)[0].args[6])
	assert.Equal(t, int64(74), n06p7t09Intents(execs, ChargeKindAgentSpend)[0].args[6])
	for _, e := range execs {
		for _, a := range e.args {
			assert.NotEqual(t, "quantum_flux", a,
				"the unsupported scope kind must not survive anywhere in the delivery")
		}
	}
}

// TestN06P7T09UnknownChargeKindRefusedAtIntentSeam — defense-in-depth at
// the intent seam: a charge kind the consumer does not know cannot become
// a durable work item (the default branch refuses it with a warning, not
// an error and not an insert), and agent_day participation is config-gated
// — with agent budgets off (nil spender) the intent is skipped.
func TestN06P7T09UnknownChargeKindRefusedAtIntentSeam(t *testing.T) {
	ctx := context.Background()
	var execs []execRecord
	db := &mockDB{
		ExecFn: func(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
			execs = append(execs, execRecord{query: query, args: args})
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	c := NewWithCreditStore(nil, db, "", silentLogger(), credits.NewStore(nil, silentLogger()))
	tx, err := db.BeginTx(ctx)
	require.NoError(t, err)

	err = c.insertScopeIntent(ctx, tx, "org-n06p7t09", "req-n06p7t09-seam",
		scopeCharge{kind: "quantum_flux", scope: "quantum", key: "k", amount: 500000},
		1, 2, 0.5, 0.5, "gpt-4")
	require.NoError(t, err, "the refusal is a skip, never a delivery error")
	assert.Empty(t, execs, "an unknown charge kind produces no durable work item")

	err = c.insertScopeIntent(ctx, tx, "org-n06p7t09", "req-n06p7t09-seam",
		scopeCharge{kind: ChargeKindAgentSpend, scope: "agent_day", key: "agent-n06p7t09", amount: 100},
		1, 2, 0.01, 0.01, "gpt-4")
	require.NoError(t, err)
	assert.Empty(t, execs, "agent budgets off (nil spender) skip the agent_day intent")
}

// TestN06P7T09ConcurrentNonChatDeliveriesSettleExactlyOnce — two
// unit-priced non-chat events of one org delivered concurrently (distinct
// stream entry ids): both settle exactly once, each with its own analytics
// row and exact amounts — no lost or duplicated work under concurrency.
func TestN06P7T09ConcurrentNonChatDeliveriesSettleExactlyOnce(t *testing.T) {
	ctx := context.Background()
	var mu sync.Mutex
	var execs []execRecord
	db := &mockDB{
		ExecFn: func(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
			mu.Lock()
			execs = append(execs, execRecord{query: query, args: args})
			mu.Unlock()
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
	c.SetAgentSpender(&fakeAgentSpender{})

	build := func(entryID, requestID, endpoint, model, quote string) redis.XMessage {
		values := n06p7t09PricedEvent(requestID, endpoint, "none", model, quote)
		values["labels"] = `{"workload":"task:n06p7t09"}`
		values["reservations"] = fmt.Sprintf(n06p7t09TuplesFmt, 61)
		return redis.XMessage{ID: entryID, Values: values}
	}
	img := build("n06p7t09-conc-a", "req-n06p7t09-conc-a", "images.generation", "stub-image", "0.5")
	speech := build("n06p7t09-conc-b", "req-n06p7t09-conc-b", "audio.speech", "stub-tts", "0.02")

	errs := make([]error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); errs[0] = c.handleRequestComplete(ctx, img) }()
	go func() { defer wg.Done(); errs[1] = c.handleRequestComplete(ctx, speech) }()
	wg.Wait()
	require.NoError(t, errs[0])
	require.NoError(t, errs[1])

	require.Len(t, n06p4ExecsByQuerySubstring(execs, "INSERT INTO request_logs"), 2,
		"each concurrent delivery keeps its own analytics row")
	wallet := n06p7t09Intents(execs, ChargeKindResaleDeduction)
	require.Len(t, wallet, 2, "each request charges the wallet exactly once")
	amounts := []int64{wallet[0].args[4].(int64), wallet[1].args[4].(int64)}
	assert.ElementsMatch(t, []int64{500000, 20000}, amounts)
	assert.Len(t, n06p7t09Intents(execs, ChargeKindTeamSpend), 2)
	assert.Len(t, n06p7t09Intents(execs, ChargeKindAgentSpend), 2)
	assert.Empty(t, n06p7t09Intents(execs, ChargeKindPendingPrice))
}
