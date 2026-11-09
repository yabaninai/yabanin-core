package consumer

// N03-P06-T08 — interruptions / retry / resume recovery, ledger leg
// (services/loggerd consumer seam, mockDB only at the pool boundary,
// mirroring the T06/T07 ledger files).
//
// A gateway that retried (or resumed) a request publishes ONE completed
// event carrying the attempt attribution (attempt_count / retry_count) and
// the WINNING attempt's cache-premium usage. This corpus pins the delivery
// side of the exactly-once contract for that event shape:
//
//   - the first delivery commits exactly one request_logs row whose bill,
//     counterfactual, cache tokens and retry attribution land in the pinned
//     projection positions (mapping positions pinned by stream_test.go and
//     T06/T07 — this pins them for the RETRY-ATTRIBUTED premium shape);
//   - a redelivery of the SAME stream entry (crash between commit and XACK —
//     the resume window) claims nothing, writes nothing and reports success:
//     the durable inbox refuses the replay, so the retry-attributed premium
//     bill can never land twice;
//   - a DIFFERENT entry id is a different delivery identity: it inserts its
//     own row (the consumer layer deliberately does not cross-dedupe
//     analytics rows by request_id — charge-level dedup belongs to the
//     credit Deductor; N06-P04 pinned the charge side, this pins the
//     analytics boundary honestly);
//   - an event without attempt attribution (legacy producer) stores NULL
//     retry columns — never fake zeros that would poison retry aggregates —
//     and still redelivers exactly-once.
//
// Distinct from N06-P04 T05 (n06p4_dup_delivery_test.go): that corpus pins
// settlement CHARGES for failed/cancelled events at reservations-mode
// boundaries; this pins the COMPLETED retry-attributed cache-premium row and
// its redelivery refusal.

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// n03p6t08Completed is a request.completed for a request the gateway
// retried once and that won on the anthropic-shaped attempt (input 1000 /
// out 200 / read 600 / creation 150): attempt_count=1, retry_count=1, the
// T06 hand bill 0.0067425 and its full-list counterfactual 0.00825. Wire
// encoding mirrors eventpublisher.RedisPublisher.Publish (T07 convention).
func n03p6t08Completed(requestID string) map[string]interface{} {
	return map[string]interface{}{
		"event_type":              "request.completed",
		"source":                  "gateway",
		"ts":                      "1770000000000",
		"request_id":              requestID,
		"session_id":              "sess-n03p6t08",
		"org_id":                  "org-n03p6t08",
		"model_requested":         "claude-sonnet-4-5",
		"model_used":              "claude-sonnet-4-5",
		"method":                  "POST",
		"status_code":             "200",
		"endpoint":                "chat.completions",
		"usage_source":            "provider",
		"cost_status":             "priced",
		"termination":             "completed",
		"tokens_in":               strconv.FormatInt(1750, 10),
		"tokens_out":              strconv.FormatInt(200, 10),
		"cache_read_tokens":       strconv.FormatInt(600, 10),
		"cache_creation_tokens":   strconv.FormatInt(150, 10),
		"estimated_cost_usd":      strconv.FormatFloat(0.0067425, 'f', -1, 64),
		"counterfactual_cost_usd": strconv.FormatFloat(0.00825, 'f', -1, 64),
		"attempt_count":           strconv.FormatInt(1, 10),
		"retry_count":             strconv.FormatInt(1, 10),
	}
}

// n03p6t08LedgerDB captures every statement; the request_logs rows are
// selected by table name so settlement intents never confuse the pin.
func n03p6t08LedgerDB(execs *[]execRecord) *mockDB {
	return &mockDB{
		ExecFn: func(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
			*execs = append(*execs, execRecord{query: query, args: args})
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
}

func n03p6t08LogInserts(execs []execRecord) []execRecord {
	var out []execRecord
	for _, e := range execs {
		if strings.Contains(e.query, "INSERT INTO request_logs") {
			out = append(out, e)
		}
	}
	return out
}

// TestN03P6T08_RetryAttributedPremiumEvent_RedeliveryBillsOnceAtLedger — the
// crash-between-commit-and-ACK window: the row commits exactly once; the
// redelivered entry claims nothing, writes nothing and reports success: the
// durable inbox refuses the replay, so the retry-attributed premium bill can
// never land twice. (Scope-charge settlement intents are deliberately out of
// scope here — the fixture carries no session/team/agent keys, so no intent
// is due; the charge-side exactly-once seam is N06-P04's corpus.)
func TestN03P6T08_RetryAttributedPremiumEvent_RedeliveryBillsOnceAtLedger(t *testing.T) {
	ctx := context.Background()

	var execs []execRecord
	c := New(nil, n03p6t08LedgerDB(&execs), "events:queue", slog.Default())

	msg := redis.XMessage{ID: "n03p6t08-redelivery", Values: n03p6t08Completed("req-n03p6t08-1")}

	require.NoError(t, c.handleRequestComplete(ctx, msg), "the first delivery commits")

	first := n03p6t08LogInserts(execs)
	require.Len(t, first, 1, "exactly one request_logs row for the retry-attributed request")

	row := first[0].args
	require.Len(t, row, 43, "the full 41-column projection + 2 attribution columns (stream_test.go shape)")
	assert.Equal(t, int64(1750), row[8], "tokens_in (canonical inclusive anthropic prompt)")
	assert.InDelta(t, 0.00825, row[14], 0, "counterfactual_cost_usd (full-list 0.00825)")
	assert.InDelta(t, 0.0067425, row[15], 0, "cost_in_usd (the winning attempt's exact bill)")
	assert.Equal(t, int64(1), row[31], "attempt_count — one chain hop")
	assert.Equal(t, int64(1), row[32], "retry_count — the intra-model retry is visible at the ledger")
	assert.Equal(t, "chat.completions", row[33], "endpoint column")
	assert.Equal(t, "provider", row[34], "usage_source column")
	assert.Equal(t, "priced", row[35], "cost_status column")
	assert.Equal(t, int64(600), row[36], "cache_read_tokens verbatim")
	assert.Equal(t, int64(150), row[37], "cache_creation_tokens — the write premium is on the row")

	before := len(execs)
	require.NoError(t, c.handleRequestComplete(ctx, msg),
		"a redelivery reports success — the delivery is done, not failed")
	require.Len(t, n03p6t08LogInserts(execs), 1,
		"the durable inbox refuses the replay: the premium bill can never land twice")
	require.Len(t, execs, before, "the redelivery writes nothing at all")

	// Σ over both deliveries: exactly one row carries the bill.
	rows := n03p6t08LogInserts(execs)
	require.Len(t, rows, 1)
	assert.InDelta(t, 0.0067425, rows[0].args[15], 0,
		"the single committed row carries the exact retry-attributed premium bill")
}

// TestN03P6T08_NewEntryId_IsNewDeliveryIdentity — the same request_id under
// a NEW stream entry id is a distinct delivery: the consumer layer inserts
// its own analytics row (no cross-dedupe by request_id at this layer). The
// delivery stays honest and observable; charge-level exactly-once for such
// duplicates belongs to the credit Deductor (N06-P04), never to silent row
// suppression here.
func TestN03P6T08_NewEntryId_IsNewDeliveryIdentity(t *testing.T) {
	ctx := context.Background()

	var execs []execRecord
	c := New(nil, n03p6t08LedgerDB(&execs), "events:queue", slog.Default())

	first := redis.XMessage{ID: "n03p6t08-entry-a", Values: n03p6t08Completed("req-n03p6t08-2")}
	second := redis.XMessage{ID: "n03p6t08-entry-b", Values: n03p6t08Completed("req-n03p6t08-2")}

	require.NoError(t, c.handleRequestComplete(ctx, first))
	require.NoError(t, c.handleRequestComplete(ctx, second))

	rows := n03p6t08LogInserts(execs)
	require.Len(t, rows, 2, "a new stream entry is a new delivery identity — both rows stay visible")
	assert.Equal(t, rows[0].args[11], rows[1].args[11],
		"both rows carry the same request_id so analytics can pair them")
	assert.InDelta(t, 0.0067425, rows[0].args[15], 0)
	assert.InDelta(t, 0.0067425, rows[1].args[15], 0,
		"both rows carry the same exact bill — visible duplicates, never silent drops")
}

// TestN03P6T08_UnattributedLegacyEvent_NullRetryColumns — a completed event
// WITHOUT attempt attribution (a pre-T08 producer, or a legacy relay) lands
// the retry columns as NULL, never as fake zeros that would poison retry
// aggregates; the premium columns stay NULL only when absent — here the
// usage fields are present and store verbatim (stream_test.go pins the
// mapping; this pins it under the recovery corpus's delivery semantics).
func TestN03P6T08_UnattributedLegacyEvent_NullRetryColumns(t *testing.T) {
	ctx := context.Background()

	var execs []execRecord
	c := New(nil, n03p6t08LedgerDB(&execs), "events:queue", slog.Default())

	values := n03p6t08Completed("req-n03p6t08-3")
	delete(values, "attempt_count")
	delete(values, "retry_count")
	msg := redis.XMessage{ID: "n03p6t08-legacy", Values: values}

	require.NoError(t, c.handleRequestComplete(ctx, msg))
	rows := n03p6t08LogInserts(execs)
	require.Len(t, rows, 1)
	assert.Nil(t, rows[0].args[31], "absent attempt_count stores NULL")
	assert.Nil(t, rows[0].args[32], "absent retry_count stores NULL")
	assert.Equal(t, int64(600), rows[0].args[36], "usage fields are unaffected by the absent attribution")

	// The legacy-shape redelivery is refused exactly like the attributed one.
	before := len(execs)
	require.NoError(t, c.handleRequestComplete(ctx, msg))
	require.Len(t, execs, before, "the inbox refuses the legacy replay too")
}
