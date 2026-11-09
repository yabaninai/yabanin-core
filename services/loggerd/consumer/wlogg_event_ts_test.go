package consumer

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// W-LOGG event-clock contract: the producer's ts (Unix ms) is the business
// time of an event. The consumer writes request_logs.created_at from it and
// buckets legacy team attribution by it, so delayed delivery (outage
// backlog, DLQ replay) can never shift billing into the wrong period.

func tsEvent(tsMs int64) redis.XMessage {
	values := map[string]interface{}{
		"event_type":      "request.completed",
		"source":          "gateway",
		"org_id":          "org-ts",
		"session_id":      "sess-ts",
		"model_requested": "gpt-4",
		"status_code":     "200",
		"duration_ms":     "10",
		"team_id":         "team-1",
	}
	if tsMs != 0 {
		values["ts"] = tsMs
	}
	return redis.XMessage{ID: "11-1", Values: values}
}

func captureLogInserts(t *testing.T) (*mockDB, *[]any) {
	t.Helper()
	var args []any
	pool := &mockDB{}
	pool.ExecFn = func(ctx context.Context, q string, callArgs ...any) (pgconn.CommandTag, error) {
		if strings.Contains(q, "INSERT INTO request_logs") {
			args = callArgs
		}
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	}
	return pool, &args
}

// created_at comes from the event ts even when delivery is delayed: the row
// must read the request moment, not the processing moment.
func TestCreatedAt_FromProducerTsOnDelayedDelivery(t *testing.T) {
	delayed := time.Now().Add(-2 * time.Hour)
	pool, args := captureLogInserts(t)
	c := New(nil, pool, "events:queue", silentLogger())

	require.NoError(t, c.handleRequestComplete(context.Background(), tsEvent(delayed.UnixMilli())))
	require.Len(t, *args, 43, "created_at appended as the last projection column")
	stored, ok := (*args)[40].(time.Time)
	require.True(t, ok, "created_at binds a time.Time, got %T", (*args)[40])
	assert.WithinDuration(t, delayed.UTC(), stored.UTC(), 2*time.Second,
		"created_at is the producer ts, not the (delayed) delivery moment")
}

// Legacy events without ts keep the legacy behavior: created_at falls back
// to the delivery time (parse moment).
func TestCreatedAt_FallsBackToDeliveryTime(t *testing.T) {
	before := time.Now().UTC()
	pool, args := captureLogInserts(t)
	c := New(nil, pool, "events:queue", silentLogger())

	require.NoError(t, c.handleRequestComplete(context.Background(), tsEvent(0)))
	require.Len(t, *args, 43)
	stored, ok := (*args)[40].(time.Time)
	require.True(t, ok)
	assert.WithinDuration(t, before, stored.UTC(), 5*time.Second)

	// A non-positive or unparseable ts is absent, not an error.
	ev := parseRequestEvent(map[string]interface{}{"ts": "-5"})
	assert.WithinDuration(t, time.Now().UTC(), ev.createdAt, 5*time.Second)
	ev = parseRequestEvent(map[string]interface{}{"ts": "not-a-number"})
	assert.WithinDuration(t, time.Now().UTC(), ev.createdAt, 5*time.Second)
}

// legacy attribution): a June request delivered in October settles against
// the June budget row.
func TestTeamPeriod_FromEventTsNotDeliveryTime(t *testing.T) {
	june := time.Date(time.Now().UTC().Year(), time.June, 15, 12, 0, 0, 0, time.UTC)
	if june.After(time.Now().UTC()) {
		june = june.AddDate(-1, 0, 0)
	}
	var payload []byte
	pool := &mockDB{}
	pool.ExecFn = func(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
		if strings.Contains(q, "INSERT INTO settlement_jobs") {
			payload, _ = args[5].([]byte)
		}
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	}
	c := New(nil, pool, "events:queue", silentLogger())

	require.NoError(t, c.handleRequestComplete(context.Background(), tsEvent(june.UnixMilli())))
	require.NotEmpty(t, payload, "team-attributed request creates a team_spend intent")
	assert.Contains(t, string(payload), `"period":"`+june.UTC().Format("2006-01")+`"`,
		"the intent period is the event's month, not the delivery month")
}

// The ts travels through the DLQ envelope and survives a replay round-trip:
// stream wire values -> JSON envelope -> stream values.
func TestTsSurvivesDLQRoundTrip(t *testing.T) {
	tsMs := time.Now().Add(-time.Hour).Truncate(time.Millisecond).UnixMilli()
	msg := tsEvent(tsMs)

	body, err := json.Marshal(eventpublisher.DLQEnvelope{
		OriginalStream: "events:queue",
		EntryID:        msg.ID,
		Error:          "max retries exceeded",
		Values:         msg.Values,
	})
	require.NoError(t, err)

	env, err := eventpublisher.ParseDLQEnvelope(body)
	require.NoError(t, err)

	got, ok := env.Values["ts"].(json.Number)
	require.True(t, ok, "ts must stay an exact number, got %T", env.Values["ts"])
	assert.Equal(t, strconv.FormatInt(tsMs, 10), got.String())

	values := env.StreamValues()
	assert.Equal(t, strconv.FormatInt(tsMs, 10), values["ts"],
		"re-published stream value is the exact producer ts")
}
