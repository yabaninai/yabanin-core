package consumer

import (
	"context"
	"math"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// CV-02 recorded-zero correction (attribution contract): the publisher emits
// attempt_count / retry_count on EVERY request.completed, but uninstrumented
// producers (pkg/gateway/embeddings_endpoint.go, images_endpoint.go,
// audio_transcriptions.go) leave the Go zero values — so key-present 0/0 is
// an UNINSTRUMENTED request, not a measurement. attempt_count>0 is the
// attribution signal; only then may retry_count bind, with 0 preserving the
// real single-attempt zero. NULL otherwise (legacy absent, zero, negative,
// fractional, NaN/Inf, out of range) — never an invented counter, never an
// erased one. first_token_ms keeps its zero-means-unknown contract: a
// present 0 means "not measured" (non-streaming), never a real 0 ms.

// captureRequestLogArgs captures the argument slice of every request_logs
// INSERT (later transactional writes — settlement intents, pending_price —
// must not clobber the projection under test).
func captureRequestLogArgs() (*mockDB, *[][]any) {
	var captured [][]any
	pool := &mockDB{
		ExecFn: func(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
			if strings.Contains(q, "INSERT INTO request_logs") {
				captured = append(captured, args)
			}
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
	}
	return pool, &captured
}

// The attribution matrix at the helper level: what attempt_count /
// retry_count bind for every wire shape the publisher or a corrupt relay
// can produce. The wire is stringified by XAdd; fixtures in this package
// use float64.
func TestAttributedCountFields(t *testing.T) {
	cases := []struct {
		name        string
		attempt     interface{} // nil = key absent
		retry       interface{} // nil = key absent
		wantAttempt interface{}
		wantRetry   interface{}
	}{
		// The corrected projection: attributed single attempt, recorded zero.
		{"recorded single-attempt zero", "1", "0", int64(1), int64(0)},
		{"float64 recorded zero", float64(1), float64(0), int64(1), int64(0)},
		// Positive retries bind as recorded.
		{"nonzero retries", "1", "3", int64(1), int64(3)},
		{"float64 nonzero retries", float64(3), float64(2), int64(3), int64(2)},
		{"multi-attempt with retries", "4", "2", int64(4), int64(2)},
		// Uninstrumented producers (embeddings/images/audio): Go zero values
		// emitted as present keys — UNKNOWN, not measured 0/0.
		{"uninstrumented zero-zero", "0", "0", nil, nil},
		{"float64 uninstrumented zero-zero", float64(0), float64(0), nil, nil},
		{"zero attempt with positive retry", "0", "4", nil, nil},
		// Legacy events predating the fields: keys absent.
		{"legacy absent both", nil, nil, nil, nil},
		{"retry absent with attributed attempt", "1", nil, int64(1), nil},
		// Invalid values never invent or truncate a counter.
		{"negative attempt", "-1", "0", nil, nil},
		{"negative retry with attributed attempt", "2", "-3", int64(2), nil},
		{"fractional attempt", "1.5", "1", nil, nil},
		{"float64 fractional retry", float64(1), 1.5, int64(1), nil},
		{"string fraction retry", "1", "1.5", int64(1), nil},
		{"NaN retry", "1", "NaN", int64(1), nil},
		{"float64 NaN attempt", math.NaN(), "0", nil, nil},
		{"float64 +Inf retry", "1", math.Inf(1), int64(1), nil},
		{"float64 -Inf attempt", math.Inf(-1), "0", nil, nil},
		{"float64 below -2^63 attempt", -9223372036854775810.0, float64(0), nil, nil},
		{"out-of-range attempt string", "9223372036854775808", "0", nil, nil},
		{"float64 2^63 overflow attempt", 9223372036854775808.0, float64(0), nil, nil},
		{"empty strings", "", "", nil, nil},
		{"bool attempt", true, "0", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fields := map[string]interface{}{}
			if tc.attempt != nil {
				fields["attempt_count"] = tc.attempt
			}
			if tc.retry != nil {
				fields["retry_count"] = tc.retry
			}
			assert.Equal(t, tc.wantAttempt, attributedAttemptCount(fields), "attempt_count")
			assert.Equal(t, tc.wantRetry, attributedRetryCount(fields), "retry_count")
		})
	}
}

// The regression pin: a real single-attempt completion (attempt_count=1,
// retry_count=0 — exactly what the chat/stream gateway publishes on a clean
// first-try completion) must bind 1 and 0 into the INSERT, not NULL.
// first_token_ms=0 (non-streaming) keeps binding NULL on the same row.
func TestHandleRequestComplete_RecordedZeroBindsZeroNotNull(t *testing.T) {
	// Wire shape: the real publisher stringifies, so Redis delivers "1"/"0".
	t.Run("string wire shape", func(t *testing.T) {
		pool, captured := captureRequestLogArgs()
		c := New(nil, pool, "events:queue", silentLogger())

		msg := redis.XMessage{Values: map[string]interface{}{
			"event_type":      "request.completed",
			"source":          "gateway",
			"session_id":      "ses_cv02_zero",
			"org_id":          testOrgUUID,
			"model_requested": "gpt-4",
			"model_used":      "gpt-4-turbo",
			"status_code":     "200",
			"duration_ms":     "1500",
			"tokens_in":       "100",
			"tokens_out":      "250",
			"method":          "POST",
			"endpoint":        "chat.completions",
			"first_token_ms":  "0",
			"attempt_count":   "1",
			"retry_count":     "0",
		}}
		require.NoError(t, c.handleRequestComplete(context.Background(), msg))

		require.Len(t, *captured, 1)
		values := (*captured)[0]
		require.Len(t, values, 43)
		assert.Equal(t, int64(1), values[31], "attempt_count")
		assert.Equal(t, int64(0), values[32], "retry_count — recorded single-attempt zero, NOT unknown")
		assert.Nil(t, values[30], "first_token_ms — present zero still means not measured")
	})

	// Fixture shape: hand-built maps in this package use float64.
	t.Run("float64 fixture shape", func(t *testing.T) {
		pool, captured := captureRequestLogArgs()
		c := New(nil, pool, "events:queue", silentLogger())

		msg := redis.XMessage{Values: map[string]interface{}{
			"event_type":      "request.completed",
			"source":          "gateway",
			"session_id":      "ses_cv02_zero_f",
			"org_id":          testOrgUUID,
			"model_requested": "gpt-4",
			"model_used":      "gpt-4-turbo",
			"status_code":     float64(200),
			"duration_ms":     float64(1500),
			"tokens_in":       float64(100),
			"tokens_out":      float64(250),
			"method":          "POST",
			"first_token_ms":  float64(0),
			"attempt_count":   float64(1),
			"retry_count":     float64(0),
		}}
		require.NoError(t, c.handleRequestComplete(context.Background(), msg))

		require.Len(t, *captured, 1)
		values := (*captured)[0]
		require.Len(t, values, 43)
		assert.Equal(t, int64(1), values[31], "attempt_count")
		assert.Equal(t, int64(0), values[32], "retry_count")
		assert.Nil(t, values[30], "first_token_ms")
	})
}

// Uninstrumented-producer control: embeddings / images / audio
// transcriptions build real request.completed events WITHOUT touching
// AttemptCount / RetryCount, so the publisher emits present "0"/"0" keys
// (Go zero values stringified). Those rows must stay NULL/NULL — unknown,
// never a measured "zero attempts". Same for first_token_ms 0.
func TestHandleRequestComplete_UninstrumentedProducerBindsNullNull(t *testing.T) {
	for _, shape := range []struct {
		name  string
		value interface{}
	}{
		{"string wire shape", "0"},
		{"float64 fixture shape", float64(0)},
	} {
		t.Run(shape.name, func(t *testing.T) {
			pool, captured := captureRequestLogArgs()
			c := New(nil, pool, "events:queue", silentLogger())

			msg := redis.XMessage{Values: map[string]interface{}{
				"event_type":      "request.completed",
				"source":          "gateway",
				"session_id":      "ses_cv02_embed",
				"org_id":          testOrgUUID,
				"model_requested": "text-embedding-3-small",
				"model_used":      "text-embedding-3-small",
				"status_code":     "200",
				"duration_ms":     "40",
				"tokens_in":       "12",
				"tokens_out":      "0",
				"method":          "POST",
				"endpoint":        "embeddings",
				"first_token_ms":  shape.value,
				"attempt_count":   shape.value,
				"retry_count":     shape.value,
			}}
			require.NoError(t, c.handleRequestComplete(context.Background(), msg))

			require.Len(t, *captured, 1)
			values := (*captured)[0]
			require.Len(t, values, 43)
			assert.Nil(t, values[31], "attempt_count — uninstrumented 0/0 is unknown, not measured")
			assert.Nil(t, values[32], "retry_count — uninstrumented 0/0 is unknown, not measured")
			assert.Nil(t, values[30], "first_token_ms")
		})
	}
}

// Isolated return-to-NULL negative: a legacy event predating the
// observability fields carries NO attempt_count / retry_count / first_token_ms
// keys — those must still bind NULL after the fix (unknown, not a fake 0/1).
func TestHandleRequestComplete_LegacyAbsentAttemptFieldsStayNull(t *testing.T) {
	pool, captured := captureRequestLogArgs()
	c := New(nil, pool, "events:queue", silentLogger())

	msg := redis.XMessage{Values: map[string]interface{}{
		"event_type":      "request.completed",
		"source":          "gateway",
		"session_id":      "ses_cv02_legacy",
		"org_id":          testOrgUUID,
		"model_requested": "gpt-4",
		"model_used":      "gpt-4-turbo",
		"status_code":     "200",
		"duration_ms":     "1500",
		"tokens_in":       "100",
		"tokens_out":      "250",
		"method":          "POST",
	}}
	require.NoError(t, c.handleRequestComplete(context.Background(), msg))

	require.Len(t, *captured, 1)
	values := (*captured)[0]
	require.Len(t, values, 43)
	assert.Nil(t, values[30], "first_token_ms")
	assert.Nil(t, values[31], "attempt_count")
	assert.Nil(t, values[32], "retry_count")
}

// Corrupt attempt/retry values bind NULL (unknown) rather than a fabricated
// zero — parseCountField never invents data.
func TestHandleRequestComplete_CorruptAttemptFieldsBindNull(t *testing.T) {
	pool, captured := captureRequestLogArgs()
	c := New(nil, pool, "events:queue", silentLogger())

	msg := redis.XMessage{Values: map[string]interface{}{
		"event_type":      "request.completed",
		"source":          "gateway",
		"session_id":      "ses_cv02_corrupt",
		"org_id":          testOrgUUID,
		"model_requested": "gpt-4",
		"model_used":      "gpt-4-turbo",
		"status_code":     "200",
		"duration_ms":     "1500",
		"tokens_in":       "100",
		"tokens_out":      "250",
		"method":          "POST",
		"first_token_ms":  "not-a-number",
		"attempt_count":   "",
		"retry_count":     "NaN",
	}}
	require.NoError(t, c.handleRequestComplete(context.Background(), msg))

	require.Len(t, *captured, 1)
	values := (*captured)[0]
	require.Len(t, values, 43)
	assert.Nil(t, values[30], "first_token_ms")
	assert.Nil(t, values[31], "attempt_count")
	assert.Nil(t, values[32], "retry_count")
}

// Isolated fractional negative: retry_count=1.5 (either wire shape) is a
// corrupt measurement — it must bind NULL, never truncate to 1 and never
// round to 2. A counter is only ever the exact recorded integer.
func TestHandleRequestComplete_FractionalRetryCountBindsNull(t *testing.T) {
	for _, shape := range []struct {
		name       string
		retryValue interface{}
	}{
		{"string wire shape", "1.5"},
		{"float64 fixture shape", 1.5},
	} {
		t.Run(shape.name, func(t *testing.T) {
			pool, captured := captureRequestLogArgs()
			c := New(nil, pool, "events:queue", silentLogger())

			msg := redis.XMessage{Values: map[string]interface{}{
				"event_type":      "request.completed",
				"source":          "gateway",
				"session_id":      "ses_cv02_fraction",
				"org_id":          testOrgUUID,
				"model_requested": "gpt-4",
				"model_used":      "gpt-4-turbo",
				"status_code":     "200",
				"duration_ms":     "1500",
				"tokens_in":       "100",
				"tokens_out":      "250",
				"method":          "POST",
				"attempt_count":   "1",
				"retry_count":     shape.retryValue,
			}}
			require.NoError(t, c.handleRequestComplete(context.Background(), msg))

			require.Len(t, *captured, 1)
			values := (*captured)[0]
			require.Len(t, values, 43)
			assert.Nil(t, values[32], "retry_count — fractional input binds NULL, not a truncated 1")
			assert.Equal(t, int64(1), values[31], "attempt_count — intact sibling field still binds")
		})
	}
}

// Negative attempt/retry controls: a negative attempt never attributes the
// family (NULL/NULL); an attributed attempt with a negative retry binds the
// attempt but NULL for the corrupt retry — never a fabricated number.
func TestHandleRequestComplete_NegativeAttemptFieldsBindNull(t *testing.T) {
	t.Run("negative attempt", func(t *testing.T) {
		pool, captured := captureRequestLogArgs()
		c := New(nil, pool, "events:queue", silentLogger())

		msg := redis.XMessage{Values: map[string]interface{}{
			"event_type":      "request.completed",
			"source":          "gateway",
			"session_id":      "ses_cv02_neg_attempt",
			"org_id":          testOrgUUID,
			"model_requested": "gpt-4",
			"model_used":      "gpt-4-turbo",
			"status_code":     "200",
			"duration_ms":     "1500",
			"tokens_in":       "100",
			"tokens_out":      "250",
			"method":          "POST",
			"attempt_count":   "-1",
			"retry_count":     "0",
		}}
		require.NoError(t, c.handleRequestComplete(context.Background(), msg))

		require.Len(t, *captured, 1)
		values := (*captured)[0]
		require.Len(t, values, 43)
		assert.Nil(t, values[31], "attempt_count")
		assert.Nil(t, values[32], "retry_count")
	})

	t.Run("attributed attempt with negative retry", func(t *testing.T) {
		pool, captured := captureRequestLogArgs()
		c := New(nil, pool, "events:queue", silentLogger())

		msg := redis.XMessage{Values: map[string]interface{}{
			"event_type":      "request.completed",
			"source":          "gateway",
			"session_id":      "ses_cv02_neg_retry",
			"org_id":          testOrgUUID,
			"model_requested": "gpt-4",
			"model_used":      "gpt-4-turbo",
			"status_code":     "200",
			"duration_ms":     "1500",
			"tokens_in":       "100",
			"tokens_out":      "250",
			"method":          "POST",
			"attempt_count":   "2",
			"retry_count":     "-3",
		}}
		require.NoError(t, c.handleRequestComplete(context.Background(), msg))

		require.Len(t, *captured, 1)
		values := (*captured)[0]
		require.Len(t, values, 43)
		assert.Equal(t, int64(2), values[31], "attempt_count")
		assert.Nil(t, values[32], "retry_count — negative retry is corrupt, not -3")
	})
}
