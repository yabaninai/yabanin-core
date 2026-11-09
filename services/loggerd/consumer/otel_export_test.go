package consumer

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/tracing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingSink is an OTelLogSink fake that remembers every exported record.
type recordingSink struct {
	mu             sync.Mutex
	records        []tracing.RequestLog
	includeContent bool
}

func (s *recordingSink) IncludeContent() bool { return s.includeContent }

func (s *recordingSink) ExportRequestLog(rec tracing.RequestLog) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, rec)
}

func (s *recordingSink) Shutdown(_ context.Context) error { return nil }

func (s *recordingSink) snapshot() []tracing.RequestLog {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]tracing.RequestLog(nil), s.records...)
}

// requestFields is a fully populated request.completed event.
func requestFields(requestID string) map[string]interface{} {
	return map[string]interface{}{
		"event_type":         "request.completed",
		"request_id":         requestID,
		"org_id":             "org-9",
		"session_id":         "client-session-3",
		"model_requested":    "gpt-5-mini",
		"model_used":         "gpt-5",
		"upstream_url":       "https://api.anthropic.com/v1/messages",
		"status_code":        "200",
		"duration_ms":        "321",
		"tokens_in":          "11",
		"tokens_out":         "7",
		"estimated_cost_usd": "0.0125",
		"cache_hit_type":     "semantic",
		"payload":            `{"messages":[{"role":"user","content":"TOP SECRET PAYLOAD"}]}`,
		"ts":                 "1759800000000",
	}
}

// sink with the content-free projection fields filled.
func TestExportOTelLog_CompletedDeliveryMirrorsToSink(t *testing.T) {
	sink := &recordingSink{}
	db := &mockDB{}
	c := New(&mockRedis{}, db, "otel-stream", silentLogger())
	c.SetOTelSink(sink)

	msg := redis.XMessage{ID: "1-0", Values: requestFields("req-mirror-1")}
	require.NoError(t, c.processMessage(context.Background(), msg))

	recs := sink.snapshot()
	require.Len(t, recs, 1, "one successful delivery → exactly one record")
	rec := recs[0]
	assert.Equal(t, "completed", rec.EventType)
	assert.Equal(t, "req-mirror-1", rec.RequestID)
	assert.Equal(t, "org-9", rec.OrgID)
	assert.Equal(t, "client-session-3", rec.SessionID)
	assert.Equal(t, "gpt-5-mini", rec.ModelRequested)
	assert.Equal(t, "gpt-5", rec.ModelUsed)
	assert.Equal(t, "https://api.anthropic.com/v1/messages", rec.UpstreamURL)
	assert.EqualValues(t, 200, rec.StatusCode)
	assert.EqualValues(t, 321, rec.DurationMs)
	assert.EqualValues(t, 11, rec.TokensIn)
	assert.EqualValues(t, 7, rec.TokensOut)
	assert.InDelta(t, 0.0125, rec.CostUSD, 1e-9)
	assert.True(t, rec.CacheHit, "cache_hit_type=semantic → cache hit")
	assert.False(t, rec.HasError)
	assert.False(t, rec.Timestamp.IsZero())
}

// The policy verdict rides along when the event carries the OP-8 field.
func TestExportOTelLog_PolicyVerdictParsed(t *testing.T) {
	sink := &recordingSink{}
	c := New(&mockRedis{}, &mockDB{}, "otel-stream", silentLogger())
	c.SetOTelSink(sink)

	fields := requestFields("req-policy-1")
	fields["policy"] = `{"policy_id":"p-1","version":2,"mode":"enforce","verdict":"deny","findings":[],"duration_ms":3}`
	msg := redis.XMessage{ID: "2-0", Values: fields}
	require.NoError(t, c.processMessage(context.Background(), msg))

	recs := sink.snapshot()
	require.Len(t, recs, 1)
	assert.Equal(t, "deny", recs[0].PolicyVerdict)

	// A legacy event (no policy) exports without a verdict — never an error.
	fields["request_id"] = "req-policy-2"
	fields["policy"] = nil
	require.NoError(t, c.processMessage(context.Background(), redis.XMessage{ID: "3-0", Values: fields}))
	recs = sink.snapshot()
	require.Len(t, recs, 2)
	assert.Empty(t, recs[1].PolicyVerdict)
}

// a FAILED delivery must not export — the retry path
// re-exports only after the (exactly-once) commit, so collectors never see
// duplicates.
func TestExportOTelLog_FailedDeliveryDoesNotExport(t *testing.T) {
	sink := &recordingSink{}
	db := &mockDB{ExecFn: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
		return pgconn.CommandTag{}, errors.New("transient database outage")
	}}
	c := New(&mockRedis{}, db, "otel-stream", silentLogger())
	c.SetOTelSink(sink)

	err := c.processMessage(context.Background(), redis.XMessage{ID: "10-0", Values: requestFields("req-fail-1")})
	require.Error(t, err)
	assert.Empty(t, sink.snapshot(), "failed delivery must not export")

	// The successful retry exports exactly once.
	db.ExecFn = nil
	require.NoError(t, c.processMessage(context.Background(), redis.XMessage{ID: "10-0", Values: requestFields("req-fail-1")}))
	assert.Len(t, sink.snapshot(), 1)
}

// Only request.* event shapes are mirrored.
func TestExportOTelLog_NonRequestEventsSkipped(t *testing.T) {
	sink := &recordingSink{}
	c := New(&mockRedis{}, &mockDB{}, "otel-stream", silentLogger())
	c.SetOTelSink(sink)

	for _, eventType := range []string{"session.created", "gateway.started", ""} {
		require.NoError(t, c.processMessage(context.Background(), redis.XMessage{
			ID: "20-0", Values: map[string]interface{}{"event_type": eventType},
		}))
	}
	assert.Empty(t, sink.snapshot())
}

// is not copied into the record at all; opting in carries the (truncated)
// sample.
func TestExportOTelLog_ContentGating(t *testing.T) {
	sink := &recordingSink{} // IncludeContent() = false
	c := New(&mockRedis{}, &mockDB{}, "otel-stream", silentLogger())
	c.SetOTelSink(sink)
	require.NoError(t, c.processMessage(context.Background(), redis.XMessage{ID: "30-0", Values: requestFields("req-content-1")}))
	recs := sink.snapshot()
	require.Len(t, recs, 1)
	assert.Empty(t, recs[0].Content, "default: no content leaves the consumer")

	contentSink := &recordingSink{includeContent: true}
	c2 := New(&mockRedis{}, &mockDB{}, "otel-stream", silentLogger())
	c2.SetOTelSink(contentSink)
	require.NoError(t, c2.processMessage(context.Background(), redis.XMessage{ID: "31-0", Values: requestFields("req-content-2")}))
	recs2 := contentSink.snapshot()
	require.Len(t, recs2, 1)
	assert.Contains(t, recs2[0].Content, "TOP SECRET PAYLOAD")

	// Oversized payloads are truncated at the source.
	long := requestFields("req-content-3")
	long["payload"] = strings.Repeat("x", otelContentMaxChars*2)
	require.NoError(t, c2.processMessage(context.Background(), redis.XMessage{ID: "32-0", Values: long}))
	recs3 := contentSink.snapshot()
	require.Len(t, recs3, 2)
	assert.LessOrEqual(t, len(recs3[1].Content), otelContentMaxChars+len("... [truncated]"))
}

// Event shapes keep their yabanin.event_type mapping: failed/budget carry
// error presence, shadow stays a distinct type.
func TestExportOTelLog_EventTypeAndErrorMapping(t *testing.T) {
	sink := &recordingSink{}
	db := &mockDB{}
	c := New(&mockRedis{}, db, "otel-stream", silentLogger())
	c.SetOTelSink(sink)

	failed := requestFields("req-evt-failed")
	failed["event_type"] = "request.failed"
	failed["error"] = "upstream 502"
	require.NoError(t, c.processMessage(context.Background(), redis.XMessage{ID: "40-0", Values: failed}))

	budget := requestFields("req-evt-budget")
	budget["event_type"] = "request.budget_exceeded"
	require.NoError(t, c.processMessage(context.Background(), redis.XMessage{ID: "41-0", Values: budget}))

	shadow := requestFields("req-evt-shadow")
	shadow["event_type"] = "request.shadow_completed"
	require.NoError(t, c.processMessage(context.Background(), redis.XMessage{ID: "42-0", Values: shadow}))

	recs := sink.snapshot()
	require.Len(t, recs, 3)
	assert.Equal(t, "failed", recs[0].EventType)
	assert.True(t, recs[0].HasError)
	assert.Equal(t, "budget_exceeded", recs[1].EventType)
	assert.Equal(t, "shadow_completed", recs[2].EventType)
}

// No sink wired (the default, no-endpoint deployment): the hot path is a
// plain no-op — no panic, no allocation path.
func TestExportOTelLog_NilSinkIsNoOp(t *testing.T) {
	c := New(&mockRedis{}, &mockDB{}, "otel-stream", silentLogger())
	require.NoError(t, c.processMessage(context.Background(), redis.XMessage{ID: "50-0", Values: requestFields("req-nosink-1")}))
}

// must not forward the payload — the profile gate sits ahead of
// IncludeContent in the export contract. Enters through handleMessage so the
// wire declaration (content_profile=metadata-only) is honored end to end.
func TestExportOTelLog_StrictProfileNeverCarriesContent(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")
	sink := &recordingSink{includeContent: true}
	db := &mockDB{}
	c := New(&mockRedis{}, db, "otel-stream", silentLogger())
	c.SetOTelSink(sink)

	fields := requestFields("req-content-strict")
	fields["content_profile"] = "metadata-only"
	c.handleMessage(context.Background(), redis.XMessage{ID: "33-0", Values: fields})

	recs := sink.snapshot()
	require.Len(t, recs, 1, "safe metadata still mirrors")
	assert.Empty(t, recs[0].Content, "metadata-only: content stays home even when the collector opted in")
	assert.Equal(t, "req-content-strict", recs[0].RequestID)
}
