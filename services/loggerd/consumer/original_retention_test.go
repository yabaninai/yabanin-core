package consumer

// N02-P06 T03/T05: the org original-text retention gate at the history
// writer. Default OFF (fail closed) persists processed text only: the
// full-fidelity ORIGINAL captures (upstream_request / upstream_response)
// and the tool-call arguments derived from them never reach the durable
// write, on every event shape, buffered or streamed, with one resolution
// per message. Explicit opt-in keeps the pre-toggle persistence contract;
// the read side (payload.read_originals + effective retention) governs
// exposure. These tests pin the negative channels: no sentinel content in
// any bound SQL argument of any shape when retention is off.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/config"
	eventpublisher "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// retStubStore is a configurable OriginalRetentionStore fake.
type retStubStore struct {
	calls int
	// err, when set, fails every lookup.
	err error
	// effective answers every lookup; nilOverride models a NULL
	// retain_original_text override (inherit the platform default).
	effective   bool
	nilOverride bool
	found       bool
	lastOrgID   string
}

func (s *retStubStore) GetOrgOriginalRetention(_ context.Context, orgID string) (*adminstore.OrgOriginalRetention, error) {
	s.calls++
	s.lastOrgID = orgID
	if s.err != nil {
		return nil, s.err
	}
	if !s.found {
		return nil, fmt.Errorf("org not found: %s: %w", orgID, adminstore.ErrNotFound)
	}
	setting := &adminstore.OrgOriginalRetention{OrgID: orgID, Effective: s.effective}
	if s.nilOverride {
		setting.Inherited = true
		setting.Effective = adminstore.OriginalRetentionPlatformDefault
	}
	return setting, nil
}

// retCall is one executed statement with its bound arguments.
type retCall struct {
	query string
	args  []any
}

// retCaptureDB records every bound argument of every statement the delivery
// transaction executes.
type retCaptureDB struct {
	mockDB
	calls []retCall
}

func (m *retCaptureDB) ExecFnImpl(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	m.calls = append(m.calls, retCall{query: query, args: args})
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

func newRetCaptureDB() *retCaptureDB {
	db := &retCaptureDB{}
	db.ExecFn = db.ExecFnImpl
	return db
}

// allArgs renders every bound argument of every recorded statement.
func (m *retCaptureDB) allArgs() string {
	var sb strings.Builder
	for _, call := range m.calls {
		for _, arg := range call.args {
			sb.WriteString(renderArg(arg))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// retConsumer builds a consumer wired with the given store (any
// OriginalRetentionStore fake — retStubStore, retOrgMapStore, …).
func retConsumer(db *retCaptureDB, store OriginalRetentionStore) *StreamConsumer {
	c := New(&mockRedis{}, db, "events:queue", silentLogger())
	if store != nil {
		c.SetOriginalRetentionStore(store)
	}
	return c
}

// renderJoin renders a full bound-argument list with []byte decoding.
func renderJoin(args []any) string {
	var sb strings.Builder
	for _, arg := range args {
		sb.WriteString(renderArg(arg))
	}
	return sb.String()
}

// renderArg renders one bound argument; JSONB columns bind []byte, which
// fmt would render as a byte array instead of its text.
func renderArg(arg any) string {
	if b, ok := arg.([]byte); ok {
		return string(b)
	}
	return fmt.Sprintf("%v", arg)
}

// assertNoSentinel fails when any bound argument or query text carries the
// fixture sentinels (the original-capture markers).
func assertNoSentinel(t *testing.T, db *retCaptureDB) {
	t.Helper()
	for _, call := range db.calls {
		var sb strings.Builder
		for _, arg := range call.args {
			sb.WriteString(renderArg(arg))
		}
		rendered := sb.String()
		assert.NotContains(t, rendered, cpSentinelUpReq, "original upstream request must not be bound")
		assert.NotContains(t, rendered, cpSentinelUpResp, "original upstream response must not be bound")
		assert.NotContains(t, rendered, "TOP SECRET COMPLETION")
		assert.NotContains(t, rendered, "get_weather", "tool-call content must not be derived when retention is off")
	}
}

// The resolver matrix (fail-closed rules, TTL caching, bounds) is pinned in
// pkg/eventpublisher/original_retention_test.go — the shared resolver moved
// there (ONE semantic, two call sites). The tests below pin the consumer
// behavior through the delivery surface.

// TestHandleMessage_RetentionOffPersistsProcessedOnly is the core T03/T05
// negative: the default org (no opt-in) must persist processed text only —
// the original captures bind SQL NULL and no tool-call content is derived.
func TestHandleMessage_RetentionOffPersistsProcessedOnly(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")
	t.Setenv("YABANIN_DEBUG_LOG_RESPONSE", "")

	msg := redis.XMessage{ID: "20-1", Values: cpCompletedFields("req-ret-off", false)}
	original := cpCopyValues(msg.Values)

	db := newRetCaptureDB()
	c := retConsumer(db, &retStubStore{}) // store answers not-found ⇒ fail-closed OFF

	require.NoError(t, c.handleRequestCompleteProfile(context.Background(), msg,
		deliveryPolicy{profile: config.LogContentProfileLegacy, retainOriginal: c.originalRetentionEnabled(context.Background(), msg.Values)}))

	var requestLogArgs []any
	for _, call := range db.calls {
		if strings.Contains(call.query, "INSERT INTO request_logs") {
			requestLogArgs = call.args
		}
	}
	require.NotEmpty(t, requestLogArgs, "the request_logs insert must run")

	// The processed snapshot and the digest survive; every bound argument
	// stays free of the original-capture sentinels.
	assertNoSentinel(t, db)
	joined := renderJoin(requestLogArgs)
	assert.Contains(t, joined, "TOP SECRET PROMPT BODY", "the processed payload snapshot persists")
	assert.NotContains(t, joined, cpSentinelUpReq, "upstream_request binds no original")
	assert.NotContains(t, joined, cpSentinelUpResp, "upstream_response binds no original")
	for _, call := range db.calls {
		assert.NotContains(t, call.query, "INSERT INTO tool_calls", "no tool-call rows derive from a dropped sample")
		assert.NotContains(t, call.query, "INSERT INTO tool_call_invocations")
	}

	// The received message is never mutated (replay/ownership contract).
	assert.Equal(t, original, msg.Values)
}

// TestHandleMessage_RetentionOnKeepsCaptures pins the opt-in parity: with
// the org explicitly opted in, the durable write is byte-for-byte the
// pre-toggle contract, tool-call extraction included.
func TestHandleMessage_RetentionOnKeepsCaptures(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")

	db := newRetCaptureDB()
	store := &retStubStore{found: true, effective: true}
	c := retConsumer(db, store)

	msg := redis.XMessage{ID: "21-1", Values: cpCompletedFields("req-ret-on", false)}
	policy := deliveryPolicy{profile: config.LogContentProfileLegacy, retainOriginal: true}
	require.NoError(t, c.handleRequestCompleteProfile(context.Background(), msg, policy))

	joined := db.allArgs()
	assert.Contains(t, joined, cpSentinelUpReq, "opt-in keeps the upstream_request capture")
	assert.Contains(t, joined, cpSentinelUpResp, "opt-in keeps the upstream_response capture")

	toolCalls, invocations := false, false
	for _, call := range db.calls {
		if strings.Contains(call.query, "INSERT INTO tool_calls") {
			toolCalls = true
		}
		if strings.Contains(call.query, "INSERT INTO tool_call_invocations") {
			invocations = true
		}
	}
	assert.True(t, toolCalls, "opt-in keeps tool-call extraction")
	assert.True(t, invocations, "opt-in keeps per-occurrence arguments")
}

// TestOriginalRetention_FailClosedOnStoreError proves a broken toggle
// source degrades to processed-only persistence, never to full captures.
func TestOriginalRetention_FailClosedOnStoreError(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")

	db := newRetCaptureDB()
	c := retConsumer(db, &retStubStore{err: errors.New("retention lookup failed")})

	msg := redis.XMessage{ID: "22-1", Values: cpCompletedFields("req-ret-err", false)}
	require.NoError(t, c.handleRequestCompleteProfile(context.Background(), msg,
		deliveryPolicy{profile: config.LogContentProfileLegacy, retainOriginal: c.originalRetentionEnabled(context.Background(), msg.Values)}))

	assertNoSentinel(t, db)
}

// TestOriginalRetention_ParityAcrossEventShapes is the no-drift contract:
// one resolution per message gates every event shape identically — the
// buffered/streamed persisted representation never diverges.
func TestOriginalRetention_ParityAcrossEventShapes(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")

	shapes := []struct {
		eventType string
		id        string
	}{
		{"request.completed", "30-1"},
		{"request.failed", "30-2"},
		{"request.shadow_completed", "30-3"},
		{"request.budget_exceeded", "30-4"},
	}
	for _, shape := range shapes {
		t.Run(shape.eventType, func(t *testing.T) {
			fields := cpCompletedFields("req-parity-"+shape.id, false)
			fields["event_type"] = shape.eventType
			db := newRetCaptureDB()
			c := retConsumer(db, &retStubStore{}) // OFF for every shape

			// Drive the exact production dispatch (one resolution at the
			// handleMessage boundary, same policy handed to every shape).
			policy := deliveryPolicy{profile: config.LogContentProfileLegacy, retainOriginal: false}
			require.NoError(t, c.deliverEventPolicy(context.Background(),
				redis.XMessage{ID: shape.id, Values: fields}, shape.eventType, policy))

			assertNoSentinel(t, db)
		})
	}
}

// TestOriginalResolution_OneReadPerMessage pins the single-source rule: the
// toggle is resolved once per org per TTL window on the delivery path, not
// re-read per handler or per column.
func TestOriginalResolution_OneReadPerMessage(t *testing.T) {
	t.Setenv("YABANIN_LOG_CONTENT_PROFILE", "")

	db := newRetCaptureDB()
	store := &retStubStore{found: true, effective: true}
	c := retConsumer(db, store)

	for _, id := range []string{"31-1", "31-2"} {
		msg := redis.XMessage{ID: id, Values: cpCompletedFields("req-cache-"+id, false)}
		c.handleMessage(context.Background(), msg)
	}
	assert.Equal(t, 1, store.calls, "two deliveries of one org share one resolution")
	assert.Equal(t, "org-cp-1", store.lastOrgID)

	// A second org resolves independently.
	msg := redis.XMessage{ID: "31-3", Values: cpCompletedFields("req-cache-org2", false)}
	msg.Values["org_id"] = "org-cp-2"
	c.handleMessage(context.Background(), msg)
	assert.Equal(t, 2, store.calls)
}

// dlqXAddCapture is a mockRedis wired past the retry budget that captures
// the DLQ XAdd values (the durable envelope write) for read-back.
func dlqXAddCapture() (*mockRedis, *map[string]interface{}) {
	var xaddValues map[string]interface{}
	rdb := &mockRedis{
		INCRFn: cpIncrPastRetries,
		XAddFn: func(ctx context.Context, args *redis.XAddArgs) *redis.StringCmd {
			xaddValues = args.Values.(map[string]interface{})
			cmd := redis.NewStringCmd(ctx)
			cmd.SetVal("40-1")
			return cmd
		},
	}
	return rdb, &xaddValues
}

// TestDLQ_RetentionOffStripsCapturesFromEnvelope is the DLQ negative
// (N02-P06): retention OFF — the DLQ envelope is a durable write, so the
// original-capture fields must be stripped from its Values before the XADD,
// even for an in-flight entry a pre-fix producer buffered raw. The envelope
// is decoded from the captured XAdd payload (the same bytes `yb dlq replay`
// would read).
func TestDLQ_RetentionOffStripsCapturesFromEnvelope(t *testing.T) {
	rdb, xaddValues := dlqXAddCapture()
	c := New(rdb, &mockDB{}, "events:queue", silentLogger())

	msg := redis.XMessage{ID: "40-1", Values: cpCompletedFields("req-dlq-off", false)}
	poison, err := c.trySendToDLQProfile(context.Background(), msg,
		deliveryPolicy{profile: config.LogContentProfileLegacy, retainOriginal: false})
	require.NoError(t, err)
	require.True(t, poison)

	// Read the envelope back exactly as the replay surface would.
	var envelope eventpublisher.DLQEnvelope
	require.NoError(t, json.Unmarshal([]byte((*xaddValues)["payload"].(string)), &envelope))
	require.NotEmpty(t, envelope.Values, "the envelope still carries the event identity")
	for _, key := range []string{"upstream_payload", "upstream_response"} {
		assert.NotContains(t, envelope.Values, key, "%s must not enter the durable DLQ when retention is off", key)
	}
	assert.NotContains(t, envelope.Values["payload"], cpSentinelUpReq)
	assert.Equal(t, "request.completed", envelope.EventType(), "metadata keeps flowing")

	// The received message is never mutated (replay/ownership contract).
	assert.Contains(t, msg.Values["upstream_payload"], cpSentinelUpReq)
}

// TestDLQ_RetentionOnKeepsEnvelopeCaptures pins the opt-in parity on the
// DLQ boundary: with retention ON the envelope keeps every original value
// byte-for-byte (the pre-toggle replay contract).
func TestDLQ_RetentionOnKeepsEnvelopeCaptures(t *testing.T) {
	rdb, xaddValues := dlqXAddCapture()
	c := New(rdb, &mockDB{}, "events:queue", silentLogger())

	msg := redis.XMessage{ID: "41-1", Values: cpCompletedFields("req-dlq-on", false)}
	poison, err := c.trySendToDLQProfile(context.Background(), msg,
		deliveryPolicy{profile: config.LogContentProfileLegacy, retainOriginal: true})
	require.NoError(t, err)
	require.True(t, poison)

	var envelope eventpublisher.DLQEnvelope
	require.NoError(t, json.Unmarshal([]byte((*xaddValues)["payload"].(string)), &envelope))
	assert.Contains(t, envelope.Values["upstream_payload"], cpSentinelUpReq,
		"opt-in keeps the upstream capture in the replayable envelope")
	assert.Contains(t, envelope.Values["upstream_response"], cpSentinelUpResp)
}

// TestDLQ_StrictProfileStillAllowlisted: the metadata-only DLQ contract is
// unchanged by the retention gate — the bounded allowlist wins.
func TestDLQ_StrictProfileStillAllowlisted(t *testing.T) {
	rdb, xaddValues := dlqXAddCapture()
	c := New(rdb, &mockDB{}, "events:queue", silentLogger())

	msg := redis.XMessage{ID: "42-1", Values: cpCompletedFields("req-dlq-strict", true)}
	poison, err := c.trySendToDLQProfile(context.Background(), msg,
		deliveryPolicy{profile: config.LogContentProfileMetadataOnly, retainOriginal: false})
	require.NoError(t, err)
	require.True(t, poison)

	var envelope eventpublisher.DLQEnvelope
	require.NoError(t, json.Unmarshal([]byte((*xaddValues)["payload"].(string)), &envelope))
	require.NotEmpty(t, envelope.Values)
	for key := range envelope.Values {
		assert.Contains(t, strictDLQAllowlistKeys, key,
			"the strict allowlist wins regardless of retention")
	}
	for _, key := range []string{"upstream_payload", "upstream_response"} {
		assert.NotContains(t, envelope.Values, key)
	}
}
