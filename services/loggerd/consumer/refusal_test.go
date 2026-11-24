package consumer

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/credits"
	"github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Typed refusal history (request.invalid with a producer-stamped status):
// the row persists with the exact wire status, stays idempotent under
// duplicate delivery, keeps unstamped producers on the legacy generic
// path, and never persists the refused payload. A stamped refusal that
// claims an invocation identity parks before any read or write: no such
// event exists upstream, and the claim could hijack a paid dispatch's
// history slot and suppress its genuine terminal row.

// refusalRowCapture records every request_logs insert (query + args)
// separately from other statements.
type refusalRowCapture struct {
	queries []string
	args    [][]any
}

func (rc *refusalRowCapture) execFn(_ context.Context, q string, args ...any) (pgconn.CommandTag, error) {
	if strings.Contains(q, "INSERT INTO request_logs") {
		rc.queries = append(rc.queries, q)
		rc.args = append(rc.args, args)
	}
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

func refusalStampedEvent(id string) redis.XMessage {
	return redis.XMessage{
		ID: id,
		Values: map[string]interface{}{
			"event_type":      "request.invalid",
			"source":          "gateway",
			"session_id":      "sess-refuse-1",
			"org_id":          "org-refuse",
			"team_id":         "team-refuse",
			"request_id":      "req-refuse-1",
			"model_requested": "ghost-model",
			"payload":         `{"model":"ghost-model","messages":[{"role":"user","content":"refused secret prompt"}]}`,
			"status_code":     float64(404),
			"error":           `model "ghost-model" is not available on this gateway`,
		},
	}
}

// Refusal regression (drain defect): the stamped unknown-model refusal is
// persisted with the exact wire status, the verbatim refusal message and a
// prompt digest — never the refused payload, never a shape-default status.
func TestProcessMessage_RequestInvalid_RefusalPersisted(t *testing.T) {
	rc := &refusalRowCapture{}
	pool := &mockDB{ExecFn: rc.execFn}
	consumer := New(nil, pool, "events:queue", slog.Default())

	require.NoError(t, consumer.processMessage(context.Background(), refusalStampedEvent("1-1")))
	require.Len(t, rc.queries, 1, "exactly one request_logs row")

	q := rc.queries[0]
	args := rc.args[0]
	assert.Contains(t, q, "INSERT INTO request_logs")
	assert.NotContains(t, q, "response", "no response/upstream capture column is bound for a refusal")
	// Column order mirrors the budget refusal shape: session_id (0),
	// org_id (1), model_requested (2), status_code (3), error (4),
	// request_id (5), team_id (6), prompt_hash (7).
	assert.Nil(t, args[0], "non-uuid org skips the session registry (fail-open nil)")
	assert.Equal(t, "org-refuse", args[1])
	assert.Equal(t, "ghost-model", args[2])
	assert.Equal(t, int64(404), args[3], "the exact wire status, not a shape default")
	assert.Equal(t, `model "ghost-model" is not available on this gateway`, args[4])
	assert.Equal(t, "req-refuse-1", args[5])
	assert.Equal(t, uuidField("team-refuse"), args[6], "team_id binds its normalized identity")
	require.NotNil(t, args[7], "the prompt digest binds under the legacy profile")
	assert.Len(t, args[7], 64, "prompt_hash is the sha-256 hex digest, never the payload")
	assert.NotContains(t, fmt.Sprint(args...), "refused secret prompt")
}

// Unstamped request.invalid producers (policy denial, tool gate, chat
// validation) keep the legacy generic behavior: no row, no delivery failure.
func TestProcessMessage_RequestInvalid_UnstampedKeepsLegacyBehavior(t *testing.T) {
	rc := &refusalRowCapture{}
	pool := &mockDB{ExecFn: rc.execFn}
	consumer := New(nil, pool, "events:queue", slog.Default())

	msg := refusalStampedEvent("1-2")
	delete(msg.Values, "status_code")

	require.NoError(t, consumer.processMessage(context.Background(), msg))
	require.Empty(t, rc.queries, "an unstamped request.invalid records no row")
}

// Duplicate delivery of the same stream entry is a no-op against
// request_logs: the durable inbox claim skips the second delivery entirely.
func TestProcessMessage_RequestInvalid_DuplicateDeliverySkipped(t *testing.T) {
	rc := &refusalRowCapture{}
	pool := &mockDB{ExecFn: rc.execFn}
	consumer := New(nil, pool, "events:queue", slog.Default())
	msg := refusalStampedEvent("1-3")

	require.NoError(t, consumer.processMessage(context.Background(), msg))
	require.NoError(t, consumer.processMessage(context.Background(), msg))
	require.Len(t, rc.queries, 1, "the duplicate delivery inserts no second row")
}

// A stamped refusal carrying any invocation identity parks before any
// database read or write: the strict lookup harness fails loudly on any
// stray query, proving the park is side-effect free.
func TestProcessMessage_RequestInvalid_InvocationClaimParks(t *testing.T) {
	rc := &refusalRowCapture{}
	db := &mockDB{
		QueryRowFn: admissionRow(1, nil, nil),
		ExecFn:     rc.execFn,
	}
	consumer := NewWithCreditStore(&mockRedis{}, db, "events:queue", silentLogger(), credits.NewStore(nil, silentLogger()))

	msg := refusalStampedEvent("1-4")
	msg.Values["invocation_id"] = testInvocationID

	err := consumer.processMessage(context.Background(), msg)
	require.ErrorIs(t, err, errRefusalInvocationConflict)
	require.Empty(t, rc.queries, "a parked refusal writes no row")
}

// The paid-history guarantee: a contradictory identity-bearing refusal
// parks without claiming the invocation slot, so the genuine completed
// event of that same paid dispatch still records its terminal history.
func TestProcessMessage_RequestInvalid_PaidHistoryNotSuppressed(t *testing.T) {
	rc := &refusalRowCapture{}
	db := &mockDB{
		// The paid dispatch's admission and its stored terminal facts: the
		// first terminal delivery of an admitted invocation must compare
		// against the authoritative facts row.
		QueryRowFn: admissionRow(1, &fakeRow{vals: []any{"org-abc", "admitted"}}, chargedTerminalFacts()),
		ExecFn:     rc.execFn,
	}
	consumer := NewWithCreditStore(&mockRedis{}, db, "events:queue", silentLogger(), credits.NewStore(nil, silentLogger()))

	refusal := refusalStampedEvent("1-5a")
	refusal.Values["org_id"] = "org-abc"
	refusal.Values["invocation_id"] = testInvocationID
	err := consumer.processMessage(context.Background(), refusal)
	require.ErrorIs(t, err, errRefusalInvocationConflict)
	require.Empty(t, rc.queries, "the refusal must not reach request_logs")

	require.NoError(t, consumer.processMessage(context.Background(), invocationChargedMsg("1-5b")))
	require.Len(t, rc.queries, 1, "the paid request's genuine history survives the parked refusal")
	assert.Contains(t, rc.queries[0], "ON CONFLICT (invocation_id) WHERE invocation_id IS NOT NULL DO NOTHING",
		"the terminal row dedupes on the invocation domain")
	require.NotEmpty(t, rc.args[0])
	assert.Equal(t, testInvocationID, rc.args[0][len(rc.args[0])-1],
		"the paid invocation identity is claimed by its own terminal event")
}

// Under the metadata-only profile the production boundary strips the
// payload, replaces the error with the fixed redacted notice and keeps no
// digest unless the producer supplied one: the refusal row binds the same
// metadata columns, never content.
func TestProcessMessage_RequestInvalid_RefusalMetadataOnlyProfile(t *testing.T) {
	rc := &refusalRowCapture{}
	pool := &mockDB{ExecFn: rc.execFn}
	consumer := New(nil, pool, "events:queue", slog.Default())

	sanitized, profile := sanitizeStreamMessageForContentProfile(
		refusalStampedEvent("1-6"), config.LogContentProfileMetadataOnly)
	require.NoError(t, consumer.processMessagePolicy(context.Background(), sanitized,
		deliveryPolicy{profile: profile}))
	require.Len(t, rc.queries, 1, "the refusal still records its history under the strict profile")
	assert.NotContains(t, rc.queries[0], "response", "no content column under the strict profile")
	assert.Equal(t, eventpublisher.ContentProfileRedactedError, rc.args[0][4],
		"the verbatim refusal text never binds under the strict profile")
	// The boundary derives the prompt digest from the payload before
	// stripping it: a 64-hex digest persists, the payload never does.
	assert.Len(t, rc.args[0][7], 64, "the boundary-derived digest persists")
	assert.NotContains(t, fmt.Sprint(rc.args[0]...), "refused secret prompt")
}
