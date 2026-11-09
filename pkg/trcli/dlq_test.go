package trcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// W-LOGG: `yb dlq replay` reads the loggerd dead-letter queue, decodes the
// structured envelopes the consumer writes and re-publishes the original
// events into the live stream. Dry-run is the default; --apply replays.

type fakeDLQRedis struct {
	entries    []redis.XMessage
	xadds      []redis.XAddArgs
	xdels      []string
	rangeCount int64
	rangeErr   error
}

func (f *fakeDLQRedis) XRangeN(ctx context.Context, _, _, _ string, count int64) *redis.XMessageSliceCmd {
	cmd := redis.NewXMessageSliceCmd(ctx)
	f.rangeCount = count
	if f.rangeErr != nil {
		cmd.SetErr(f.rangeErr)
		return cmd
	}
	cmd.SetVal(f.entries)
	return cmd
}

func (f *fakeDLQRedis) XAdd(ctx context.Context, args *redis.XAddArgs) *redis.StringCmd {
	f.xadds = append(f.xadds, *args)
	cmd := redis.NewStringCmd(ctx)
	cmd.SetVal("replayed-id")
	return cmd
}

func (f *fakeDLQRedis) XDel(ctx context.Context, _ string, ids ...string) *redis.IntCmd {
	f.xdels = append(f.xdels, ids...)
	cmd := redis.NewIntCmd(ctx)
	cmd.SetVal(int64(len(ids)))
	return cmd
}

func (f *fakeDLQRedis) XLen(ctx context.Context, _ string) *redis.IntCmd {
	cmd := redis.NewIntCmd(ctx)
	cmd.SetVal(int64(len(f.entries)))
	return cmd
}

func dlqEntry(id string, values map[string]interface{}) redis.XMessage {
	body, err := json.Marshal(eventpublisher.DLQEnvelope{
		OriginalStream: "events:queue",
		EntryID:        id,
		RetryCount:     4,
		Error:          "max retries exceeded",
		FailedAt:       "2026-10-04T00:00:00Z",
		Values:         values,
	})
	if err != nil {
		panic(err)
	}
	return redis.XMessage{ID: id, Values: map[string]interface{}{"payload": string(body)}}
}

func sampleEventValues() map[string]interface{} {
	return map[string]interface{}{
		"event_type":         "request.completed",
		"request_id":         "req-replay-1",
		"org_id":             "org-1",
		"session_id":         "sess-1",
		"status_code":        "200",
		"estimated_cost_usd": "0.05",
	}
}

func replayOpts(apply bool) dlqReplayOptions {
	return dlqReplayOptions{
		RedisAddr: dlqDefaultAddr,
		Stream:    dlqDefaultStream,
		DLQ:       dlqDefaultName,
		Limit:     10,
		Apply:     apply,
	}
}

// Dry-run is the default and mutates nothing: every entry parses and is
// reported, but no XADD/XDEL happens.
func TestReplayDLQ_DryRunByDefault(t *testing.T) {
	fake := &fakeDLQRedis{entries: []redis.XMessage{
		dlqEntry("1-1", sampleEventValues()),
	}}
	var out bytes.Buffer

	require.NoError(t, replayDLQ(context.Background(), fake, replayOpts(false), &out))

	assert.Empty(t, fake.xadds, "dry-run must not publish")
	assert.Empty(t, fake.xdels, "dry-run must not delete")
	assert.Contains(t, out.String(), "dry-run")
	assert.Contains(t, out.String(), "would replay")
	assert.Contains(t, out.String(), "type=request.completed")
	assert.Contains(t, out.String(), "request=req-replay-1")
	assert.Equal(t, int64(10), fake.rangeCount, "limit is passed to XRANGE")
}

// --apply re-publishes the exact original event into the live stream and
// removes the DLQ entry.
func TestReplayDLQ_ApplyRepublishesAndDeletes(t *testing.T) {
	fake := &fakeDLQRedis{entries: []redis.XMessage{
		dlqEntry("2-1", sampleEventValues()),
	}}
	var out bytes.Buffer

	require.NoError(t, replayDLQ(context.Background(), fake, replayOpts(true), &out))

	require.Len(t, fake.xadds, 1)
	add := fake.xadds[0]
	values, ok := add.Values.(map[string]interface{})
	require.True(t, ok, "replay must XADD a field map, got %T", add.Values)
	assert.Equal(t, dlqDefaultStream, add.Stream, "replays into the live queue")
	assert.Equal(t, "200", values["status_code"], "string values round-trip verbatim")
	assert.Equal(t, "0.05", values["estimated_cost_usd"])
	assert.Equal(t, "request.completed", values["event_type"])
	assert.Equal(t, []string{"2-1"}, fake.xdels, "processed entries leave the DLQ")
	assert.Contains(t, out.String(), "done: 1 entries, 1 replayed, 0 skipped")
}

// Numeric field values survive the JSON round-trip exactly (json.Number,
// never float-rewritten) so the replayed event matches the original wire
// form of a Redis stream entry.
func TestReplayDLQ_NumericFidelity(t *testing.T) {
	values := sampleEventValues()
	values["ts"] = 1728000000000
	values["duration_ms"] = 1500
	fake := &fakeDLQRedis{entries: []redis.XMessage{dlqEntry("3-1", values)}}
	var out bytes.Buffer

	require.NoError(t, replayDLQ(context.Background(), fake, replayOpts(true), &out))

	require.Len(t, fake.xadds, 1)
	replayed, ok := fake.xadds[0].Values.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, strconv.FormatInt(1728000000000, 10), replayed["ts"])
	assert.Equal(t, "1500", replayed["duration_ms"])
}

// A pre-W-LOGG entry (no structured payload) is reported and skipped, not a
// batch failure.
func TestReplayDLQ_LegacyEntrySkipped(t *testing.T) {
	fake := &fakeDLQRedis{entries: []redis.XMessage{
		{ID: "4-0", Values: map[string]interface{}{"event_type": "request.completed", "error": "max retries exceeded"}},
		dlqEntry("4-1", sampleEventValues()),
	}}
	var out bytes.Buffer

	require.NoError(t, replayDLQ(context.Background(), fake, replayOpts(true), &out))

	require.Len(t, fake.xadds, 1, "only the structured entry replays")
	assert.Contains(t, out.String(), "no structured payload (pre-W-LOGG entry)")
	assert.Contains(t, out.String(), "1 replayed, 1 skipped")
}

// A limit smaller than the DLQ depth only touches the first limit entries
// (XRANGE count), leaving the rest for the next run.
func TestReplayDLQ_RespectsLimit(t *testing.T) {
	entries := []redis.XMessage{
		dlqEntry("5-1", sampleEventValues()),
		dlqEntry("5-2", sampleEventValues()),
		dlqEntry("5-3", sampleEventValues()),
	}
	fake := &fakeDLQRedis{entries: entries[:2]} // Redis returns at most count
	var out bytes.Buffer
	opts := replayOpts(true)
	opts.Limit = 2

	require.NoError(t, replayDLQ(context.Background(), fake, opts, &out))
	assert.Equal(t, int64(2), fake.rangeCount)
	assert.Len(t, fake.xadds, 2)
}

// Range read failures surface as command errors.
func TestReplayDLQ_RangeError(t *testing.T) {
	fake := &fakeDLQRedis{rangeErr: errors.New("connection refused")}
	var out bytes.Buffer

	require.Error(t, replayDLQ(context.Background(), fake, replayOpts(false), &out))
}

// ParseDLQEnvelope rejects envelopes without values — replaying them would
// silently drop the event.
func TestReplayDLQ_EmptyEnvelopeRejected(t *testing.T) {
	body, err := json.Marshal(eventpublisher.DLQEnvelope{OriginalStream: "events:queue"})
	require.NoError(t, err)
	fake := &fakeDLQRedis{entries: []redis.XMessage{
		{ID: "6-1", Values: map[string]interface{}{"payload": string(body)}},
	}}
	var out bytes.Buffer

	require.NoError(t, replayDLQ(context.Background(), fake, replayOpts(true), &out))
	assert.Empty(t, fake.xadds)
	assert.Contains(t, out.String(), "carries no event values")
}

// The command surface: dlq is registered on the root command, replay is its
// subcommand, --apply defaults to false (dry-run default) and a non-positive
// limit is rejected before any connection is made.
func TestDLQReplay_CommandSurface(t *testing.T) {
	cmd := dlqReplayCmd()
	require.NotNil(t, cmd.Flags().Lookup("apply"))
	require.NotNil(t, cmd.Flags().Lookup("limit"))
	require.NotNil(t, cmd.Flags().Lookup("redis-addr"))

	applyFlag := cmd.Flags().Lookup("apply")
	require.NotNil(t, applyFlag)
	assert.Equal(t, "false", applyFlag.DefValue, "dry-run must be the default")

	root := RootCommand()
	found := false
	for _, sub := range root.Commands() {
		if sub.Name() == "dlq" {
			found = true
			assert.True(t, sub.HasSubCommands(), "dlq exposes subcommands")
		}
	}
	assert.True(t, found, "yb exposes the dlq command")

	cmd.SetArgs([]string{"--limit", "0"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	assert.Error(t, cmd.Execute(), "non-positive --limit is rejected")
}
