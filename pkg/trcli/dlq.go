package trcli

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/spf13/cobra"
)

// dlq defaults mirror the loggerd consumer (services/loggerd/consumer): the
// DLQ stream and the live queue it replays into.
const (
	dlqDefaultStream = "events:queue"
	dlqDefaultName   = "events:queue:dlq"
	dlqDefaultLimit  = 100
	dlqDefaultAddr   = "127.0.0.1:6379"
)

func dlqCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dlq",
		Short: "Inspect and replay the loggerd dead-letter queue",
	}
	cmd.AddCommand(dlqReplayCmd())
	return cmd
}

func dlqReplayCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "replay",
		Short: "Re-publish dead-lettered events back into the live queue",
		Long: `Read events from the dead-letter queue and re-publish them to the live
event stream for the loggerd consumer. The durable event_inbox dedupes
re-deliveries, so replaying an already-processed event is always safe.

DRY-RUN BY DEFAULT: without --apply nothing is written — the command only
prints what it would replay.`,
		RunE: runDLQReplay,
	}
	cmd.Flags().Int64("limit", dlqDefaultLimit, "Maximum number of DLQ entries to process")
	cmd.Flags().String("redis-addr", dlqDefaultAddr, "Redis address")
	cmd.Flags().String("stream", dlqDefaultStream, "Live stream to re-publish into")
	cmd.Flags().String("dlq", dlqDefaultName, "Dead-letter stream to read from")
	cmd.Flags().Bool("apply", false, "Perform the replay (default: dry-run)")
	return cmd
}

type dlqReplayOptions struct {
	RedisAddr string
	Stream    string
	DLQ       string
	Limit     int64
	Apply     bool
}

// dlqRedis is the Redis surface replay needs (satisfied by *redis.Client).
type dlqRedis interface {
	XRangeN(ctx context.Context, stream, start, stop string, count int64) *redis.XMessageSliceCmd
	XAdd(ctx context.Context, args *redis.XAddArgs) *redis.StringCmd
	XDel(ctx context.Context, stream string, ids ...string) *redis.IntCmd
	XLen(ctx context.Context, stream string) *redis.IntCmd
}

type dlqReplayResult struct {
	EntryID   string
	EventType string
	RequestID string
	OK        bool
	Reason    string
}

// runDLQReplay parses the flags, connects and delegates to replayDLQ.
func runDLQReplay(cmd *cobra.Command, _ []string) error {
	limit, err := cmd.Flags().GetInt64("limit")
	if err != nil {
		return err
	}
	addr, err := cmd.Flags().GetString("redis-addr")
	if err != nil {
		return err
	}
	stream, err := cmd.Flags().GetString("stream")
	if err != nil {
		return err
	}
	dlqName, err := cmd.Flags().GetString("dlq")
	if err != nil {
		return err
	}
	apply, err := cmd.Flags().GetBool("apply")
	if err != nil {
		return err
	}
	opts := dlqReplayOptions{
		RedisAddr: addr,
		Stream:    stream,
		DLQ:       dlqName,
		Limit:     limit,
		Apply:     apply,
	}
	if opts.Limit <= 0 {
		return fmt.Errorf("--limit must be positive, got %d", opts.Limit)
	}

	rdb := redis.NewClient(&redis.Options{Addr: opts.RedisAddr})
	defer func() { _ = rdb.Close() }()

	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

	return replayDLQ(ctx, rdb, opts, cmd.OutOrStdout())
}

// replayDLQ reads up to Limit entries from the DLQ, decodes each structured
// payload and — when Apply is set — re-publishes the original event into the
// live stream and removes the DLQ entry. A re-add that succeeds while the
// XDel fails leaves the entry in place; the next replay re-adds it and the
// durable inbox dedupes, so the loop is safe.
func replayDLQ(ctx context.Context, rdb dlqRedis, opts dlqReplayOptions, out io.Writer) error {
	entries, err := rdb.XRangeN(ctx, opts.DLQ, "-", "+", opts.Limit).Result()
	if err != nil {
		return fmt.Errorf("read dlq %s: %w", opts.DLQ, err)
	}

	mode := "dry-run (pass --apply to replay)"
	if opts.Apply {
		mode = "apply"
	}
	_, _ = fmt.Fprintf(out, "dlq %s -> %s, limit %d, mode: %s\n", opts.DLQ, opts.Stream, opts.Limit, mode)

	replayed := 0
	for _, entry := range entries {
		result := replayOne(ctx, rdb, opts, entry, opts.Apply)
		if result.OK {
			replayed++
		}
		printReplayResult(out, result)
	}

	_, _ = fmt.Fprintf(out, "done: %d entries, %d replayed, %d skipped\n", len(entries), replayed, len(entries)-replayed)
	return nil
}

// replayOne decodes one DLQ entry and optionally replays it. Errors are
// reported per entry (OK=false + reason) — one corrupt entry must not stop
// the batch.
func replayOne(ctx context.Context, rdb dlqRedis, opts dlqReplayOptions, entry redis.XMessage, apply bool) dlqReplayResult {
	result := dlqReplayResult{EntryID: entry.ID}

	payload, _ := entry.Values["payload"].(string)
	if payload == "" {
		result.Reason = "no structured payload (pre-W-LOGG entry)"
		return result
	}
	env, err := eventpublisher.ParseDLQEnvelope([]byte(payload))
	if err != nil {
		result.Reason = "undecodable payload: " + err.Error()
		return result
	}
	result.EventType = env.EventType()
	result.RequestID = env.RequestID()

	if !apply {
		result.OK = true
		result.Reason = "would replay (dry-run)"
		return result
	}

	if _, err := rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: opts.Stream,
		Values: env.StreamValues(),
	}).Result(); err != nil {
		result.Reason = "xadd failed: " + err.Error()
		return result
	}

	if _, err := rdb.XDel(ctx, opts.DLQ, entry.ID).Result(); err != nil {
		// The event is already re-published; the durable inbox dedupes the
		// eventual duplicate. The stale DLQ entry is reported and cleaned up
		// on the next replay.
		result.OK = true
		result.Reason = "replayed, but dlq delete failed: " + err.Error()
		return result
	}

	result.OK = true
	return result
}

func printReplayResult(out io.Writer, r dlqReplayResult) {
	status := "error"
	if r.OK {
		status = "ok"
	}
	_, _ = fmt.Fprintf(out, "%s\t%s\ttype=%s\trequest=%s\t%s\n", status, r.EntryID, r.EventType, r.RequestID, r.Reason)
}
