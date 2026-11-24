//go:build integration

package accounting

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// Redis-level oracle for the stand's per-run event stream: discover the
// original committed notification for a request, delete it (facts-recovery
// case), replay its exact field map under fresh entry IDs (redelivery
// cases), and prove the consumer actually processed replayed entries via
// the consumer group's delivery cursor when one exists.

type streamEntry struct {
	ID     string
	Values map[string]interface{}
}

// redisClient opens a client on the stand's Redis instance. Observation
// only, except for the documented fault injections (XDEL of the target's
// entries, XADD replays of already-observed field maps).
func (s *stand) redisClient(t *testing.T) *redis.Client {
	t.Helper()
	rdb := redis.NewClient(&redis.Options{Addr: s.redisAddr})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Fatalf("redis: ping: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

// findStreamEntries returns every entry in the stand's event stream whose
// serialized field map contains needle (the target correlation id).
func (s *stand) findStreamEntries(t *testing.T, rdb *redis.Client, needle string) []streamEntry {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var found []streamEntry
	start := "-"
	for {
		msgs, err := rdb.XRangeN(ctx, s.eventStream, start, "+", 200).Result()
		if err != nil {
			t.Fatalf("redis: XRANGE %s: %v", s.eventStream, err)
		}
		for _, m := range msgs {
			if entryContains(m.Values, needle) {
				found = append(found, streamEntry{ID: m.ID, Values: m.Values})
			}
		}
		if len(msgs) < 200 {
			return found
		}
		// Continue strictly after the last seen id (exclusive range).
		start = "(" + msgs[len(msgs)-1].ID
	}
}

// entryContains reports whether any serialized field or value contains
// needle.
func entryContains(values map[string]interface{}, needle string) bool {
	for k, v := range values {
		if strings.Contains(fmt.Sprint(k), needle) || strings.Contains(fmt.Sprint(v), needle) {
			return true
		}
	}
	return false
}

// deleteStreamEntriesFor removes the target's entries and proves by re-scan
// that no copy of rid remains anywhere in the stream.
func (s *stand) deleteStreamEntriesFor(t *testing.T, rdb *redis.Client, rid string, ids []string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := rdb.XDel(ctx, s.eventStream, ids...).Err(); err != nil {
		t.Fatalf("redis: XDEL %v: %v", ids, err)
	}
	if remain := s.findStreamEntries(t, rdb, rid); len(remain) != 0 {
		t.Fatalf("redis: %d entries for %s still present after XDEL", len(remain), rid)
	}
}

// replayEntryUnderFreshID re-adds the exact original field map, letting
// Redis mint a fresh entry id, and returns it.
func (s *stand) replayEntryUnderFreshID(t *testing.T, rdb *redis.Client, e streamEntry) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	id, err := rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: s.eventStream,
		Values: e.Values,
	}).Result()
	if err != nil {
		t.Fatalf("redis: XADD replay: %v", err)
	}
	return id
}

// assertNoRetryCarrier proves no side stream (retry/dead-letter/parking)
// carries a copy of the target's notification: after the main-stream
// deletion, nothing anywhere in Redis can redeliver the target live.
func (s *stand) assertNoRetryCarrier(t *testing.T, rdb *redis.Client, needle string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var cursor uint64
	for {
		keys, next, err := rdb.Scan(ctx, cursor, "*", 200).Result()
		if err != nil {
			t.Fatalf("redis: SCAN: %v", err)
		}
		for _, key := range keys {
			if key == s.eventStream {
				continue
			}
			kind, err := rdb.Type(ctx, key).Result()
			if err != nil || kind != "stream" {
				continue
			}
			s.assertStreamHoldsNoCopy(ctx, t, rdb, key, needle)
		}
		cursor = next
		if cursor == 0 {
			return
		}
	}
}

// assertStreamHoldsNoCopy walks every entry of one Redis stream (the
// event stream is excluded by the caller) and fails the test if the
// target's notification appears anywhere in it. Full pages are followed
// with an exclusive-start scan so a long stream cannot hide the tail.
func (s *stand) assertStreamHoldsNoCopy(ctx context.Context, t *testing.T, rdb *redis.Client, key, needle string) {
	t.Helper()
	msgs, err := rdb.XRangeN(ctx, key, "-", "+", 200).Result()
	if err != nil {
		return
	}
	requireNoStreamCopy(t, key, msgs, needle)
	if len(msgs) < 200 {
		return
	}
	// A full page may hide more; keep scanning this stream.
	for {
		more, err := rdb.XRangeN(ctx, key, "("+msgs[len(msgs)-1].ID, "+", 200).Result()
		if err != nil {
			break
		}
		requireNoStreamCopy(t, key, more, needle)
		if len(more) < 200 {
			break
		}
		msgs = more
	}
}

// requireNoStreamCopy fails the test when any scanned stream entry
// carries the target's notification.
func requireNoStreamCopy(t *testing.T, key string, msgs []redis.XMessage, needle string) {
	t.Helper()
	for _, m := range msgs {
		if entryContains(m.Values, needle) {
			t.Fatalf("redis: retry carrier stream %q holds a copy of target %s (entry %s)", key, needle, m.ID)
		}
	}
}

// groupDeliveryCursor returns the consumer group's last-delivered-id on
// the event stream, or ok=false when the consumer reads without a group.
// Delivery-cursor evidence alone only proves the group saw an entry —
// never that processing committed — so replay cases must use
// requireInboxClaimsCommitted + requireGroupDrained instead.
func (s *stand) groupDeliveryCursor(t *testing.T, rdb *redis.Client) (string, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	groups, err := rdb.XInfoGroups(ctx, s.eventStream).Result()
	if err != nil {
		t.Fatalf("redis: XINFO GROUPS %s: %v", s.eventStream, err)
	}
	if len(groups) == 0 {
		return "", false
	}
	return groups[0].LastDeliveredID, true
}

// observedConsumerGroup binds the stand's consumer group identity from the
// live stream (the product creates it at consumer start). Black-box: the
// name is discovered, not assumed from source constants.
func (s *stand) observedConsumerGroup(t *testing.T, rdb *redis.Client) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	groups, err := rdb.XInfoGroups(ctx, s.eventStream).Result()
	if err != nil {
		t.Fatalf("redis: XINFO GROUPS %s: %v", s.eventStream, err)
	}
	if len(groups) == 0 {
		t.Fatalf("redis: no consumer group on %s although the consumer is running — the inbox consumer identity cannot be bound", s.eventStream)
	}
	return groups[0].Name
}

// requireInboxClaimsCommitted polls until EVERY given fresh stream entry
// id has a committed event_inbox row with the stand's stream as source and
// the observed consumer group as consumer. Fresh entry ids are never
// inbox-deduped (dedupe keys on event_id), so a committed claim per replay
// is the durable proof the consumer actually took each replayed entry —
// unlike a delivery cursor, which only proves the group saw it and whose
// absence silently skipped the proof entirely.
func (s *stand) requireInboxClaimsCommitted(t *testing.T, rdb *redis.Client, ids []string) {
	t.Helper()
	group := s.observedConsumerGroup(t, rdb)
	for _, id := range ids {
		claimID := id
		pollUntil(t, 2*time.Minute, fmt.Sprintf("inbox claim committed for entry %s", claimID), func() error {
			if _, ok := s.oracleEventInboxClaim(t, s.eventStream, group, claimID); ok {
				return nil
			}
			return fmt.Errorf("no event_inbox row (source=%s, consumer=%s, event_id=%s) — the consumer has not claimed the replay", s.eventStream, group, claimID)
		})
	}
	t.Logf("redis: all %d replayed entries claimed in event_inbox (source=%s, consumer=%s)", len(ids), s.eventStream, group)
}

// requireGroupDrainedWithin waits, inside an EXPLICIT observation horizon,
// until the consumer group's pending list is empty, then point-asserts the
// drain via requireGroupDrained. Delivered-but-unfinished entries hold PEL
// slots and can still redeliver, so charge-completeness or idempotence
// conclusions drawn while entries are pending would be premature; the
// horizon makes the waiting budget a stated contract instead of an
// accident of check ordering.
func (s *stand) requireGroupDrainedWithin(t *testing.T, rdb *redis.Client, horizon time.Duration) {
	t.Helper()
	pollUntil(t, horizon, fmt.Sprintf("consumer group on %s drains its pending list", s.eventStream), func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		groups, err := rdb.XInfoGroups(ctx, s.eventStream).Result()
		if err != nil {
			return fmt.Errorf("XINFO GROUPS: %w", err)
		}
		if len(groups) == 0 {
			return abortf("no consumer group on %s although the consumer is running", s.eventStream)
		}
		if groups[0].Pending != 0 {
			return fmt.Errorf("%d delivered-but-unacknowledged entries", groups[0].Pending)
		}
		return nil
	})
	s.requireGroupDrained(t, rdb)
}

// requireGroupDrained asserts the consumer group exists on the stand's
// stream and has zero pending (delivered-but-unacknowledged) entries. A
// non-zero PEL means an entry was delivered but never finished processing
// — it can redeliver later, so no idempotence conclusion may be drawn
// while it is pending.
func (s *stand) requireGroupDrained(t *testing.T, rdb *redis.Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	groups, err := rdb.XInfoGroups(ctx, s.eventStream).Result()
	if err != nil {
		t.Fatalf("redis: XINFO GROUPS %s: %v", s.eventStream, err)
	}
	if len(groups) == 0 {
		t.Fatalf("redis: no consumer group on %s although the consumer is running — replays cannot be proven drained", s.eventStream)
	}
	if groups[0].Pending != 0 {
		t.Fatalf("redis: consumer group %s on %s has %d pending entries — a delivered-but-unprocessed entry can still redeliver and double-charge", groups[0].Name, s.eventStream, groups[0].Pending)
	}
}

// entryIDAfter compares millisecond-sequence Redis stream IDs.
func entryIDAfter(a, b string) bool {
	as := strings.SplitN(a, "-", 2)
	bs := strings.SplitN(b, "-", 2)
	if len(as) != 2 || len(bs) != 2 {
		return a > b
	}
	var am, bm int64
	fmt.Sscanf(as[0], "%d", &am)
	fmt.Sscanf(bs[0], "%d", &bm)
	if am != bm {
		return am > bm
	}
	var asq, bsq int64
	fmt.Sscanf(as[1], "%d", &asq)
	fmt.Sscanf(bs[1], "%d", &bsq)
	return asq > bsq
}
