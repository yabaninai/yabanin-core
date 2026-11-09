package inventory

// E02-P01 W04-C03: freshness/staleness battery — late, replayed,
// out-of-order and clock-skewed deliveries must never corrupt the
// registry: last_seen is monotone (never rewinds), first_seen is
// immovable, payloads are write-once, and concurrent observers converge
// on the max timestamp. All under -race.

import (
	"context"
	"encoding/json"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func stTimes(t *testing.T) (time.Time, time.Time, time.Time) {
	t.Helper()
	return time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC), // t1
		time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC), // t2
		time.Date(2026, 11, 7, 14, 0, 0, 0, time.UTC) // t3
}

func stEvent(ts time.Time, reqID string) *eventpublisher.Event {
	return &eventpublisher.Event{
		TS: ts.UnixMilli(), RequestID: reqID, SessionID: "sess-1",
		AgentID: "agent-st", ModelRequested: "m-st", ModelUsed: "m-st",
		UpstreamURL: "https://up.example",
	}
}

// TestObserveStaleLateDelivery: a late delivery older than the stored
// last_seen (same observer, dedup defeated by distinct request ids) moves
// nothing — every count is unchanged.
func TestObserveStaleLateDelivery(t *testing.T) {
	s := newTestStore(t)
	o, err := NewObserver(s)
	require.NoError(t, err)
	t1, t2, _ := stTimes(t)

	_, err = o.ObserveEvent(context.Background(), "org-st1", stEvent(t2, "st-a"))
	require.NoError(t, err)

	rep, err := o.ObserveEvent(context.Background(), "org-st1", stEvent(t1, "st-b")) // older
	require.NoError(t, err)
	assert.Equal(t, ImportCounts{Unchanged: 3}, rep.Counts)

	row, ok, err := s.GetAsset(context.Background(), "org-st1", KindAgent, AgentKey("agent-st"))
	require.NoError(t, err)
	require.True(t, ok)
	assert.True(t, row.LastSeen.Equal(t2), "late delivery must not rewind last_seen")
	assert.True(t, row.FirstSeen.Equal(t2))
}

// TestObserveStaleOutOfOrderBatch: within one process, deliveries landing
// out of order converge — the earlier delivery after the later one is a
// no-op; the later one after the earlier advances.
func TestObserveStaleOutOfOrderBatch(t *testing.T) {
	s := newTestStore(t)
	o, err := NewObserver(s)
	require.NoError(t, err)
	t1, t2, t3 := stTimes(t)

	_, err = o.ObserveEvent(context.Background(), "org-st2", stEvent(t3, "st-c"))
	require.NoError(t, err)
	rep, err := o.ObserveEvent(context.Background(), "org-st2", stEvent(t1, "st-d"))
	require.NoError(t, err)
	assert.Equal(t, ImportCounts{Unchanged: 3}, rep.Counts)
	rep, err = o.ObserveEvent(context.Background(), "org-st2", stEvent(t2, "st-e"))
	require.NoError(t, err)
	assert.Equal(t, ImportCounts{Unchanged: 3}, rep.Counts, "t2 < stored t3: still unchanged")

	row, ok, err := s.GetAsset(context.Background(), "org-st2", KindModel, observedModelKey("m-st"))
	require.NoError(t, err)
	require.True(t, ok)
	assert.True(t, row.LastSeen.Equal(t3))
}

// TestObserveStaleFirstSeenImmovable: across fresh and stale touches
// first_seen never moves in either direction — it stays the creation
// instant.
func TestObserveStaleFirstSeenImmovable(t *testing.T) {
	s := newTestStore(t)
	o, err := NewObserver(s)
	require.NoError(t, err)
	t1, t2, t3 := stTimes(t)

	_, err = o.ObserveEvent(context.Background(), "org-st3", stEvent(t1, "st-f"))
	require.NoError(t, err)
	for _, ts := range []time.Time{t3, t2} { // newer then older
		_, err = o.ObserveEvent(context.Background(), "org-st3", stEvent(ts, "req-"+ts.Format("15-04-05")))
		require.NoError(t, err)
	}
	row, ok, err := s.GetAsset(context.Background(), "org-st3", KindAgent, AgentKey("agent-st"))
	require.NoError(t, err)
	require.True(t, ok)
	assert.True(t, row.FirstSeen.Equal(t1), "first_seen is the creation instant, immovable")
	assert.True(t, row.LastSeen.Equal(t3))
}

// TestObserveStalePayloadWriteOnce: a later observation carrying different
// context cannot rewrite the creating observation's payload — identity
// fields of a row are set at creation only.
func TestObserveStalePayloadWriteOnce(t *testing.T) {
	s := newTestStore(t)
	o, err := NewObserver(s)
	require.NoError(t, err)
	t1, _, t3 := stTimes(t)

	_, err = o.ObserveEvent(context.Background(), "org-st4", stEvent(t1, "st-g"))
	require.NoError(t, err)
	// Same identities, different context on the wire.
	ev := stEvent(t3, "st-h")
	ev.SessionID = "sess-OTHER"
	ev.ModelUsed = "m-other"
	ev.UpstreamURL = "https://other.example"
	_, err = o.ObserveEvent(context.Background(), "org-st4", ev)
	require.NoError(t, err)

	row, ok, err := s.GetAsset(context.Background(), "org-st4", KindAgent, AgentKey("agent-st"))
	require.NoError(t, err)
	require.True(t, ok)
	var ao agentObservation
	require.NoError(t, json.Unmarshal(row.Payload, &ao))
	assert.Equal(t, "sess-1", ao.SessionID, "creating payload is frozen")
	assert.Equal(t, "https://up.example", ao.UpstreamURL)
	assert.True(t, ao.ObservedAt.Equal(t1))
	assert.True(t, row.LastSeen.Equal(t3), "but the touch still advances last_seen")
}

// TestObserveStaleTombstoneResurrectedByFreshObservation: a tombstoned
// observed identity resurrects on a NEW observation delivery (existence is
// the payload); a merely replayed old timestamp also clears the tombstone
// — an observation, however stale, attests existence.
func TestObserveStaleTombstoneResurrectedByFreshObservation(t *testing.T) {
	s := newTestStore(t)
	o, err := NewObserver(s)
	require.NoError(t, err)
	t1, t2, t3 := stTimes(t)

	_, err = o.ObserveEvent(context.Background(), "org-st5", stEvent(t1, "st-i"))
	require.NoError(t, err)
	_, err = s.TombstoneAssets(context.Background(), "org-st5", KindModel,
		t2, []string{observedModelKey("m-st")})
	require.NoError(t, err)

	_, err = o.ObserveEvent(context.Background(), "org-st5", stEvent(t3, "st-j"))
	require.NoError(t, err)
	row, ok, err := s.GetAsset(context.Background(), "org-st5", KindModel, observedModelKey("m-st"))
	require.NoError(t, err)
	require.True(t, ok)
	assert.False(t, row.Tombstone)
	assert.True(t, row.LastSeen.Equal(t3))
	assert.True(t, row.FirstSeen.Equal(t1), "resurrection keeps the original birth")
}

// TestObserveStaleClockSkewBackward: a producer clock running behind the
// registry (same shape as a late delivery, via secevents OccurredAt) is
// clamped by the SQL max-semantics, not by the observer process.
func TestObserveStaleClockSkewBackward(t *testing.T) {
	s := newTestStore(t)
	o, err := NewObserver(s)
	require.NoError(t, err)
	t1, _, t3 := stTimes(t)

	// Fresh observer per delivery: no in-memory state can mask the skew.
	o1, err := NewObserver(s)
	require.NoError(t, err)
	_, err = o1.ObserveEvent(context.Background(), "org-st6", stEvent(t3, "st-k"))
	require.NoError(t, err)
	rep, err := o.ObserveEvent(context.Background(), "org-st6", stEvent(t1, "st-l"))
	require.NoError(t, err)
	assert.Equal(t, ImportCounts{Unchanged: 3}, rep.Counts)

	// W05-C01: service keys are the canonical URL spelling — the empty
	// path of https://up.example normalizes to "/".
	row, ok, err := s.GetAsset(context.Background(), "org-st6", KindService, ServiceKey("https://up.example/"))
	require.NoError(t, err)
	require.True(t, ok)
	assert.True(t, row.LastSeen.Equal(t3))
}

// TestObserveStaleConcurrentObservers: concurrent observers delivering
// around one identity (same org) converge on the max last_seen with no
// lost rows and no corruption — the durability guarantee under -race.
func TestObserveStaleConcurrentObservers(t *testing.T) {
	s := newTestStore(t)
	base, _, _ := stTimes(t)

	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	observers := make([]*Observer, n)
	for i := range observers {
		o, err := NewObserver(s)
		require.NoError(t, err)
		observers[i] = o
	}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ts := base.Add(time.Duration(i) * time.Minute) // i minutes: 0..7
			reqID := "st-cc-" + strconv.Itoa(i)
			_, err := observers[i].ObserveEvent(context.Background(), "org-st7",
				stEvent(ts, reqID))
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	maxTS := base.Add(7 * time.Minute)
	for _, key := range []struct {
		kind AssetKind
		key  string
	}{
		{KindAgent, AgentKey("agent-st")},
		{KindModel, observedModelKey("m-st")},
		// W05-C01: canonical URL spelling (empty path ⇒ "/").
		{KindService, ServiceKey("https://up.example/")},
	} {
		row, ok, err := s.GetAsset(context.Background(), "org-st7", key.kind, key.key)
		require.NoError(t, err)
		require.True(t, ok, "concurrency must not lose the row %s", key.key)
		assert.True(t, row.LastSeen.Equal(maxTS), "%s: last_seen must be the max delivery", key.key)
	}
}
