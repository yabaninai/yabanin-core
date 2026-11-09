package secevents

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// recordingSink counts sink invocations and keeps the recorded events.
type recordingSink struct {
	mu     sync.Mutex
	events []Event
	failN  int // fail the first N Record calls
}

func (s *recordingSink) Record(e Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failN > 0 {
		s.failN--
		return errors.New("sink unavailable")
	}
	s.events = append(s.events, e)
	return nil
}

func (s *recordingSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

func TestIngestRedeliveryDoesNotDoubleCount(t *testing.T) {
	sink := &recordingSink{}
	ing := NewIngester(sink)
	ev := validEvent()

	res, err := ing.Ingest(ev, anchorOcc.Add(30*time.Second))
	if err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	if res.Outcome != OutcomeRecorded {
		t.Fatalf("first outcome = %q", res.Outcome)
	}

	// Redelivery: the exact same event again.
	res, err = ing.Ingest(ev, anchorOcc.Add(31*time.Second))
	if err != nil {
		t.Fatalf("redelivery ingest: %v", err)
	}
	if res.Outcome != OutcomeDuplicate {
		t.Fatalf("redelivery outcome = %q, want duplicate", res.Outcome)
	}
	if sink.count() != 1 {
		t.Fatalf("sink saw %d events, want exactly 1 (redelivery must not double-count)", sink.count())
	}

	// Replay fidelity: the redelivered bytes decode to an equal event and
	// dedup still holds (the DLQ replay path).
	wireBytes := mustEncode(t, ev)
	decoded, _, err := Decode(wireBytes)
	if err != nil {
		t.Fatalf("replay decode: %v", err)
	}
	res, err = ing.Ingest(decoded, anchorOcc.Add(32*time.Second))
	if err != nil {
		t.Fatalf("replay ingest: %v", err)
	}
	if res.Outcome != OutcomeDuplicate || sink.count() != 1 {
		t.Fatalf("replay: outcome=%q sink=%d, want duplicate/1", res.Outcome, sink.count())
	}
}

func TestIngestCrossOrgSameEventIDBothRecorded(t *testing.T) {
	sink := &recordingSink{}
	ing := NewIngester(sink)
	orgA, orgB := validEvent(), validEvent()
	orgB.OrgID = "org-2"

	for _, ev := range []Event{orgA, orgB} {
		res, err := ing.Ingest(ev, anchorReceived)
		if err != nil {
			t.Fatalf("ingest %s: %v", ev.OrgID, err)
		}
		if res.Outcome != OutcomeRecorded {
			t.Fatalf("org %s outcome = %q, want recorded (dedup key must be org-scoped)", ev.OrgID, res.Outcome)
		}
	}
	if sink.count() != 2 {
		t.Fatalf("sink saw %d events, want 2", sink.count())
	}
}

// M4 anchor: skew is preserved verbatim and never rebases the event —
// the sink receives the producer timestamp whatever the delivery delay.
func TestIngestSkewPreservedNeverClamped(t *testing.T) {
	sink := &recordingSink{}
	ing := NewIngester(sink)

	t.Run("late_delivery", func(t *testing.T) {
		ev := validEvent()
		res, err := ing.Ingest(ev, anchorOcc.Add(90*time.Second))
		if err != nil || res.Outcome != OutcomeRecorded {
			t.Fatalf("late delivery must not be rejected: res=%+v err=%v", res, err)
		}
		if res.Skew != 90*time.Second {
			t.Fatalf("Skew = %v, want exactly 90s", res.Skew)
		}
		if !sink.events[0].OccurredAt.Equal(anchorOcc) {
			t.Fatalf("sink got OccurredAt %v, want producer time %v (no rebase)", sink.events[0].OccurredAt, anchorOcc)
		}
	})
	t.Run("negative_skew_kept", func(t *testing.T) {
		ev := validEvent()
		ev.EventID = "01JKLA-security-0002"
		res, err := ing.Ingest(ev, anchorOcc.Add(-5*time.Second))
		if err != nil || res.Outcome != OutcomeRecorded {
			t.Fatalf("future-dated event must not be rejected: res=%+v err=%v", res, err)
		}
		if res.Skew != -5*time.Second {
			t.Fatalf("Skew = %v, want exactly -5s (no clamping)", res.Skew)
		}
	})
}

// M3 anchor: an unknown cost survives the whole ingest path as unknown —
// it never becomes a zero or known value.
func TestIngestUnknownCostStaysUnknown(t *testing.T) {
	sink := &recordingSink{}
	ing := NewIngester(sink)
	ev := validEvent() // Cost{State: CostUnknown}

	res, err := ing.Ingest(ev, anchorReceived)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if res.Cost.State != CostUnknown {
		t.Fatalf("result cost = %+v, want unknown state", res.Cost)
	}
	recorded := sink.events[0]
	if recorded.Cost.State != CostUnknown || recorded.Cost.MicroUSD != 0 {
		t.Fatalf("recorded cost = %+v, want {unknown, 0} — the sink must be able to distinguish unknown from known-zero", recorded.Cost)
	}
}

func TestIngestSinkErrorAllowsRetry(t *testing.T) {
	sink := &recordingSink{failN: 1}
	ing := NewIngester(sink)
	ev := validEvent()

	if _, err := ing.Ingest(ev, anchorReceived); err == nil {
		t.Fatalf("expected sink error to propagate")
	}
	if sink.count() != 0 {
		t.Fatalf("failed attempt must not record")
	}
	// Retry after the sink recovered: must be recorded, not treated as a
	// duplicate of the failed attempt.
	res, err := ing.Ingest(ev, anchorReceived)
	if err != nil || res.Outcome != OutcomeRecorded {
		t.Fatalf("retry: res=%+v err=%v, want recorded", res, err)
	}
	if sink.count() != 1 {
		t.Fatalf("sink saw %d events after retry, want 1", sink.count())
	}
}

func TestIngestValidationGates(t *testing.T) {
	sink := &recordingSink{}
	ing := NewIngester(sink)

	t.Run("invalid_event_rejected", func(t *testing.T) {
		ev := validEvent()
		ev.Cost = Cost{State: CostUnknown, MicroUSD: 5}
		if _, err := ing.Ingest(ev, anchorReceived); !errors.Is(err, ErrInvalidEvent) {
			t.Fatalf("err = %v, want ErrInvalidEvent", err)
		}
		if sink.count() != 0 {
			t.Fatalf("invalid event must not reach the sink")
		}
	})
	t.Run("zero_received_rejected", func(t *testing.T) {
		ev := validEvent()
		ev.EventID = "another-id"
		if _, err := ing.Ingest(ev, time.Time{}); err == nil {
			t.Fatalf("zero receivedAt must be rejected (skew anchoring)")
		}
	})
}

// Concurrency: N simultaneous deliveries of the same event record exactly
// one copy (the dedup lock is held across the sink call).
func TestIngestConcurrentSameEventExactlyOnce(t *testing.T) {
	sink := &recordingSink{}
	ing := NewIngester(sink)
	ev := validEvent()

	const n = 8
	var wg sync.WaitGroup
	results := make([]IngestResult, n)
	errs := make([]error, n)
	for k := 0; k < n; k++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			results[k], errs[k] = ing.Ingest(ev, anchorReceived.Add(time.Duration(k)*time.Second))
		}(k)
	}
	wg.Wait()

	recorded, duplicated := 0, 0
	for k := 0; k < n; k++ {
		if errs[k] != nil {
			t.Fatalf("goroutine %d: %v", k, errs[k])
		}
		switch results[k].Outcome {
		case OutcomeRecorded:
			recorded++
		case OutcomeDuplicate:
			duplicated++
		default:
			t.Fatalf("goroutine %d: outcome %q", k, results[k].Outcome)
		}
	}
	if recorded != 1 || duplicated != n-1 {
		t.Fatalf("recorded=%d duplicated=%d, want exactly 1 recorded and %d duplicates", recorded, duplicated, n-1)
	}
	if sink.count() != 1 {
		t.Fatalf("sink saw %d events under concurrency, want exactly 1", sink.count())
	}
}

// End-to-end acceptance chain (W04+W05): a core event delivered twice
// (original + DLQ-style replay) adapts to the same security events, and
// the ingester records each finding exactly once.
func TestEndToEndCoreReplayDoesNotDoubleCount(t *testing.T) {
	sink := &recordingSink{}
	ing := NewIngester(sink)
	adapter := CoreAdapter{}

	for attempt := 1; attempt <= 2; attempt++ {
		events, err := adapter.AdaptPublisherEvent(coreEvent(policyRecord), anchorReceived)
		if err != nil {
			t.Fatalf("attempt %d: adapt: %v", attempt, err)
		}
		if len(events) != 3 {
			t.Fatalf("attempt %d: events = %d", attempt, len(events))
		}
		for i, ev := range events {
			res, err := ing.Ingest(ev, anchorReceived.Add(time.Duration(attempt)*time.Minute))
			if err != nil {
				t.Fatalf("attempt %d event %d: ingest: %v", attempt, i, err)
			}
			want := OutcomeRecorded
			if attempt == 2 {
				want = OutcomeDuplicate
			}
			if res.Outcome != want {
				t.Fatalf("attempt %d event %d: outcome = %q, want %q", attempt, i, res.Outcome, want)
			}
		}
	}
	if sink.count() != 3 {
		t.Fatalf("sink saw %d events, want exactly 3 (one per finding across the replay)", sink.count())
	}
}

// Recorded() reflects the dedup state (diagnostics helper); SinkFunc is
// exercised as the sink adapter.
func TestRecordedQuery(t *testing.T) {
	var calls int
	sink := SinkFunc(func(Event) error { calls++; return nil })
	ing := NewIngester(sink)
	ev := validEvent()
	if ing.Recorded(ev) {
		t.Fatalf("unknown event reported as recorded")
	}
	if _, err := ing.Ingest(ev, anchorReceived); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if calls != 1 {
		t.Fatalf("SinkFunc called %d times, want 1", calls)
	}
	if !ing.Recorded(ev) {
		t.Fatalf("recorded event not found")
	}
}

// Compile-time interface guards.
var _ Sink = (*recordingSink)(nil)
