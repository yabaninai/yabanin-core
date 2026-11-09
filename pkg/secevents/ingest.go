// Idempotent ingest (E01-P03-W05).
//
// Delivery into the security store is at-least-once: DLQ replays (see
// pkg/eventpublisher DLQEnvelope), consumer restarts and upstream retries
// can redeliver the same event. The packet acceptance invariant is:
//
//	redelivery does not double-count events; timestamp skew and
//	unknown cost never collapse into success or zero.
//
// The Ingester enforces it:
//
//   - deduplication is keyed by the (org, event_id) pair — an explicit
//     EventID or a deterministic adapter-derived id; a redelivery is
//     reported as OutcomeDuplicate and the sink sees it exactly once;
//   - the sink is invoked while the dedup lock is held, so concurrent
//     deliveries of the same event still record exactly one copy;
//   - deduplication state is per instance: a redelivery after a restart
//     or a delivery to a second ingester instance reaches the sink again
//     (AUD-EVENT-01 reproduced the double-record with an append-only
//     sink). Exact-once durability across restarts and instances is
//     therefore enforced by the sink, not by the Ingester: DurableSink
//     (durable.go) commits the document and the dedup decision in a
//     single statement (INSERT ... ON CONFLICT DO NOTHING), so every
//     retry and every instance converges to one durable JSON document;
//   - a sink failure does NOT mark the event as seen: the next delivery
//     attempt retries the record (at-least-once into the sink; a durable
//     sink converges every retry to the single committed document);
//   - skew is returned verbatim as receivedAt - OccurredAt (it may be
//     negative) and the sink always receives the producer timestamp —
//     delivery delay never rebases event time, and skew never flips an
//     event to invalid;
//   - the cost dimension is propagated with its state: an unknown cost
//     stays unknown, it is never converted to a zero/known value.

package secevents

import (
	"fmt"
	"sync"
	"time"
)

// IngestOutcome is the dedup decision for one delivery attempt.
type IngestOutcome string

const (
	// OutcomeRecorded is reported when the event was new to this ingester
	// and the sink recorded it.
	OutcomeRecorded IngestOutcome = "recorded"
	// OutcomeDuplicate is reported when the same (org, event_id) pair was
	// recorded before — a redelivery; the sink is not called again.
	OutcomeDuplicate IngestOutcome = "duplicate"
)

// IngestResult reports what one delivery attempt did, including the
// preserved skew and cost semantics.
type IngestResult struct {
	// Outcome is the dedup decision.
	Outcome IngestOutcome
	// Skew is receivedAt - OccurredAt, verbatim (may be negative). It is
	// reported, never clamped and never used to rebase the event.
	Skew time.Duration
	// Cost is the event's cost dimension with its state: unknown stays
	// unknown, known carries its value (0 = known-free), none = N/A.
	Cost Cost
}

// Sink is the consumer-provided recorder of security events.
type Sink interface {
	// Record persists one event. A returned error aborts the ingest
	// without marking the event as seen.
	Record(Event) error
}

// SinkFunc adapts a function to Sink.
type SinkFunc func(Event) error

// Record implements Sink.
func (f SinkFunc) Record(e Event) error { return f(e) }

// Ingester is the idempotent front door of the security store.
type Ingester struct {
	mu   sync.Mutex
	seen map[string]struct{}
	sink Sink
}

// NewIngester wraps sink with redelivery deduplication.
func NewIngester(sink Sink) *Ingester {
	return &Ingester{seen: make(map[string]struct{}), sink: sink}
}

// dedupKey scopes deduplication per organization: the same EventID in two
// orgs is two events, not a collision.
func dedupKey(e Event) string {
	return e.OrgID + "\x00" + e.EventID
}

// Ingest delivers one event. receivedAt is the consumer-side reception
// time and must be non-zero (it anchors the reported skew).
func (i *Ingester) Ingest(e Event, receivedAt time.Time) (IngestResult, error) {
	if err := e.Validate(); err != nil {
		return IngestResult{}, fmt.Errorf("secevents: ingest: %w", err)
	}
	if receivedAt.IsZero() {
		return IngestResult{}, fmt.Errorf("secevents: ingest: receivedAt must be set")
	}
	skew := receivedAt.Sub(e.OccurredAt)
	key := dedupKey(e)

	i.mu.Lock()
	defer i.mu.Unlock()
	if _, isDup := i.seen[key]; isDup {
		return IngestResult{Outcome: OutcomeDuplicate, Skew: skew, Cost: e.Cost}, nil
	}
	if err := i.sink.Record(e); err != nil {
		// Not marked seen: the redelivery may retry into a healthy sink.
		return IngestResult{}, fmt.Errorf("secevents: ingest: sink: %w", err)
	}
	i.seen[key] = struct{}{}
	return IngestResult{Outcome: OutcomeRecorded, Skew: skew, Cost: e.Cost}, nil
}

// Recorded reports whether the (org, event_id) pair has been recorded.
func (i *Ingester) Recorded(e Event) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	_, ok := i.seen[dedupKey(e)]
	return ok
}
