package lineage

import (
	"context"
	"log/slog"
	"time"
)

// AsyncLedger is the lineage intake surface used by the gateway.
//
// L02 (durable evidence, the L01 decision): Append writes the attestation into
// the lineage_outbox table — durable once it returns nil, lossless across hard
// kills and restarts. A background relay consumer (Outbox.RelayLoop) moves
// pending outbox rows into request_lineage; it is the single chained-row
// writer and is idempotent on request_id.
//
// The previous design (in-memory channel + batch writer) is superseded: an
// in-memory queue loses up to its capacity on a hard kill, which is
// unacceptable for evidence. The outbox INSERT is the accepted +1 round-trip
// on the request path.
type AsyncLedger struct {
	outbox *Outbox
	log    *slog.Logger
	cancel context.CancelFunc
	done   chan struct{}
}

// NewAsyncLedger starts the background relay consumer bound to ctx. When ctx
// is cancelled the relay drains one final pass before exiting.
func NewAsyncLedger(store *LedgerStore, l *slog.Logger, ctx context.Context) *AsyncLedger {
	return newAsyncLedgerWithOutbox(NewOutbox(store.pool, l), l, ctx)
}

// newAsyncLedgerWithOutbox is the constructor core, shared with tests so the
// relay can be driven against a fake database handle.
func newAsyncLedgerWithOutbox(ob *Outbox, l *slog.Logger, ctx context.Context) *AsyncLedger {
	runCtx, cancel := context.WithCancel(ctx)
	al := &AsyncLedger{
		outbox: ob,
		log:    l,
		cancel: cancel,
		done:   make(chan struct{}),
	}
	go func() {
		defer close(al.done)
		ob.RelayLoop(runCtx, 500*time.Millisecond)
	}()
	return al
}

// Append records an attestation durably: the row is committed to the outbox
// before this returns (nil = durable). The background relay moves it into
// request_lineage. A DB failure returns an error — evidence is never silently
// dropped.
func (al *AsyncLedger) Append(ctx context.Context, att Attestation, sigB64, keyID string) error {
	return al.outbox.Enqueue(ctx, att, sigB64, keyID)
}

// Close stops the relay loop (triggering one final drain pass) and waits up to
// timeout for it to finish. Call after server shutdown.
func (al *AsyncLedger) Close(timeout time.Duration) {
	al.cancel()
	select {
	case <-al.done:
	case <-time.After(timeout):
		al.log.Warn("lineage outbox relay did not stop in time")
	}
}
