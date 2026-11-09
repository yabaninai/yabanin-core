// History admission signal publisher (N10-P04-T03; owner decisions I40/I44).
//
// loggerd owns the only direct view of the durable-history path (the T02
// HistoryBufferGate and its own Redis/store writes), but the admission
// policy lives in the gateway process. This file is the inter-process seam:
// the consumer folds every durability observation into one Redis key —
// budget.HistorySignalKey(stream) — as a TTL-heartbeated JSON payload the
// gateway's budget.RedisHistoryProbe reads (pkg/budget/admission_history.go).
//
// State priority (worst wins): a durable WRITE outage (Postgres unreachable,
// the pauseForOutage path) outranks a saturated buffer, which outranks ok.
// The write-outage latch is cleared only by a successful delivery; the next
// gate observation heartbeats the recovered state, so a stale outage signal
// can over-signal for at most one consume iteration — the safe direction.
//
// Every publish failure is loud but never fatal to consumption: losing the
// signal must not take delivery down with it (the gateway fails CLOSED on
// an unreadable signal under the default reject policy, so silence here is
// never silently exploited).
package consumer

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/reireirei/yabanin/pkg/budget"
)

// HistorySignalWriter is the minimal Redis surface the publisher needs;
// *redis.Client (and the production redisXAckWrapper) satisfy it. Test
// mocks without Set leave the publisher disarmed — zero behavior change.
type HistorySignalWriter interface {
	Set(ctx context.Context, key string, value any, expiration time.Duration) *redis.StatusCmd
}

// historySignalTTL is the heartbeat lease: the gateway treats a missing or
// expired key as "loggerd down, durable stream intact" (admission stays
// open unless the direct depth check saturates). It must comfortably exceed
// the once-per-iteration heartbeat cadence.
const historySignalTTL = 15 * time.Second

// HistorySignalPublisher folds durability observations into the
// budget.HistorySignal payload and heartbeats it to Redis. Safe for
// concurrent use; nil-receiver safe (disarmed).
type HistorySignalPublisher struct {
	writer HistorySignalWriter
	key    string
	logger *slog.Logger
	ttl    time.Duration

	mu            sync.Mutex
	dbDown        bool
	lastGateErr   error
	lastDepth     int64
	desired       budget.HistoryState // recomputed each publish
	lastPublished budget.HistoryState // last state successfully written ("" = none)
	failLogged    bool                // one loud Warn per publish-failure run
}

// NewHistorySignalPublisher builds a publisher for one stream. writer nil =
// disarmed.
func NewHistorySignalPublisher(writer HistorySignalWriter, stream string, log *slog.Logger) *HistorySignalPublisher {
	if log == nil {
		log = slog.Default()
	}
	return &HistorySignalPublisher{
		writer: writer,
		key:    budget.HistorySignalKey(stream),
		logger: log,
		ttl:    historySignalTTL,
	}
}

// ObserveGate folds one HistoryBufferGate evaluation (per consume
// iteration) into the signal and heartbeats it. A gate error that is not
// ErrHistoryBufferFull still maps to buffer_full: an unverifiable capacity
// must not be advertised as healthy.
func (p *HistorySignalPublisher) ObserveGate(ctx context.Context, gateErr error, depth int64) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.lastGateErr = gateErr
	p.lastDepth = depth
	p.mu.Unlock()
	p.publish(ctx)
}

// ObserveWriteOutage latches a durable-write outage (the pauseForOutage
// path: the store refused a write, so buffered events are no longer being
// durably appended) and republishes immediately.
func (p *HistorySignalPublisher) ObserveWriteOutage(ctx context.Context) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.dbDown = true
	p.mu.Unlock()
	p.publish(ctx)
}

// ClearWriteOutage drops the write-outage latch after a successful durable
// delivery. It deliberately does NOT publish: the next gate observation
// heartbeats the recovered state within one consume iteration, and a
// stale outage signal in between is the safe direction.
func (p *HistorySignalPublisher) ClearWriteOutage() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.dbDown = false
	p.mu.Unlock()
}

// desired computes the worst observed state.
func (p *HistorySignalPublisher) desiredState() budget.HistoryState {
	if p.dbDown {
		return budget.HistoryStateWriteUnavailable
	}
	if p.lastGateErr != nil {
		// Conservative: any gate failure (saturation or probe error) means
		// the buffer cannot currently be trusted to have spare capacity.
		return budget.HistoryStateBufferFull
	}
	return budget.HistoryStateOK
}

// publish recomputes the desired state and writes the payload. Transition
// logs fire once per state change on a successful write; a failed write
// logs one loud Warn per failure run (reset on success or state change).
func (p *HistorySignalPublisher) publish(ctx context.Context) {
	if p == nil || p.writer == nil {
		return
	}
	p.mu.Lock()
	desired := p.desiredState()
	p.desired = desired
	payload := budget.HistorySignal{
		State:   desired,
		Detail:  p.detail(desired),
		Depth:   p.lastDepth,
		UnixSec: time.Now().Unix(),
	}
	p.mu.Unlock()

	raw, err := budget.EncodeHistorySignal(payload)
	if err != nil { // unreachable for these field types, but stay honest
		p.logger.Error("history admission signal encode failed", slog.String("error", err.Error()))
		return
	}
	if err := p.writer.Set(ctx, p.key, string(raw), p.ttl).Err(); err != nil {
		p.mu.Lock()
		quiet := p.failLogged
		p.failLogged = true
		p.mu.Unlock()
		if !quiet {
			p.logger.Warn("history admission signal publish FAILED — gateway will fail closed under the default reject policy",
				slog.String("key", p.key),
				slog.String("desired_state", string(desired)),
				slog.String("error", err.Error()),
			)
		}
		return
	}

	p.mu.Lock()
	prev := p.lastPublished
	p.lastPublished = desired
	p.failLogged = false
	p.mu.Unlock()
	if prev == desired {
		return // heartbeat of a steady state: silent
	}
	switch {
	case prev == "" && desired == budget.HistoryStateOK:
		p.logger.Info("history admission signal armed: durable history healthy",
			slog.String("key", p.key))
	case desired == budget.HistoryStateOK:
		p.logger.Info("history admission signal cleared: durable history healthy again",
			slog.String("key", p.key), slog.String("previous_state", string(prev)))
	default:
		p.logger.Warn("history admission signal raised: durable history degraded",
			slog.String("key", p.key),
			slog.String("state", string(desired)),
			slog.String("previous_state", string(prev)),
		)
	}
}

// detail returns the short operator-facing cause carried in the payload.
func (p *HistorySignalPublisher) detail(state budget.HistoryState) string {
	switch state {
	case budget.HistoryStateWriteUnavailable:
		return "durable write unavailable (store outage)"
	case budget.HistoryStateBufferFull:
		if p.lastGateErr != nil {
			return p.lastGateErr.Error()
		}
		return "history buffer saturated"
	default:
		return ""
	}
}
