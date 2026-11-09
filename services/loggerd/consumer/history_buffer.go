package consumer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/redis/go-redis/v9"
)

// N10-P04-T02 (durable history, outbox, admission choice; owner decisions
// I40/I44): the Redis stream `events:queue` is the bounded durable history
// buffer that survives restart. Its producer-side bound is approximate
// (XADD MAXLEN ~1M, pkg/eventpublisher) — at saturation the oldest entries
// are evicted silently, which is exactly the "full buffer turns into a
// quiet successful save" outcome the packet forbids. I40 requires the
// opposite: when the buffer cannot accept history durably, new requests are
// rejected by default (the continue-serving mode is an explicit, separate
// setting owned by N10-P04-T03).
//
// HistoryBufferGate is the consumer-side backpressure signal over that
// buffer: it measures the buffer depth once per consume-loop iteration and
// reports ErrHistoryBufferFull while the depth is at/over the bound. The
// signal is advisory until T03 wires it into admission — consuming never
// stops on saturation (draining the backlog is the way out of it), and no
// existing admission behavior changes until an enforcement point consults
// the gate. The bound is deliberately conservative: XLEN counts every entry
// still in the stream, including already-acked ones below the consumer
// group's read horizon, so the gate trips earlier than the eviction horizon
// rather than later — under uncertainty the gate may only ever reject more,
// never silently admit more (I40 direction).

// ErrHistoryBufferFull is the backpressure sentinel returned by
// HistoryBufferGate.Evaluate when the durable history buffer is saturated
// (or its capacity cannot be verified). Callers must treat it with
// errors.Is; the default admission policy for this signal is reject (I40).
var ErrHistoryBufferFull = errors.New("history buffer full")

// DefaultHistoryBufferMaxEntries is the default buffer bound. The producer
// trims the stream at ~1M entries (approximate MAXLEN in
// pkg/eventpublisher); the gate trips at half of that so the loud
// backpressure signal fires before the silent-eviction zone is reachable.
const DefaultHistoryBufferMaxEntries = 500_000

// BufferProber is the capacity-probe surface of the durable buffer. The
// production RedisOps adapter (*redis.Client via redisXAckWrapper) satisfies
// it natively; test mocks that do not implement XLen simply leave the gate
// disarmed (zero behavior change).
type BufferProber interface {
	XLen(ctx context.Context, stream string) *redis.IntCmd
}

// HistoryBufferGate tracks the durable history buffer's depth against a
// bound with hysteresis and turns saturation into the ErrHistoryBufferFull
// backpressure signal plus a loud log transition. State transitions are
// logged exactly once (Warn on saturation, Info on recovery) so a saturated
// buffer is observable in operations logs without log spam at one probe per
// consume iteration.
//
// Probe failures are fail-closed (I40): a capacity that cannot be verified
// is reported as ErrHistoryBufferFull, never as a silent "all clear" — an
// unreachable Redis is precisely the outage in which history cannot be
// acknowledged durably.
type HistoryBufferGate struct {
	prober BufferProber
	stream string
	logger *slog.Logger

	// maxEntries is the saturation bound; recoverEntries is the depth at
	// which saturation clears (hysteresis, 90% of the bound) so the signal
	// does not flap when the depth oscillates around the bound.
	maxEntries     int64
	recoverEntries int64

	mu        sync.Mutex
	saturated bool
	depth     int64
}

// NewHistoryBufferGate builds a gate over prober/stream with the given
// bound. A nil prober or a non-positive bound disarms the gate: Evaluate
// then always reports healthy capacity and nothing else changes — an
// unmeasurable buffer must not fabricate a saturation signal.
func NewHistoryBufferGate(prober BufferProber, stream string, maxEntries int64, logger *slog.Logger) *HistoryBufferGate {
	if logger == nil {
		logger = slog.Default()
	}
	g := &HistoryBufferGate{
		prober: prober,
		stream: stream,
		logger: logger,
		depth:  -1, // no observation yet
	}
	if maxEntries > 0 {
		g.maxEntries = maxEntries
		g.recoverEntries = maxEntries - maxEntries/10 // 90% hysteresis floor
	}
	return g
}

// Evaluate probes the buffer depth once and returns ErrHistoryBufferFull
// while the gate is saturated. It never blocks consumption and never fails:
// the consume loop calls it every iteration and ignores the result — the
// signal exists for the admission policy (N10-P04-T03) and operations.
func (g *HistoryBufferGate) Evaluate(ctx context.Context) error {
	if g == nil || g.prober == nil || g.maxEntries <= 0 {
		return nil // disarmed
	}

	depth, err := g.prober.XLen(ctx, g.stream).Result()
	if err != nil {
		g.transition(true)
		return fmt.Errorf("%w (capacity probe failed: %v)", ErrHistoryBufferFull, err)
	}

	g.mu.Lock()
	g.depth = depth
	wasSaturated := g.saturated
	g.mu.Unlock()

	switch {
	case depth >= g.maxEntries:
		g.transition(true)
		return fmt.Errorf("%w (depth=%d max=%d)", ErrHistoryBufferFull, depth, g.maxEntries)
	case wasSaturated && depth <= g.recoverEntries:
		g.transition(false)
	}

	g.mu.Lock()
	saturated := g.saturated
	g.mu.Unlock()
	if saturated {
		// Between the recover floor and the bound: hold the backpressure
		// signal (hysteresis — no flapping, no fresh log).
		return fmt.Errorf("%w (depth=%d max=%d, above recover floor %d)", ErrHistoryBufferFull, depth, g.maxEntries, g.recoverEntries)
	}
	return nil
}

// transition records a saturated-state change and logs it exactly once per
// transition. Fail-closed probe errors saturate the gate with the last
// known depth untouched — the sentinel carries the probe failure instead.
func (g *HistoryBufferGate) transition(saturated bool) {
	g.mu.Lock()
	changed := g.saturated != saturated
	g.saturated = saturated
	depth := g.depth
	g.mu.Unlock()

	if !changed {
		return
	}
	if saturated {
		g.logger.Warn("history buffer saturated — backpressure signal active (I40: default admission policy is reject)",
			slog.String("stream", g.stream),
			slog.Int64("depth", depth),
			slog.Int64("max_entries", g.maxEntries),
		)
		return
	}
	g.logger.Info("history buffer recovered — backpressure signal cleared",
		slog.String("stream", g.stream),
		slog.Int64("depth", depth),
		slog.Int64("recover_floor", g.recoverEntries),
	)
}

// Saturated reports whether the gate currently holds the backpressure
// signal. Safe for concurrent admission-policy readers (T03).
func (g *HistoryBufferGate) Saturated() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.saturated
}

// Depth reports the last observed buffer depth (-1 = no observation yet).
func (g *HistoryBufferGate) Depth() int64 {
	if g == nil {
		return -1
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.depth
}
