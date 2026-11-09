package consumer

// N12-P02-T04 — the loggerd half of the failure-recovery surface. The
// consume loop already folds every buffer observation into the
// inter-process Redis signal (N10-P04-T02); these tests pin the NEW
// /metrics export on the same observation: the durable-buffer BACKLOG
// (depth gauge, -1 = unobserved) and its fail-closed saturation flag —
// visible across the whole outage→drain→recovery cycle to anyone scraping
// loggerd, not only to the gateway reading the TTL-expiring signal key.
//
// Saturation follows the gate's fail-closed contract exactly: a depth at
// or over the bound saturates, and an UNVERIFIABLE capacity (probe error —
// Redis down, DB down, disk full) saturates too, never reporting healthy
// on missing evidence.

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/metrics"
)

// TestHistoryBufferMetrics_TracksGateObservations: the export mirrors the
// gate's verdicts one-to-one — depth verbatim (including the disarmed -1),
// saturation exactly when the gate fails closed.
func TestHistoryBufferMetrics_TracksGateObservations(t *testing.T) {
	ctx := context.Background()
	c := New(&mockRedis{}, &mockDB{}, "events:queue", slog.New(slog.DiscardHandler))

	// Disarmed gate: the consume loop evaluates no-op and exports the
	// unobserved state — -1 depth, never mistaken for an empty buffer.
	gateErr := c.bufferGate.Evaluate(ctx) // nil gate: no-op
	c.exportHistoryBufferMetrics(gateErr, c.bufferGate.Depth())
	assert.InDelta(t, -1, testutil.ToFloat64(metrics.HistoryBufferDepth), 1e-9,
		"an unobserved buffer must export -1, never 0 (=empty)")
	assert.InDelta(t, 0, testutil.ToFloat64(metrics.HistoryBufferSaturated), 1e-9)

	// Armed gate, healthy drain: depth visible, not saturated.
	p := &fakeProber{depth: 7}
	c.SetHistoryBufferGate(NewHistoryBufferGate(p, "events:queue", 100, slog.New(slog.DiscardHandler)))
	gateErr = c.bufferGate.Evaluate(ctx)
	require.NoError(t, gateErr)
	c.exportHistoryBufferMetrics(gateErr, c.bufferGate.Depth())
	assert.InDelta(t, 7, testutil.ToFloat64(metrics.HistoryBufferDepth), 1e-9)
	assert.InDelta(t, 0, testutil.ToFloat64(metrics.HistoryBufferSaturated), 1e-9)

	// Backlog grows past the bound: saturated, depth verbatim.
	p.set(150, nil)
	gateErr = c.bufferGate.Evaluate(ctx)
	require.ErrorIs(t, gateErr, ErrHistoryBufferFull)
	c.exportHistoryBufferMetrics(gateErr, c.bufferGate.Depth())
	assert.InDelta(t, 150, testutil.ToFloat64(metrics.HistoryBufferDepth), 1e-9)
	assert.InDelta(t, 1, testutil.ToFloat64(metrics.HistoryBufferSaturated), 1e-9,
		"a backlog at/over the bound is the fail-closed signal")

	// Probe FAILURE (unverifiable capacity — Redis/DB/disk outage): the
	// gate fails closed keeping the last KNOWN depth untouched (it cannot
	// verify a fresh one, so it never fabricates one), and the export must
	// not report healthy.
	p.set(3, errors.New("xlen: i/o timeout"))
	gateErr = c.bufferGate.Evaluate(ctx)
	require.Error(t, gateErr)
	c.exportHistoryBufferMetrics(gateErr, c.bufferGate.Depth())
	assert.InDelta(t, 150, testutil.ToFloat64(metrics.HistoryBufferDepth), 1e-9,
		"the depth gauge shows the last known observation — never a fabricated fresh one")
	assert.InDelta(t, 1, testutil.ToFloat64(metrics.HistoryBufferSaturated), 1e-9,
		"an unverifiable capacity counts as saturated, never healthy")

	// Recovery: the outage clears, the backlog drains below the bound —
	// the gauges show the drain to recovery (I44: the cycle is visible).
	p.set(2, nil)
	gateErr = c.bufferGate.Evaluate(ctx)
	require.NoError(t, gateErr)
	c.exportHistoryBufferMetrics(gateErr, c.bufferGate.Depth())
	assert.InDelta(t, 2, testutil.ToFloat64(metrics.HistoryBufferDepth), 1e-9)
	assert.InDelta(t, 0, testutil.ToFloat64(metrics.HistoryBufferSaturated), 1e-9)
}

// TestHistoryBufferMetrics_DisarmResets: disarming the gate must drop the
// export back to the unobserved pair (-1 depth, not saturated) — a torn
// down consumer must not leave a stale healthy/depth impression on the
// next scrape of a fresh process.
func TestHistoryBufferMetrics_DisarmResets(t *testing.T) {
	ctx := context.Background()
	c := New(&mockRedis{}, &mockDB{}, "events:queue", slog.New(slog.DiscardHandler))
	c.SetHistoryBufferGate(NewHistoryBufferGate(&fakeProber{depth: 42}, "events:queue", 100, slog.New(slog.DiscardHandler)))

	gateErr := c.bufferGate.Evaluate(ctx)
	require.NoError(t, gateErr)
	c.exportHistoryBufferMetrics(gateErr, c.bufferGate.Depth())
	assert.InDelta(t, 42, testutil.ToFloat64(metrics.HistoryBufferDepth), 1e-9)

	c.SetHistoryBufferGate(nil)
	gateErr = c.bufferGate.Evaluate(ctx)
	require.NoError(t, gateErr)
	c.exportHistoryBufferMetrics(gateErr, c.bufferGate.Depth())
	assert.InDelta(t, -1, testutil.ToFloat64(metrics.HistoryBufferDepth), 1e-9)
	assert.InDelta(t, 0, testutil.ToFloat64(metrics.HistoryBufferSaturated), 1e-9)
}
