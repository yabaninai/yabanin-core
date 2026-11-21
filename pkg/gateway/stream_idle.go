package cli

import (
	"io"
	"sync/atomic"
	"time"
)

// idleReader watches an upstream stream body for silence: when no bytes
// arrive for d, onIdle runs (serveStream cancels the stream context, which
// aborts the upstream read). Every read that delivers bytes pushes the
// deadline back, so slow-but-alive streams are never aborted.
type idleReader struct {
	r     io.Reader
	d     time.Duration
	timer *time.Timer
	fired atomic.Bool
}

// newIdleReader arms the watchdog immediately; Stop disarms it at drain end.
// The callback is exactly-once: Timer.Reset on an already-expired AfterFunc
// timer re-arms the callback (Go timer contract), so without the CAS guard a
// reader that keeps flowing after one legitimate fire can trigger a second
// onIdle run — the CI run 44814334185 double-close panic came from exactly
// that second run (close of the same "fired" channel twice).
func newIdleReader(r io.Reader, d time.Duration, onIdle func()) *idleReader {
	ir := &idleReader{r: r, d: d}
	ir.timer = time.AfterFunc(d, func() {
		if !ir.fired.CompareAndSwap(false, true) {
			return
		}
		if onIdle != nil {
			onIdle()
		}
	})
	return ir
}

func (ir *idleReader) Read(p []byte) (int, error) {
	n, err := ir.r.Read(p)
	// Once fired, stop re-arming: Reset would schedule a fresh callback run
	// for a watchdog that already did its job (see newIdleReader).
	if n > 0 && !ir.fired.Load() {
		ir.timer.Reset(ir.d)
	}
	return n, err
}

// Stop disarms the watchdog — a drain that ended normally must not report
// an idle abort.
func (ir *idleReader) Stop() { _ = ir.timer.Stop() }

// Fired reports whether the watchdog fired at least once.
func (ir *idleReader) Fired() bool { return ir.fired.Load() }
