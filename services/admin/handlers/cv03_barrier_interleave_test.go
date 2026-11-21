//go:build integration

package handlers

// Deterministic interleave fixtures for the CV-03 barrier's honest outcome
// counters (the reviewer's cancel/release race, reproduced locally):
//
//	cancel() BEFORE Release(), with the parking goroutine not yet
//	rescheduled to deregister itself, must still count cancelled — the
//	old len(waiters)-based Release reported it flushed.
//
// GOMAXPROCS(1) plus a no-yield window between cancel() and Release()
// makes the interleaving deterministic: once counters() has observed
// parked==1 the parking goroutine has released the mutex and is (about to
// be) blocked in its select; it cannot run its post-wake lock section
// between the test's two back-to-back statements. The fixed barrier does
// not depend on that determinism — Release observes the waiter's context
// state under the mutex, so ANY scheduling yields the same single final
// outcome — but pinning the race keeps a regression loud instead of flaky.
//
// The timeout path is exercised with a shortened holdLimit (production
// keeps cv02BarrierHoldLimit).
import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// cv03BarrierFixture parks one GET for orgPath through the barrier and
// returns handles for the deterministic scenario drivers.
type cv03BarrierFixture struct {
	barrier  *cv03Barrier
	forward  chan struct{}
	forwards int32
	start    func()
}

func cv03NewBarrierFixture(t *testing.T, orgID string, hold time.Duration) (*cv03BarrierFixture, context.CancelFunc) {
	t.Helper()
	f := &cv03BarrierFixture{
		barrier: cv03NewBarrier(orgID),
		forward: make(chan struct{}, 1),
	}
	f.barrier.holdLimit = hold
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&f.forwards, 1)
		f.forward <- struct{}{}
		w.WriteHeader(http.StatusOK)
	})
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/api/organizations/"+orgID, nil).WithContext(ctx)
	f.barrier.setArmed(true)
	// start hands scheduling control to the caller: each scenario decides
	// whether the request is launched before or after a release.
	f.start = func() {
		go f.barrier.Handler(next).ServeHTTP(httptest.NewRecorder(), req)
	}
	return f, cancel
}

// cv03WaitParked blocks until the fixture's request is registered.
func (f *cv03BarrierFixture) cv03WaitParked(t *testing.T) {
	t.Helper()
	require.Eventually(t, func() bool {
		parked, _, _, _ := f.barrier.counters()
		return parked == 1
	}, 5*time.Second, time.Millisecond, "fixture: request never parked")
}

func cv03AssertCounters(t *testing.T, f *cv03BarrierFixture, parked, flushed, cancelled, timedOut int) {
	t.Helper()
	gp, gf, gc, gt := f.barrier.counters()
	require.Equal(t, parked, gp, "parked counter")
	require.Equal(t, flushed, gf, "flushed counter")
	require.Equal(t, cancelled, gc, "cancelled counter")
	require.Equal(t, timedOut, gt, "timed_out counter")
}

// TestCV03BarrierCancelBeforeReleaseIsNotFlushed: the exact reviewer race.
// The waiter's context dies first; Release runs before the parking
// goroutine has deregistered itself. The honest outcome is cancelled —
// the parked GET was never served through the release — and the request
// is still forwarded exactly once (late-upstream semantics).
func TestCV03BarrierCancelBeforeReleaseIsNotFlushed(t *testing.T) {
	old := runtime.GOMAXPROCS(1)
	t.Cleanup(func() { runtime.GOMAXPROCS(old) })

	f, cancel := cv03NewBarrierFixture(t, "cv03-org", cv02BarrierHoldLimit)
	f.start()
	f.cv03WaitParked(t)

	// No-yield window: cancel, then immediately release, on this
	// goroutine — under GOMAXPROCS(1) the parked goroutine cannot run
	// its post-wake lock section between the two calls.
	cancel()
	f.barrier.Release()

	select {
	case <-f.forward:
	case <-time.After(5 * time.Second):
		t.Fatal("fixture: parked request was never forwarded")
	}
	require.Equal(t, int32(1), atomic.LoadInt32(&f.forwards), "exactly one forward")
	cv03AssertCounters(t, f, 1, 0, 1, 0)
}

// TestCV03BarrierReleaseBeforeCancelStaysFlushed: the release observes a
// live context and flushes; the later cancellation cannot retroactively
// re-count the waiter as cancelled.
func TestCV03BarrierReleaseBeforeCancelStaysFlushed(t *testing.T) {
	old := runtime.GOMAXPROCS(1)
	t.Cleanup(func() { runtime.GOMAXPROCS(old) })

	f, cancel := cv03NewBarrierFixture(t, "cv03-org", cv02BarrierHoldLimit)
	defer cancel()
	f.start()
	f.cv03WaitParked(t)

	f.barrier.Release()
	cancel() // after the release — must not change the recorded outcome

	select {
	case <-f.forward:
	case <-time.After(5 * time.Second):
		t.Fatal("fixture: parked request was never forwarded")
	}
	require.Equal(t, int32(1), atomic.LoadInt32(&f.forwards), "exactly one forward")
	cv03AssertCounters(t, f, 1, 1, 0, 0)
}

// TestCV03BarrierTimedOutPath: with no release and no cancellation, the
// bounded hold deadline forwards the request and counts timed_out (never
// flushed, never cancelled).
func TestCV03BarrierTimedOutPath(t *testing.T) {
	f, _ := cv03NewBarrierFixture(t, "cv03-org", 40*time.Millisecond)
	f.start()
	f.cv03WaitParked(t)

	select {
	case <-f.forward:
	case <-time.After(5 * time.Second):
		t.Fatal("fixture: parked request was never forwarded by the hold deadline")
	}
	require.Equal(t, int32(1), atomic.LoadInt32(&f.forwards), "exactly one forward")
	cv03AssertCounters(t, f, 1, 0, 0, 1)
}

// TestCV03BarrierUnarmedForwardsImmediately: a matching GET arriving after
// disarm (or before arm) is forwarded untouched and never parked.
func TestCV03BarrierUnarmedForwardsImmediately(t *testing.T) {
	old := runtime.GOMAXPROCS(1)
	t.Cleanup(func() { runtime.GOMAXPROCS(old) })

	// Disarm BEFORE launching: the barrier must forward the request
	// untouched and never park it (deterministic — no registration
	// attempt precedes the disarm).
	f, cancel := cv03NewBarrierFixture(t, "cv03-org", cv02BarrierHoldLimit)
	defer cancel()
	f.barrier.Release()
	f.start()

	select {
	case <-f.forward:
	case <-time.After(5 * time.Second):
		t.Fatal("fixture: request was never forwarded")
	}
	cv03AssertCounters(t, f, 0, 0, 0, 0)
}
