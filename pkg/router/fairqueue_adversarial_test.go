// Adversarial negative battery over the N09-P02-T04 fair-admission deltas
// (N09-P02-T05): multi-waiter dead-queue sweeps, deadline-vs-cancel parity,
// and the noisy-storm acceptance scenario at scale with both retirement
// paths (grant-scan drop and waiter abandon) exercised in one deterministic
// sequence. Observable outcome: grants reach live waiters only, every
// retirement is counted exactly once, shed accounting stays silent during
// pure cancel storms, and slot accounting is exact after every drain.
package router

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// A single freed slot must retire an entire run of dead head-of-line waiters
// and still be FREE afterwards — never consumed by the dead run, never lost.
// Late abandons from the retired waiters are accounting-neutral (exactly
// once), and the slot then serves the next live request directly.
func TestFairAdmission_GrantScanRetiresAllDeadSlotStaysFree(t *testing.T) {
	fa := NewFairAdmission(FairAdmissionConfig{
		Capacity:     1,
		MaxPerTenant: 1,
		QueueLimit:   8,
	})
	holder, err := fa.Admit(context.Background(), "holder", "wl")
	if err != nil {
		t.Fatalf("holder must pass, got %v", err)
	}

	const dead = 5
	deadWaiters := make([]*fairWaiter, 0, dead)
	canceledBefore := testutil.ToFloat64(fairDecisions.WithLabelValues("canceled"))
	for i := 0; i < dead; i++ {
		deadWaiters = append(deadWaiters, enqueueDeadWaiter(t, fa, "dead-"+string(rune('a'+i)), "wl"))
	}

	holder.Release()

	if st := fa.stats(); st.Free != 1 || st.InFlight != 0 || st.Queued != 0 {
		t.Fatalf("dead run must retire without consuming the slot, got %+v", st)
	}
	if got := testutil.ToFloat64(fairDecisions.WithLabelValues("canceled")); got != canceledBefore+dead {
		t.Fatalf("each dead waiter must count exactly once: want %v, got %v", canceledBefore+dead, got)
	}
	for i, w := range deadWaiters {
		fa.mu.Lock()
		dropped, granted := w.dropped, w.granted
		fa.mu.Unlock()
		if !dropped || granted {
			t.Fatalf("dead waiter %d must be dropped by the scan: dropped=%v granted=%v", i, dropped, granted)
		}
		// Whenever its own abandon path runs afterwards — always a no-op.
		if err := fa.abandon(w, context.Canceled, false); !errors.Is(err, context.Canceled) {
			t.Fatalf("dead waiter %d late abandon must report the cause, got %v", i, err)
		}
	}
	if got := testutil.ToFloat64(fairDecisions.WithLabelValues("canceled")); got != canceledBefore+dead {
		t.Fatalf("late abandons must not double count: want %v, got %v", canceledBefore+dead, got)
	}

	// The slot survived the dead run: a live request is admitted directly.
	ticket, err := fa.Admit(context.Background(), "live", "wl")
	if err != nil {
		t.Fatalf("live request must get the surviving slot, got %v", err)
	}
	ticket.Release()
	if st := fa.stats(); st.Free != 1 || st.InFlight != 0 || st.Queued != 0 {
		t.Fatalf("final accounting must be exact, got %+v", st)
	}
}

// runQueuedEndCase saturates capacity, queues one waiter whose context ends
// while parked, and asserts the observable outcome. Used to prove
// deadline-vs-cancel parity: both endings produce the same accounting, the
// same ledger treatment and no ticket.
func runQueuedEndCase(t *testing.T, name string, newCtx func(t *testing.T) (context.Context, func()), wantErr error) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		fa := NewFairAdmission(FairAdmissionConfig{
			Capacity:     1,
			MaxPerTenant: 1,
			QueueLimit:   4,
			WaitTimeout:  30 * time.Second, // far above the test horizon
		})
		holder, err := fa.Admit(context.Background(), "holder", "wl")
		if err != nil {
			t.Fatalf("holder must pass, got %v", err)
		}

		canceledBefore := testutil.ToFloat64(fairDecisions.WithLabelValues("canceled"))
		timeoutBefore := testutil.ToFloat64(fairDecisions.WithLabelValues("shed_queue_timeout"))

		ctx, end := newCtx(t)
		ch := admitAsync(fa, ctx, "waiter", "wl")
		waitForQueueDepth(t, fa, "waiter", "wl", 1)
		end() // ends the queued waiter's context (explicit cancel or deadline firing)

		res := receiveAdmit(t, ch, 5*time.Second)
		if res.ticket != nil || !errors.Is(res.err, wantErr) {
			t.Fatalf("queued waiter must end with %v and no ticket, got %v/%v", wantErr, res.ticket, res.err)
		}
		if got := testutil.ToFloat64(fairDecisions.WithLabelValues("canceled")); got != canceledBefore+1 {
			t.Fatalf("ending must count exactly one cancellation: want %v, got %v", canceledBefore+1, got)
		}
		if got := testutil.ToFloat64(fairDecisions.WithLabelValues("shed_queue_timeout")); got != timeoutBefore {
			t.Fatalf("caller-context ending must not count as a queue timeout: want %v, got %v", timeoutBefore, got)
		}

		holder.Release()
		if st := fa.stats(); st.Free != 1 || st.InFlight != 0 || st.Queued != 0 {
			t.Fatalf("accounting must be exact after drain, got %+v", st)
		}
	})
}

// Deadline-vs-cancel parity: a queued waiter whose deadline expires is
// retired exactly like a canceled one — context.DeadlineExceeded reported,
// one canceled decision, no shed_timeout, exact accounting.
func TestFairAdmission_QueuedDeadlineExpiryParityWithCancel(t *testing.T) {
	runQueuedEndCase(t, "canceled", func(t *testing.T) (context.Context, func()) {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		return ctx, cancel
	}, context.Canceled)

	// The ENDING is the deadline firing — an explicit cancel of a deadline
	// context would report Canceled, not DeadlineExceeded. The ending is
	// deterministic (once the deadline fires the result is fixed); only its
	// moment is wall-clock, absorbed by the 5s receive horizon. The cancel
	// func is still registered for leak-free cleanup.
	runQueuedEndCase(t, "deadline-expired", func(t *testing.T) (context.Context, func()) {
		t.Helper()
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(20*time.Millisecond))
		t.Cleanup(cancel)
		return ctx, func() {}
	}, context.DeadlineExceeded)
}

// Acceptance negative at scale: a noisy tenant's cancel storm queued ahead
// of quiet tenants — every freed slot reaches a live quiet waiter, never a
// dead one; every noisy waiter ends canceled with no ticket, counted
// exactly once (whichever of the grant-scan drop or its own abandon won the
// wake race); shed accounting stays silent through the whole storm; the
// storming tenant is served again immediately after; and an abandon-only
// retirement (no release ever follows the cancel) is pinned separately.
func TestFairAdmission_CancelStormVsQuietGrantsWaves(t *testing.T) {
	fa := NewFairAdmission(FairAdmissionConfig{
		Capacity:     3,
		MaxPerTenant: 1,
		QueueLimit:   16,
	})
	ctx := context.Background()

	holders := make([]*FairTicket, 0, 3)
	for i := 0; i < 3; i++ {
		h, err := fa.Admit(ctx, "holder"+string(rune('1'+i)), "wl")
		if err != nil {
			t.Fatalf("holder %d must pass, got %v", i, err)
		}
		holders = append(holders, h)
	}

	canceledBefore := testutil.ToFloat64(fairDecisions.WithLabelValues("canceled"))
	admittedBefore := testutil.ToFloat64(fairDecisions.WithLabelValues("admitted"))
	shedBefore := map[string]float64{
		string(ShedCapacity):    testutil.ToFloat64(fairDecisions.WithLabelValues("shed_capacity")),
		string(ShedTenantLimit): testutil.ToFloat64(fairDecisions.WithLabelValues("shed_tenant_limit")),
		string(ShedQueueFull):   testutil.ToFloat64(fairDecisions.WithLabelValues("shed_queue_full")),
		string(ShedQueueWait):   testutil.ToFloat64(fairDecisions.WithLabelValues("shed_queue_timeout")),
	}

	// Noisy tenant queues 6 waiters; ALL are canceled before any release,
	// so no live noisy waiter is ever eligible ahead of a quiet one (the
	// scan grants the first live waiter at its tenant bound — a live storm
	// waiter would correctly win FIFO order).
	const noise = 6
	type noisyReq struct {
		ch     <-chan admitResult
		cancel context.CancelFunc
	}
	noisy := make([]noisyReq, 0, noise)
	for i := 0; i < noise; i++ {
		nctx, ncancel := context.WithCancel(ctx)
		ch := admitAsync(fa, nctx, "noisy", "wl")
		waitForQueueDepth(t, fa, "noisy", "wl", i+1)
		noisy = append(noisy, noisyReq{ch: ch, cancel: ncancel})
	}
	for i := 0; i < noise; i++ {
		noisy[i].cancel()
	}

	// Quiet tenants queue behind the whole dead storm.
	q1ch := admitAsync(fa, ctx, "quiet1", "wl")
	waitForQueueDepth(t, fa, "quiet1", "wl", 1)
	q2ch := admitAsync(fa, ctx, "quiet2", "wl")
	waitForQueueDepth(t, fa, "quiet2", "wl", 1)

	// First release: the dead run retires in place, quiet1 gets the slot —
	// never a dead waiter.
	holders[0].Release()
	q1 := receiveAdmit(t, q1ch, 2*time.Second)
	if q1.ticket == nil {
		t.Fatalf("quiet1 must be granted past the noisy storm, got %v", q1.err)
	}

	// Second release: quiet2 granted past any remaining dead waiters.
	holders[1].Release()
	q2 := receiveAdmit(t, q2ch, 2*time.Second)
	if q2.ticket == nil {
		t.Fatalf("quiet2 must be granted on the second freed slot, got %v", q2.err)
	}

	// Third release: nothing live waits; the slot stays free, not lost.
	holders[2].Release()
	if st := fa.stats(); st.Free != 1 || st.InFlight != 2 || st.Queued != 0 {
		t.Fatalf("end state must be free=1 in-flight=2 queued=0, got %+v", st)
	}

	// Every noisy waiter retired exactly once, whichever of the drop scan
	// or its own abandon won the wake race.
	for i := 0; i < noise; i++ {
		res := receiveAdmit(t, noisy[i].ch, 2*time.Second)
		if res.ticket != nil || !errors.Is(res.err, context.Canceled) {
			t.Fatalf("noisy waiter %d must retire canceled with no ticket, got %v/%v", i, res.ticket, res.err)
		}
	}
	if got := testutil.ToFloat64(fairDecisions.WithLabelValues("canceled")); got != canceledBefore+noise {
		t.Fatalf("each of the %d noisy waiters must count exactly once: want %v, got %v", noise, canceledBefore+noise, got)
	}
	if got := testutil.ToFloat64(fairDecisions.WithLabelValues("admitted")); got != admittedBefore+2 {
		t.Fatalf("exactly the two quiet grants may count as admitted: want %v, got %v", admittedBefore+2, got)
	}
	for reason, before := range shedBefore {
		if got := testutil.ToFloat64(fairDecisions.WithLabelValues("shed_" + reason)); got != before {
			t.Fatalf("pure cancel storm must stay silent on shed_%s: want %v, got %v", reason, before, got)
		}
	}

	// Isolation recovery: the previously storming tenant now takes the free
	// slot directly (its load is zero — the storm left no residue).
	nLive, err := fa.Admit(ctx, "noisy", "wl")
	if err != nil {
		t.Fatalf("noisy tenant must be served again after its storm, got %v", err)
	}

	// Abandon-only retirement, deterministic: saturated again, a queued
	// waiter's context ends with no release ever following — its own
	// abandon path is the only possible retirer.
	q3ctx, q3cancel := context.WithCancel(ctx)
	q3ch := admitAsync(fa, q3ctx, "quiet3", "wl")
	waitForQueueDepth(t, fa, "quiet3", "wl", 1)
	q3bctx, q3bcancel := context.WithCancel(ctx)
	q3bch := admitAsync(fa, q3bctx, "quiet3b", "wl")
	waitForQueueDepth(t, fa, "quiet3b", "wl", 1)
	q3bcancel()
	q3bres := receiveAdmit(t, q3bch, 2*time.Second)
	if q3bres.ticket != nil || !errors.Is(q3bres.err, context.Canceled) {
		t.Fatalf("abandon-only waiter must retire canceled with no ticket, got %v/%v", q3bres.ticket, q3bres.err)
	}
	if got := testutil.ToFloat64(fairDecisions.WithLabelValues("canceled")); got != canceledBefore+noise+1 {
		t.Fatalf("abandon-only retirement must count exactly once: want %v, got %v", canceledBefore+noise+1, got)
	}

	// Retire the remaining queued waiter the same way, then drain in-flight
	// load: exact accounting restored, nothing leaked.
	q3cancel()
	q3res := receiveAdmit(t, q3ch, 2*time.Second)
	if q3res.ticket != nil || !errors.Is(q3res.err, context.Canceled) {
		t.Fatalf("remaining queued waiter must retire canceled with no ticket, got %v/%v", q3res.ticket, q3res.err)
	}
	q1.ticket.Release()
	q2.ticket.Release()
	nLive.Release()
	if got := testutil.ToFloat64(fairDecisions.WithLabelValues("canceled")); got != canceledBefore+noise+2 {
		t.Fatalf("full-drain ledger must count every retirement: want %v, got %v", canceledBefore+noise+2, got)
	}
	if st := fa.stats(); st.Free != 3 || st.InFlight != 0 || st.Queued != 0 {
		t.Fatalf("drain must restore exact accounting, got %+v", st)
	}
}
