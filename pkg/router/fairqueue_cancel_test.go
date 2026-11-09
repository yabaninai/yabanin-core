// Deadline/cancellation-coherence tests for FairAdmission (N09-P02-T04):
// a request that can never run must never consume a slot or a queue place,
// and a grant must never be delivered to — or displaced by — a waiter whose
// context has already ended.
package router

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// Admit with an already-ended context (canceled or past its deadline) is
// refused before any accounting: no slot, no queue place, no "admitted"
// decision — the decision ledger only ever describes runnable requests.
func TestFairAdmission_AdmitEndedContextNoAccounting(t *testing.T) {
	fa := NewFairAdmission(FairAdmissionConfig{
		Capacity:     1,
		MaxPerTenant: 1,
		QueueLimit:   2,
	})

	tests := []struct {
		name    string
		wantErr error
		ctx     func(t *testing.T) context.Context
	}{
		{
			name:    "canceled context",
			wantErr: context.Canceled,
			ctx: func(t *testing.T) context.Context {
				t.Helper()
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
		},
		{
			name:    "expired deadline",
			wantErr: context.DeadlineExceeded,
			ctx: func(t *testing.T) context.Context {
				t.Helper()
				ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				defer cancel()
				return ctx
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := fa.stats()
			canceledBefore := testutil.ToFloat64(fairDecisions.WithLabelValues("canceled"))
			admittedBefore := testutil.ToFloat64(fairDecisions.WithLabelValues("admitted"))

			ticket, err := fa.Admit(tt.ctx(t), "org", "wl")
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ended context must be refused with %v, got %v", tt.wantErr, err)
			}
			if ticket != nil {
				t.Fatal("ended context must not receive a ticket")
			}

			if after := fa.stats(); after != before {
				t.Fatalf("ended-context admit must not change accounting, before %+v after %+v", before, after)
			}
			if got := testutil.ToFloat64(fairDecisions.WithLabelValues("canceled")); got != canceledBefore+1 {
				t.Fatalf("decision ledger must count one cancellation, got %v", got)
			}
			if got := testutil.ToFloat64(fairDecisions.WithLabelValues("admitted")); got != admittedBefore {
				t.Fatalf("ended-context admit must not count as admitted, got %v", got)
			}
			if got := testutil.ToFloat64(fairQueueDepth); got != 0 {
				t.Fatalf("ended-context admit must not park in queue, depth %v", got)
			}
		})
	}

	// Fail-open parity (documented): with the controller disabled there is
	// no accounting to protect, so Admit stays unconditional.
	disabled := NewFairAdmission(FairAdmissionConfig{Capacity: 0})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ticket, err := disabled.Admit(ctx, "org", "wl")
	if err != nil {
		t.Fatalf("disabled controller must fail open even on an ended context, got %v", err)
	}
	ticket.Release()
}

// enqueueDeadWaiter parks a synthetic waiter whose context is already dead
// at the head of the queue — the exact state the grant scan must handle:
// a waiter that ended after enqueueing but before its abandon path ran.
// Returns the waiter; its goroutine (if any) is not running, so the grant
// scan is the only code that can retire it.
func enqueueDeadWaiter(t *testing.T, fa *FairAdmission, org, workload string) *fairWaiter {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	fa.mu.Lock()
	defer fa.mu.Unlock()
	tenant := fa.tenantLocked(FairTenantKey(org, workload))
	w := &fairWaiter{tenant: tenant, ready: make(chan struct{}), ctx: ctx}
	tenant.queuedWaiters++
	fa.queue = append(fa.queue, w)
	fa.queued.Set(float64(len(fa.queue)))
	return w
}

// The grant scan retires a dead head-of-line waiter in place: removed from
// the queue, its place and counters settled, one canceled decision counted —
// and the freed slot is NOT consumed by the dead request. The waiter's own
// abandon afterwards is a no-op: exactly-once accounting.
func TestFairAdmission_GrantScanRetiresDeadWaiterInPlace(t *testing.T) {
	fa := NewFairAdmission(FairAdmissionConfig{
		Capacity:     1,
		MaxPerTenant: 1,
		QueueLimit:   4,
	})
	holder, err := fa.Admit(context.Background(), "holder", "wl")
	if err != nil {
		t.Fatalf("holder must pass, got %v", err)
	}

	w := enqueueDeadWaiter(t, fa, "dead", "wl")
	canceledBefore := testutil.ToFloat64(fairDecisions.WithLabelValues("canceled"))

	holder.Release() // runs the grant scan against a queue with only the dead waiter

	if st := fa.stats(); st.Free != 1 || st.InFlight != 0 || st.Queued != 0 {
		t.Fatalf("dead waiter must retire without consuming the freed slot, got %+v", st)
	}
	if got := testutil.ToFloat64(fairDecisions.WithLabelValues("canceled")); got != canceledBefore+1 {
		t.Fatalf("drop scan must count the retired waiter once, want %v, got %v", canceledBefore+1, got)
	}

	fa.mu.Lock()
	dropped := w.dropped
	granted := w.granted
	fa.mu.Unlock()
	if !dropped || granted {
		t.Fatalf("dead waiter must be dropped by the scan, dropped=%v granted=%v", dropped, granted)
	}

	// Whenever the waiter's own abandon path runs (here: after the drop),
	// it must not account again.
	if err := fa.abandon(w, context.Canceled, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("abandon after drop must report the cause, got %v", err)
	}
	if got := testutil.ToFloat64(fairDecisions.WithLabelValues("canceled")); got != canceledBefore+1 {
		t.Fatalf("abandon after drop must not double count, want %v, got %v", canceledBefore+1, got)
	}
	if st := fa.stats(); st.Free != 1 || st.Queued != 0 {
		t.Fatalf("abandon after drop must be accounting-neutral, got %+v", st)
	}
}

// The freed slot goes past a dead head-of-line waiter to the first live
// waiter: the dead request never holds the slot, not even transiently.
func TestFairAdmission_GrantScanGrantsLivePastDeadWaiter(t *testing.T) {
	fa := NewFairAdmission(FairAdmissionConfig{
		Capacity:     1,
		MaxPerTenant: 1,
		QueueLimit:   4,
	})
	holder, err := fa.Admit(context.Background(), "holder", "wl")
	if err != nil {
		t.Fatalf("holder must pass, got %v", err)
	}

	dead := enqueueDeadWaiter(t, fa, "dead", "wl")

	// The live waiter queues behind the dead one and waits for real.
	liveCh := admitAsync(fa, context.Background(), "live", "wl")
	waitForQueueDepth(t, fa, "live", "wl", 1)

	holder.Release()

	live := receiveAdmit(t, liveCh, 2*time.Second)
	if live.ticket == nil {
		t.Fatalf("live waiter must be granted past the dead head-of-line waiter, got %v", live.err)
	}

	fa.mu.Lock()
	dropped, granted := dead.dropped, dead.granted
	fa.mu.Unlock()
	if !dropped || granted {
		t.Fatalf("dead waiter must be dropped, not granted: dropped=%v granted=%v", dropped, granted)
	}

	if st := fa.stats(); st.Free != 0 || st.InFlight != 1 || st.Queued != 0 {
		t.Fatalf("live waiter must hold exactly the freed slot, got %+v", st)
	}
	live.ticket.Release()
	if st := fa.stats(); st.Free != 1 || st.InFlight != 0 || st.Queued != 0 {
		t.Fatalf("drain must restore exact accounting, got %+v", st)
	}
}

// Acceptance (noisy tenant does not displace the others under saturation,
// cancellation leg): a noisy tenant floods the queue and every one of its
// waiters' contexts ends — a storm of dead waiters ahead of the quiet
// tenant's live request. The quiet tenant still gets its grant on the first
// freed slot, every dead waiter ends with context.Canceled and no ticket,
// and each retirement is counted exactly once (whichever of the drop scan
// or the waiter's own abandon wins the wake race).
func TestFairAdmission_NoisyCancelStormDoesNotDisplaceQuietGrant(t *testing.T) {
	fa := NewFairAdmission(FairAdmissionConfig{
		Capacity:     1,
		MaxPerTenant: 1,
		QueueLimit:   8,
	})
	ctx := context.Background()

	holder, err := fa.Admit(ctx, "holder", "wl")
	if err != nil {
		t.Fatalf("holder must pass, got %v", err)
	}

	const noise = 4
	canceledBefore := testutil.ToFloat64(fairDecisions.WithLabelValues("canceled"))
	noiseCancels := make([]context.CancelFunc, 0, noise)
	noiseChs := make([]<-chan admitResult, 0, noise)
	for i := 0; i < noise; i++ {
		nctx, ncancel := context.WithCancel(ctx)
		ch := admitAsync(fa, nctx, "noisy", "wl")
		waitForQueueDepth(t, fa, "noisy", "wl", i+1)
		noiseCancels = append(noiseCancels, ncancel)
		noiseChs = append(noiseChs, ch)
	}
	for _, cancel := range noiseCancels {
		cancel()
	}

	// The quiet tenant queues behind the noisy tenant's waiters.
	quietCh := admitAsync(fa, ctx, "quiet", "wl")
	waitForQueueDepth(t, fa, "quiet", "wl", 1)

	holder.Release()

	quiet := receiveAdmit(t, quietCh, 2*time.Second)
	if quiet.ticket == nil {
		t.Fatalf("quiet tenant must be granted past the noisy cancel storm, got %v", quiet.err)
	}
	for i, ch := range noiseChs {
		res := receiveAdmit(t, ch, 2*time.Second)
		if res.ticket != nil || !errors.Is(res.err, context.Canceled) {
			t.Fatalf("noisy waiter %d must retire canceled with no ticket, got %v/%v", i, res.ticket, res.err)
		}
	}

	// Each canceled waiter is counted exactly once, drop scan or abandon.
	if got := testutil.ToFloat64(fairDecisions.WithLabelValues("canceled")); got != canceledBefore+noise {
		t.Fatalf("storm must count each canceled waiter exactly once: want %v, got %v", canceledBefore+noise, got)
	}

	quiet.ticket.Release()
	if st := fa.stats(); st.Free != 1 || st.InFlight != 0 || st.Queued != 0 {
		t.Fatalf("storm drain must restore exact accounting, got %+v", st)
	}
}
