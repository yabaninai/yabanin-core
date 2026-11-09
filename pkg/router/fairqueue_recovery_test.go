package router

import (
	"context"
	"errors"
	"testing"
	"time"
)

// N09-P02-T08 recovery corpus, aspect pkg/router: interruption, retry and
// resume at the fair-admission gate, with result recovery (grants, tickets,
// queue places) that is free of duplicates and losses. Where T04 pinned the
// cancellation-coherence invariants and T07 the boundary clamps, this
// corpus pins the recovery narrative end to end: a duplicated Release
// cannot double-grant or corrupt accounting, a wait-timeout shed frees its
// queue place so the client can resume, a queue-full shed is backpressure
// rather than a permanent loss, and a canceled wait can be retried with a
// fresh context and served. All cases are deterministic: grants are
// triggered synchronously by Release from the test goroutine, the only
// goroutines are queue waiters resolved through waitForQueueDepth and
// receiveAdmit hard deadlines, shed hints run with zero jitter so every
// value is exact, and process-global ledger assertions are deltas
// (shuffle-safe).

// TestFairTicket_DoubleReleaseGrantsExactlyOnce pins ticket exactly-once
// accounting: a duplicated Release is a no-op (no second grant, no negative
// free), the granted ticket can itself be released twice for one slot, and
// after the dust settles the slot is alive and immediately grantable —
// nothing lost, nothing duplicated.
func TestFairTicket_DoubleReleaseGrantsExactlyOnce(t *testing.T) {
	fa := NewFairAdmission(FairAdmissionConfig{
		Capacity:     1,
		MaxPerTenant: 1,
		QueueLimit:   2,
	})
	ledger := snapshotFairLedger()
	ctx := context.Background()

	a, err := fa.Admit(ctx, "a", "wl")
	if err != nil {
		t.Fatalf("first admit must pass, got %v", err)
	}

	// b queues behind a, then a's ticket is released twice.
	bCh := admitAsync(fa, ctx, "b", "wl")
	waitForQueueDepth(t, fa, "b", "wl", 1)
	a.Release()
	a.Release() // duplicate: must be a no-op

	b := receiveAdmit(t, bCh, 2*time.Second)
	if b.ticket == nil {
		t.Fatalf("exactly one grant must reach b, got %v", b.err)
	}
	if st := fa.stats(); st.Free != 0 || st.InFlight != 1 || st.Queued != 0 {
		t.Fatalf("double release must grant b exactly once, got %+v", st)
	}

	// b's ticket is released twice too: still exactly one slot back.
	b.ticket.Release()
	b.ticket.Release()
	if st := fa.stats(); st.Free != 1 || st.InFlight != 0 || st.Queued != 0 {
		t.Fatalf("double release must not corrupt accounting, got %+v", st)
	}

	// The slot is alive: the next request is admitted immediately.
	c, err := fa.Admit(ctx, "c", "wl")
	if err != nil {
		t.Fatalf("recovered slot must admit the next request, got %v", err)
	}
	c.Release()
	if st := fa.stats(); st.Free != 1 || st.InFlight != 0 || st.Queued != 0 {
		t.Fatalf("drain must restore exact accounting, got %+v", st)
	}
	if got := ledger.delta(t, "admitted"); got != 3 {
		t.Fatalf("each of the three admissions must be counted exactly once, delta %v", got)
	}
}

// TestFairAdmission_WaitTimeoutShedThenResume pins the wait-timeout
// interruption: a request that sits in queue past WaitTimeout is shed with
// a ShedQueueWait error carrying the exact backpressure hint, its queue
// place is freed, and the very next request from that tenant is admitted
// immediately — the shed interrupted one request, not the tenant.
func TestFairAdmission_WaitTimeoutShedThenResume(t *testing.T) {
	fa := NewFairAdmission(FairAdmissionConfig{
		Capacity:       1,
		MaxPerTenant:   1,
		QueueLimit:     4,
		WaitTimeout:    10 * time.Millisecond,
		ShedRetryAfter: 25 * time.Millisecond,
		ShedJitter:     0, // exact hints: the assertion is deterministic
	})
	ledger := snapshotFairLedger()
	ctx := context.Background()

	holder, err := fa.Admit(ctx, "holder", "wl")
	if err != nil {
		t.Fatalf("holder must pass, got %v", err)
	}

	_, err = fa.Admit(ctx, "waiter", "wl") // parks past the 10ms wait deadline
	var shed *FairShedError
	if !errors.As(err, &shed) {
		t.Fatalf("wait past WaitTimeout must shed, got %v", err)
	}
	if shed.Reason != ShedQueueWait {
		t.Fatalf("timeout shed must carry reason %s, got %s", ShedQueueWait, shed.Reason)
	}
	if shed.RetryAfter != 25*time.Millisecond {
		t.Fatalf("timeout shed hint must be the exact configured base, got %v", shed.RetryAfter)
	}

	// The interrupted request left nothing behind: no queue place, no slot.
	if st := fa.stats(); st.Queued != 0 || st.Free != 0 || st.InFlight != 1 {
		t.Fatalf("timeout shed must free its queue place only, got %+v", st)
	}
	if got := fa.pendingWaiters("waiter", "wl"); got != 0 {
		t.Fatalf("shed waiter must be gone from its tenant's queue, got %d", got)
	}
	if got := ledger.delta(t, "shed_queue_timeout"); got != 1 {
		t.Fatalf("the timeout shed must be counted exactly once, delta %v", got)
	}

	// Resume: with the holder gone, the tenant's next request is admitted
	// immediately — no phantom wait, the queue state fully recovered.
	holder.Release()
	resumed, err := fa.Admit(ctx, "waiter", "wl")
	if err != nil {
		t.Fatalf("resume after the shed must be admitted immediately, got %v", err)
	}
	resumed.Release()
	if st := fa.stats(); st.Free != 1 || st.InFlight != 0 || st.Queued != 0 {
		t.Fatalf("drain must restore exact accounting, got %+v", st)
	}
}

// TestFairAdmission_QueueFullShedThenRetryResumes pins the queue-full
// boundary as backpressure rather than a loss: the request refused at
// QueueFull gets a hint and never enters the queue, and when the tenant's
// load drains, retrying that same request is served immediately — the shed
// was a deferral, not a dropped result.
func TestFairAdmission_QueueFullShedThenRetryResumes(t *testing.T) {
	fa := NewFairAdmission(FairAdmissionConfig{
		Capacity:       1,
		MaxPerTenant:   1,
		QueueLimit:     1,
		WaitTimeout:    5 * time.Second, // far above the test horizon
		ShedRetryAfter: 25 * time.Millisecond,
		ShedJitter:     0,
	})
	ledger := snapshotFairLedger()
	ctx := context.Background()

	a, err := fa.Admit(ctx, "a", "wl")
	if err != nil {
		t.Fatalf("first admit must pass, got %v", err)
	}
	// The bound is per-tenant (pinned prior behavior): the queued waiter
	// and the refused request share the "busy" tenant key.
	bCh := admitAsync(fa, ctx, "busy", "wl")
	waitForQueueDepth(t, fa, "busy", "wl", 1)

	// The tenant's queue bound refuses the next request before it waits.
	_, err = fa.Admit(ctx, "busy", "wl")
	var shed *FairShedError
	if !errors.As(err, &shed) {
		t.Fatalf("queue-full must shed, got %v", err)
	}
	if shed.Reason != ShedQueueFull {
		t.Fatalf("queue-full shed must carry reason %s, got %s", ShedQueueFull, shed.Reason)
	}
	if shed.Tenant != FairTenantKey("busy", "wl") {
		t.Fatalf("shed must name the saturated tenant, got %q", shed.Tenant)
	}
	if shed.RetryAfter != 25*time.Millisecond {
		t.Fatalf("queue-full hint must be the exact configured base, got %v", shed.RetryAfter)
	}
	if got := ledger.delta(t, "shed_queue_full"); got != 1 {
		t.Fatalf("the shed must be counted exactly once, delta %v", got)
	}

	// Resume: the load drains, the previously shed request retries and is
	// served — the queue-full shed cost it one round of backoff, no more.
	a.Release()
	b := receiveAdmit(t, bCh, 2*time.Second)
	if b.ticket == nil {
		t.Fatalf("queued b must be granted, got %v", b.err)
	}
	b.ticket.Release()
	c, err := fa.Admit(ctx, "busy", "wl")
	if err != nil {
		t.Fatalf("the shed request's retry must be admitted, got %v", err)
	}
	c.Release()
	if st := fa.stats(); st.Free != 1 || st.InFlight != 0 || st.Queued != 0 {
		t.Fatalf("drain must restore exact accounting, got %+v", st)
	}
	if got := ledger.delta(t, "admitted"); got != 3 {
		t.Fatalf("each admission (a, b, resumed c) must be counted once, delta %v", got)
	}
	if st := fa.stats(); st.Tenants > 3 {
		t.Fatalf("no stray tenant entries may remain, got %d", st.Tenants)
	}
}

// TestFairAdmission_CanceledWaitThenResumeWithFreshContext pins the
// interrupted-wait recovery path end to end: a queued request whose context
// is canceled ends with context.Canceled and no ticket, leaves exact
// accounting behind, and the same logical request retried under a fresh
// context is served immediately — an interruption is recoverable state,
// not a lost request.
func TestFairAdmission_CanceledWaitThenResumeWithFreshContext(t *testing.T) {
	fa := NewFairAdmission(FairAdmissionConfig{
		Capacity:     1,
		MaxPerTenant: 1,
		QueueLimit:   4,
	})
	ledger := snapshotFairLedger()
	ctx := context.Background()

	holder, err := fa.Admit(ctx, "holder", "wl")
	if err != nil {
		t.Fatalf("holder must pass, got %v", err)
	}

	waitCtx, waitCancel := context.WithCancel(ctx)
	waiterCh := admitAsync(fa, waitCtx, "client", "wl")
	waitForQueueDepth(t, fa, "client", "wl", 1)
	waitCancel() // interrupt the queued wait

	interrupted := receiveAdmit(t, waiterCh, 2*time.Second)
	if interrupted.ticket != nil || !errors.Is(interrupted.err, context.Canceled) {
		t.Fatalf("interrupted wait must end canceled with no ticket, got %v/%v", interrupted.ticket, interrupted.err)
	}
	if st := fa.stats(); st.Queued != 0 || st.Free != 0 || st.InFlight != 1 {
		t.Fatalf("interrupted wait must leave exact accounting, got %+v", st)
	}
	if got := ledger.delta(t, "canceled"); got != 1 {
		t.Fatalf("the interruption must be counted exactly once, delta %v", got)
	}

	// Resume: the same logical request retries with a fresh context and is
	// served as soon as a slot frees — no lost place, no penalty wait.
	holder.Release()
	resumed, err := fa.Admit(ctx, "client", "wl")
	if err != nil {
		t.Fatalf("resumed request must be admitted immediately, got %v", err)
	}
	resumed.Release()
	if st := fa.stats(); st.Free != 1 || st.InFlight != 0 || st.Queued != 0 {
		t.Fatalf("drain must restore exact accounting, got %+v", st)
	}
	if got := ledger.delta(t, "admitted"); got != 2 {
		t.Fatalf("holder and resumed request must be the only admissions, delta %v", got)
	}
}
