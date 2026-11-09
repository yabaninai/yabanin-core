// Boundary corpus for FairAdmission (N09-P02-T07, aspect pkg/router): the
// controller pinned at its exact configuration and grant boundaries — the
// per-tenant clamp against capacity, the minimal queue, FIFO grant order
// across tenants, the zero and endpoint shed hints, and the packet acceptance
// boundary (a noisy tenant held at its exact bound with a full queue must not
// displace quiet tenants). Every case pins prior behavior at an exact edge;
// async queue parks are synchronized through waitForQueueDepth so assertions
// never depend on scheduling order.
package router

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestFairAdmission_BoundaryMaxPerTenantClamp pins the per-tenant bound at
// its edge against the global capacity: equality is a valid "no isolation"
// configuration (one tenant may hold every slot and others shed on capacity),
// and a bound above capacity clamps to the capacity rather than exceeding it.
func TestFairAdmission_BoundaryMaxPerTenantClamp(t *testing.T) {
	cases := []struct {
		name         string
		capacity     int
		maxPerTenant int
	}{
		{name: "equal to capacity grants no isolation", capacity: 2, maxPerTenant: 2},
		{name: "above capacity clamps to capacity", capacity: 2, maxPerTenant: 10},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fa := NewFairAdmission(FairAdmissionConfig{
				Capacity:     tc.capacity,
				MaxPerTenant: tc.maxPerTenant,
				QueueLimit:   0,
			})
			ctx := context.Background()

			// One tenant fills every slot: at the clamp boundary the
			// effective per-tenant bound is the capacity itself.
			var holder []*FairTicket
			for i := 0; i < tc.capacity; i++ {
				ticket, err := fa.Admit(ctx, "solo", "wl")
				if err != nil {
					t.Fatalf("solo admit %d must pass at the clamp boundary, got %v", i, err)
				}
				holder = append(holder, ticket)
			}
			if st := fa.stats(); st.Free != 0 {
				t.Fatalf("solo tenant must hold the whole capacity, got %+v", st)
			}

			// A second tenant finds no headroom: the shed reason is
			// capacity (its own in-flight count is below the effective
			// bound).
			_, err := fa.Admit(ctx, "other", "wl")
			var shed *FairShedError
			if !errors.As(err, &shed) {
				t.Fatalf("saturated admit must shed, got %v", err)
			}
			if shed.Reason != ShedCapacity {
				t.Fatalf("second tenant must shed on capacity at the clamp boundary, got %s", shed.Reason)
			}

			for _, ticket := range holder {
				ticket.Release()
			}
			if st := fa.stats(); st.Free != tc.capacity || st.InFlight != 0 {
				t.Fatalf("drain must restore exact accounting, got %+v", st)
			}
		})
	}
}

// TestFairAdmission_BoundaryQueueLimitOne pins the minimal bounded queue at
// its per-tenant boundary: exactly one waiter of a tenant parks, the same
// tenant's next request sheds queue_full (its queue is at the exact limit
// while other tenants' queues are untouched), a release grants the parked
// waiter, and the queue place is immediately reusable.
func TestFairAdmission_BoundaryQueueLimitOne(t *testing.T) {
	fa := NewFairAdmission(FairAdmissionConfig{
		Capacity:     1,
		MaxPerTenant: 1,
		QueueLimit:   1,
	})
	ctx := context.Background()

	holder, err := fa.Admit(ctx, "holder", "wl")
	if err != nil {
		t.Fatalf("holder must pass, got %v", err)
	}

	parked := admitAsync(fa, ctx, "parked", "wl")
	waitForQueueDepth(t, fa, "parked", "wl", 1)

	// The "parked" tenant's queue is at its exact limit: its own next
	// request must shed queue_full (a different tenant would get a fresh
	// per-tenant queue and park).
	_, err = fa.Admit(ctx, "parked", "wl")
	var shed *FairShedError
	if !errors.As(err, &shed) || shed.Reason != ShedQueueFull {
		t.Fatalf("overflow at the tenant's queue limit must shed queue_full, got %v", err)
	}

	// Releasing the holder grants the parked waiter.
	holder.Release()
	got := receiveAdmit(t, parked, time.Second)
	if got.err != nil {
		t.Fatalf("parked waiter must be granted on release, got %v", got.err)
	}

	// The queue place is reusable right away: a fresh waiter parks again.
	next := admitAsync(fa, ctx, "next", "wl")
	waitForQueueDepth(t, fa, "next", "wl", 1)
	got.ticket.Release()
	nextRes := receiveAdmit(t, next, time.Second)
	if nextRes.err != nil {
		t.Fatalf("re-parked waiter must be granted, got %v", nextRes.err)
	}
	nextRes.ticket.Release()

	if st := fa.stats(); st.Free != 1 || st.InFlight != 0 || st.Queued != 0 {
		t.Fatalf("final accounting must be exact, got %+v", st)
	}
}

// TestFairAdmission_BoundaryFIFOGrantOrderAcrossTenants pins the grant-scan
// order boundary: with several eligible waiters from different tenants, slots
// are granted in arrival order — proven here with a lexically-last tenant
// queued first, so any name-ordered or map-ordered scan would fail the pin.
func TestFairAdmission_BoundaryFIFOGrantOrderAcrossTenants(t *testing.T) {
	fa := NewFairAdmission(FairAdmissionConfig{
		Capacity:     1,
		MaxPerTenant: 1,
		QueueLimit:   2,
	})
	ctx := context.Background()

	holder, err := fa.Admit(ctx, "holder", "wl")
	if err != nil {
		t.Fatalf("holder must pass, got %v", err)
	}

	// "zz" queues first, "aa" second: the grant order must follow the
	// queue, not the names.
	first := admitAsync(fa, ctx, "zz", "wl")
	waitForQueueDepth(t, fa, "zz", "wl", 1)
	second := admitAsync(fa, ctx, "aa", "wl")
	waitForQueueDepth(t, fa, "aa", "wl", 1)

	holder.Release()
	firstRes := receiveAdmit(t, first, time.Second)
	if firstRes.err != nil {
		t.Fatalf("first-queued tenant must be granted first, got %v", firstRes.err)
	}
	// "aa" must still be queued while "zz" holds the granted slot.
	if got := fa.pendingWaiters("aa", "wl"); got != 1 {
		t.Fatalf("second-queued tenant must still wait, queued=%d", got)
	}

	firstRes.ticket.Release()
	secondRes := receiveAdmit(t, second, time.Second)
	if secondRes.err != nil {
		t.Fatalf("second-queued tenant must be granted next, got %v", secondRes.err)
	}
	secondRes.ticket.Release()

	if st := fa.stats(); st.Free != 1 || st.Queued != 0 {
		t.Fatalf("final accounting must be exact, got %+v", st)
	}
}

// TestFairAdmission_BoundaryZeroHintStaysZero pins the disabled-hint
// boundary: ShedRetryAfter=0 must produce sheds with exactly a zero hint even
// under jitter — a zero base must never be widened into a fabricated
// backpressure hint (and never into a negative one).
func TestFairAdmission_BoundaryZeroHintStaysZero(t *testing.T) {
	restore := withFairShedRandom(t, func() float64 { return 1 })
	defer restore()

	fa := NewFairAdmission(FairAdmissionConfig{
		Capacity:       1,
		MaxPerTenant:   1,
		QueueLimit:     0,
		ShedRetryAfter: 0,
		ShedJitter:     0.5,
	})
	ctx := context.Background()

	holder, err := fa.Admit(ctx, "holder", "wl")
	if err != nil {
		t.Fatalf("holder must pass, got %v", err)
	}
	defer holder.Release()

	_, err = fa.Admit(ctx, "refused", "wl")
	var shed *FairShedError
	if !errors.As(err, &shed) {
		t.Fatalf("saturated admit must shed, got %v", err)
	}
	if shed.RetryAfter != 0 {
		t.Fatalf("zero base must keep the hint at exactly zero, got %v", shed.RetryAfter)
	}
	if strings.Contains(shed.Error(), "retry after") {
		t.Fatalf("zero hint must be absent from the error text, got %q", shed.Error())
	}
}

// TestFairAdmission_BoundaryJitterEndpoints pins the shed-hint widening at
// its endpoints through the controller: draw 0 widens nothing (hint is
// exactly the base), and draw 1 with the maximal fraction lands on exactly
// double the base (the clamp endpoint — the hint may never exceed it).
func TestFairAdmission_BoundaryJitterEndpoints(t *testing.T) {
	base := 2 * time.Second

	t.Run("draw zero widens nothing", func(t *testing.T) {
		restore := withFairShedRandom(t, func() float64 { return 0 })
		defer restore()
		fa := NewFairAdmission(FairAdmissionConfig{
			Capacity: 1, MaxPerTenant: 1, QueueLimit: 0,
			ShedRetryAfter: base, ShedJitter: 0.5,
		})
		if got := shedHintWithRelease(t, fa); got != base {
			t.Fatalf("draw 0 must keep the exact base hint, got %v", got)
		}
	})

	t.Run("draw one at maximal fraction doubles exactly", func(t *testing.T) {
		restore := withFairShedRandom(t, func() float64 { return 1 })
		defer restore()
		fa := NewFairAdmission(FairAdmissionConfig{
			Capacity: 1, MaxPerTenant: 1, QueueLimit: 0,
			ShedRetryAfter: base, ShedJitter: 1,
		})
		if got := shedHintWithRelease(t, fa); got != 2*base {
			t.Fatalf("draw 1 at fraction 1 must clamp to exactly 2x base, got %v", got)
		}
	})
}

// TestFairAdmission_BoundaryNoisyAtExactBounds is the packet acceptance line
// ("a noisy tenant does not evict the others under saturation") pinned at the
// boundary values: the noisy tenant holds its exact per-tenant bound and its
// queue is at its exact limit, every further noisy request sheds pre-upstream,
// quiet tenants keep being served, and every freed slot is accounted exactly.
func TestFairAdmission_BoundaryNoisyAtExactBounds(t *testing.T) {
	fa := NewFairAdmission(FairAdmissionConfig{
		Capacity:       3,
		MaxPerTenant:   1,
		QueueLimit:     1,
		ShedRetryAfter: 25 * time.Millisecond,
		ShedJitter:     0,
	})
	ctx := context.Background()

	// The noisy tenant reaches its exact footprint: one in-flight slot and
	// one queued waiter — everything else must shed.
	noisy, err := fa.Admit(ctx, "noisy", "wl")
	if err != nil {
		t.Fatalf("noisy first admit must pass, got %v", err)
	}
	noisyQueuedCtx, cancelQueued := context.WithCancel(ctx)
	noisyQueued := admitAsync(fa, noisyQueuedCtx, "noisy", "wl")
	waitForQueueDepth(t, fa, "noisy", "wl", 1)

	for i := 0; i < 5; i++ {
		_, err := fa.Admit(ctx, "noisy", "wl")
		var shed *FairShedError
		if !errors.As(err, &shed) || shed.Reason != ShedQueueFull {
			t.Fatalf("noisy overflow %d must shed queue_full pre-upstream, got %v", i, err)
		}
		if shed.RetryAfter != 25*time.Millisecond {
			t.Fatalf("noisy overflow %d must carry the exact hint, got %v", i, shed.RetryAfter)
		}
	}

	// Quiet tenants are admitted throughout: the noisy footprint never
	// touches their slots.
	quietA, err := fa.Admit(ctx, "quiet-a", "wl")
	if err != nil {
		t.Fatalf("quiet tenant a must be served under the saturated noisy tenant, got %v", err)
	}
	quietB, err := fa.Admit(ctx, "quiet-b", "wl")
	if err != nil {
		t.Fatalf("quiet tenant b must be served under the saturated noisy tenant, got %v", err)
	}
	if st := fa.stats(); st.Free != 0 || st.InFlight != 3 || st.Queued != 1 {
		t.Fatalf("saturation state must be exact, got %+v", st)
	}

	// The noisy queued waiter gives up: its place is freed without touching
	// slot accounting, and the controller reports the cancellation.
	cancelQueued()
	if res := receiveAdmit(t, noisyQueued, time.Second); !errors.Is(res.err, context.Canceled) {
		t.Fatalf("canceled noisy waiter must report context.Canceled, got %v", res.err)
	}
	if got := fa.pendingWaiters("noisy", "wl"); got != 0 {
		t.Fatalf("cancellation must free the noisy queue place, queued=%d", got)
	}
	if st := fa.stats(); st.Free != 0 || st.InFlight != 3 {
		t.Fatalf("cancellation must not change slot accounting, got %+v", st)
	}

	// Releasing the noisy in-flight slot frees exactly one slot; the queue
	// is empty, so nothing is granted and the noisy tenant itself may
	// re-admit into its own freed slot.
	noisy.Release()
	noisyAgain, err := fa.Admit(ctx, "noisy", "wl")
	if err != nil {
		t.Fatalf("noisy tenant must re-admit into its own freed slot, got %v", err)
	}
	if st := fa.stats(); st.Free != 0 || st.InFlight != 3 || st.Queued != 0 {
		t.Fatalf("re-admission must be accounted exactly, got %+v", st)
	}

	// Full drain restores the initial state.
	quietA.Release()
	quietB.Release()
	noisyAgain.Release()
	if st := fa.stats(); st.Free != 3 || st.InFlight != 0 || st.Queued != 0 || st.Tenants != 3 {
		t.Fatalf("drain must restore exact accounting, got %+v", st)
	}
}
