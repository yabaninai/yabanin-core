package router

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestFairTenantKeyComposition(t *testing.T) {
	cases := []struct {
		name     string
		org      string
		workload string
	}{
		{"plain", "org1", "wl1"},
		{"concatenation collision pair a", "a", "bc"},
		{"concatenation collision pair b", "ab", "c"},
		{"empty org", "", "wl"},
		{"empty workload", "org", ""},
		{"both empty", "", ""},
	}
	seen := make(map[string]string)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := FairTenantKey(tc.org, tc.workload)
			if again := FairTenantKey(tc.org, tc.workload); again != key {
				t.Fatalf("tenant key must be stable: %q then %q", key, again)
			}
			if prev, clash := seen[key]; clash {
				t.Fatalf("tenant key collision: (%q,%q) and (%q,%q) both %q",
					prev, "", tc.org, tc.workload, key)
			}
			seen[key] = tc.org
		})
	}
	if FairTenantKey("a", "bc") == FairTenantKey("ab", "c") {
		t.Fatal(`("a","bc") and ("ab","c") must not share a key`)
	}
}

func TestFairShedErrorText(t *testing.T) {
	cases := []struct {
		name string
		err  *FairShedError
		want string
	}{
		{
			name: "with hint",
			err:  &FairShedError{Tenant: "1:org", Reason: ShedQueueFull, RetryAfter: 3 * time.Second},
			want: `fair admission shed request (tenant "1:org", reason queue_full, retry after 3s)`,
		},
		{
			name: "without hint",
			err:  &FairShedError{Tenant: "1:org", Reason: ShedCapacity},
			want: `fair admission shed request (tenant "1:org", reason capacity)`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFairAdmission_DisabledFailsOpen(t *testing.T) {
	cases := []struct {
		name string
		fa   *FairAdmission
	}{
		{"nil controller", nil},
		{"zero capacity", NewFairAdmission(FairAdmissionConfig{Capacity: 0})},
		{"negative capacity", NewFairAdmission(FairAdmissionConfig{Capacity: -1})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Far beyond any capacity a live controller would have.
			for i := 0; i < 10; i++ {
				ticket, err := tc.fa.Admit(context.Background(), "org", "wl")
				if err != nil {
					t.Fatalf("disabled admission must fail open, got %v", err)
				}
				if ticket == nil {
					t.Fatal("disabled admission must return a no-op ticket")
				}
				ticket.Release()
				ticket.Release() // idempotent
			}
			// nil-safe release.
			var noTicket *FairTicket
			noTicket.Release()
		})
	}
}

func TestFairAdmission_AdmitReleaseCycle(t *testing.T) {
	fa := NewFairAdmission(FairAdmissionConfig{
		Capacity:       1,
		MaxPerTenant:   1,
		QueueLimit:     0,
		ShedRetryAfter: 3 * time.Second,
	})
	ctx := context.Background()

	first, err := fa.Admit(ctx, "org-a", "wl")
	if err != nil {
		t.Fatalf("first admit must pass, got %v", err)
	}

	_, err = fa.Admit(ctx, "org-b", "wl")
	var shed *FairShedError
	if !errors.As(err, &shed) {
		t.Fatalf("saturated admit must shed, got %v", err)
	}
	if shed.Reason != ShedCapacity {
		t.Fatalf("expected capacity shed, got %s", shed.Reason)
	}
	if shed.RetryAfter != 3*time.Second {
		t.Fatalf("shed must carry the configured hint, got %v", shed.RetryAfter)
	}

	first.Release()
	second, err := fa.Admit(ctx, "org-b", "wl")
	if err != nil {
		t.Fatalf("released slot must be reusable, got %v", err)
	}
	second.Release()

	if st := fa.stats(); st.Free != 1 || st.InFlight != 0 || st.Queued != 0 {
		t.Fatalf("slot accounting must be exact, got %+v", st)
	}
}

// Acceptance: a noisy tenant cannot displace other tenants under saturation.
// The per-tenant bound keeps the noisy tenant to its own share while every
// other tenant keeps getting slots.
func TestFairAdmission_NoisyTenantIsolated(t *testing.T) {
	cases := []struct {
		name         string
		capacity     int
		maxPerTenant int
	}{
		{"quarter share", 4, 1},
		{"half share", 4, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fa := NewFairAdmission(FairAdmissionConfig{
				Capacity:     tc.capacity,
				MaxPerTenant: tc.maxPerTenant,
				QueueLimit:   0,
			})
			ctx := context.Background()

			// The noisy tenant fills its bound and only its bound.
			var noisy []*FairTicket
			for i := 0; i < tc.maxPerTenant; i++ {
				ticket, err := fa.Admit(ctx, "noisy", "wl")
				if err != nil {
					t.Fatalf("noisy admit %d within its bound must pass, got %v", i, err)
				}
				noisy = append(noisy, ticket)
			}
			for i := 0; i < 5; i++ {
				_, err := fa.Admit(ctx, "noisy", "wl")
				var shed *FairShedError
				if !errors.As(err, &shed) || shed.Reason != ShedTenantLimit {
					t.Fatalf("noisy excess must shed with tenant_limit, got %v", err)
				}
			}

			// Other tenants keep their share while the noisy tenant is
			// saturated at its bound.
			others := make([]*FairTicket, 0, tc.capacity-tc.maxPerTenant)
			for i := 0; i < tc.capacity-tc.maxPerTenant; i++ {
				ticket, err := fa.Admit(ctx, "tenant-"+string(rune('a'+i)), "wl")
				if err != nil {
					t.Fatalf("other tenant %d must get a slot under saturation, got %v", i, err)
				}
				others = append(others, ticket)
			}
			if st := fa.stats(); st.Free != 0 {
				t.Fatalf("capacity must now be saturated, got %+v", st)
			}

			// The noisy tenant stays shed even as capacity churns among
			// the others; the others keep re-admitting.
			_, err := fa.Admit(ctx, "noisy", "wl")
			var shed *FairShedError
			if !errors.As(err, &shed) {
				t.Fatalf("noisy must stay bounded, got %v", err)
			}
			others[0].Release()
			again, err := fa.Admit(ctx, "tenant-a", "wl")
			if err != nil {
				t.Fatalf("other tenant must re-admit on a freed slot, got %v", err)
			}

			// Drain: every release is honored and accounting is exact.
			for _, ticket := range others {
				ticket.Release()
			}
			again.Release()
			for _, ticket := range noisy {
				ticket.Release()
			}
			if st := fa.stats(); st.Free != tc.capacity || st.InFlight != 0 || st.Queued != 0 {
				t.Fatalf("drain must restore the initial state, got %+v", st)
			}
		})
	}
}

// Negative: a retry storm is refused at admission with a backpressure hint
// and never reaches the upstream path — the storm cannot grow in-flight
// upstream load and cannot push the shared breaker around.
func TestFairAdmission_RetryStormShedWithHint(t *testing.T) {
	fa := NewFairAdmission(FairAdmissionConfig{
		Capacity:       2,
		MaxPerTenant:   1,
		QueueLimit:     0,
		ShedRetryAfter: 5 * time.Second,
	})
	ctx := context.Background()

	// One slot per tenant: the storming tenant holds exactly one.
	storm, err := fa.Admit(ctx, "storm", "wl")
	if err != nil {
		t.Fatalf("storm first request must pass, got %v", err)
	}
	defer storm.Release()

	for i := 0; i < 50; i++ {
		_, err := fa.Admit(ctx, "storm", "wl")
		var shed *FairShedError
		if !errors.As(err, &shed) {
			t.Fatalf("storm request %d must be shed, got %v", i, err)
		}
		if shed.Reason != ShedTenantLimit {
			t.Fatalf("storm request %d must shed on the tenant bound, got %s", i, shed.Reason)
		}
		if shed.RetryAfter != 5*time.Second {
			t.Fatalf("shed %d must carry the backpressure hint, got %v", i, shed.RetryAfter)
		}
	}

	// The storm did not consume any other tenant's capacity.
	other, err := fa.Admit(ctx, "calm", "wl")
	if err != nil {
		t.Fatalf("calm tenant must be admitted throughout the storm, got %v", err)
	}

	if st := fa.stats(); st.InFlight != 2 || st.Free != 0 || st.Queued != 0 {
		t.Fatalf("storm must not change slot accounting, got %+v", st)
	}
	other.Release()
	if st := fa.stats(); st.InFlight != 1 || st.Free != 1 {
		t.Fatalf("calm release must be accounted, got %+v", st)
	}
}

func TestFairAdmission_QueueBoundedPerTenantAndDrains(t *testing.T) {
	fa := NewFairAdmission(FairAdmissionConfig{
		Capacity:       1,
		MaxPerTenant:   1,
		QueueLimit:     2,
		ShedRetryAfter: time.Second,
	})
	ctx := context.Background()

	holder, err := fa.Admit(ctx, "holder", "wl")
	if err != nil {
		t.Fatalf("holder must pass, got %v", err)
	}

	// Park the waiters sequentially so the queue order is deterministic:
	// pendingWaiters reflects count, not arrival order.
	b1 := admitAsync(fa, ctx, "queued", "wl")
	waitForQueueDepth(t, fa, "queued", "wl", 1)
	b2 := admitAsync(fa, ctx, "queued", "wl")
	waitForQueueDepth(t, fa, "queued", "wl", 2)

	// Third waiter exceeds the tenant queue bound: immediate shed.
	_, err = fa.Admit(ctx, "queued", "wl")
	var shed *FairShedError
	if !errors.As(err, &shed) || shed.Reason != ShedQueueFull {
		t.Fatalf("queue overflow must shed with queue_full, got %v", err)
	}
	if shed.RetryAfter != time.Second {
		t.Fatalf("default hint must apply, got %v", shed.RetryAfter)
	}

	// FIFO drain: the first queued request is granted first.
	holder.Release()
	first := receiveAdmit(t, b1, 2*time.Second)
	if first.ticket == nil {
		t.Fatalf("first waiter must be granted, got %v", first.err)
	}
	if st := fa.stats(); st.Free != 0 || st.InFlight != 1 || st.Queued != 1 {
		t.Fatalf("grant must consume the slot exactly once, got %+v", st)
	}

	first.ticket.Release()
	second := receiveAdmit(t, b2, 2*time.Second)
	if second.ticket == nil {
		t.Fatalf("second waiter must be granted, got %v", second.err)
	}
	second.ticket.Release()

	if st := fa.stats(); st.Free != 1 || st.InFlight != 0 || st.Queued != 0 {
		t.Fatalf("drain must restore accounting, got %+v", st)
	}
}

// The grant scan skips waiters whose own tenant is at its bound: a noisy
// tenant's queued requests cannot hold the queue head against other tenants.
func TestFairAdmission_QueueGrantSkipsTenantAtBound(t *testing.T) {
	fa := NewFairAdmission(FairAdmissionConfig{
		Capacity:     3,
		MaxPerTenant: 2,
		QueueLimit:   8,
	})
	ctx := context.Background()

	a1, err := fa.Admit(ctx, "noisy", "wl")
	if err != nil {
		t.Fatalf("a1 must pass, got %v", err)
	}
	a2, err := fa.Admit(ctx, "noisy", "wl")
	if err != nil {
		t.Fatalf("a2 must pass, got %v", err)
	}
	b1, err := fa.Admit(ctx, "other", "wl")
	if err != nil {
		t.Fatalf("b1 must pass, got %v", err)
	}

	// Queue order: noisy first, other behind it.
	qNoisy := admitAsync(fa, ctx, "noisy", "wl")
	waitForQueueDepth(t, fa, "noisy", "wl", 1)
	qOther := admitAsync(fa, ctx, "other", "wl")
	waitForQueueDepth(t, fa, "other", "wl", 1)

	// The freed slot skips the noisy tenant's head-of-queue waiter (its
	// tenant is at the bound) and reaches the eligible tenant behind it.
	b1.Release()
	granted := receiveAdmit(t, qOther, 2*time.Second)
	if granted.ticket == nil {
		t.Fatalf("eligible waiter behind the head must be granted, got %v", granted.err)
	}

	if st := fa.stats(); st.Free != 0 || st.InFlight != 3 || st.Queued != 1 {
		t.Fatalf("unexpected state after the skip-grant, got %+v", st)
	}
	select {
	case res := <-qNoisy:
		t.Fatalf("noisy waiter must still be parked at its bound, got %+v", res)
	default:
	}

	// Drain: releasing a noisy slot unblocks its own waiter.
	a1.Release()
	noisyGrant := receiveAdmit(t, qNoisy, 2*time.Second)
	if noisyGrant.ticket == nil {
		t.Fatalf("noisy waiter must be granted once its tenant frees a slot, got %v", noisyGrant.err)
	}
	noisyGrant.ticket.Release()
	a2.Release()
	granted.ticket.Release()

	if st := fa.stats(); st.Free != 3 || st.InFlight != 0 || st.Queued != 0 {
		t.Fatalf("drain must restore accounting, got %+v", st)
	}
}

func TestFairAdmission_QueueWaitTimeoutSheds(t *testing.T) {
	fa := NewFairAdmission(FairAdmissionConfig{
		Capacity:       1,
		MaxPerTenant:   1,
		QueueLimit:     4,
		WaitTimeout:    30 * time.Millisecond,
		ShedRetryAfter: 5 * time.Second,
	})
	ctx := context.Background()

	holder, err := fa.Admit(ctx, "holder", "wl")
	if err != nil {
		t.Fatalf("holder must pass, got %v", err)
	}
	defer holder.Release()

	res := receiveAdmit(t, admitAsync(fa, ctx, "queued", "wl"), 2*time.Second)
	if res.ticket != nil {
		t.Fatal("timed-out waiter must not hold a ticket")
	}
	var shed *FairShedError
	if !errors.As(res.err, &shed) || shed.Reason != ShedQueueWait {
		t.Fatalf("wait deadline must shed with queue_timeout, got %v", res.err)
	}
	if shed.RetryAfter != 5*time.Second {
		t.Fatalf("queue timeout must carry the hint, got %v", shed.RetryAfter)
	}
	if got := fa.pendingWaiters("queued", "wl"); got != 0 {
		t.Fatalf("timed-out waiter must leave the queue, got %d pending", got)
	}
	if st := fa.stats(); st.Free != 0 || st.InFlight != 1 {
		t.Fatalf("timeout must not disturb slot accounting, got %+v", st)
	}
}

func TestFairAdmission_QueueContextCancel(t *testing.T) {
	fa := NewFairAdmission(FairAdmissionConfig{
		Capacity:     1,
		MaxPerTenant: 1,
		QueueLimit:   4,
	})
	ctx := context.Background()

	holder, err := fa.Admit(ctx, "holder", "wl")
	if err != nil {
		t.Fatalf("holder must pass, got %v", err)
	}

	waiterCtx, cancel := context.WithCancel(ctx)
	resCh := admitAsync(fa, waiterCtx, "queued", "wl")
	waitForQueueDepth(t, fa, "queued", "wl", 1)
	cancel()

	res := receiveAdmit(t, resCh, 2*time.Second)
	if res.ticket != nil {
		t.Fatal("canceled waiter must not hold a ticket")
	}
	if !errors.Is(res.err, context.Canceled) {
		t.Fatalf("canceled waiter must report context.Canceled, got %v", res.err)
	}
	if got := fa.pendingWaiters("queued", "wl"); got != 0 {
		t.Fatalf("canceled waiter must leave the queue, got %d pending", got)
	}

	// The canceled request consumed nothing: the slot is still held by
	// the holder, and a fresh admit parks in queue instead of fast-path.
	nextCh := admitAsync(fa, ctx, "next", "wl")
	waitForQueueDepth(t, fa, "next", "wl", 1)
	if st := fa.stats(); st.Free != 0 || st.InFlight != 1 {
		t.Fatalf("cancellation must not free or consume a slot, got %+v", st)
	}

	holder.Release()
	nextRes := receiveAdmit(t, nextCh, 2*time.Second)
	if nextRes.ticket == nil {
		t.Fatalf("released slot must reach the queued admit, got %v", nextRes.err)
	}
	nextRes.ticket.Release()

	if st := fa.stats(); st.Free != 1 || st.Queued != 0 {
		t.Fatalf("cancel must not leak queue places or slots, got %+v", st)
	}
}

// The grant-vs-abandon race must never leak a slot: whichever side wins,
// the slot ends up either held by a released ticket or back in free.
func TestFairAdmission_GrantCancelRace(t *testing.T) {
	fa := NewFairAdmission(FairAdmissionConfig{
		Capacity:     1,
		MaxPerTenant: 1,
		QueueLimit:   1,
	})

	for i := 0; i < 200; i++ {
		ctx := context.Background()
		holder, err := fa.Admit(ctx, "holder", "wl")
		if err != nil {
			t.Fatalf("iteration %d: holder must pass, got %v", i, err)
		}

		waiterCtx, cancel := context.WithCancel(ctx)
		resCh := admitAsync(fa, waiterCtx, "queued", "wl")
		waitForQueueDepth(t, fa, "queued", "wl", 1)

		// Alternate the order so both interleavings of cancel and grant
		// are exercised.
		if i%2 == 0 {
			cancel()
			holder.Release()
		} else {
			holder.Release()
			cancel()
		}

		res := receiveAdmit(t, resCh, 2*time.Second)
		if res.ticket != nil {
			res.ticket.Release()
		} else if !errors.Is(res.err, context.Canceled) {
			t.Fatalf("iteration %d: unexpected waiter outcome %v", i, res.err)
		}
		cancel()

		if st := fa.stats(); st.Free != 1 || st.InFlight != 0 || st.Queued != 0 {
			t.Fatalf("iteration %d: race leaked a slot: %+v", i, st)
		}
	}
}

func TestFairAdmission_ConcurrentStormAccounting(t *testing.T) {
	fa := NewFairAdmission(FairAdmissionConfig{
		Capacity:     8,
		MaxPerTenant: 2,
		QueueLimit:   1,
		WaitTimeout:  2 * time.Millisecond,
	})
	tenants := []string{"t0", "t1", "t2", "t3", "t4", "t5"}

	var wg sync.WaitGroup
	for g := 0; g < 48; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			tenant := tenants[g%len(tenants)]
			for i := 0; i < 25; i++ {
				ticket, err := fa.Admit(context.Background(), tenant, "wl")
				if err != nil {
					continue // shed: capacity, tenant bound, queue full or timeout
				}
				runtime.Gosched()
				ticket.Release()
			}
		}(g)
	}
	wg.Wait()

	if st := fa.stats(); st.Free != 8 || st.InFlight != 0 || st.Queued != 0 || st.Tenants != len(tenants) {
		t.Fatalf("storm must leave exact accounting, got %+v", st)
	}
}

func TestFairAdmission_TenantEvictionKeepsActive(t *testing.T) {
	fa := NewFairAdmission(FairAdmissionConfig{
		Capacity:     4,
		MaxPerTenant: 2,
		QueueLimit:   0,
		MaxTenants:   2,
	})
	ctx := context.Background()

	// Eviction picks idle entries only: the active tenant stays pinned.
	active, err := fa.Admit(ctx, "active", "wl")
	if err != nil {
		t.Fatalf("active must pass, got %v", err)
	}
	idle, err := fa.Admit(ctx, "idle", "wl")
	if err != nil {
		t.Fatalf("idle must pass, got %v", err)
	}
	idle.Release()

	third, err := fa.Admit(ctx, "third", "wl")
	if err != nil {
		t.Fatalf("third must pass, got %v", err)
	}
	if st := fa.stats(); st.Tenants != 2 {
		t.Fatalf("idle tenant must be evicted, got %+v", st)
	}
	active.Release() // must still find its entry and free its slot

	if st := fa.stats(); st.Free != 3 || st.InFlight != 1 {
		t.Fatalf("active tenant release must be accounted, got %+v", st)
	}
	third.Release()

	// All tracked tenants active: a new tenant still gets in (transient
	// overshoot of the table bound, never of the capacity).
	hold1, err := fa.Admit(ctx, "hold1", "wl")
	if err != nil {
		t.Fatalf("hold1 must pass, got %v", err)
	}
	hold2, err := fa.Admit(ctx, "hold2", "wl")
	if err != nil {
		t.Fatalf("hold2 must pass, got %v", err)
	}
	extra, err := fa.Admit(ctx, "extra", "wl")
	if err != nil {
		t.Fatalf("active tenants must never block a new tenant outright, got %v", err)
	}
	if st := fa.stats(); st.Tenants != 3 {
		t.Fatalf("concurrently active tenants may exceed the bound, got %+v", st)
	}
	hold1.Release()
	hold2.Release()
	extra.Release()

	if st := fa.stats(); st.Free != 4 || st.Tenants > 3 {
		t.Fatalf("final accounting must be exact, got %+v", st)
	}
}

func TestFairAdmission_DecisionMetrics(t *testing.T) {
	fa := NewFairAdmission(FairAdmissionConfig{
		Capacity:     1,
		MaxPerTenant: 1,
		QueueLimit:   0,
	})
	ctx := context.Background()

	admittedBefore := testutil.ToFloat64(fairDecisions.WithLabelValues("admitted"))
	shedBefore := testutil.ToFloat64(fairDecisions.WithLabelValues("shed_capacity"))

	ticket, err := fa.Admit(ctx, "org", "wl")
	if err != nil {
		t.Fatalf("admit must pass, got %v", err)
	}
	if got := testutil.ToFloat64(fairDecisions.WithLabelValues("admitted")); got != admittedBefore+1 {
		t.Fatalf("admitted counter must advance by 1, got %v", got)
	}

	if _, err := fa.Admit(ctx, "other", "wl"); err == nil {
		t.Fatal("saturated admit must shed")
	}
	if got := testutil.ToFloat64(fairDecisions.WithLabelValues("shed_capacity")); got != shedBefore+1 {
		t.Fatalf("shed_capacity counter must advance by 1, got %v", got)
	}

	ticket.Release()
	if got := testutil.ToFloat64(fairInFlight); got != 0 {
		t.Fatalf("in-flight gauge must return to 0, got %v", got)
	}
	if got := testutil.ToFloat64(fairQueueDepth); got != 0 {
		t.Fatalf("queue depth gauge must stay 0, got %v", got)
	}
}

// Acceptance verification (N09-P02-T03, overload shedding): under an
// overload burst the controller admits at most the global capacity to the
// upstream path, parks at most QueueLimit per tenant, and sheds the rest
// with backpressure hints — shed requests never reach the upstream path,
// so a burst cannot amplify load against a saturated upstream.
func TestFairAdmission_OverloadShedBoundedUpstream(t *testing.T) {
	fa := NewFairAdmission(FairAdmissionConfig{
		Capacity:       2,
		MaxPerTenant:   1,
		QueueLimit:     1,
		ShedRetryAfter: time.Second,
	})
	ctx := context.Background()

	// Two holders fill the global capacity: exactly this many requests can
	// reach the upstream path.
	a, err := fa.Admit(ctx, "a", "wl")
	if err != nil {
		t.Fatalf("first holder must pass, got %v", err)
	}
	b, err := fa.Admit(ctx, "b", "wl")
	if err != nil {
		t.Fatalf("second holder must pass, got %v", err)
	}

	// The burst arrives from one tenant: the first request parks in the
	// bounded queue instead of reaching the upstream path...
	burst := admitAsync(fa, ctx, "burst", "wl")
	waitForQueueDepth(t, fa, "burst", "wl", 1)
	// ...and every further request is shed with a hint.
	for i := 0; i < 5; i++ {
		_, err := fa.Admit(ctx, "burst", "wl")
		var shed *FairShedError
		if !errors.As(err, &shed) || shed.Reason != ShedQueueFull {
			t.Fatalf("burst overflow %d must shed with queue_full, got %v", i, err)
		}
		if shed.RetryAfter != time.Second {
			t.Fatalf("burst shed %d must carry the hint, got %v", i, shed.RetryAfter)
		}
	}

	if st := fa.stats(); st.InFlight != 2 || st.Free != 0 || st.Queued != 1 {
		t.Fatalf("overload burst must leave capacity held and one queued place, got %+v", st)
	}

	// Draining the holders admits exactly the queued request, then restores
	// the initial state — no queued request is lost or double-granted.
	a.Release()
	granted := receiveAdmit(t, burst, 2*time.Second)
	if granted.ticket == nil {
		t.Fatalf("queued burst must be granted on release, got %v", granted.err)
	}
	granted.ticket.Release()
	b.Release()

	if st := fa.stats(); st.Free != 2 || st.InFlight != 0 || st.Queued != 0 {
		t.Fatalf("drain must restore accounting, got %+v", st)
	}
}

// Shed hints must jitter (spread retries) and never shorten the base
// backpressure: disabled jitter keeps the hint exact, an injected draw
// widens deterministically, and the real source stays inside the window.
func TestFairAdmission_ShedHintJitter(t *testing.T) {
	base := 2 * time.Second
	newFA := func(jitter float64) *FairAdmission {
		return NewFairAdmission(FairAdmissionConfig{
			Capacity:       1,
			MaxPerTenant:   1,
			QueueLimit:     0,
			ShedRetryAfter: base,
			ShedJitter:     jitter,
		})
	}
	shedHint := func(t *testing.T, fa *FairAdmission) time.Duration {
		t.Helper()
		if _, err := fa.Admit(context.Background(), "holder", "wl"); err != nil {
			t.Fatalf("holder must pass, got %v", err)
		}
		_, err := fa.Admit(context.Background(), "refused", "wl")
		var shed *FairShedError
		if !errors.As(err, &shed) {
			t.Fatalf("saturated admit must shed, got %v", err)
		}
		return shed.RetryAfter
	}

	t.Run("disabled keeps the hint exact", func(t *testing.T) {
		if got := shedHint(t, newFA(0)); got != base {
			t.Fatalf("jitter 0 must keep the exact hint, got %v", got)
		}
	})

	t.Run("deterministic widening", func(t *testing.T) {
		restore := withFairShedRandom(t, func() float64 { return 0.5 })
		defer restore()
		// draw 0.5 × fraction 0.5 → +25% of base.
		if got := shedHint(t, newFA(0.5)); got != base+base/4 {
			t.Fatalf("jittered hint must be exactly %v, got %v", base+base/4, got)
		}
	})

	t.Run("bounds and spread under the real source", func(t *testing.T) {
		fa := newFA(1)
		seen := make(map[time.Duration]bool)
		for i := 0; i < 32; i++ {
			// Release the previous slot so every iteration can shed again.
			if st := fa.stats(); st.InFlight > 0 {
				t.Fatal("iteration must start unsaturated")
			}
			hint := shedHintWithRelease(t, fa)
			if hint < base || hint >= 2*base {
				t.Fatalf("full jitter must keep the hint in [base, 2×base), got %v", hint)
			}
			seen[hint] = true
		}
		if len(seen) < 2 {
			t.Fatal("jitter must spread shed hints, all 32 were identical")
		}
	})
}

// shedHintWithRelease performs one shed round and releases the holder's slot
// so the next round starts unsaturated.
func shedHintWithRelease(t *testing.T, fa *FairAdmission) time.Duration {
	t.Helper()
	holder, err := fa.Admit(context.Background(), "holder", "wl")
	if err != nil {
		t.Fatalf("holder must pass, got %v", err)
	}
	_, err = fa.Admit(context.Background(), "refused", "wl")
	holder.Release()
	var shed *FairShedError
	if !errors.As(err, &shed) {
		t.Fatalf("saturated admit must shed, got %v", err)
	}
	return shed.RetryAfter
}

// withFairShedRandom swaps the shed-hint draw for fn and returns a restore
// function. Tests are serial within a package, so the swap is race-free.
func withFairShedRandom(t *testing.T, fn func() float64) func() {
	t.Helper()
	prev := fairShedRandom
	fairShedRandom = fn
	return func() {
		fairShedRandom = prev
	}
}

// admitAsync runs one Admit in the background and reports its outcome.
func admitAsync(fa *FairAdmission, ctx context.Context, org, workload string) <-chan admitResult {
	ch := make(chan admitResult, 1)
	go func() {
		ticket, err := fa.Admit(ctx, org, workload)
		ch <- admitResult{ticket: ticket, err: err}
	}()
	return ch
}

type admitResult struct {
	ticket *FairTicket
	err    error
}

// receiveAdmit waits for an async admit outcome with a hard deadline so a
// broken grant path fails the test instead of hanging it.
func receiveAdmit(t *testing.T, ch <-chan admitResult, within time.Duration) admitResult {
	t.Helper()
	select {
	case res := <-ch:
		return res
	case <-time.After(within):
		t.Fatalf("admit outcome did not arrive within %v", within)
		return admitResult{}
	}
}

// waitForQueueDepth polls the controller until the tenant has exactly want
// waiters parked (admission bookkeeping is asynchronous to the caller).
func waitForQueueDepth(t *testing.T, fa *FairAdmission, org, workload string, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if fa.pendingWaiters(org, workload) == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("queue depth for (%q,%q) never reached %d", org, workload, want)
}
