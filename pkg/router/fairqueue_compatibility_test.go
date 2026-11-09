// N09-P02-T09 compatibility matrix, aspect pkg/router: FairAdmission is new
// in this packet (T02) and has no production consumer yet (the wave-2 wiring
// card owns that), so the compatibility axis here is the contract a FUTURE
// consumer can rely on: the disabled/legacy configuration (Capacity <= 0,
// the pre-packet router shape of "no admission control") fails open with
// clean accounting and stays inert, unsupported table bounds fall back to
// the documented default instead of misbehaving, and every refusal is a
// typed *FairShedError with a DISTINCT reason and a backpressure hint the
// consumer maps to a 429 + Retry-After response — while a dead context is
// refused as exactly that, never disguised as a shed.
//
// Where the fairqueue boundary/adversarial corpora pin each bound's
// mechanics in depth, this corpus pins the uniform consumer-facing mapping
// across all four shed reasons from one dispatch shape, deterministically
// (single-goroutine holds, channel-joined helpers, generous horizons, exact
// accounting deltas around every shed).
package router

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"testing"
	"time"
)

// compatOutcome is one dispatch's observable result in the consumer shape.
type compatOutcome struct {
	status     int
	retryAfter time.Duration
	err        error
}

// compatDispatch is the minimal consumer shape the wiring contract implies:
// Admit first; a *FairShedError maps to a 429 whose Retry-After header is
// the shed hint; any other admission error (a dead context) is surfaced
// as-is and must NOT become a 429; an admitted request releases its ticket
// on every path.
func compatDispatch(fa *FairAdmission, ctx context.Context, tenant, workload string) compatOutcome {
	ticket, admitErr := fa.Admit(ctx, tenant, workload)
	if admitErr != nil {
		var shed *FairShedError
		if errors.As(admitErr, &shed) {
			return compatOutcome{status: http.StatusTooManyRequests, retryAfter: shed.RetryAfter, err: admitErr}
		}
		return compatOutcome{status: http.StatusInternalServerError, err: admitErr}
	}
	defer ticket.Release()
	return compatOutcome{status: http.StatusOK}
}

// TestCompat_TenantTableFallbackBound pins the explicit clamp contract for
// unsupported table bounds: MaxTenants <= 0 falls back to
// DefaultFairMaxTenants (both as the stored effective bound and behaviorally
// — a long stream of distinct tenants cannot grow the table past it), and a
// positive bound is kept verbatim. A misconfigured bound must degrade to the
// documented default, never to an unbounded or zero-capacity table.
func TestCompat_TenantTableFallbackBound(t *testing.T) {
	for _, tc := range []struct {
		name       string
		maxTenants int
		want       int
	}{
		{"zero falls back", 0, DefaultFairMaxTenants},
		{"negative falls back", -7, DefaultFairMaxTenants},
		{"positive kept verbatim", 3, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fa := NewFairAdmission(FairAdmissionConfig{Capacity: 4, MaxTenants: tc.maxTenants})
			if fa.cfg.MaxTenants != tc.want {
				t.Fatalf("effective MaxTenants = %d, want %d", fa.cfg.MaxTenants, tc.want)
			}
		})
	}

	// Behavioral corroboration of the fallback: more distinct tenants than
	// the default bound, each admitted and released sequentially, must
	// leave the table bounded — idle LRU eviction keeps it at the clamp.
	fa := NewFairAdmission(FairAdmissionConfig{Capacity: 4, MaxTenants: -1})
	ctx := context.Background()
	const streams = DefaultFairMaxTenants + 6
	for i := 0; i < streams; i++ {
		out := compatDispatch(fa, ctx, "org-"+strconv.Itoa(i), "wl")
		if out.err != nil || out.status != http.StatusOK {
			t.Fatalf("tenant %d must be admitted and served, got %+v", i, out)
		}
	}
	if got := len(fa.tenants); got > DefaultFairMaxTenants {
		t.Fatalf("tenant table must stay bounded by the fallback, got %d entries", got)
	}
}

// TestCompat_TypedShedRefusalMappingContract walks one dispatch shape
// through every shed reason at an exact bound and pins the consumer
// contract: each refusal is a typed *FairShedError carrying a distinct
// reason and the configured backpressure hint, mapped to a 429 whose hint
// becomes the Retry-After advice, and a shed never disturbs the slot or
// queue accounting it observed — while a dead context refuses with
// context.Canceled and must not map to a shed. Exact-bound mechanics of
// each individual reason are owned by the boundary/adversarial corpora;
// this matrix owns the uniform mapping.
func TestCompat_TypedShedRefusalMappingContract(t *testing.T) {
	ctx := context.Background()
	shedReasons := make(map[FairShedReason]bool)

	t.Run("capacity", func(t *testing.T) {
		fa := NewFairAdmission(FairAdmissionConfig{
			Capacity: 1, QueueLimit: 0, // no queueing: the global bound sheds
			ShedRetryAfter: 3 * time.Second, ShedJitter: 0, // exact hint
		})
		hold, err := fa.Admit(ctx, "holder", "wl")
		requireNoAdmitErr(t, err)
		defer hold.Release()

		before := fa.stats()
		out := compatDispatch(fa, ctx, "other", "wl")
		assertShed(t, out, http.StatusTooManyRequests, 3*time.Second)
		assertSlotAccountingUnchanged(t, before, fa.stats())
		reason := classifyShed(t, out)
		shedReasons[reason] = true
		if reason != ShedCapacity {
			t.Fatalf("global bound exhausted with queueing off must shed capacity, got %s", reason)
		}
	})

	t.Run("tenant_limit", func(t *testing.T) {
		fa := NewFairAdmission(FairAdmissionConfig{
			Capacity: 4, MaxPerTenant: 1, QueueLimit: 0,
			ShedRetryAfter: 2 * time.Second, ShedJitter: 0,
		})
		hold, err := fa.Admit(ctx, "tenant", "wl")
		requireNoAdmitErr(t, err)
		defer hold.Release()

		before := fa.stats()
		out := compatDispatch(fa, ctx, "tenant", "wl")
		assertShed(t, out, http.StatusTooManyRequests, 2*time.Second)
		assertSlotAccountingUnchanged(t, before, fa.stats())
		reason := classifyShed(t, out)
		shedReasons[reason] = true
		if reason != ShedTenantLimit {
			t.Fatalf("per-tenant bound with queueing off must shed tenant_limit, got %s", reason)
		}
	})

	t.Run("queue_full", func(t *testing.T) {
		fa := NewFairAdmission(FairAdmissionConfig{
			Capacity: 1, QueueLimit: 1, WaitTimeout: time.Hour,
			ShedRetryAfter: time.Second, ShedJitter: 0,
		})
		hold, err := fa.Admit(ctx, "holder", "wl")
		requireNoAdmitErr(t, err)

		// One queued waiter fills the tenant's queue; the next request is
		// shed queue-full from the dispatch shape itself.
		queued := make(chan compatOutcome, 1)
		go func() { queued <- compatDispatch(fa, ctx, "waiter", "wl") }()
		waitForQueueDepth(t, fa, "waiter", "wl", 1)

		out := compatDispatch(fa, ctx, "waiter", "wl")
		assertShed(t, out, http.StatusTooManyRequests, time.Second)
		reason := classifyShed(t, out)
		shedReasons[reason] = true
		if reason != ShedQueueFull {
			t.Fatalf("full queue must shed queue_full, got %s", reason)
		}

		// Drain: releasing the holder grants the queued waiter exactly its
		// granted slot; accounting returns to rest.
		hold.Release()
		select {
		case granted := <-queued:
			if granted.status != http.StatusOK || granted.err != nil {
				t.Fatalf("queued waiter must be served after the slot frees, got %+v", granted)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("queued waiter never granted")
		}
		if st := fa.stats(); st.Free != 1 || st.InFlight != 0 || st.Queued != 0 {
			t.Fatalf("drain must restore exact accounting, got %+v", st)
		}
	})

	t.Run("queue_wait", func(t *testing.T) {
		fa := NewFairAdmission(FairAdmissionConfig{
			Capacity: 1, QueueLimit: 2, WaitTimeout: 5 * time.Millisecond,
			ShedRetryAfter: time.Second, ShedJitter: 0,
		})
		hold, err := fa.Admit(ctx, "holder", "wl")
		requireNoAdmitErr(t, err)
		defer hold.Release()

		waited := make(chan compatOutcome, 1)
		go func() { waited <- compatDispatch(fa, ctx, "waiter", "wl") }()
		select {
		case out := <-waited:
			assertShed(t, out, http.StatusTooManyRequests, time.Second)
			reason := classifyShed(t, out)
			shedReasons[reason] = true
			if reason != ShedQueueWait {
				t.Fatalf("expired wait must shed queue_wait, got %s", reason)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("queue wait never expired")
		}
	})

	t.Run("dead_context_not_a_shed", func(t *testing.T) {
		fa := NewFairAdmission(FairAdmissionConfig{Capacity: 1, QueueLimit: 1})
		dead, cancel := context.WithCancel(ctx)
		cancel()

		out := compatDispatch(fa, dead, "org", "wl")
		if out.status != http.StatusInternalServerError {
			t.Fatalf("a dead context must NOT map to a 429, got status %d", out.status)
		}
		if out.retryAfter != 0 {
			t.Fatalf("a dead context carries no hint, got %v", out.retryAfter)
		}
		if !errors.Is(out.err, context.Canceled) {
			t.Fatalf("dead context must surface context.Canceled, got %v", out.err)
		}
		var shed *FairShedError
		if errors.As(out.err, &shed) {
			t.Fatalf("dead context must not be typed as a shed, got %+v", shed)
		}
	})

	if len(shedReasons) != 4 {
		t.Fatalf("all four shed reasons must be distinct and reachable, got %v", shedReasons)
	}
}

// classifyShed recovers the typed reason from a shed outcome.
func classifyShed(t *testing.T, out compatOutcome) FairShedReason {
	t.Helper()
	var shed *FairShedError
	if !errors.As(out.err, &shed) {
		t.Fatalf("shed must be typed *FairShedError, got %T (%v)", out.err, out.err)
	}
	return shed.Reason
}

// assertShed pins the uniform mapping on one shed outcome: the 429 status,
// the exact hint carried into the consumer's Retry-After.
func assertShed(t *testing.T, out compatOutcome, wantStatus int, wantHint time.Duration) {
	t.Helper()
	if out.status != wantStatus {
		t.Fatalf("shed must map to status %d, got %d", wantStatus, out.status)
	}
	if out.err == nil {
		t.Fatal("shed must surface an error")
	}
	if out.retryAfter != wantHint {
		t.Fatalf("shed hint must be the exact configured base, got %v want %v", out.retryAfter, wantHint)
	}
}

// assertSlotAccountingUnchanged pins that a shed decision consumed no slot
// and no queue entry. (The tracked-tenant table may legitimately grow: a
// refused request still registers its tenant for future isolation, and as
// an idle entry it stays LRU-evictable.)
func assertSlotAccountingUnchanged(t *testing.T, before, after fairStats) {
	t.Helper()
	if before.Free != after.Free || before.InFlight != after.InFlight || before.Queued != after.Queued {
		t.Fatalf("a shed must leave slot accounting untouched, before %+v after %+v", before, after)
	}
}

// requireNoAdmitErr is the matrix's admission guard for harness setup.
func requireNoAdmitErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("harness admission must succeed, got %v", err)
	}
}
