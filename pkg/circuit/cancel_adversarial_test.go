// Adversarial negative battery over the N09-P02-T04 cancellation deltas
// (N09-P02-T05): every sweep tries to break the RecordCanceled terminal-path
// discipline — double frees, cancels for slots never owned, cancel/success
// races, stale records from dead half-open epochs — and pins the observable
// recovery: slots never go negative or over-limit, health counters never
// move, and the breaker never wedges into permanent refusal.
package circuit

import (
	"sync"
	"testing"
	"time"
)

// Double RecordCanceled for one admitted probe frees the slot exactly once:
// the surplus records are no-ops, accounting stays exact and the epoch keeps
// admitting exactly its limit — a double free can never mint phantom probe
// slots.
func TestBreaker_DoubleRecordCanceledFreesSlotExactlyOnce(t *testing.T) {
	b := newHalfOpenBreaker(t, Config{Name: "adv-double", SuccessThreshold: 2})
	before := b.Metrics()
	if before.HalfOpenInFlight != 1 {
		t.Fatalf("one probe must be in flight, got %d", before.HalfOpenInFlight)
	}

	// One cancel for the owned slot, then two more for the same attempt:
	// exactly the misuse a panic-and-retry caller could produce.
	b.RecordCanceled()
	b.RecordCanceled()
	b.RecordCanceled()

	after := b.Metrics()
	if after.HalfOpenInFlight != 0 {
		t.Fatalf("triple cancel must leave the counter at exactly 0, got %d", after.HalfOpenInFlight)
	}
	if after.State != StateHalfOpen {
		t.Fatalf("double cancel must not change the state, got %s", after.State)
	}
	if after.FailureCount != before.FailureCount || after.SuccessCount != before.SuccessCount {
		t.Fatalf("double cancel must not touch health counters: before %+v after %+v", before, after)
	}

	// Exact accounting: a double free would have minted phantom slots and
	// over-admitted. The limit is SuccessThreshold = 2: exactly two admits
	// pass, the third is refused.
	for i := 0; i < 2; i++ {
		if err := b.Allow(); err != nil {
			t.Fatalf("admit %d after double cancel must pass, got %v", i+1, err)
		}
	}
	if err := b.Allow(); err == nil {
		t.Fatal("admit 3 after double cancel must be refused (no phantom slots)")
	}
	if got := b.Metrics().HalfOpenInFlight; got != 2 {
		t.Fatalf("counter must sit exactly at the limit after two admits, got %d", got)
	}
}

// A cancel storm from callers that never owned a probe (refused callers
// misrecording outcomes) cannot drive the half-open counter negative or
// block a genuine probe: the floor-0 release keeps the epoch live.
func TestBreaker_CancelWithoutOwnedSlotNoOp(t *testing.T) {
	b := newHalfOpenBreaker(t, Config{Name: "adv-unowned", SuccessThreshold: 1})

	// Retire the helper's probe so no slot is owned at all.
	b.RecordCanceled()

	before := b.Metrics()
	for i := 0; i < 500; i++ {
		b.RecordCanceled()
	}

	after := b.Metrics()
	if after.HalfOpenInFlight != 0 {
		t.Fatalf("unowned cancels must leave the counter at 0, got %d", after.HalfOpenInFlight)
	}
	if after.State != StateHalfOpen {
		t.Fatalf("unowned cancel storm must not change the state, got %s", after.State)
	}
	if after.FailureCount != before.FailureCount || after.SuccessCount != before.SuccessCount {
		t.Fatalf("unowned cancels must not touch health counters: before %+v after %+v", before, after)
	}

	// The epoch is live and admits exactly its single slot.
	if err := b.Allow(); err != nil {
		t.Fatalf("epoch must admit after an unowned cancel storm, got %v", err)
	}
	if err := b.Allow(); err == nil {
		t.Fatal("second admit must be refused (limit 1, no phantom slots)")
	}
}

// Cancel-then-success and success-then-cancel land in the identical state
// when the threshold is not met: order parity. The epoch stays half-open
// with its slot freed and closes only on the next genuine success.
func TestBreaker_CancelThenSuccessOrderParity(t *testing.T) {
	build := func(name string) *Breaker {
		return newHalfOpenBreaker(t, Config{Name: name, SuccessThreshold: 2})
	}

	states := make(map[string]BreakerMetrics)
	for _, order := range []struct {
		name string
		run  func(b *Breaker)
	}{
		{"cancel-then-success", func(b *Breaker) { b.RecordCanceled(); b.RecordSuccess() }},
		{"success-then-cancel", func(b *Breaker) { b.RecordSuccess(); b.RecordCanceled() }},
	} {
		b := build(order.name)
		order.run(b)

		m := b.Metrics()
		if m.State != StateHalfOpen {
			t.Fatalf("%s: one success below threshold must stay half-open, got %s", order.name, m.State)
		}
		if m.HalfOpenInFlight != 0 {
			t.Fatalf("%s: both records must have freed the single slot, got %d in flight", order.name, m.HalfOpenInFlight)
		}
		if m.SuccessCount != 1 {
			t.Fatalf("%s: exactly one success must be counted, got %d", order.name, m.SuccessCount)
		}
		states[order.name] = m
	}

	// Wall-clock snapshot fields (WindowAge/WindowProgress) are noise;
	// parity is pinned on the state-machine fields.
	stateOnly := func(m BreakerMetrics) BreakerMetrics {
		return BreakerMetrics{State: m.State, FailureCount: m.FailureCount, SuccessCount: m.SuccessCount, HalfOpenInFlight: m.HalfOpenInFlight}
	}
	if stateOnly(states["cancel-then-success"]) != stateOnly(states["success-then-cancel"]) {
		t.Fatalf("orders must land in identical states: %+v vs %+v",
			states["cancel-then-success"], states["success-then-cancel"])
	}

	// The epoch is live and a genuine success closes it.
	b := build("parity-close")
	b.RecordSuccess()
	b.RecordCanceled()
	if err := b.Allow(); err != nil {
		t.Fatalf("epoch must admit after cancel+success, got %v", err)
	}
	b.RecordSuccess()
	if b.State() != StateClosed {
		t.Fatalf("second success must close the circuit, got %s", b.State())
	}
}

// With threshold 1, cancel-then-success and success-then-cancel both close
// the circuit and leave no phantom slot: the canceled record of a probe
// whose epoch already closed is a strict no-op.
func TestBreaker_CancelThenSuccessCloseParity(t *testing.T) {
	for _, order := range []struct {
		name string
		run  func(b *Breaker)
	}{
		{"cancel-then-success", func(b *Breaker) { b.RecordCanceled(); b.RecordSuccess() }},
		{"success-then-cancel", func(b *Breaker) { b.RecordSuccess(); b.RecordCanceled() }},
	} {
		b := newHalfOpenBreaker(t, Config{Name: "adv-parity-" + order.name, SuccessThreshold: 1})
		order.run(b)

		m := b.Metrics()
		if m.State != StateClosed {
			t.Fatalf("%s: threshold-1 success must close the circuit, got %s", order.name, m.State)
		}
		if m.HalfOpenInFlight != 0 {
			t.Fatalf("%s: no slot may survive the close, got %d in flight", order.name, m.HalfOpenInFlight)
		}
		// Closed circuit serves freely; the stale cancel minted nothing.
		if err := b.Allow(); err != nil {
			t.Fatalf("%s: closed breaker must serve, got %v", order.name, err)
		}
		if m := b.Metrics(); m.HalfOpenInFlight != 0 {
			t.Fatalf("%s: closed-state traffic must not touch the probe counter, got %d", order.name, m.HalfOpenInFlight)
		}
	}
}

// A cancellation recorded after its half-open epoch died (a sibling failure
// re-opened the breaker) must not wedge the NEXT epoch: the stale record is
// refused by the state machine and the new epoch still admits exactly its
// limit. This is the wedge attempt: flooding dead-epoch records to exhaust
// the next epoch's probe budget before it starts.
func TestBreaker_StaleCancelAfterReopenNoEpochWedge(t *testing.T) {
	b := newHalfOpenBreaker(t, Config{Name: "adv-stale", SuccessThreshold: 2})

	// Sibling failure kills epoch 1 while a probe is in flight.
	b.RecordFailure()
	if b.State() != StateOpen {
		t.Fatalf("sibling failure must re-open, got %s", b.State())
	}

	// Flood of stale epoch-1 records against the Open state.
	for i := 0; i < 100; i++ {
		b.RecordCanceled()
	}
	if m := b.Metrics(); m.HalfOpenInFlight != 0 {
		t.Fatalf("stale records must not touch the counter, got %d", m.HalfOpenInFlight)
	}

	// Next epoch: admits exactly the limit, then refuses — no carry-over,
	// no pre-exhausted budget.
	b.openAt.Store(time.Now().Add(-time.Minute).UnixNano())
	for i := 0; i < 2; i++ {
		if err := b.Allow(); err != nil {
			t.Fatalf("epoch 2 admit %d must pass, got %v", i+1, err)
		}
	}
	if err := b.Allow(); err == nil {
		t.Fatal("epoch 2 third admit must be refused (limit intact)")
	}
}

// Mechanism pin for the mutex re-check in RecordCanceled: a torn snapshot
// that still says HalfOpen while the breaker has moved on must not release
// a slot into a state that no longer owns it. Without the re-check the
// stale record would steal an in-flight probe's slot (the white-box
// construction below is exactly that residue state).
func TestBreaker_TornSnapshotCancelDoesNotStealForeignSlot(t *testing.T) {
	b := newHalfOpenBreaker(t, Config{Name: "adv-torn", SuccessThreshold: 1})

	// Build the residue state the re-check exists for: the counter holds a
	// live probe while the machine is already Closed (cross-epoch residue —
	// bounded and accepted at the epoch flip; constructed here directly).
	b.mu.Lock()
	b.st = StateClosed
	b.state.Store(int32(StateClosed))
	b.mu.Unlock()

	// Torn window: the canceller's atomic snapshot still reads HalfOpen.
	b.state.Store(int32(StateHalfOpen))
	b.RecordCanceled()
	b.state.Store(int32(StateClosed))

	if m := b.Metrics(); m.HalfOpenInFlight != 1 {
		t.Fatalf("stale torn-snapshot cancel must not release the live slot, got %d in flight", m.HalfOpenInFlight)
	}

	// Sanity: the probe itself still terminates coherently once the state
	// is back to half-open.
	b.mu.Lock()
	b.st = StateHalfOpen
	b.state.Store(int32(StateHalfOpen))
	b.mu.Unlock()
	b.RecordCanceled()
	if m := b.Metrics(); m.HalfOpenInFlight != 0 {
		t.Fatalf("live-epoch cancel must free the slot, got %d in flight", m.HalfOpenInFlight)
	}
}

// Cross-epoch cancel residue stays bounded and cannot wedge recovery: a
// stale record from epoch 1 landing in a live epoch 2 may free one slot
// early, but the counter never goes negative, never exceeds the limit, and
// genuine successes still close the circuit.
func TestBreaker_CrossEpochCancelResidueBounded(t *testing.T) {
	b := newHalfOpenBreaker(t, Config{Name: "adv-residue", SuccessThreshold: 2})

	// Epoch 1: two probes; one cancels, the other survives unrecorded.
	if err := b.Allow(); err != nil {
		t.Fatalf("epoch 1 probe 1 must pass, got %v", err)
	}
	b.RecordCanceled()
	if err := b.Allow(); err != nil {
		t.Fatalf("epoch 1 probe 2 must pass, got %v", err)
	}

	// Sibling failure re-opens (releasing probe 2's slot) and epoch 2
	// begins.
	b.RecordFailure()
	b.openAt.Store(time.Now().Add(-time.Minute).UnixNano())

	// Epoch 2 admits one real probe.
	if err := b.Allow(); err != nil {
		t.Fatalf("epoch 2 probe must pass, got %v", err)
	}

	// The stale epoch-1 record lands now, inside live epoch 2: bounded
	// residue by design — it may free the slot early, but the counter stays
	// inside [0, limit] and the epoch remains coherent.
	b.RecordCanceled()
	if m := b.Metrics(); m.HalfOpenInFlight < 0 || m.HalfOpenInFlight > b.halfOpenLimit {
		t.Fatalf("residue must keep the counter within [0, %d], got %d", b.halfOpenLimit, m.HalfOpenInFlight)
	}

	// Recovery is intact: the epoch keeps admitting and genuine successes
	// close the circuit. After the residue freed the slot early, the counter
	// walks 0 → 1 (admit) → 0 (success releases) → 1 → close.
	if err := b.Allow(); err != nil {
		t.Fatalf("epoch 2 must keep admitting after residue, got %v", err)
	}
	b.RecordSuccess()
	if err := b.Allow(); err != nil {
		t.Fatalf("slot freed by the first success must admit again, got %v", err)
	}
	b.RecordSuccess()
	if b.State() != StateClosed {
		t.Fatalf("genuine successes must close the circuit, got %s", b.State())
	}
	if m := b.Metrics(); m.HalfOpenInFlight != 0 {
		t.Fatalf("close must leave no slots in flight, got %d", m.HalfOpenInFlight)
	}
}

// Race sweep: a cancel-only storm hammering Allow + (double) RecordCanceled
// across workers can never trip the breaker, never drive the probe counter
// out of [0, limit], and never wedge the epoch — after the storm the
// breaker still admits a live probe. Cancel-only outcomes cannot change the
// state, so the final assertions are deterministic.
func TestBreaker_CancelOnlyStormRaceEpochStaysLive(t *testing.T) {
	b := newHalfOpenBreaker(t, Config{Name: "adv-race-storm", SuccessThreshold: 2})
	before := b.Metrics()

	const workers = 8
	const rounds = 100
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				if err := b.Allow(); err != nil {
					// Refused callers sometimes misrecord anyway (the
					// unowned-cancel sweep, under contention).
					if (w+i)%4 == 0 {
						b.RecordCanceled()
					}
					continue
				}
				b.RecordCanceled()
				if (w+i)%2 == 0 {
					b.RecordCanceled() // double record under contention
				}
			}
		}(w)
	}
	wg.Wait()

	m := b.Metrics()
	if m.State != StateHalfOpen {
		t.Fatalf("cancel-only storm must not change the state, got %s", m.State)
	}
	if m.HalfOpenInFlight < 0 || m.HalfOpenInFlight > b.halfOpenLimit {
		t.Fatalf("probe counter must stay within [0, %d] under the storm, got %d", b.halfOpenLimit, m.HalfOpenInFlight)
	}
	if m.FailureCount != before.FailureCount || m.SuccessCount != before.SuccessCount {
		t.Fatalf("storm must not touch health counters: before %+v after %+v", before, m)
	}
	if err := b.Allow(); err != nil {
		t.Fatalf("epoch must still admit a live probe after the storm, got %v", err)
	}
}

// Map-level negative: a cancel storm against a tripped endpoint breaker
// across half-open epochs never trips or misattributes, and the endpoint
// still recovers on genuine successes.
func TestMap_CancelStormNeverTripsRecovers(t *testing.T) {
	m := NewMap(Config{Enabled: true, FailureThreshold: 1, SuccessThreshold: 2, OpenTimeout: time.Minute}, 0, nil)

	if err := m.Allow("ep"); err != nil {
		t.Fatalf("first allow must pass, got %v", err)
	}
	m.RecordFailure("ep")
	b := m.Breaker("ep")
	b.openAt.Store(time.Now().Add(-time.Minute).UnixNano())

	// Storm: admit-then-cancel across five epochs, with surplus unowned
	// cancels in between.
	for epoch := 0; epoch < 5; epoch++ {
		if err := m.Allow("ep"); err != nil {
			t.Fatalf("epoch %d: probe must pass, got %v", epoch, err)
		}
		for i := 0; i < 50; i++ {
			m.RecordCanceled("ep")
		}
		if s := b.State(); s != StateHalfOpen {
			t.Fatalf("epoch %d: storm must keep half-open, got %s", epoch, s)
		}
	}

	// Recovery is driven only by genuine outcomes.
	if err := m.Allow("ep"); err != nil {
		t.Fatalf("probe must pass after the storm, got %v", err)
	}
	m.RecordSuccess("ep")
	m.RecordSuccess("ep")
	if s := m.State("ep"); s != StateClosed {
		t.Fatalf("genuine successes must close the endpoint breaker, got %s", s)
	}
}

// TenantMap-level acceptance invariant: one tenant's cancel storm across
// its own half-open epochs leaves every other tenant's breaker untouched —
// no state change, no counter drift, no interference via the shared map.
func TestTenantMap_NoisyCancelStormQuietUntouched(t *testing.T) {
	tm := NewTenantMap(Config{Enabled: true, FailureThreshold: 2, SuccessThreshold: 2, OpenTimeout: time.Minute}, 0, nil)

	// Noisy tenant trips its own breaker.
	for i := 0; i < 2; i++ {
		if err := tm.Allow("noisy", "https://up.example"); err != nil {
			t.Fatalf("noisy allow %d must pass, got %v", i, err)
		}
		tm.RecordFailure("noisy", "https://up.example")
	}
	nb := tm.Breaker("noisy", "https://up.example")
	nb.openAt.Store(time.Now().Add(-time.Minute).UnixNano())
	if err := tm.Allow("noisy", "https://up.example"); err != nil {
		t.Fatalf("noisy probe must pass, got %v", err)
	}

	quietState := func() BreakerMetrics {
		m := tm.Breaker("quiet", "https://up.example").Metrics()
		// Wall-clock snapshot fields are noise; invariants live in the
		// state-machine fields.
		return BreakerMetrics{State: m.State, FailureCount: m.FailureCount, SuccessCount: m.SuccessCount, HalfOpenInFlight: m.HalfOpenInFlight}
	}
	before := quietState()

	// Storm: noisy cancels its probe and hammers unowned/double records.
	tm.RecordCanceled("noisy", "https://up.example")
	for i := 0; i < 300; i++ {
		tm.RecordCanceled("noisy", "https://up.example")
	}

	if s := tm.State("noisy", "https://up.example"); s != StateHalfOpen {
		t.Fatalf("noisy storm must keep its own breaker half-open, got %s", s)
	}
	if m := nb.Metrics(); m.HalfOpenInFlight != 0 {
		t.Fatalf("noisy probe slot must be freed, got %d in flight", m.HalfOpenInFlight)
	}

	// Quiet tenant: state and counters identical through the storm.
	if after := quietState(); after != before {
		t.Fatalf("quiet breaker must be untouched: before %+v after %+v", before, after)
	}
	if s := tm.State("quiet", "https://up.example"); s != StateClosed {
		t.Fatalf("quiet breaker must stay closed, got %s", s)
	}

	// And quiet traffic still flows on its own breaker.
	if err := tm.Allow("quiet", "https://up.example"); err != nil {
		t.Fatalf("quiet allow must pass after the storm, got %v", err)
	}
	tm.RecordSuccess("quiet", "https://up.example")
}
