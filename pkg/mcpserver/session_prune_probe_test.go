package mcpserver

// AUDIT-P2-09 regression probes (2026-11-04, Codex independent audit of
// ba80021b, confirmed probe: deterministic exit 1 under -race -shuffle).
//
// The audited defect: validate() decided freshness OUTSIDE the registry
// lock (via verify) and consulted the revocation set in a SECOND, separate
// locked step. With the registry at capacity, a pressure-pruner could run
// in the gap: verify read the clock at exactly the expiry second (still
// fresh under the now > expiry predicate), the pruner saw expiry+1 and
// DELETED the cancelled id's record, and the subsequent lookup had nothing
// left to reject — a cancelled AND strictly expired id validated. A
// logical TOCTOU between two individually mutex-consistent steps, not a
// data race.
//
// The fix pinned here: ONE coherent checkpoint — validate re-checks
// freshness and looks up the record inside a single s.mu.RLock critical
// section, the same mutex pruneLocked takes for writing, so a read section
// never overlaps the pruner's write section and the two decisions cannot
// interleave with a delete.
//
// The deterministic probe reproduces the audited interleave single-goroutine
// (no sleeps, no scheduling luck) by letting the injected clock play the
// "other goroutine": the instant validate's fast path captures its time
// reading, the world advances past expiry and the REAL pressure path
// (maybePrune → pruneLocked at capacity) deletes the record. On the
// pre-fix layout this script ends with validate ACCEPTING the cancelled id
// (the locked lookup misses); the repaired in-lock freshness re-check
// rejects it — that is the discriminating assertion.

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestValidatePruneRaceWindowNeverResurrectsCancelled is the adapted audit
// probe: cancelled → boundary-second validate → capacity prune deletes the
// record while validate is "between" its captured freshness instant and its
// locked checkpoint → the same validate must still reject.
func TestValidatePruneRaceWindowNeverResurrectsCancelled(t *testing.T) {
	const ttl = time.Hour
	s := newSessionSigner([]byte("prune-seam-secret"), ttl)
	// The single cancel below puts the registry exactly AT capacity, so the
	// next issue/revoke pressure really prunes (the audited precondition).
	s.revocationCap = 1

	base := time.Now()
	clock := base
	seamArmed := false
	var seam func()
	s.now = func() time.Time {
		if seamArmed {
			seamArmed = false // one-shot, cleared BEFORE the nested prune re-enters this clock
			captured := clock // the instant validate's fast path "read" (audit: exactly at expiry)
			seam()            // meanwhile the world moves on: clock passes expiry, record deleted
			return captured   // the fast path still acts on its stale reading — the audited TOCTOU input
		}
		return clock
	}
	expiry := base.Add(ttl)

	sid := s.issue() // embedded expiry = base+ttl
	if err := s.revoke(sid); err != nil {
		t.Fatalf("setup cancel: %v", err)
	}
	s.mu.Lock()
	size := len(s.revoked)
	s.mu.Unlock()
	if size != 1 {
		t.Fatalf("setup: registry = %d entries, want 1", size)
	}

	// 1. At the boundary second (now == expiry, still fresh by the shared
	// predicate) the cancelled id is rejected through its record: cancel is
	// enforced through the very last valid second.
	clock = expiry
	if err := s.validate(sid); err == nil {
		t.Fatal("cancelled id accepted at its last valid second")
	}

	// 2. The audited interleave, deterministically: validate captures its
	// freshness reading at exactly expiry; inside that reading's "pause"
	// the clock passes expiry and the capacity prune DELETES the record;
	// validate then reaches its locked checkpoint with the record already
	// gone and a stale fresh reading in hand. It must STILL reject.
	seam = func() {
		clock = expiry.Add(time.Second) // the pruner's view: strictly past expiry
		s.maybePrune()                  // real pressure path: at capacity → pruneLocked deletes
	}
	seamArmed = true
	if err := s.validate(sid); err == nil {
		t.Fatal("cancelled-then-expired-then-pruned id validated across the prune race window (AUDIT-P2-09)")
	}
	s.mu.Lock()
	size = len(s.revoked)
	s.mu.Unlock()
	if size != 0 {
		t.Fatalf("post-window registry = %d entries, want 0 (the prune must really have deleted the record)", size)
	}

	// 3. Quiesced epilogue: nothing left to consult, clock past expiry.
	if err := s.validate(sid); err == nil {
		t.Fatal("pruned cancelled id accepted after the window")
	}
}

// TestConcurrentExpiryPrunePressureValidate is the combined cell: real
// concurrent validate traffic swept continuously across the embedded expiry
// boundary while the registry sits AT capacity and live issue-path pressure
// prunes expired cancelled records underneath the readers. Monotonicity
// makes every assertion deterministic under ANY interleave: a cancelled id
// is rejected by its record while unexpired (records are pruned only
// strictly after expiry, and the clock only advances) and by validate's
// in-lock freshness check after that — never accepted. The race detector
// sees the validate read sections interleaved with pruner/issuer write
// sections throughout.
func TestConcurrentExpiryPrunePressureValidate(t *testing.T) {
	const ttl = time.Hour
	const capSessions = 16
	s := newSessionSigner([]byte("prune-conc-secret"), ttl)
	s.revocationCap = capSessions

	var clock atomic.Int64 // unix nanos; advances monotonically, single writer direction
	base := time.Now()
	clock.Store(base.UnixNano())
	s.now = func() time.Time { return time.Unix(0, clock.Load()) }

	ids := make([]string, capSessions)
	for i := range ids {
		ids[i] = s.issue()
		if err := s.revoke(ids[i]); err != nil {
			t.Fatalf("setup cancel %d: %v", i, err)
		}
	}
	end := base.Add(3 * ttl) // all records strictly expired well before the sweep ends
	const steps = 400
	inc := int64(end.Sub(base) / steps)

	fail := func(format string, args ...any) {
		t.Errorf(format, args...) // Errorf is race-safe (t.Fatal is not, off the test goroutine)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Validators: the cancelled ids must never validate — before expiry
	// (record present), across it, or after (record pruned by the issuer
	// pressure below), including ids whose records are already deleted.
	for w := 0; w < 3; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				for _, sid := range ids {
					if err := s.validate(sid); err == nil {
						fail("cancelled id validated during prune pressure")
					}
				}
			}
		}()
	}
	// Issuers: at capacity every issue() takes the write lock and prunes —
	// real deletion pressure against the readers — and each fresh id must
	// stay valid (the strengthened checkpoint rejects nothing live).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			sid := s.issue()
			if err := s.validate(sid); err != nil {
				fail("freshly issued id rejected: %v", err)
			}
		}
	}()
	// The clock marches across the embedded expiry while all of the above
	// runs — the audited window is swept continuously, not sampled once.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(stop)
		for i := 0; i < steps; i++ {
			clock.Add(inc)
			time.Sleep(50 * time.Microsecond)
		}
	}()
	wg.Wait()

	// Quiesced epilogue: strictly expired + cancelled (records possibly
	// long-pruned) → reject; registry stays bounded.
	for _, sid := range ids {
		if err := s.validate(sid); err == nil {
			t.Fatal("expired cancelled id validated after quiesce")
		}
	}
	s.mu.Lock()
	size := len(s.revoked)
	s.mu.Unlock()
	if size > capSessions {
		t.Fatalf("registry = %d entries, cap %d", size, capSessions)
	}
}
