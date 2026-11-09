package kms

// T06 joint no-stop rotation scenario: key versions are rotated, drained and
// retired WHILE traffic flows. The orchestrator runs the contract sequence —
// rotate 1→2→3 (no pause of any kind), then backlog drain, then retire —
// while reader traffic runs unbroken for the whole scenario and writer
// traffic runs unbroken until the (modeled) backlog freeze that precedes
// retirement. The runbook semantics being pinned:
//
//   - rotation itself never stops traffic: writers immediately emit the new
//     version, readers keep decrypting old-version envelopes (dual trust);
//   - retirement happens only after the version's backlog is re-encrypted;
//     in-flight operations that already captured a pre-retirement snapshot
//     may still observe the version (lock-free snapshot semantics), so a
//     reader is allowed to see ErrRetiredKeyVersion only after retire was
//     actually issued;
//   - after the sequence every surviving envelope decrypts, and artifacts
//     from retired versions refuse with ErrRetiredKeyVersion, never
//     returning payload.
//
// Everything runs under the race detector: the ring swap is a lock-free
// atomic snapshot, so the test fails on any unsynchronized access. Keys are
// deterministic test material (mock-KMS-grade unit scenario); the
// container-backed lifecycle evidence lives in kms_lifecycle_int_test.go
// (build tag `integration`) and is deliberately a different check.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

func TestVersionedKMS_NoStopRotation_UnderTraffic(t *testing.T) {
	const (
		writers    = 4
		readers    = 4
		opsPerWork = 150
	)
	payload := []byte("no-stop-rotation-payload")
	ctx := context.Background()

	v, err := NewVersioned(Keyset{Current: 1, Versions: []VersionedKey{{Version: 1, Key: verKey(0x80)}}})
	if err != nil {
		t.Fatalf("NewVersioned: %v", err)
	}

	var (
		mu           sync.Mutex
		envelopes    = make(map[int][]byte) // op id → ciphertext (all versions)
		nextID       int
		writerStop   = make(chan struct{})
		readerStop   = make(chan struct{})
		writerWG     sync.WaitGroup
		readerWG     sync.WaitGroup
		started      sync.WaitGroup // signals each worker completed its first op
		errs         = make(chan error, 16)
		rotations    atomic.Bool // set before the first Retire is issued
		opsEncrypted atomic.Int64
		opsDecrypted atomic.Int64
	)
	started.Add(writers + readers)

	// Writers: continuously encrypt under whatever version is current.
	// Work-first ordering: each writer performs an op BEFORE checking the
	// stop channel, so a fast orchestrator can never close the scenario
	// before every writer produced at least one envelope.
	for w := 0; w < writers; w++ {
		writerWG.Add(1)
		go func() {
			defer writerWG.Done()
			var signal sync.Once
			defer signal.Do(started.Done) // never leave the barrier waiting
			for {
				ct, err := v.Encrypt(ctx, payload)
				if err != nil {
					errs <- fmt.Errorf("encrypt during rotation: %w", err)
					return
				}
				opsEncrypted.Add(1)
				mu.Lock()
				envelopes[nextID] = ct
				nextID++
				mu.Unlock()
				signal.Do(started.Done)
				select {
				case <-writerStop:
					return
				default:
				}
			}
		}()
	}

	// Readers: continuously decrypt a rolling sample of everything written
	// so far — old and new versions interleave (the dual-trust window).
	// The sample is copied under the lock and decrypted outside it: stored
	// envelopes are immutable values, so a stale snapshot is safe, and the
	// map itself is never touched unlocked.
	for r := 0; r < readers; r++ {
		readerWG.Add(1)
		go func() {
			defer readerWG.Done()
			var signal sync.Once
			defer signal.Do(started.Done) // never leave the barrier waiting
			for {
				mu.Lock()
				sample := make([][]byte, 0, len(envelopes))
				for _, ct := range envelopes {
					sample = append(sample, ct)
				}
				mu.Unlock()
				for _, ct := range sample {
					got, err := v.Decrypt(ctx, ct)
					if err != nil {
						// A retire that landed mid-read legitimately closes
						// the dual-trust window; anything else is a bug.
						// rotations is set strictly before the first Retire
						// is issued, so a true flag means retire was (or may
						// have been) in flight — a false flag means it was
						// never issued and the refusal is a real defect.
						if errors.Is(err, ErrRetiredKeyVersion) && rotations.Load() {
							continue
						}
						errs <- fmt.Errorf("decrypt during rotation: %w", err)
						return
					}
					if string(got) != string(payload) {
						errs <- fmt.Errorf("decrypt during rotation returned %q", got)
						return
					}
					opsDecrypted.Add(1)
				}
				signal.Do(started.Done)
				select {
				case <-readerStop:
					return
				default:
				}
			}
		}()
	}

	// Every worker is in its loop before the first rotation lands, so the
	// scenario always interleaves traffic with the contract sequence.
	started.Wait()

	// --- Phase 1: three rotations while writers AND readers flow. ---------
	if err := v.Rotate(2, verKey(0x81)); err != nil {
		t.Fatalf("Rotate(2): %v", err)
	}
	if err := v.Rotate(3, verKey(0x82)); err != nil {
		t.Fatalf("Rotate(3): %v", err)
	}
	if v.Current() != 3 {
		t.Fatalf("Current = %d, want 3", v.Current())
	}

	// --- Phase 2: freeze the backlog, then drain it. -----------------------
	// Writers stop only AFTER the rotation is complete (rotation itself
	// required no stop); this bounds the backlog the way a real deployment's
	// finite row count does.
	close(writerStop)
	writerWG.Wait()

	drain := func(from uint64) {
		mu.Lock()
		defer mu.Unlock()
		for id, ct := range envelopes {
			if ver, _ := v.EnvelopeVersion(ct); ver == from {
				migrated, err := v.Reencrypt(ctx, ct)
				if err != nil {
					t.Fatalf("drain re-encrypt v%d (envelope %d): %v", from, id, err)
				}
				envelopes[id] = migrated
			}
		}
	}
	drain(1)
	drain(2)

	// --- Phase 3: revoke the drained versions while readers flow. ----------
	rotations.Store(true) // from here a reader may lawfully see the refusal
	if err := v.Retire(1); err != nil {
		t.Fatalf("Retire(1): %v", err)
	}
	if err := v.Retire(2); err != nil {
		t.Fatalf("Retire(2): %v", err)
	}

	// Writers keep flowing the whole time in a real deployment; here they
	// stopped only for the backlog freeze, so re-check that v3 traffic is
	// unaffected by two retires.
	ct, err := v.Encrypt(ctx, payload)
	if err != nil {
		t.Fatalf("post-retire Encrypt: %v", err)
	}
	if got, err := v.Decrypt(ctx, ct); err != nil || string(got) != string(payload) {
		t.Fatalf("post-retire traffic must be unaffected: %q, %v", got, err)
	}

	close(readerStop)
	readerWG.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("traffic error during no-stop rotation: %v", err)
	}

	// Traffic actually flowed through every stage.
	if opsEncrypted.Load() == 0 || opsDecrypted.Load() == 0 {
		t.Fatalf("scenario produced no traffic: enc=%d dec=%d", opsEncrypted.Load(), opsDecrypted.Load())
	}

	// --- Post-sequence invariants ------------------------------------------
	mu.Lock()
	defer mu.Unlock()
	if len(envelopes) == 0 {
		t.Fatal("the scenario stored no envelopes")
	}
	for id, ct := range envelopes {
		got, err := v.Decrypt(ctx, ct)
		if err != nil {
			t.Fatalf("envelope %d must decrypt after the rotation sequence: %v", id, err)
		}
		if string(got) != string(payload) {
			t.Fatalf("envelope %d decrypted to %q", id, got)
		}
	}
}

// TestVersionedKMS_RetiredEnvelopesFailClosedAfterSequence pins the second
// half of the contract: artifacts minted BEFORE retirement keep refusing
// with ErrRetiredKeyVersion after the rotation completed — across further
// rotations — and never return payload alongside the error.
func TestVersionedKMS_RetiredEnvelopesFailClosedAfterSequence(t *testing.T) {
	ctx := context.Background()
	v := newOneVersionKMS(t, 0x90)
	payload := []byte("post-retire-refusal-payload")
	ct1, err := v.Encrypt(ctx, payload)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// This probe copy deliberately skips the drain: it must stay a v1
	// artifact to prove revocation (the contract drains before retiring).
	if err := v.Rotate(2, verKey(0x91)); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if err := v.Retire(1); err != nil {
		t.Fatalf("Retire: %v", err)
	}

	got, err := v.Decrypt(ctx, ct1)
	if !errors.Is(err, ErrRetiredKeyVersion) {
		t.Fatalf("post-retire decrypt = %q, %v; want ErrRetiredKeyVersion", got, err)
	}
	if got != nil {
		t.Fatalf("post-retire decrypt returned payload alongside the error: %q", got)
	}

	// The refusal is stable across further rotations and repeated reads.
	if err := v.Rotate(3, verKey(0x92)); err != nil {
		t.Fatalf("Rotate(3): %v", err)
	}
	for i := 0; i < 100; i++ {
		if _, err := v.Decrypt(ctx, ct1); !errors.Is(err, ErrRetiredKeyVersion) {
			t.Fatalf("refusal must be stable across further rotations: %v", err)
		}
	}
}
