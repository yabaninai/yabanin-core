package cache

// N03-P05-T09 independent review pins.
//
// Finding (dissolve-after-publish race): runLease's select can pick the TTL
// timer after publish already closed f.done. On the pre-fix code dissolve
// then reset f.published to false, so waiters already waking on <-f.done read
// a plain miss and fell through upstream although a payload had been frozen
// for them — a bounded (miss-direction only, one window per 60s TTL) but real
// violation of the "publish wakes every waiter as a hit" contract. The reset
// was also dead code on dissolve's intended path: a never-published flight
// already has published == false (only publish ever sets it true).

import (
	"bytes"
	"context"
	"testing"
	"time"
)

// seedPartitionFlight registers a flight exactly the way await's creator
// path does, but without a leader goroutine: the test drives publish and
// dissolve by hand for deterministic interleavings.
func seedPartitionFlight(p *partitionFlights, key string) *partitionFlight {
	p.mu.Lock()
	defer p.mu.Unlock()
	f := &partitionFlight{
		key:   key,
		done:  make(chan struct{}),
		lease: make(chan struct{}, 1),
	}
	p.flights[key] = f
	return f
}

// A dissolve that loses the publish race (runLease picked timer.C after
// publish closed done) must not unfreeze the published outcome: the flight
// stays reported as published with its payload intact.
func TestN03P5T09_LateDissolvePreservesPublishedOutcome(t *testing.T) {
	p := newPartitionFlights(8, time.Hour, time.Hour) // lease/TTL far beyond the test horizon
	const key = "n03p5t09:late-dissolve"
	f := seedPartitionFlight(p, key)

	sealed := []byte(`{"answer":"forty-two"}`)
	p.publish(key, sealed) // publish wins: payload frozen, done closed, table entry removed
	p.dissolve(f)          // the raced late dissolve from runLease's timer branch

	p.mu.Lock()
	published, payload := f.published, f.payload
	p.mu.Unlock()
	if !published {
		t.Fatal("late dissolve reset published on an already-published flight: waiters would fall through upstream despite a frozen payload")
	}
	if !bytes.Equal(payload, sealed) {
		t.Fatalf("payload mutated by late dissolve: got %q, want %q", payload, sealed)
	}
	if got := p.active(); got != 0 {
		t.Fatalf("table entries = %d after publish, want 0 (publish removes the flight)", got)
	}
}

// Waiter-level end-to-end variant: waiters already blocked on the flight are
// served the published payload even when a raced late dissolve runs after the
// publish — the outcome is frozen at publish time, not at wake time.
func TestN03P5T09_LateDissolveWaitersStillServedPublishedPayload(t *testing.T) {
	p := newPartitionFlights(8, time.Hour, time.Hour)
	const key = "n03p5t09:late-dissolve-waiters"
	f := seedPartitionFlight(p, key)

	const waiters = 4
	type outcome struct {
		payload   []byte
		published bool
	}
	results := make(chan outcome, waiters)
	for i := 0; i < waiters; i++ {
		go func() {
			payload, published := p.await(context.Background(), key)
			results <- outcome{payload, published}
		}()
	}
	waitFor(t, func() bool { return f.waiters.Load() == waiters }, 2*time.Second)

	sealed := []byte(`{"answer":"forty-two"}`)
	p.publish(key, sealed) // wakes every waiter with the frozen pair
	p.dissolve(f)          // raced late dissolve: must leave the frozen pair intact

	for i := 0; i < waiters; i++ {
		select {
		case r := <-results:
			if !r.published || !bytes.Equal(r.payload, sealed) {
				t.Fatalf("waiter %d: payload=%q published=%v, want the published payload (late dissolve unfroze the outcome)",
					i, r.payload, r.published)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("waiter %d did not wake within 2s after publish", i)
		}
	}
}
