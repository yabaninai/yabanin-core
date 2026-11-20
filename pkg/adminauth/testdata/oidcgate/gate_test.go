package adminauth

import (
	"context"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Deterministic timing-gate cases for the retired-kid invariant, run by the
// qualification against the CURRENT sources via go's -overlay: this file is
// added to pkg/adminauth while go-oidc/v3's jwks.go is overlaid with the
// instrumented testdata copy (one-shot writer gate between inflight.done and
// the locked cachedKeys assignment, one-shot reader-snapshot gate in
// keysFromCache). The real client, verifier, JWKS path, provider and oracles
// are untouched; with no gate armed, the overlaid dependency is inert.
//
// The corrected and omitted cases differ in EXACTLY ONE operation: whether
// the real adoptFreshKid(k3) barrier ran. Neither releases the parked k4
// writer early: the corrected case runs that barrier as a nested t.Run
// subtest whose first keyset read parks at the reader gate, and the fixed
// writer-then-reader release lets the real barrier logic force the parked
// write to land; the omitted case keeps the writer parked until the
// identical final helper releases it. Both evaluate the unchanged oracle
// through the identical gateFinalDeny helper — same arming, same fixed
// release order, same reader snapshot.
//
// Frozen outcomes (the runner enforces exactly these):
//
//   - TestGateRetiredKidStaleWindow_CorrectedBarrierPasses MUST PASS
//   - TestGateRetiredKidStaleWindow_OmittedBarrierFails    MUST FAIL with
//     "evicted retired kid now fails closed on the same long-lived client: must fail closed"
//
// (The ORIGINAL 371c50b9 case lives in gate_old_test.go, run against the
// byte-identical original test support, using the identical final helper.)
//
// Every case must first observe its gate arrivals; a miss is a setup
// failure, never a pass. t.Cleanup releases both gates so nothing stays
// parked past its test.
func gateArrived(t *testing.T, arrive <-chan struct{}) {
	t.Helper()
	select {
	case <-arrive:
		return
	case <-time.After(2 * time.Second):
		oidc.ReleaseWriterGate()
		t.Fatalf("gate: writer never arrived at the k4 refetch gate")
	}
}

// gateFinalDeny runs the REAL final retired-kid exchange under the
// one-shot reader-snapshot gate and evaluates the unchanged committed
// deny oracle against the snapshot the reader took while holding the
// keyset RLock: arm the reader gate, run the exchange in a goroutine,
// require the reader to arrive (a miss is a setup failure), release the
// k4 writer (a no-op when none is parked — in the corrected case the k3
// barrier already forced it to finish), then release the reader, in that
// fixed order. The writer cannot replace cachedKeys for that reader
// while it holds the RLock, and the exchange evaluates the already
// snapshotted slice, so the denial is judged against keys that predate
// any release. No sleeps, no polling.
func gateFinalDeny(t *testing.T, c *OIDCClient) {
	t.Helper()
	arrive, _ := oidc.ArmReaderGate()
	t.Cleanup(oidc.ReleaseReaderGate)
	type gateResult struct{ err error }
	done := make(chan gateResult, 1)
	go func() {
		_, err := c.ExchangeAndVerify(context.Background(), "code", "boundary-nonce", "verifier")
		done <- gateResult{err}
	}()
	select {
	case <-arrive:
	case <-time.After(2 * time.Second):
		oidc.ReleaseReaderGate()
		t.Fatalf("gate: final retired-kid exchange never reached the keyset snapshot gate")
	}
	oidc.ReleaseWriterGate() // fixed order: writer first, reader second
	oidc.ReleaseReaderGate()
	select {
	case r := <-done:
		if r.err == nil {
			t.Fatalf("evicted retired kid now fails closed on the same long-lived client: must fail closed")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("gate: final retired-kid exchange never completed after release")
	}
}

// TestGateRetiredKidStaleWindow_CorrectedBarrierPasses runs the committed
// 389da54 ladder with the writer held at the gate across the k4 adoption
// and NEVER released early. The real k3 barrier (adoptFreshKid, verbatim,
// unmodified) runs as a nested t.Run subtest in a goroutine while the k4
// writer is still parked; its first keyset read parks at the one-shot
// reader gate, and only after that arrival does this test release the k4
// writer and the reader in the fixed order. The barrier cannot complete
// while the writer is parked — every refetch it triggers joins the parked
// k4 inflight result, which has no k3 — so the nested subtest passing is
// what proves the real barrier forced the parked [k2, k4] cache write to
// land. The final retired-kid deny then runs through the IDENTICAL
// gateFinalDeny helper. No sleeps, no polling, no cloned barrier.
func TestGateRetiredKidStaleWindow_CorrectedBarrierPasses(t *testing.T) {
	p := newBoundaryProvider(t)
	c, err := NewOIDCClient(context.Background(), p.server.URL, "cid", "sec", "https://adm/cb")
	if err != nil {
		t.Fatalf("NewOIDCClient: %v", err)
	}

	exchangeWith(t, c, true, "warmup k1") // fresh keyset: refetch [k1]; cache: [k1]

	p.setPublished("k1", "k2")
	adoptFreshKid(t, p, c, "k2", "forward rotation adopts k2") // refetch; cache: [k1, k2]

	p.setPublished("k2") // retire k1
	p.setSignKid("k1")
	exchangeWith(t, c, true, "retired kid still verifies from cache (transient retention, cache untouched)")

	// The next rotation lands with the writer held at the gate: the k4
	// adoption verifies caller-side from the inflight result while the
	// [k2, k4] cache write is deterministically parked. NO release here —
	// the writer stays parked until the fixed-order release below.
	p.setPublished("k2", "k4")
	arrive, _ := oidc.ArmWriterGate()
	t.Cleanup(oidc.ReleaseWriterGate)
	adoptFreshKid(t, p, c, "k4", "unknown kid k4 forces a refetch")
	gateArrived(t, arrive)

	// The real k3 barrier, unmodified, as a nested subtest in a goroutine
	// (adoptFreshKid's Fatalf then runs on the subtest's own testing.T).
	p.setPublished("k2", "k4", "k3")
	readerArrive, _ := oidc.ArmReaderGate()
	t.Cleanup(oidc.ReleaseReaderGate)
	barrierDone := make(chan bool, 1)
	go func() {
		barrierDone <- t.Run("post-rotation-cache-write-barrier", func(t *testing.T) {
			adoptFreshKid(t, p, c, "k3", "post-rotation cache-write barrier")
		})
	}()
	select {
	case <-readerArrive: // the barrier's first keyset read is parked under RLock
	case <-time.After(2 * time.Second):
		oidc.ReleaseReaderGate()
		t.Fatalf("gate: barrier reader never reached the keyset snapshot gate")
	}
	oidc.ReleaseWriterGate() // fixed order: writer first, reader second
	oidc.ReleaseReaderGate()
	select {
	case ok := <-barrierDone:
		if !ok {
			t.Fatalf("gate: nested k3 barrier subtest failed")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("gate: nested k3 barrier subtest never completed")
	}

	p.setSignKid("k1")
	gateFinalDeny(t, c) // identical final helper; unchanged

	// Fresh client on the retired-key world: rejects without ever caching it.
	exchange(t, p, false, "fresh client rejects the retired kid")
	p.setSignKid("k2")
	exchange(t, p, true, "fresh client accepts the current kid")
}

// TestGateRetiredKidStaleWindow_OmittedBarrierFails is the corrected
// ladder with ONLY the k3 barrier omitted. Everything else is identical,
// including the final gateFinalDeny helper: the k4 writer stays parked
// until the helper releases it, the reader snapshots the still-stale
// [k1, k2] cache while holding the RLock, and the same unchanged oracle
// must then observe stale acceptance and fail.
func TestGateRetiredKidStaleWindow_OmittedBarrierFails(t *testing.T) {
	p := newBoundaryProvider(t)
	c, err := NewOIDCClient(context.Background(), p.server.URL, "cid", "sec", "https://adm/cb")
	if err != nil {
		t.Fatalf("NewOIDCClient: %v", err)
	}

	exchangeWith(t, c, true, "warmup k1")

	p.setPublished("k1", "k2")
	adoptFreshKid(t, p, c, "k2", "forward rotation adopts k2")

	p.setPublished("k2") // retire k1
	p.setSignKid("k1")
	exchangeWith(t, c, true, "retired kid still verifies from cache (transient retention, cache untouched)")

	p.setPublished("k2", "k4")
	arrive, _ := oidc.ArmWriterGate()
	t.Cleanup(oidc.ReleaseWriterGate)
	adoptFreshKid(t, p, c, "k4", "unknown kid k4 forces a refetch")
	gateArrived(t, arrive)

	// Barrier OMITTED — the ONLY behavioral difference from the corrected
	// case: the k4 cache write never lands, and the writer stays parked
	// until the identical final helper releases it.
	p.setPublished("k2", "k4", "k3")

	p.setSignKid("k1")
	gateFinalDeny(t, c) // identical final helper; must Fatalf on stale acceptance
}
