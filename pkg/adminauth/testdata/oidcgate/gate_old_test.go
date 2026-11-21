package adminauth

import (
	"context"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Timing-gate case for the ORIGINAL 371c50b9 test support, run by the
// qualification via go's -overlay: pkg/adminauth's oidc_boundary_test.go is
// replaced with the byte-identical 371c50b9 original (newBoundaryProvider,
// exchangeWith, exchange — no adoptFreshKid exists in that source), this
// file is added, and go-oidc/v3's jwks.go is overlaid with the instrumented
// testdata copy (one-shot writer and reader-snapshot gates).
//
// Frozen outcome (the runner enforces exactly this):
//
//   - TestGateRetiredKidStaleWindow_OriginalBehaviorFails MUST FAIL with
//     "evicted retired kid now fails closed on the same long-lived client: must fail closed"
//
// The failure must be the named behavioral failure: both gate arrivals
// must be observed first; a compile error, a zero-discovery run or a
// gate-arrival guard firing are setup failures, never a pass and never
// the expected result.
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

// gateFinalDeny is byte-identical to the helper in the gate fixture: the
// REAL final retired-kid exchange runs under the one-shot reader-snapshot
// gate, the reader must arrive while holding the keyset RLock, the k4
// writer is released first, the reader second, and the unchanged deny
// oracle is evaluated against the pre-release snapshot. No sleeps, no
// polling.
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

// TestGateRetiredKidStaleWindow_OriginalBehaviorFails runs the ORIGINAL
// 371c50b9 synchronization (plain exchangeWith steps, no cache-write
// barrier — exactly this source's own test pattern) with the k4 cache
// writer held at the gate: the k4 exchange returns with the CALLER
// holding [k2, k4] from the inflight result while the cache still
// contains [k1, k2]. The identical final helper then snapshots that
// stale cache while holding the RLock, releases the writer, releases the
// reader, and the retired-kid deny must observe stale acceptance and
// fail — the real stale-cache effect, deterministically held open.
func TestGateRetiredKidStaleWindow_OriginalBehaviorFails(t *testing.T) {
	p := newBoundaryProvider(t)
	c, err := NewOIDCClient(context.Background(), p.server.URL, "cid", "sec", "https://adm/cb")
	if err != nil {
		t.Fatalf("NewOIDCClient: %v", err)
	}

	exchangeWith(t, c, true, "warmup k1") // cache: [k1]

	p.setPublished("k1", "k2")
	p.setSignKid("k2")
	exchangeWith(t, c, true, "forward rotation adopts k2") // refetch; cache: [k1, k2]

	p.setPublished("k2") // retire k1
	p.setSignKid("k1")
	exchangeWith(t, c, true, "retired kid still verifies from cache (transient retention, cache untouched)")

	p.setPublished("k2", "k4") // next rotation lands
	p.setSignKid("k4")
	arrive, _ := oidc.ArmWriterGate()
	t.Cleanup(oidc.ReleaseWriterGate)
	// Caller-side k4 verifies from the inflight result while the writer
	// parks after done(); the cache still holds [k1, k2].
	exchangeWith(t, c, true, "unknown kid k4 forces a refetch")
	gateArrived(t, arrive)

	// Writer still parked — this original synchronization has no barrier
	// and no release of its own; the identical final helper releases it.
	p.setSignKid("k1")
	gateFinalDeny(t, c) // identical final helper; must Fatalf on stale acceptance
}
