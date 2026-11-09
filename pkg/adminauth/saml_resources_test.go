package adminauth

// N04-P02-T10 independent verification corpus (test-only): SAML resource
// bounds at the unit level.
//
// REPLAY CAP — the assertion replay cache never prunes a fresh entry (a
// fresh entry guards a still-valid assertion: pruning one would re-admit a
// replay), and its documented growth beyond the soft cap is linear in
// verified logins, exactly once per assertion ID under concurrency.
// REFRESH CONCURRENCY — failed refresh storms (HTTP 500 and descriptor-free
// documents) leave the cached ServiceProvider pointer untouched while
// concurrent readers keep seeing a consistent view; a successful refresh
// storm swaps the pointer atomically and readers never observe a torn state.

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestSAML_ReplayCap_FreshEntriesNeverPruned pins the safety-critical
// property of the replay cache: churn past the soft cap prunes ONLY expired
// entries. Every fresh entry — including the earliest of a full cap plus
// another full cap of churn — stays refused on re-presentation, and the
// service keeps accepting brand-new assertion IDs.
func TestSAML_ReplayCap_FreshEntriesNeverPruned(t *testing.T) {
	sp := &SAMLSP{replay: make(map[string]time.Time)}

	id := func(i int) string { return fmt.Sprintf("_assertion-%06d", i) }

	// Fill to exactly the cap: every ID accepted exactly once.
	for i := 0; i < assertionReplayCap; i++ {
		require.True(t, sp.MarkAssertionSeen(id(i)), "first presentation of %s must be accepted", id(i))
	}
	require.Len(t, sp.replay, assertionReplayCap)
	for _, probe := range []int{0, assertionReplayCap / 2, assertionReplayCap - 1} {
		require.False(t, sp.MarkAssertionSeen(id(probe)), "re-presentation of %s must be refused", id(probe))
	}

	// A full cap of additional churn: no entry is expired, so nothing may
	// be pruned — the cache grows to 2×cap (documented: bounded by the
	// verified-login rate, drained by TTL expiry).
	for i := assertionReplayCap; i < 2*assertionReplayCap; i++ {
		require.True(t, sp.MarkAssertionSeen(id(i)), "first presentation of %s must be accepted", id(i))
	}
	require.Len(t, sp.replay, 2*assertionReplayCap,
		"fresh entries must never be pruned to make room")

	// The whole range — earliest through latest — must still refuse.
	for _, probe := range []int{0, 1, assertionReplayCap - 1, assertionReplayCap, 2*assertionReplayCap - 1} {
		require.False(t, sp.MarkAssertionSeen(id(probe)),
			"fresh entry %s must survive the churn (a pruned fresh entry re-admits a replay)", id(probe))
	}

	// A brand-new assertion ID is still accepted: the cap never wedges the
	// service shut.
	require.True(t, sp.MarkAssertionSeen("_assertion-brand-new"))
}

// TestSAML_ReplayCap_ConcurrentFirstPresentation races concurrent inserters
// at the guard: every assertion ID is accepted exactly once, duplicates are
// refused, and the map ends with exactly the number of unique IDs inserted
// (under -race this also validates the replayMu discipline).
func TestSAML_ReplayCap_ConcurrentFirstPresentation(t *testing.T) {
	sp := &SAMLSP{replay: make(map[string]time.Time)}

	const workers = 8
	const perWorker = 256

	var accepted atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				id := fmt.Sprintf("_race-%02d-%04d", worker, i)
				if sp.MarkAssertionSeen(id) {
					accepted.Add(1)
				} else {
					t.Errorf("first presentation of %s was refused", id)
				}
			}
		}(w)
	}
	wg.Wait()

	require.Equal(t, int64(workers*perWorker), accepted.Load())
	require.Len(t, sp.replay, workers*perWorker)

	// Post-storm duplicates: all refused.
	for w := 0; w < workers; w++ {
		for i := 0; i < perWorker; i += 32 {
			require.False(t, sp.MarkAssertionSeen(fmt.Sprintf("_race-%02d-%04d", w, i)))
		}
	}
}

// TestSAML_RefreshMetadata_FailureStormsLeaveCacheUntouched hammers
// RefreshMetadata with a failing (HTTP 500) and then a degraded
// (descriptor-free) metadata endpoint. Every refresh must fail, the cached
// ServiceProvider pointer must survive unchanged, and concurrent readers
// must keep observing a consistent, parseable view throughout.
func TestSAML_RefreshMetadata_FailureStormsLeaveCacheUntouched(t *testing.T) {
	server, _, fail, degrade, _ := rotatableMetadataServer(t)
	sp, err := NewSAMLSP(context.Background(), samlTestOptions(server.URL+"/metadata"))
	if err != nil {
		t.Fatalf("NewSAMLSP: %v", err)
	}

	entityID := sp.IDPEntityID()
	require.NotEmpty(t, entityID)
	before := sp.currentSP()
	require.NotNil(t, before, "the SP must be armed before the storms")

	stop := make(chan struct{})
	var readerErrs atomic.Int64
	readers := &sync.WaitGroup{}
	for r := 0; r < 4; r++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				md := sp.SPMetadata()
				if md == nil || len(md.SPSSODescriptors) == 0 {
					readerErrs.Add(1)
					continue
				}
				if sp.IDPEntityID() != entityID {
					readerErrs.Add(1)
				}
				if sp.currentSP() == nil {
					readerErrs.Add(1)
				}
			}
		}()
	}

	// Storm 1: HTTP 500.
	fail(true)
	var wg sync.WaitGroup
	errCount := make([]error, 8)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			errCount[g] = sp.RefreshMetadata(context.Background())
		}(g)
	}
	wg.Wait()
	for g, err := range errCount {
		require.Error(t, err, "refresh %d against a failing endpoint must error", g)
	}
	require.Same(t, before, sp.currentSP(), "a failed refresh storm must leave the cached SP pointer untouched")

	// Storm 2: descriptor-free document.
	fail(false)
	degrade(true)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := sp.RefreshMetadata(context.Background()); err == nil {
				t.Error("refresh against a descriptor-free document must error")
			}
		}()
	}
	wg.Wait()
	degrade(false)
	require.Same(t, before, sp.currentSP(), "a refused refresh storm must leave the cached SP pointer untouched")

	close(stop)
	readers.Wait()
	require.Zero(t, readerErrs.Load(), "concurrent readers must never observe a torn or empty SP view")

	// The cached metadata still validates identity-wise after the storms.
	require.Equal(t, entityID, sp.IDPEntityID())
}

// TestSAML_RefreshMetadata_ConcurrentSuccessSwapsAtomically races successful
// refreshes against readers: the pointer swap is atomic, readers never see a
// torn view, and the final state is a fully working SP whose metadata equals
// the currently published identity.
func TestSAML_RefreshMetadata_ConcurrentSuccessSwapsAtomically(t *testing.T) {
	server, _, _, _, _ := rotatableMetadataServer(t)
	sp, err := NewSAMLSP(context.Background(), samlTestOptions(server.URL+"/metadata"))
	if err != nil {
		t.Fatalf("NewSAMLSP: %v", err)
	}

	entityID := sp.IDPEntityID()
	spCertBefore := sp.currentSP().Certificate
	stop := make(chan struct{})
	readers := &sync.WaitGroup{}
	var readerErrs atomic.Int64
	for r := 0; r < 4; r++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				md := sp.SPMetadata()
				if md == nil || md.EntityID == "" || len(md.SPSSODescriptors) == 0 {
					readerErrs.Add(1)
					continue
				}
				if _, err := sp.NewAuthnRequest(""); err != nil {
					readerErrs.Add(1)
				}
				if got := sp.IDPEntityID(); got != entityID {
					readerErrs.Add(1)
				}
			}
		}()
	}

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := sp.RefreshMetadata(context.Background()); err != nil {
				t.Errorf("refresh: %v", err)
			}
		}()
	}
	wg.Wait()

	close(stop)
	readers.Wait()
	require.Zero(t, readerErrs.Load(), "concurrent readers must never observe a torn SP view")

	// Final state: the SP identity is untouched (refresh swaps IdP metadata
	// only) and the cached metadata is the published one.
	require.Equal(t, entityID, sp.IDPEntityID())
	require.Equal(t, "https://admin.test", sp.currentSP().EntityID)
	require.Equal(t, spCertBefore, sp.currentSP().Certificate, "refresh must not disturb the SP signing identity")
	require.NotNil(t, sp.currentSP().IDPMetadata)
}
