package cli

// Real-Postgres integration for the durable guard-pack reconciliation
// (testdb posture): the gateway lifecycle construction drives the actual
// guard_pack_state row (migration 0013) through policystore.GuardPolicyCAS.
//
// Locked scenarios (the two-replica story, one durable row):
//  1. replica B bootstrap: the first env-configured startup CAS-bootstraps
//     the row (core → golden@1);
//  2. replica A (the admin surface) API-activates alpha@2 → the row moves;
//  3. replica B restarts with the ALIGNED env pack: it adopts A's activation
//     through the durable CAS with ZERO CAS writes — replicas adopt API
//     activations without any replica-local coordination;
//  4. a stale-env replica re-asserts through the CAS (documented posture:
//     env-based startup activation keeps working; the row records it);
//  5. the admin hydration rebases on the row, so a rollback right after a
//     restart CASes the live durable transition.

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/reireirei/yabanin/pkg/guardhooks"
	"github.com/reireirei/yabanin/pkg/policystore"
	"github.com/reireirei/yabanin/pkg/testdb"
)

// countingGuardStore delegates to the real durable CAS and counts writes so
// the adopt path can prove it did not touch the row.
type countingGuardStore struct {
	GuardPackPolicyStore
	mu       sync.Mutex
	casCount int
}

func (c *countingGuardStore) CompareAndSwap(ctx context.Context, from, to string) error {
	c.mu.Lock()
	c.casCount++
	c.mu.Unlock()
	return c.GuardPackPolicyStore.CompareAndSwap(ctx, from, to)
}

func (c *countingGuardStore) casWrites() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.casCount
}

func TestGuardPackDurableReconcile_Integration(t *testing.T) {
	pool := testdb.Postgres(t)
	ctx := context.Background()
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, `DELETE FROM guard_pack_state WHERE id = 1`); err != nil {
			t.Errorf("cleanup guard_pack_state: %v", err)
		}
	})
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	packRoot := t.TempDir()
	writeVersionedPack(t, packRoot, "golden", "1", "GOLDEN_INT_[A-Z]+")
	writeVersionedPack(t, packRoot, "alpha", "2", "ALPHA_INT_[A-Z]+")

	// The coordination point, wrapped so the adopt path can prove it is
	// read-only (the durable CAS itself is exercised for real underneath).
	cas := &countingGuardStore{GuardPackPolicyStore: policystore.NewGuardPolicyCAS(pool)}
	reconcile := func(packIDs ...string) *guardhooks.PackLifecycle {
		t.Helper()
		lifecycle, err := reconcileGuardPackLifecycle(ctx, cas, logger, guardhooks.ModeDeny, packRoot, testPackSources(t, packRoot, packIDs...), nil)
		if err != nil {
			t.Fatalf("reconcile %v: %v", packIDs, err)
		}
		if lifecycle == nil {
			t.Fatalf("reconcile %v degraded to built-in hooks unexpectedly", packIDs)
		}
		return lifecycle
	}

	// 1. Replica B bootstrap: no durable record → CAS bootstraps core→golden@1.
	b1 := reconcile("golden")
	if _, _, err := b1.ActiveHook().Apply("GOLDEN_INT_VALUE"); !isGuardDenied(err) {
		t.Fatalf("bootstrap hook not enforced: %v", err)
	}
	state, err := cas.ActiveGuardPackState(ctx)
	if err != nil || state.ActiveVersion != "golden@1" || state.PreviousVersion != "core" {
		t.Fatalf("durable row after bootstrap = %+v, %v", state, err)
	}
	writesAfterBootstrap := cas.casWrites()
	if writesAfterBootstrap != 1 {
		t.Fatalf("bootstrap must be exactly one durable CAS write, got %d", writesAfterBootstrap)
	}

	// 2. Replica A (admin surface) activates alpha@2 through the same row —
	// exactly what the admin handler drives its hydrated lifecycle through.
	a := mustHydrated(t, ctx, cas, packRoot) // hydration rebases A onto the durable active golden@1
	if _, _, err := a.ActiveHook().Apply("GOLDEN_INT_VALUE"); !isGuardDenied(err) {
		t.Fatalf("replica A hydration must enforce the durable active pack: %v", err)
	}
	if _, err := stageAndActivate(t, a, packRoot, "alpha"); err != nil {
		t.Fatalf("API-path activation: %v", err)
	}
	state, err = cas.ActiveGuardPackState(ctx)
	if err != nil || state.ActiveVersion != "alpha@2" || state.PreviousVersion != "golden@1" {
		t.Fatalf("durable row after API activation = %+v, %v", state, err)
	}
	writesAfterAPIActivation := cas.casWrites()

	// 3. Replica B restarts with the ALIGNED env pack: it adopts A's API
	// activation through the durable CAS with zero CAS writes.
	b2 := reconcile("alpha")
	if _, _, err := b2.ActiveHook().Apply("ALPHA_INT_VALUE"); !isGuardDenied(err) {
		t.Fatalf("replica B must adopt the API-activated pack: %v", err)
	}
	if cas.casWrites() != writesAfterAPIActivation {
		t.Fatalf("adoption must not write the durable row (writes %d → %d)", writesAfterAPIActivation, cas.casWrites())
	}

	// 4. A stale-env replica (still listing golden) re-asserts through the
	// CAS; the row records the transition (documented env posture).
	b3 := reconcile("golden")
	if _, _, err := b3.ActiveHook().Apply("GOLDEN_INT_VALUE"); !isGuardDenied(err) {
		t.Fatalf("re-asserted pack not enforced: %v", err)
	}
	if cas.casWrites() != writesAfterAPIActivation+1 {
		t.Fatalf("stale-env restart must re-assert through exactly one CAS write (got %d)", cas.casWrites())
	}
	state, err = cas.ActiveGuardPackState(ctx)
	if err != nil || state.ActiveVersion != "golden@1" || state.PreviousVersion != "alpha@2" {
		t.Fatalf("durable row after re-assertion = %+v, %v", state, err)
	}

	// 5. Admin restart + immediate rollback: hydration rebases onto the live
	// row, loads the durable active AND previous packs, so the rollback
	// CASes the live durable transition (golden@1 → alpha@2) and restores
	// the REAL alpha@2 detector chain — the hydrated lifecycle's prior is
	// the loaded previous pack, never a version-label-only swap onto the
	// built-ins.
	a2 := mustHydrated(t, ctx, cas, packRoot)
	if _, _, err := a2.ActiveHook().Apply("GOLDEN_INT_VALUE"); !isGuardDenied(err) {
		t.Fatalf("hydrated lifecycle must enforce the durable active pack: %v", err)
	}
	if err := a2.Rollback(ctx); err != nil {
		t.Fatalf("rollback right after a restart (hydration payoff): %v", err)
	}
	state, err = cas.ActiveGuardPackState(ctx)
	if err != nil || state.ActiveVersion != "alpha@2" || state.PreviousVersion != "golden@1" {
		t.Fatalf("durable row after post-restart rollback = %+v, %v", state, err)
	}
	if _, _, err := a2.ActiveHook().Apply("ALPHA_INT_VALUE"); !isGuardDenied(err) {
		t.Fatalf("post-restart rollback must restore the real previous detector chain: %v", err)
	}
	if _, _, err := a2.ActiveHook().Apply("GOLDEN_INT_VALUE"); isGuardDenied(err) {
		t.Fatalf("post-restart rollback must stop enforcing the rolled-back pack: %v", err)
	}
	// A gateway replica starting now with the aligned env pack adopts the
	// rolled-back durable state without touching the row.
	b4 := reconcile("alpha")
	if cas.casWrites() != writesAfterAPIActivation+2 { // +1 re-assertion, +1 rollback; the adopt writes nothing
		t.Fatalf("post-rollback restart must adopt without CAS writes (got %d)", cas.casWrites())
	}
	if _, _, err := b4.ActiveHook().Apply("ALPHA_INT_VALUE"); !isGuardDenied(err) {
		t.Fatalf("replica must have adopted the durable rollback: %v", err)
	}
	if _, _, err := b4.ActiveHook().Apply("GOLDEN_INT_VALUE"); isGuardDenied(err) {
		t.Fatalf("replica must not enforce the rolled-back pack: %v", err)
	}
}

// mustHydrated runs the admin-side read-only hydration (the exact core the
// admin runner drives) against the wrapped durable CAS.
func mustHydrated(t *testing.T, ctx context.Context, cas GuardPackPolicyStore, packRoot string) *guardhooks.PackLifecycle {
	t.Helper()
	lifecycle, err := hydrateGuardPackLifecycle(ctx, cas, slog.New(slog.NewTextHandler(os.Stderr, nil)), guardhooks.ModeDeny, packRoot, nil)
	if err != nil {
		t.Fatalf("hydrate: %v", err)
	}
	return lifecycle
}

// stageAndActivate drives the admin-handler activation shape: stage the
// requested pack, then publish through the durable CAS.
func stageAndActivate(t *testing.T, lifecycle *guardhooks.PackLifecycle, packRoot, packID string) (string, error) {
	t.Helper()
	manifest, err := os.ReadFile(filepath.Join(packRoot, packID, "manifest.json")) // #nosec G304 -- both components are test-controlled fixture paths, never user input.
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.Stage(filepath.Join(packRoot, packID), manifest); err != nil {
		return "", err
	}
	return lifecycle.StagedVersion(), lifecycle.Activate(context.Background())
}

func isGuardDenied(err error) bool {
	return errors.Is(err, guardhooks.ErrDenied)
}
