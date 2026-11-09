package cli

// FIX-02 (CA-04) durable regressions: a lifecycle hydrated from the durable
// record must load the previous pack too, so a rollback restores the REAL
// previous detector chain. A rollback that only swaps the version label
// while the active hook falls back to the built-ins is a false enforcement
// claim. A missing or corrupt previous pack fails closed: explicit error,
// no durable CAS write, and the active pack keeps enforcing.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/reireirei/yabanin/pkg/guardhooks"
	"github.com/reireirei/yabanin/pkg/policystore"
)

// TestHydrateRollbackRestoresPreviousPackDetectors pins CA-04: a lifecycle
// hydrated from the durable record (active alpha@2, previous golden@1) must
// load the previous pack, so the post-restart rollback restores the real
// golden detectors — not the built-in chain under the golden version label.
func TestHydrateRollbackRestoresPreviousPackDetectors(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	writeVersionedPack(t, root, "golden", "1", "GOLDEN_PRIOR_[A-Z]+")
	writeVersionedPack(t, root, "alpha", "2", "ALPHA_ACTIVE_[A-Z]+")
	store := &scriptedGuardStore{state: policystore.GuardPackState{ActiveVersion: "alpha@2", PreviousVersion: "golden@1"}}
	lifecycle, err := hydrateGuardPackLifecycle(ctx, store, testLogger(), guardhooks.ModeDeny, root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := lifecycle.ActiveHook().Apply("ALPHA_ACTIVE_VALUE"); !errors.Is(err, guardhooks.ErrDenied) {
		t.Fatalf("hydrated lifecycle does not enforce the durable active pack: %v", err)
	}
	if err := lifecycle.Rollback(ctx); err != nil {
		t.Fatalf("rollback right after hydration: %v", err)
	}
	if got := store.casCalls(); len(got) != 1 || got[0] != "alpha@2->golden@1" {
		t.Fatalf("rollback CAS calls = %v, want [alpha@2->golden@1]", got)
	}
	// The payoff: the restored chain is the REAL previous pack — golden's
	// detector denies its pattern where the built-in chain would let it pass.
	if _, _, err := lifecycle.ActiveHook().Apply("GOLDEN_PRIOR_VALUE"); !errors.Is(err, guardhooks.ErrDenied) {
		t.Fatalf("rollback after hydration must restore the real previous detector, got %v", err)
	}
	if _, _, err := lifecycle.ActiveHook().Apply("ALPHA_ACTIVE_VALUE"); err != nil {
		t.Fatalf("rolled-back chain must not keep enforcing the rolled-back pack: %v", err)
	}
}

// TestReconcileIdenticalAdoptRollbackRestoresPreviousPackDetectors pins the
// gateway restart path: an identical restart adopting the durable active
// pack loads the durable previous pack too, so its rollback restores the
// real previous detectors.
func TestReconcileIdenticalAdoptRollbackRestoresPreviousPackDetectors(t *testing.T) {
	root := t.TempDir()
	writeVersionedPack(t, root, "golden", "1", "GOLDEN_RESTART_[A-Z]+")
	writeVersionedPack(t, root, "alpha", "2", "ALPHA_RESTART_[A-Z]+")
	store := &scriptedGuardStore{state: policystore.GuardPackState{ActiveVersion: "alpha@2", PreviousVersion: "golden@1"}}
	lifecycle, err := reconcileForTest(t, store, root, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	if calls := store.casCalls(); len(calls) != 0 {
		t.Fatalf("identical restart ran the CAS: %v", calls)
	}
	if _, _, err := lifecycle.ActiveHook().Apply("ALPHA_RESTART_VALUE"); !errors.Is(err, guardhooks.ErrDenied) {
		t.Fatalf("adopted active pack not enforced: %v", err)
	}
	if err := lifecycle.Rollback(context.Background()); err != nil {
		t.Fatalf("rollback after adopt: %v", err)
	}
	if got := store.casCalls(); len(got) != 1 || got[0] != "alpha@2->golden@1" {
		t.Fatalf("rollback CAS calls = %v, want [alpha@2->golden@1]", got)
	}
	if _, _, err := lifecycle.ActiveHook().Apply("GOLDEN_RESTART_VALUE"); !errors.Is(err, guardhooks.ErrDenied) {
		t.Fatalf("rollback after adopt must restore the real previous detector, got %v", err)
	}
}

// TestLostRaceAdoptRollbackRestoresPreviousPackDetectors pins the lost-race
// path: the adopted winner's previous pack is loaded too, so even a replica
// that lost the startup race can return to the pre-winner detectors.
func TestLostRaceAdoptRollbackRestoresPreviousPackDetectors(t *testing.T) {
	root := t.TempDir()
	writeVersionedPack(t, root, "golden", "1", "GOLDEN_LOST_[A-Z]+")
	writeVersionedPack(t, root, "alpha", "2", "ALPHA_LOST_[A-Z]+")
	store := &scriptedGuardStore{
		state:  policystore.GuardPackState{ActiveVersion: "alpha@2", PreviousVersion: "golden@1"},
		casErr: policystore.ErrGuardPackConflict,
	}
	lifecycle, err := reconcileForTest(t, store, root, "golden")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := lifecycle.ActiveHook().Apply("ALPHA_LOST_VALUE"); !errors.Is(err, guardhooks.ErrDenied) {
		t.Fatalf("durable winner not enforced after the lost race: %v", err)
	}
	store.casErr = nil
	if err := lifecycle.Rollback(context.Background()); err != nil {
		t.Fatalf("rollback after lost-race adopt: %v", err)
	}
	// Two CAS calls, both alpha@2 -> golden@1: the losing startup activation
	// attempt and the rollback. The adopt itself wrote nothing.
	got := store.casCalls()
	if len(got) != 2 || got[0] != "alpha@2->golden@1" || got[1] != "alpha@2->golden@1" {
		t.Fatalf("rollback CAS calls = %v, want the lost activation attempt plus the rollback", got)
	}
	if _, _, err := lifecycle.ActiveHook().Apply("GOLDEN_LOST_VALUE"); !errors.Is(err, guardhooks.ErrDenied) {
		t.Fatalf("rollback must restore the real pre-winner detector, got %v", err)
	}
}

// TestHydrateUnrestorablePreviousPackFailsClosed pins the missing/corrupt
// previous posture: hydration still serves the durable active pack, but the
// rollback refuses BEFORE the CAS with an explicit error — no durable write,
// no hook swap, never a built-in chain claimed as the previous pack.
func TestHydrateUnrestorablePreviousPackFailsClosed(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	writeVersionedPack(t, root, "alpha", "2", "ALPHA_GHOST_[A-Z]+")
	writeVersionedPack(t, root, "corrupt", "1", "CORRUPT_PRIOR_[A-Z]+")
	// Corrupt the previous pack's detector payload (digest mismatch).
	if err := os.WriteFile(filepath.Join(root, "corrupt", "detector.json"), []byte(`{"detectors":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, previous := range map[string]string{
		"missing previous": "ghost@1",
		"corrupt previous": "corrupt@1",
	} {
		t.Run(name, func(t *testing.T) {
			store := &scriptedGuardStore{state: policystore.GuardPackState{ActiveVersion: "alpha@2", PreviousVersion: previous}}
			lifecycle, err := hydrateGuardPackLifecycle(ctx, store, testLogger(), guardhooks.ModeDeny, root, nil)
			if err != nil {
				t.Fatal(err)
			}
			// The durable ACTIVE pack keeps enforcing ...
			if _, _, err := lifecycle.ActiveHook().Apply("ALPHA_GHOST_VALUE"); !errors.Is(err, guardhooks.ErrDenied) {
				t.Fatalf("active pack must keep enforcing despite an unloadable previous: %v", err)
			}
			// ... while the rollback fails closed before the CAS.
			if err := lifecycle.Rollback(ctx); err == nil {
				t.Fatal("rollback without the previous detector chain must fail closed")
			}
			if got := store.casCalls(); len(got) != 0 {
				t.Fatalf("failed rollback must not write the durable row: %v", got)
			}
			if _, _, err := lifecycle.ActiveHook().Apply("ALPHA_GHOST_VALUE"); !errors.Is(err, guardhooks.ErrDenied) {
				t.Fatalf("failed rollback must leave the active pack enforcing: %v", err)
			}
		})
	}
}

// TestReconcileIdenticalAdoptUnrestorablePreviousKeepsActive pins the
// gateway-startup variant of the same posture: the adopt succeeds for the
// active pack, the unrestorable previous is reported, and the rollback
// fails closed instead of claiming the previous pack.
func TestReconcileIdenticalAdoptUnrestorablePreviousKeepsActive(t *testing.T) {
	root := t.TempDir()
	writeVersionedPack(t, root, "alpha", "2", "ALPHA_NOREST_[A-Z]+")
	store := &scriptedGuardStore{state: policystore.GuardPackState{ActiveVersion: "alpha@2", PreviousVersion: "ghost@1"}}
	lifecycle, err := reconcileForTest(t, store, root, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := lifecycle.ActiveHook().Apply("ALPHA_NOREST_VALUE"); !errors.Is(err, guardhooks.ErrDenied) {
		t.Fatalf("adopted active pack not enforced: %v", err)
	}
	if err := lifecycle.Rollback(context.Background()); err == nil {
		t.Fatal("rollback without the previous detector chain must fail closed")
	}
	if got := store.casCalls(); len(got) != 0 {
		t.Fatalf("failed rollback must not write the durable row: %v", got)
	}
	if _, _, err := lifecycle.ActiveHook().Apply("ALPHA_NOREST_VALUE"); !errors.Is(err, guardhooks.ErrDenied) {
		t.Fatalf("failed rollback must leave the active pack enforcing: %v", err)
	}
}
