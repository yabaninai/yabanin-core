package guardhooks

// FIX-02 (CA-03) regressions: staging a candidate and a failed activation
// are history-neutral operations. The rollback CAS must always name the
// transition the activation history actually recorded — never the degenerate
// current -> current a history-rewriting stage produces.

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

// TestStageBetweenActivationsPreservesRollbackHistory pins CA-03: after
// activating A from the built-in chain, staging B (without activating) must
// leave previous at the built-in identity, so the rollback CASes A -> core —
// not the degenerate A -> A — and the restored chain is the one the history
// names.
func TestStageBetweenActivationsPreservesRollbackHistory(t *testing.T) {
	base := t.TempDir()
	rootA := filepath.Join(base, "alpha")
	manifestA := writeLifecyclePackIn(t, rootA, "user.alpha", "secret", "ALPHA_HISTORY_[A-Z]+")
	rootB := filepath.Join(base, "beta")
	manifestB := writeLifecyclePackIn(t, rootB, "user.beta", "credential", "BETA_HISTORY_[A-Z]+")

	cas := &lifecycleCAS{}
	lifecycle := NewPackLifecycle("core", ModeDeny, cas)
	if _, err := lifecycle.StageSources([]PackSource{{Root: rootA, Manifest: manifestA}}); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if cas.from != "core" || cas.to != "user.alpha@1" {
		t.Fatalf("activate CAS = %q -> %q, want core -> user.alpha@1", cas.from, cas.to)
	}
	if _, _, err := lifecycle.ActiveHook().Apply("ALPHA_HISTORY_VALUE"); !errors.Is(err, ErrDenied) {
		t.Fatalf("activated pack A not enforced: %v", err)
	}

	// Stage B without activating: the stage must not touch the history
	// (previous stays the built-in chain A was activated from).
	if _, err := lifecycle.StageSources([]PackSource{{Root: rootB, Manifest: manifestB}}); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if cas.from != "user.alpha@1" || cas.to != "core" {
		t.Fatalf("rollback CAS = %q -> %q, want user.alpha@1 -> core: staging rewrote the activation history", cas.from, cas.to)
	}
	if _, _, err := lifecycle.ActiveHook().Apply("ALPHA_HISTORY_VALUE"); err != nil {
		t.Fatalf("rollback must restore the chain the history names (A's prior was the built-ins): %v", err)
	}

	// The lifecycle stays usable: a fresh candidate activates from core.
	if _, err := lifecycle.StageSources([]PackSource{{Root: rootB, Manifest: manifestB}}); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if cas.from != "core" || cas.to != "user.beta@1" {
		t.Fatalf("post-rollback activate CAS = %q -> %q, want core -> user.beta@1", cas.from, cas.to)
	}
}

// TestFailedActivateLeavesActivationHistoryUntouched pins the other CA-03
// half: a losing CAS moves neither current nor previous, so the follow-up
// rollback still CASes the true recorded transition.
func TestFailedActivateLeavesActivationHistoryUntouched(t *testing.T) {
	base := t.TempDir()
	rootA := filepath.Join(base, "alpha")
	manifestA := writeLifecyclePackIn(t, rootA, "user.alpha", "secret", "ALPHA_FAILED_[A-Z]+")
	rootB := filepath.Join(base, "beta")
	manifestB := writeLifecyclePackIn(t, rootB, "user.beta", "credential", "BETA_FAILED_[A-Z]+")

	cas := &lifecycleCAS{}
	lifecycle := NewPackLifecycle("core", ModeDeny, cas)
	if _, err := lifecycle.StageSources([]PackSource{{Root: rootA, Manifest: manifestA}}); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.StageSources([]PackSource{{Root: rootB, Manifest: manifestB}}); err != nil {
		t.Fatal(err)
	}
	cas.err = errors.New("policy version conflict")
	if err := lifecycle.Activate(context.Background()); !errors.Is(err, cas.err) {
		t.Fatalf("expected the CAS failure to surface, got %v", err)
	}
	cas.err = nil
	// History untouched: current is still A and previous is still the
	// built-in chain, so the rollback CASes exactly A -> core.
	if err := lifecycle.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if cas.from != "user.alpha@1" || cas.to != "core" {
		t.Fatalf("rollback CAS after a failed activate = %q -> %q, want user.alpha@1 -> core", cas.from, cas.to)
	}
	if _, _, err := lifecycle.ActiveHook().Apply("ALPHA_FAILED_VALUE"); err != nil {
		t.Fatalf("rollback after a failed activate must restore the true previous chain: %v", err)
	}
}

// concurrentLifecycleCAS is a conflict-checked CAS that records the durable
// active version so the stage/activate storm can assert that the activated
// hook chain and the durable record always name the same pack.
type concurrentLifecycleCAS struct {
	mu      sync.Mutex
	version string
}

func (c *concurrentLifecycleCAS) CompareAndSwap(_ context.Context, from, to string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.version != from {
		return errors.New("policy version conflict")
	}
	c.version = to
	return nil
}

func (c *concurrentLifecycleCAS) activeVersion() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.version
}

// TestConcurrentStageActivateMatchesDurableRecord pins the concurrent
// stage/activate acceptance: whatever candidate wins the interleaving, the
// activated hook and the durable CAS record agree — a confirmed activation
// is never split across two candidates, and concurrent staging never breaks
// the hook readers.
func TestConcurrentStageActivateMatchesDurableRecord(t *testing.T) {
	base := t.TempDir()
	const packCount = 4
	roots := make([]string, packCount)
	manifests := make([][]byte, packCount)
	for i := 0; i < packCount; i++ {
		roots[i] = filepath.Join(base, fmt.Sprintf("pack%d", i))
		manifests[i] = writeLifecyclePackIn(t, roots[i], fmt.Sprintf("user.pack%d", i), "secret", fmt.Sprintf("PACK%d_CONCUR_[A-Z]+", i))
	}
	store := &concurrentLifecycleCAS{version: "core"}
	lifecycle := NewPackLifecycle("core", ModeDeny, store)

	var wg sync.WaitGroup
	var activateMu sync.Mutex
	for writer := 0; writer < 4; writer++ {
		wg.Add(1)
		go func(writer int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				pick := (writer + i) % packCount
				if _, err := lifecycle.StageSources([]PackSource{{Root: roots[pick], Manifest: manifests[pick]}}); err != nil {
					t.Errorf("stage: %v", err)
					return
				}
				activateMu.Lock()
				err := lifecycle.Activate(context.Background())
				if err != nil {
					activateMu.Unlock()
					continue
				}
				// The durable record names the actually activated candidate;
				// the active hook must enforce exactly that pack.
				active := store.activeVersion()
				hook := lifecycle.ActiveHook()
				activateMu.Unlock()
				enforced := false
				for j := 0; j < packCount; j++ {
					if active != fmt.Sprintf("user.pack%d@1", j) {
						continue
					}
					enforced = true
					if _, _, err := hook.Apply(fmt.Sprintf("PACK%d_CONCUR_VALUE", j)); !errors.Is(err, ErrDenied) {
						t.Errorf("durable record names %q but the active hook does not enforce it: %v", active, err)
						return
					}
				}
				if !enforced {
					t.Errorf("durable record names unknown version %q", active)
					return
				}
			}
		}(writer)
	}
	for reader := 0; reader < 2; reader++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				if hook := lifecycle.ActiveHook(); hook == nil {
					t.Error("ActiveHook() returned nil")
					return
				}
				_ = lifecycle.ShadowHook()
			}
		}()
	}
	wg.Wait()

	// After the storm the lifecycle stays consistent end-to-end: one more
	// stage/activate round trip must land hook and durable record on the
	// same candidate.
	if _, err := lifecycle.StageSources([]PackSource{{Root: roots[2], Manifest: manifests[2]}}); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := store.activeVersion(); got != "user.pack2@1" {
		t.Fatalf("final durable version = %q, want user.pack2@1", got)
	}
	if _, _, err := lifecycle.ActiveHook().Apply("PACK2_CONCUR_VALUE"); !errors.Is(err, ErrDenied) {
		t.Fatalf("final active hook does not enforce the durable version: %v", err)
	}
}

// TestAdoptStagedUnrestorableFailsRollbackClosed pins the CA-04 fail-closed
// posture at the lifecycle level: an adopt whose previous pack could not be
// loaded keeps the active chain enforcing, while the rollback refuses BEFORE
// the CAS — explicit error, no durable write, no hook swap. A later
// successful activation re-anchors the history and rollback works again.
func TestAdoptStagedUnrestorableFailsRollbackClosed(t *testing.T) {
	base := t.TempDir()
	rootA := filepath.Join(base, "alpha")
	manifestA := writeLifecyclePackIn(t, rootA, "user.alpha", "secret", "ALPHA_UNREST_[A-Z]+")
	rootB := filepath.Join(base, "beta")
	manifestB := writeLifecyclePackIn(t, rootB, "user.beta", "credential", "BETA_UNREST_[A-Z]+")

	cas := &lifecycleCAS{}
	lifecycle := NewPackLifecycle("user.alpha@1", ModeDeny, cas)
	if _, err := lifecycle.StageSources([]PackSource{{Root: rootA, Manifest: manifestA}}); err != nil {
		t.Fatal(err)
	}
	reason := errors.New(`read manifest for durable pack "user.prior": not on disk`)
	if err := lifecycle.AdoptStagedUnrestorable("user.prior@1", reason); err != nil {
		t.Fatalf("unrestorable adopt: %v", err)
	}
	if _, _, err := lifecycle.ActiveHook().Apply("ALPHA_UNREST_VALUE"); !errors.Is(err, ErrDenied) {
		t.Fatalf("unrestorable adopt must keep the active chain enforcing: %v", err)
	}
	// The rollback refuses before the CAS: nothing recorded, nothing swapped.
	if err := lifecycle.Rollback(context.Background()); !errors.Is(err, reason) {
		t.Fatalf("rollback must fail closed with the unrestorable reason, got %v", err)
	}
	if cas.from != "" {
		t.Fatalf("failed rollback must not write the CAS, got %q -> %q", cas.from, cas.to)
	}
	if _, _, err := lifecycle.ActiveHook().Apply("ALPHA_UNREST_VALUE"); !errors.Is(err, ErrDenied) {
		t.Fatalf("failed rollback must leave the active chain enforcing: %v", err)
	}
	// A successful activation re-anchors the history: the new prior is the
	// chain that was actually active, and rollback restores it for real.
	if _, err := lifecycle.StageSources([]PackSource{{Root: rootB, Manifest: manifestB}}); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Rollback(context.Background()); err != nil {
		t.Fatalf("rollback after re-anchoring activation: %v", err)
	}
	if cas.from != "user.beta@1" || cas.to != "user.alpha@1" {
		t.Fatalf("rollback CAS = %q -> %q, want user.beta@1 -> user.alpha@1", cas.from, cas.to)
	}
	if _, _, err := lifecycle.ActiveHook().Apply("ALPHA_UNREST_VALUE"); !errors.Is(err, ErrDenied) {
		t.Fatalf("rollback must restore the real re-anchored prior chain: %v", err)
	}
}

// TestAdoptStagedUnrestorableRejectsBuiltinPrevious pins the guard: the
// built-in previous chain is always restorable, so the unrestorable adopt
// must not be used for it.
func TestAdoptStagedUnrestorableRejectsBuiltinPrevious(t *testing.T) {
	lifecycle := NewPackLifecycle("core", ModeDeny, &lifecycleCAS{})
	for _, previous := range []string{"", BuiltinChainVersion} {
		if err := lifecycle.AdoptStagedUnrestorable(previous, errors.New("unused")); err == nil {
			t.Fatalf("built-in previous %q must adopt through AdoptStaged", previous)
		}
	}
}

// TestLoadPackHook pins the hydration loader: the sources are verified and
// compiled into an enforce-mode chain without touching any lifecycle state;
// single and multi-pack candidates load, and broken sources fail.
func TestLoadPackHook(t *testing.T) {
	base := t.TempDir()
	rootA := filepath.Join(base, "alpha")
	manifestA := writeLifecyclePackIn(t, rootA, "user.alpha", "secret", "ALPHA_LOADER_[A-Z]+")
	rootB := filepath.Join(base, "beta")
	manifestB := writeLifecyclePackIn(t, rootB, "user.beta", "credential", "BETA_LOADER_[A-Z]+")

	hook, err := LoadPackHook(ModeDeny, []PackSource{{Root: rootA, Manifest: manifestA}, {Root: rootB, Manifest: manifestB}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := hook.Apply("ALPHA_LOADER_VALUE"); !errors.Is(err, ErrDenied) {
		t.Fatalf("loaded single-pack chain does not enforce: %v", err)
	}
	if _, _, err := hook.Apply("BETA_LOADER_VALUE"); !errors.Is(err, ErrDenied) {
		t.Fatalf("loaded multi-pack chain lost the second pack: %v", err)
	}
	if _, _, err := hook.Apply("clean input"); err != nil {
		t.Fatalf("loaded chain flags clean input: %v", err)
	}
	if _, err := LoadPackHook(ModeDeny, nil); err == nil {
		t.Fatal("empty source list must fail")
	}
	if _, err := LoadPackHook(ModeDeny, []PackSource{{Root: rootA, Manifest: []byte("{")}}); err == nil {
		t.Fatal("broken manifest must fail")
	}
}
