package guardhooks

// NF-1 (REPRO-2) regressions: the two-slot activation history must stay REAL
// across consecutive rollbacks. Rollback keeps the deactivated chain as the
// prior of the version the swap writes into previous, so a second rollback
// restores that version's actual detectors and the durable row never names a
// version the active hook does not enforce. Before the fix, the second
// rollback dropped to the built-in chain while the CAS claimed the previous
// pack's version label (TestRepro2SecondRollbackTwoSlotToggle pins the
// reported symptom; these tests pin the acceptance semantics).

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
)

// secondRollbackPack builds one version-distinct pack: the enforced pattern
// reveals exactly which pack version the hook chain serves.
func secondRollbackPack(t *testing.T, root, packID, pattern string) []byte {
	t.Helper()
	return writeLifecyclePackIn(t, root, packID, "secret", pattern)
}

// assertSecondRollbackEnforcement checks the hook chain against the
// pattern-distinct packs: exactly the named pack (if any) must be denied.
// Pack patterns are "<NAME>_NF1_[A-Z]+" (writeLifecyclePackIn), so the probe
// value is "<NAME>_NF1_VALUE".
func assertSecondRollbackEnforcement(t *testing.T, hook *Hook, denied string, packIDs ...string) {
	t.Helper()
	for _, packID := range packIDs {
		_, _, err := hook.Apply(packID + "_NF1_VALUE")
		if packID == denied && !errors.Is(err, ErrDenied) {
			t.Fatalf("chain must enforce %q: %v", packID, err)
		}
		if packID != denied && err != nil {
			t.Fatalf("chain must not enforce %q while serving %q: %v", packID, denied, err)
		}
	}
}

// TestSecondRollbackTogglesRealChainsDurableAgrees pins the repaired
// semantics: after pack-to-pack rollbacks in both directions, every CAS write
// names exactly the version whose real detectors the active chain serves.
func TestSecondRollbackTogglesRealChainsDurableAgrees(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	rootA := base + "/alpha"
	manifestA := secondRollbackPack(t, rootA, "user.alpha", "ALPHA_NF1_[A-Z]+")
	rootB := base + "/beta"
	manifestB := secondRollbackPack(t, rootB, "user.beta", "BETA_NF1_[A-Z]+")

	cas := &lifecycleCAS{}
	lifecycle := NewPackLifecycle(BuiltinChainVersion, ModeDeny, cas)
	if _, err := lifecycle.StageSources([]PackSource{{Root: rootA, Manifest: manifestA}}); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Activate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.StageSources([]PackSource{{Root: rootB, Manifest: manifestB}}); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Activate(ctx); err != nil {
		t.Fatal(err)
	}
	assertSecondRollbackEnforcement(t, lifecycle.ActiveHook(), "BETA", "ALPHA", "BETA")

	// Rollback 1 (B -> A): the REAL alpha chain returns.
	if err := lifecycle.Rollback(ctx); err != nil {
		t.Fatalf("rollback 1: %v", err)
	}
	if cas.from != "user.beta@1" || cas.to != "user.alpha@1" {
		t.Fatalf("rollback1 CAS = %q -> %q, want user.beta@1 -> user.alpha@1", cas.from, cas.to)
	}
	assertSecondRollbackEnforcement(t, lifecycle.ActiveHook(), "ALPHA", "ALPHA", "BETA")

	// Rollback 2 (A -> B, the REPRO-2 gap): must restore the REAL beta chain,
	// never the built-ins under the beta version label.
	if err := lifecycle.Rollback(ctx); err != nil {
		t.Fatalf("rollback 2 must restore the real previous pack: %v", err)
	}
	if cas.from != "user.alpha@1" || cas.to != "user.beta@1" {
		t.Fatalf("rollback2 CAS = %q -> %q, want user.alpha@1 -> user.beta@1", cas.from, cas.to)
	}
	assertSecondRollbackEnforcement(t, lifecycle.ActiveHook(), "BETA", "ALPHA", "BETA")

	// The toggle stays real in both directions: rollback 3 serves alpha again.
	if err := lifecycle.Rollback(ctx); err != nil {
		t.Fatalf("rollback 3: %v", err)
	}
	if cas.to != "user.alpha@1" {
		t.Fatalf("rollback3 CAS to = %q, want user.alpha@1", cas.to)
	}
	assertSecondRollbackEnforcement(t, lifecycle.ActiveHook(), "ALPHA", "ALPHA", "BETA")
}

// TestRollbackToCoreBuiltinsSemanticsPreserved pins the built-in rollback
// semantics: a rollback to BuiltinChainVersion serves the built-ins (built-ins
// ARE core — the legitimate no-prior case), a rollback FROM the built-in chain
// is refused without any CAS write, and the lifecycle stays fully usable
// (re-activate, roll back to core again).
func TestRollbackToCoreBuiltinsSemanticsPreserved(t *testing.T) {
	ctx := context.Background()
	rootA := t.TempDir() + "/alpha"
	manifestA := secondRollbackPack(t, rootA, "user.alpha", "ALPHA_CORE_RB_[A-Z]+")

	cas := &lifecycleCAS{}
	lifecycle := NewPackLifecycle(BuiltinChainVersion, ModeDeny, cas)
	if _, err := lifecycle.StageSources([]PackSource{{Root: rootA, Manifest: manifestA}}); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Activate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if cas.from != "user.alpha@1" || cas.to != BuiltinChainVersion {
		t.Fatalf("rollback1 CAS = %q -> %q, want user.alpha@1 -> core", cas.from, cas.to)
	}
	// Built-ins ARE core: the alpha pattern passes, nothing is denied.
	if _, _, err := lifecycle.ActiveHook().Apply("ALPHA_CORE_RB_VALUE"); err != nil {
		t.Fatalf("rollback to core must serve the built-in chain: %v", err)
	}
	// A rollback FROM the built-in chain is refused (rollback restores a
	// previous version FROM an active pack; on core there is nothing to roll
	// back from). Fail-closed and honest: no CAS write, the durable row stays
	// on core, and the built-ins keep serving — never a label mismatch.
	if err := lifecycle.Rollback(ctx); err == nil {
		t.Fatal("rollback from the built-in chain must be refused")
	}
	if cas.from != "user.alpha@1" || cas.to != BuiltinChainVersion {
		t.Fatalf("refused rollback must not write the CAS, got %q -> %q", cas.from, cas.to)
	}
	if _, _, err := lifecycle.ActiveHook().Apply("ALPHA_CORE_RB_VALUE"); err != nil {
		t.Fatalf("refused rollback must keep the built-ins serving: %v", err)
	}
	// Re-activating works from the rolled-back core state, and the history
	// stays real: activating again and rolling back restores the REAL alpha
	// chain.
	if _, err := lifecycle.StageSources([]PackSource{{Root: rootA, Manifest: manifestA}}); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Activate(ctx); err != nil {
		t.Fatal(err)
	}
	if cas.from != BuiltinChainVersion || cas.to != "user.alpha@1" {
		t.Fatalf("reactivation CAS = %q -> %q, want core -> user.alpha@1", cas.from, cas.to)
	}
	if err := lifecycle.Rollback(ctx); err != nil {
		t.Fatalf("rollback after reactivation: %v", err)
	}
	if cas.from != "user.alpha@1" || cas.to != BuiltinChainVersion {
		t.Fatalf("final rollback CAS = %q -> %q, want user.alpha@1 -> core", cas.from, cas.to)
	}
	if _, _, err := lifecycle.ActiveHook().Apply("ALPHA_CORE_RB_VALUE"); err != nil {
		t.Fatalf("rollback to core must serve the built-in chain again: %v", err)
	}
}

// TestAdoptedRollbackThenSecondRollbackRestoresRealChain pins the same
// invariant for the hydration/adopt path: after an adopted lifecycle rolls
// back to the loaded prior, a second rollback restores the adopted pack's
// real chain (the durable row claims it; the hook must enforce it).
func TestAdoptedRollbackThenSecondRollbackRestoresRealChain(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	rootAlpha := base + "/alpha"
	manifestAlpha := secondRollbackPack(t, rootAlpha, "user.alpha", "ALPHA_ADOPT_RB_[A-Z]+")
	rootPrior := base + "/prior"
	manifestPrior := secondRollbackPack(t, rootPrior, "user.prior", "PRIOR_ADOPT_RB_[A-Z]+")
	priorHook, err := LoadPackHook(ModeDeny, []PackSource{{Root: rootPrior, Manifest: manifestPrior}})
	if err != nil {
		t.Fatal(err)
	}

	cas := &lifecycleCAS{}
	lifecycle := NewPackLifecycle("user.alpha@1", ModeDeny, cas)
	if _, err := lifecycle.StageSources([]PackSource{{Root: rootAlpha, Manifest: manifestAlpha}}); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.AdoptStaged("user.prior@1", priorHook); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Rollback(ctx); err != nil {
		t.Fatalf("rollback 1 (alpha -> prior): %v", err)
	}
	if _, _, err := lifecycle.ActiveHook().Apply("PRIOR_ADOPT_RB_VALUE"); !errors.Is(err, ErrDenied) {
		t.Fatalf("rollback 1 must serve the loaded prior chain: %v", err)
	}
	// Rollback 2 (prior -> alpha): the durable row claims user.alpha@1, so the
	// real alpha chain must come back.
	if err := lifecycle.Rollback(ctx); err != nil {
		t.Fatalf("rollback 2 must restore the real adopted chain: %v", err)
	}
	if cas.from != "user.prior@1" || cas.to != "user.alpha@1" {
		t.Fatalf("rollback2 CAS = %q -> %q, want user.prior@1 -> user.alpha@1", cas.from, cas.to)
	}
	if _, _, err := lifecycle.ActiveHook().Apply("ALPHA_ADOPT_RB_VALUE"); !errors.Is(err, ErrDenied) {
		t.Fatalf("second rollback must enforce the real alpha chain, got %v", err)
	}
	if _, _, err := lifecycle.ActiveHook().Apply("PRIOR_ADOPT_RB_VALUE"); err != nil {
		t.Fatalf("second rollback must stop enforcing the prior chain: %v", err)
	}
}

// TestConcurrentRollbackActivateMatchesDurableRecord drives concurrent
// stage/activate/rollback storms against a conflict-checked CAS: after every
// successful operation the durable record names exactly the version whose
// detectors the active hook enforces (or core with no pack enforced).
func TestConcurrentRollbackActivateMatchesDurableRecord(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	const packCount = 4
	roots := make([]string, packCount)
	manifests := make([][]byte, packCount)
	for i := 0; i < packCount; i++ {
		roots[i] = fmt.Sprintf("%s/pack%d", base, i)
		manifests[i] = secondRollbackPack(t, roots[i], fmt.Sprintf("user.pack%d", i), fmt.Sprintf("PACK%d_NF1CONCUR_[A-Z]+", i))
	}
	store := &concurrentLifecycleCAS{version: BuiltinChainVersion}
	lifecycle := NewPackLifecycle(BuiltinChainVersion, ModeDeny, store)

	// checkAgreement must run while opMu is held (a writer's critical
	// section), so failures inside it use t.Errorf, never t.Fatalf.
	checkAgreement := func() {
		durable := store.activeVersion()
		hook := lifecycle.ActiveHook()
		for i := 0; i < packCount; i++ {
			_, _, err := hook.Apply(fmt.Sprintf("PACK%d_NF1CONCUR_VALUE", i))
			wantDeny := durable == fmt.Sprintf("user.pack%d@1", i)
			if wantDeny && !errors.Is(err, ErrDenied) {
				t.Errorf("durable record names %q but the hook does not enforce pack%d: %v", durable, i, err)
				return
			}
			if !wantDeny && err != nil {
				t.Errorf("durable record names %q but the hook denies pack%d: %v", durable, i, err)
				return
			}
		}
	}

	var wg sync.WaitGroup
	var opMu sync.Mutex
	for writer := 0; writer < 4; writer++ {
		wg.Add(1)
		go func(writer int) {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				pick := (writer + i) % packCount
				if _, err := lifecycle.StageSources([]PackSource{{Root: roots[pick], Manifest: manifests[pick]}}); err != nil {
					t.Errorf("stage: %v", err)
					return
				}
				opMu.Lock()
				if err := lifecycle.Activate(ctx); err == nil {
					checkAgreement()
				}
				if err := lifecycle.Rollback(ctx); err == nil {
					checkAgreement()
				}
				opMu.Unlock()
			}
		}(writer)
	}
	for reader := 0; reader < 2; reader++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 300; i++ {
				if hook := lifecycle.ActiveHook(); hook == nil {
					t.Error("ActiveHook() returned nil")
					return
				}
			}
		}()
	}
	wg.Wait()

	// End state stays consistent: one more activate round trip lands the hook
	// and the durable record on the same candidate.
	if _, err := lifecycle.StageSources([]PackSource{{Root: roots[1], Manifest: manifests[1]}}); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Activate(ctx); err != nil {
		t.Fatal(err)
	}
	if got := store.activeVersion(); got != "user.pack1@1" {
		t.Fatalf("final durable version = %q, want user.pack1@1", got)
	}
	checkAgreement()
}
