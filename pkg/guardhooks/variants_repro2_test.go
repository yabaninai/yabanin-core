package guardhooks

// Reproduction harness for the guard-pack lifecycle history findings
// (stage-vs-history and adopt-then-rollback detector restoration). Asserts
// activation-history invariants across staging, a failed CAS activation,
// concurrent staging, built-in rollback and repeated rollback. The distinct
// per-version detector pattern makes the served hook chain observable.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// repro2Pack writes one valid unsigned pack (id user.repro2) whose detector
// pattern is unique per version suffix, so the active chain's enforced set
// reveals exactly which version the hook serves.
func repro2Pack(t *testing.T, version string) (string, []byte) {
	t.Helper()
	root := t.TempDir()
	pattern := "PACK_SECRET_" + version + "_[A-Z]+"
	content := []byte(`{"detectors":[{"rule_id":"repro2-token","rule_version":"1","category":"secret","pattern":"` + pattern + `"}]}`)
	if err := os.WriteFile(filepath.Join(root, "detector.json"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	manifest, err := json.Marshal(PackManifest{SchemaVersion: GuardPackManifestVersion, PackID: "user.repro2", PackVersion: version, RuntimeAPI: RuntimeVersion, Files: []PackFile{{Path: "detector.json", SHA256: hex.EncodeToString(sum[:])}}})
	if err != nil {
		t.Fatal(err)
	}
	return root, manifest
}

// V1: stage B -> FAILED CAS (Activate refuses) -> stage C -> Rollback.
// Contract: a failed Activate and any re-staging must leave previous=="core".
func TestRepro2FailedActivateThenRestageKeepsRollbackTarget(t *testing.T) {
	ctx := context.Background()
	cas := &lifecycleCAS{}
	p := NewPackLifecycle("core", ModeDeny, cas)
	rootA, rawA := repro2Pack(t, "A")
	if _, err := p.Stage(rootA, rawA); err != nil {
		t.Fatal(err)
	}
	if err := p.Activate(ctx); err != nil {
		t.Fatal(err)
	}
	cas.err = errors.New("durable conflict")
	rootB, rawB := repro2Pack(t, "B")
	if _, err := p.Stage(rootB, rawB); err != nil {
		t.Fatal(err)
	}
	if err := p.Activate(ctx); err == nil {
		t.Fatal("expected the injected CAS failure")
	}
	cas.err = nil
	rootC, rawC := repro2Pack(t, "C")
	if _, err := p.Stage(rootC, rawC); err != nil {
		t.Fatal(err)
	}
	t.Logf("history after failed activate + restage: current=%q previous=%q", p.current, p.previous)
	if err := p.Rollback(ctx); err != nil {
		t.Fatalf("rollback refused after failed activate + restage: %v", err)
	}
	t.Logf("rollback CAS %q -> %q", cas.from, cas.to)
	if cas.to != "core" {
		t.Fatalf("rollback target = %q, want core (failed activate / re-stage clobbered history)", cas.to)
	}
}

// V2: two concurrent Stages racing an Activate. Winner is whichever staged
// candidate Activate observes; invariants: the active chain enforces exactly
// the CASed-to version, and history never becomes degenerate (previous==current).
func TestRepro2ConcurrentStagesThenActivateConsistent(t *testing.T) {
	ctx := context.Background()
	cas := &lifecycleCAS{}
	p := NewPackLifecycle("core", ModeDeny, cas)
	rootA, rawA := repro2Pack(t, "A")
	if _, err := p.Stage(rootA, rawA); err != nil {
		t.Fatal(err)
	}
	if err := p.Activate(ctx); err != nil {
		t.Fatal(err)
	}
	roots := make([]string, 2)
	raws := make([][]byte, 2)
	roots[0], raws[0] = repro2Pack(t, "B")
	roots[1], raws[1] = repro2Pack(t, "C")
	// Stage B synchronously so a candidate exists, then race Stage C against
	// Activate: both orderings (stage-before / stage-after activate) are valid
	// and the invariants below are order-independent.
	if _, err := p.Stage(roots[0], raws[0]); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := p.Stage(roots[1], raws[1]); err != nil {
			t.Error(err)
		}
	}()
	done := make(chan error, 1)
	go func() { done <- p.Activate(ctx) }()
	wg.Wait()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	winner := cas.to
	t.Logf("activate winner=%q stagedAfter=%q history current=%q previous=%q", winner, p.StagedVersion(), p.current, p.previous)
	var want string
	switch winner {
	case "user.repro2@B":
		want = "PACK_SECRET_B_VALUE"
	case "user.repro2@C":
		want = "PACK_SECRET_C_VALUE"
	default:
		t.Fatalf("unexpected winner %q", winner)
	}
	if _, _, err := p.ActiveHook().Apply(want); !errors.Is(err, ErrDenied) {
		t.Fatalf("active chain does not enforce activated version %q: %v", winner, err)
	}
	if p.previous == p.current {
		t.Fatalf("degenerate history after concurrent stage/activate: previous==current==%q", p.current)
	}
}

// V4 (control): rollback to the core built-ins is the legitimate
// built-in-restoring path and must keep working.
func TestRepro2RollbackToCoreBuiltins(t *testing.T) {
	ctx := context.Background()
	cas := &lifecycleCAS{}
	p := NewPackLifecycle("core", ModeDeny, cas)
	rootA, rawA := repro2Pack(t, "A")
	if _, err := p.Stage(rootA, rawA); err != nil {
		t.Fatal(err)
	}
	if err := p.Activate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.ActiveHook().Apply("PACK_SECRET_A_VALUE"); !errors.Is(err, ErrDenied) {
		t.Fatalf("activated pack not enforced: %v", err)
	}
	if err := p.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if cas.from != "user.repro2@A" || cas.to != "core" {
		t.Fatalf("rollback CAS = %q -> %q, want user.repro2@A -> core", cas.from, cas.to)
	}
	if _, _, err := p.ActiveHook().Apply("PACK_SECRET_A_VALUE"); err != nil {
		t.Fatalf("rollback-to-core must serve the built-in chain (pattern passes): %v", err)
	}
}

// V6: second rollback — the two-slot history has no third slot. After the
// first rollback prior is nil and no unrestorable marker is set, so the
// second rollback CASes A->B and swaps in a nil prior (built-in chain) while
// the durable row would claim version B. Safety invariant asserted: after a
// successful rollback, the active chain must enforce the version the CAS
// just wrote (or the rollback must refuse).
func TestRepro2SecondRollbackTwoSlotToggle(t *testing.T) {
	ctx := context.Background()
	cas := &lifecycleCAS{}
	p := NewPackLifecycle("core", ModeDeny, cas)
	rootA, rawA := repro2Pack(t, "A")
	if _, err := p.Stage(rootA, rawA); err != nil {
		t.Fatal(err)
	}
	if err := p.Activate(ctx); err != nil {
		t.Fatal(err)
	}
	rootB, rawB := repro2Pack(t, "B")
	if _, err := p.Stage(rootB, rawB); err != nil {
		t.Fatal(err)
	}
	if err := p.Activate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := p.Rollback(ctx); err != nil {
		t.Fatalf("rollback 1 (B->A): %v", err)
	}
	t.Logf("rollback1 CAS %q -> %q, history now current=%q previous=%q", cas.from, cas.to, p.current, p.previous)
	// Patterns are version-distinct: the restored A chain must deny the A pattern.
	if _, _, err := p.ActiveHook().Apply("PACK_SECRET_A_VALUE"); !errors.Is(err, ErrDenied) {
		t.Fatalf("after rollback1 (durable=%q) the A detector is gone: %v", cas.to, err)
	}
	err2 := p.Rollback(ctx)
	t.Logf("rollback2 err=%v CAS %q -> %q, history now current=%q previous=%q", err2, cas.from, cas.to, p.current, p.previous)
	if err2 != nil {
		t.Logf("second rollback refused fail-closed (acceptable posture): %v", err2)
		return
	}
	if _, _, err := p.ActiveHook().Apply("PACK_SECRET_B_VALUE"); !errors.Is(err, ErrDenied) {
		t.Fatalf("SECOND-ROLLBACK GAP: second rollback wrote durable version %q but the active chain serves no B detector (built-ins under a pack label): %v", cas.to, err)
	}
}
