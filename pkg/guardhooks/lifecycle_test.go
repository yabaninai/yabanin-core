package guardhooks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type lifecycleCAS struct {
	from, to string
	err      error
}

func (c *lifecycleCAS) CompareAndSwap(_ context.Context, from, to string) error {
	c.from, c.to = from, to
	return c.err
}

func writeLifecyclePack(t *testing.T) (string, []byte) {
	t.Helper()
	root := t.TempDir()
	content := []byte(`{"detectors":[{"rule_id":"test-token","rule_version":"1","category":"secret","pattern":"PACK_SECRET_[A-Z]+"}]}`)
	if err := os.WriteFile(filepath.Join(root, "detector.json"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	manifest, err := json.Marshal(PackManifest{SchemaVersion: GuardPackManifestVersion, PackID: "user.test", PackVersion: "2", RuntimeAPI: RuntimeVersion, Files: []PackFile{{Path: "detector.json", SHA256: hex.EncodeToString(sum[:])}}})
	if err != nil {
		t.Fatal(err)
	}
	return root, manifest
}

func TestPackLifecycleStageShadowActivateRollback(t *testing.T) {
	root, manifest := writeLifecyclePack(t)
	cas := &lifecycleCAS{}
	lifecycle := NewPackLifecycle("1", ModeDeny, cas)
	if _, err := lifecycle.Stage(root, manifest); err != nil {
		t.Fatal(err)
	}
	shadow, hits, err := lifecycle.ShadowHook().Apply("PACK_SECRET_VALUE")
	if err != nil || shadow != nil || len(hits) == 0 || hits[0].Outcome != OutcomeLog {
		t.Fatalf("shadow = %q, %#v, %v", shadow, hits, err)
	}
	if _, hits, err = lifecycle.ActiveHook().Apply("PACK_SECRET_VALUE"); err != nil || len(hits) != 0 {
		t.Fatalf("staging changed active chain: %#v, %v", hits, err)
	}
	if err := lifecycle.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The single-pack version identity carries the pack id: the CAS "to"
	// value is the durable activation identity compared across replicas, so
	// a bare pack version ("2") would be ambiguous between packs.
	if cas.from != "1" || cas.to != "user.test@2" {
		t.Fatalf("activate CAS = %q -> %q, want 1 -> user.test@2", cas.from, cas.to)
	}
	if _, hits, err = lifecycle.ActiveHook().Apply("PACK_SECRET_VALUE"); err != ErrDenied || len(hits) == 0 {
		t.Fatalf("active = %#v, %v", hits, err)
	}
	if err := lifecycle.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if cas.from != "user.test@2" || cas.to != "1" {
		t.Fatalf("rollback CAS = %q -> %q, want user.test@2 -> 1", cas.from, cas.to)
	}
	if _, hits, err = lifecycle.ActiveHook().Apply("PACK_SECRET_VALUE"); err != nil || len(hits) != 0 {
		t.Fatalf("rollback did not restore builtin chain: %#v, %v", hits, err)
	}
}

func TestLoadDetectorPackRejectsIncompatibleAndMissingFiles(t *testing.T) {
	root, manifest := writeLifecyclePack(t)
	var decoded map[string]any
	if err := json.Unmarshal(manifest, &decoded); err != nil {
		t.Fatal(err)
	}
	decoded["runtime_api"] = "guardrails.v999"
	badVersion, _ := json.Marshal(decoded)
	if _, _, err := LoadDetectorPack(root, badVersion); err == nil {
		t.Fatal("expected incompatible SPI rejection")
	}
	if err := os.Remove(filepath.Join(root, "detector.json")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadDetectorPack(root, manifest); err == nil {
		t.Fatal("expected missing detector file rejection")
	}
}

func TestPanickingDetectorFailsClosedOrAudits(t *testing.T) {
	evaluator, err := NewExtendedEvaluator(panicDetector{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		mode    Mode
		wantErr error
		want    Outcome
	}{{ModeDeny, ErrDenied, OutcomeDeny}, {ModeLog, nil, OutcomeLog}} {
		_, hits, gotErr := NewWithEvaluator(tc.mode, evaluator).Apply("request")
		if gotErr != tc.wantErr || len(hits) != 1 || hits[0].Category != CatDetectorFailure || hits[0].Outcome != tc.want {
			t.Errorf("mode %s: hits=%#v err=%v", tc.mode, hits, gotErr)
		}
	}
}

func TestPackLifecycleFailuresRemainTransactional(t *testing.T) {
	root, manifest := writeLifecyclePack(t)
	casErr := errors.New("CAS conflict")
	cas := &lifecycleCAS{err: casErr}
	lifecycle := NewPackLifecycle("old", ModeDeny, cas)
	if err := lifecycle.Activate(context.Background()); err == nil {
		t.Fatal("activate without staged pack should fail")
	}
	if err := lifecycle.Rollback(context.Background()); err == nil {
		t.Fatal("rollback without active pack should fail")
	}
	if _, err := lifecycle.Stage(root, manifest); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Activate(context.Background()); !errors.Is(err, casErr) {
		t.Fatalf("CAS failure lost: %v", err)
	}
	if _, hits, err := lifecycle.ActiveHook().Apply("CUSTOM_BLOCK_X"); err != nil || len(hits) != 0 {
		t.Fatalf("failed CAS exposed candidate: %#v %v", hits, err)
	}
	if err := lifecycle.Rollback(context.Background()); err == nil {
		t.Fatal("rollback before activation should fail")
	}
	noCAS := NewPackLifecycle("old", ModeDeny, nil)
	if err := noCAS.Activate(context.Background()); err == nil {
		t.Fatal("activate without staged pack should fail")
	}
	if _, err := noCAS.Stage(root, manifest); err != nil {
		t.Fatal(err)
	}
	if err := noCAS.Activate(context.Background()); err == nil {
		t.Fatal("activate without policy API should fail")
	}
	var nilLifecycle *PackLifecycle
	if nilLifecycle.ShadowHook() != nil || nilLifecycle.ActiveHook() != nil {
		t.Fatal("nil lifecycle should have no hooks")
	}
	// The nil check must run before any pack loading work.
	if _, err := nilLifecycle.Stage(root, manifest); err == nil {
		t.Fatal("nil lifecycle Stage must fail without loading a pack")
	}
	if _, err := nilLifecycle.Stage(filepath.Join(root, "does-not-exist"), nil); err == nil {
		t.Fatal("nil lifecycle Stage must fail even with an invalid pack")
	}
	if err := nilLifecycle.Activate(context.Background()); err == nil {
		t.Fatal("nil lifecycle Activate must fail")
	}
	if err := nilLifecycle.Rollback(context.Background()); err == nil {
		t.Fatal("nil lifecycle Rollback must fail")
	}
	// Stage must propagate pack-load failures instead of silently keeping the
	// previously staged candidate.
	if _, err := noCAS.Stage(root, []byte("{")); err == nil {
		t.Fatal("Stage must reject an undecodable manifest")
	}
}

// TestStageRejectsShadowingCorePackIdentities pins that a user pack cannot
// declare identities that collide with the built-in core chain: staging such
// a pack fails instead of silently extending or replacing core detectors.
func TestStageRejectsShadowingCorePackIdentities(t *testing.T) {
	root := t.TempDir()
	content := []byte(`{"detectors":[{"rule_id":"credential:key-value","rule_version":"1","category":"credential","pattern":"CORE_SHADOW_[A-Z]+"}]}`)
	if err := os.WriteFile(filepath.Join(root, "detector.json"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	manifest, err := json.Marshal(PackManifest{SchemaVersion: GuardPackManifestVersion, PackID: "core.guardrails", PackVersion: "1", RuntimeAPI: RuntimeVersion, Files: []PackFile{{Path: "detector.json", SHA256: hex.EncodeToString(sum[:])}}})
	if err != nil {
		t.Fatal(err)
	}
	lifecycle := NewPackLifecycle("1", ModeDeny, &lifecycleCAS{})
	if _, err := lifecycle.Stage(root, manifest); err == nil || !strings.Contains(err.Error(), "duplicate detector") {
		t.Fatalf("core-identity collision not rejected: %v", err)
	}
	if lifecycle.ShadowHook() != nil {
		t.Fatal("failed Stage must not publish a shadow hook")
	}
}

// TestLoadDetectorPackRejectsOversizedDetectorList pins the per-pack detector
// cap: a detector.json declaring more than MaxDetectorsPerPack detectors is
// rejected with an explicit error before any regex is compiled, so a large
// file cannot multiply per-request evaluation cost.
func TestLoadDetectorPackRejectsOversizedDetectorList(t *testing.T) {
	root := t.TempDir()
	specs := make([]map[string]string, MaxDetectorsPerPack+1)
	for i := range specs {
		specs[i] = map[string]string{
			"rule_id": "r" + strconv.Itoa(i), "rule_version": "1",
			"category": "secret", "pattern": "PATTERN_",
		}
	}
	content, err := json.Marshal(map[string]any{"detectors": specs})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "detector.json"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	manifest, err := json.Marshal(PackManifest{SchemaVersion: GuardPackManifestVersion, PackID: "user.toobig", PackVersion: "1", RuntimeAPI: RuntimeVersion, Files: []PackFile{{Path: "detector.json", SHA256: hex.EncodeToString(sum[:])}}})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = LoadDetectorPack(root, manifest)
	if err == nil || !strings.Contains(err.Error(), "detector limit") {
		t.Fatalf("expected detector-count limit rejection, got %v", err)
	}
}

// TestRollbackDropsStagedCandidate pins the rollback semantics: a candidate
// staged but not activated does not survive a rollback, so Activate after a
// rollback fails until a pack is explicitly re-staged.
func TestRollbackDropsStagedCandidate(t *testing.T) {
	root, manifest := writeLifecyclePack(t)
	lifecycle := NewPackLifecycle("1", ModeDeny, &lifecycleCAS{})
	if _, err := lifecycle.Stage(root, manifest); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.Stage(root, manifest); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Activate(context.Background()); err == nil {
		t.Fatal("staged candidate must not survive rollback for later activation")
	}
}

// TestRegexDetectorRejectsInvalidInvocation pins the invocation contract of
// pack detectors: a version/phase/kind that does not match the runtime SPI is
// an error, never a silent zero-finding scan.
func TestRegexDetectorRejectsInvalidInvocation(t *testing.T) {
	root, manifest := writeLifecyclePack(t)
	_, detectors, err := LoadDetectorPack(root, manifest)
	if err != nil || len(detectors) != 1 {
		t.Fatalf("pack load: %v (%d detectors)", err, len(detectors))
	}
	for _, invocation := range []Invocation{
		{Context: context.Background(), Version: "wrong", Phase: PhaseBefore, Kind: ContentText, Text: "PACK_SECRET_VALUE"},
		{Context: context.Background(), Version: RuntimeVersion, Phase: "sideways", Kind: ContentText, Text: "PACK_SECRET_VALUE"},
		{Context: context.Background(), Version: RuntimeVersion, Phase: PhaseBefore, Kind: "binary", Text: "PACK_SECRET_VALUE"},
	} {
		if _, err := detectors[0].Detect(invocation); err == nil {
			t.Fatalf("invalid invocation accepted: %#v", invocation)
		}
	}
}

func TestLoadDetectorPackRejectsInvalidDetectorDefinitions(t *testing.T) {
	root, manifest := writeLifecyclePack(t)
	contentPath := filepath.Join(root, "detector.json")
	for _, test := range []struct{ name, content string }{
		{name: "malformed", content: "{"},
		{name: "empty", content: `{"detectors":[]}`},
		{name: "missing fields", content: `{"detectors":[{"rule_id":"r"}]}`},
		{name: "bad regex", content: `{"detectors":[{"rule_id":"r","rule_version":"1","category":"secret","pattern":"("}]}`},
		{name: "duplicate", content: `{"detectors":[{"rule_id":"r","rule_version":"1","category":"secret","pattern":"x"},{"rule_id":"r","rule_version":"1","category":"secret","pattern":"y"}]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			content := []byte(test.content)
			if err := os.WriteFile(contentPath, content, 0o600); err != nil {
				t.Fatal(err)
			}
			var packManifest PackManifest
			if err := json.Unmarshal(manifest, &packManifest); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(content)
			packManifest.Files[0].SHA256 = hex.EncodeToString(sum[:])
			updatedManifest, err := json.Marshal(packManifest)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := LoadDetectorPack(root, updatedManifest); err == nil {
				t.Fatal("invalid detector definition accepted")
			}
		})
	}
}

type synchronizedLifecycleCAS struct {
	mu      sync.Mutex
	version string
}

func (c *synchronizedLifecycleCAS) CompareAndSwap(_ context.Context, from, to string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.version != from {
		return errors.New("policy version conflict")
	}
	c.version = to
	return nil
}

func TestPackLifecycleConcurrentStageActivateRollback(t *testing.T) {
	root, manifest := writeLifecyclePack(t)
	cas := &synchronizedLifecycleCAS{version: "1"}
	lifecycle := NewPackLifecycle("1", ModeDeny, cas)
	var wg sync.WaitGroup
	for worker := 0; worker < 6; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				_, _ = lifecycle.Stage(root, manifest)
				_ = lifecycle.Activate(context.Background())
				_ = lifecycle.Rollback(context.Background())
			}
		}()
	}
	wg.Wait()
}

func TestPackLifecycleActiveHookConcurrentReader(t *testing.T) {
	root, manifest := writeLifecyclePack(t)
	lifecycle := NewPackLifecycle("1", ModeDeny, &lifecycleCAS{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			if _, err := lifecycle.Stage(root, manifest); err != nil {
				t.Errorf("Stage(): %v", err)
				return
			}
			_ = lifecycle.Activate(context.Background())
			_ = lifecycle.Rollback(context.Background())
		}
	}()
	for i := 0; i < 500; i++ {
		if hook := lifecycle.ActiveHook(); hook == nil {
			t.Fatal("ActiveHook() returned nil")
		}
	}
	wg.Wait()
}

// writeLifecyclePackIn writes one named pack with the given pattern under
// root, so multi-pack staging can combine packs from different directories.
func writeLifecyclePackIn(t *testing.T, root, packID, category, pattern string) []byte {
	t.Helper()
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	content, err := json.Marshal(map[string]any{"detectors": []map[string]string{{
		"rule_id": packID + "-rule", "rule_version": "1", "category": category, "pattern": pattern,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "detector.json"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	manifest, err := json.Marshal(PackManifest{SchemaVersion: GuardPackManifestVersion, PackID: packID, PackVersion: "1", RuntimeAPI: RuntimeVersion, Files: []PackFile{{Path: "detector.json", SHA256: hex.EncodeToString(sum[:])}}})
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

// TestStageSourcesCombinesMultiplePacks pins the multi-pack candidate
// contract: one atomic staged chain, a synthetic identity naming every
// contributing pack, and a digest derived from the per-pack digests.
func TestStageSourcesCombinesMultiplePacks(t *testing.T) {
	base := t.TempDir()
	rootA := filepath.Join(base, "alpha")
	rootB := filepath.Join(base, "beta")
	manifestA := writeLifecyclePackIn(t, rootA, "user.alpha", "secret", "ALPHA_SECRET_[A-Z]+")
	manifestB := writeLifecyclePackIn(t, rootB, "user.beta", "credential", "BETA_SECRET_[A-Z]+")
	lifecycle := NewPackLifecycle("core", ModeDeny, &lifecycleCAS{})
	verified, err := lifecycle.StageSources([]PackSource{{Root: rootA, Manifest: manifestA}, {Root: rootB, Manifest: manifestB}})
	if err != nil {
		t.Fatal(err)
	}
	if verified.Manifest.PackID != "active-packs" {
		t.Fatalf("multi-pack candidate identity = %q, want active-packs", verified.Manifest.PackID)
	}
	if !strings.Contains(verified.Manifest.PackVersion, "user.alpha@1") || !strings.Contains(verified.Manifest.PackVersion, "user.beta@1") {
		t.Fatalf("multi-pack candidate version must name both packs: %q", verified.Manifest.PackVersion)
	}
	if verified.Digest == "" {
		t.Fatal("multi-pack candidate digest is empty")
	}
	// Both packs evaluate on the staged chain before activation.
	hits := lifecycle.ShadowHook().Scan("ALPHA_SECRET_VALUE and BETA_SECRET_VALUE")
	if len(hits) == 0 {
		t.Fatal("staged multi-pack chain detected nothing in shadow mode")
	}
	if err := lifecycle.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	hits = lifecycle.ActiveHook().Scan("ALPHA_SECRET_VALUE and BETA_SECRET_VALUE")
	if len(hits) < 2 {
		t.Fatalf("activated multi-pack chain lost detections: %#v", hits)
	}
}

// TestStageSourcesConcurrentWithReaders exercises the new multi-pack staging
// entry point under the race detector alongside hook readers.
func TestStageSourcesConcurrentWithReaders(t *testing.T) {
	base := t.TempDir()
	rootA := filepath.Join(base, "alpha")
	rootB := filepath.Join(base, "beta")
	manifestA := writeLifecyclePackIn(t, rootA, "user.alpha", "secret", "ALPHA_SECRET_[A-Z]+")
	manifestB := writeLifecyclePackIn(t, rootB, "user.beta", "credential", "BETA_SECRET_[A-Z]+")
	lifecycle := NewPackLifecycle("1", ModeDeny, &lifecycleCAS{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			if _, err := lifecycle.StageSources([]PackSource{{Root: rootA, Manifest: manifestA}, {Root: rootB, Manifest: manifestB}}); err != nil {
				t.Errorf("StageSources(): %v", err)
				return
			}
			_ = lifecycle.Activate(context.Background())
			_ = lifecycle.Rollback(context.Background())
		}
	}()
	for i := 0; i < 200; i++ {
		if hook := lifecycle.ActiveHook(); hook == nil {
			t.Fatal("ActiveHook() returned nil")
		}
		_ = lifecycle.ShadowHook()
	}
	wg.Wait()
}

// TestStageSourcesRejectsEmptyAndFailingSources pins the guard clauses: no
// sources and a broken source both fail without publishing any hook.
func TestStageSourcesRejectsEmptyAndFailingSources(t *testing.T) {
	lifecycle := NewPackLifecycle("1", ModeDeny, &lifecycleCAS{})
	if _, err := lifecycle.StageSources(nil); err == nil {
		t.Fatal("empty source list must fail")
	}
	root, _ := writeLifecyclePack(t)
	if _, err := lifecycle.StageSources([]PackSource{{Root: root, Manifest: []byte("{")}}); err == nil {
		t.Fatal("broken manifest must fail")
	}
	if lifecycle.ShadowHook() != nil {
		t.Fatal("failed staging must not publish a shadow hook")
	}
	if err := lifecycle.Activate(context.Background()); err == nil {
		t.Fatal("a failed stage must leave nothing to activate")
	}
}

// TestStagedVersionIdentity pins the durable-identity accessor: the exact
// string the policy CAS records and replicas compare ("pack@version" single,
// joined multi-pack form, empty when nothing is staged).
func TestStagedVersionIdentity(t *testing.T) {
	var nilLifecycle *PackLifecycle
	if got := nilLifecycle.StagedVersion(); got != "" {
		t.Fatalf("nil lifecycle StagedVersion = %q, want empty", got)
	}
	fresh := NewPackLifecycle("core", ModeDeny, &lifecycleCAS{})
	if got := fresh.StagedVersion(); got != "" {
		t.Fatalf("unstaged StagedVersion = %q, want empty", got)
	}
	base := t.TempDir()
	rootA := filepath.Join(base, "alpha")
	manifestA := writeLifecyclePackIn(t, rootA, "user.alpha", "secret", "ALPHA_ID_[A-Z]+")
	single := NewPackLifecycle("core", ModeDeny, &lifecycleCAS{})
	if _, err := single.StageSources([]PackSource{{Root: rootA, Manifest: manifestA}}); err != nil {
		t.Fatal(err)
	}
	if got := single.StagedVersion(); got != "user.alpha@1" {
		t.Fatalf("single-pack StagedVersion = %q, want user.alpha@1", got)
	}
	rootB := filepath.Join(base, "beta")
	manifestB := writeLifecyclePackIn(t, rootB, "user.beta", "credential", "BETA_ID_[A-Z]+")
	multi := NewPackLifecycle("core", ModeDeny, &lifecycleCAS{})
	if _, err := multi.StageSources([]PackSource{{Root: rootA, Manifest: manifestA}, {Root: rootB, Manifest: manifestB}}); err != nil {
		t.Fatal(err)
	}
	got := multi.StagedVersion()
	if !strings.Contains(got, "user.alpha@1") || !strings.Contains(got, "user.beta@1") {
		t.Fatalf("multi-pack StagedVersion must name both packs: %q", got)
	}
}

// TestAdoptStaged pins the replica-adopt contract: publishing the staged
// candidate WITHOUT a CAS, refused unless the staged identity equals the
// lifecycle's current (durable) version, with the version history re-anchored
// to the caller's durable record and the loaded previous chain, so a later
// rollback CASes the transition the durable row expects AND restores the
// real previous detectors.
func TestAdoptStaged(t *testing.T) {
	var nilLifecycle *PackLifecycle
	if err := nilLifecycle.AdoptStaged("", nil); err == nil {
		t.Fatal("nil lifecycle adopt must fail")
	}
	base := t.TempDir()
	root := filepath.Join(base, "alpha")
	manifest := writeLifecyclePackIn(t, root, "user.alpha", "secret", "ALPHA_ADOPT_[A-Z]+")
	priorRoot := filepath.Join(base, "prior")
	priorManifest := writeLifecyclePackIn(t, priorRoot, "user.prior", "secret", "PRIOR_ADOPT_[A-Z]+")
	priorHook, err := LoadPackHook(ModeDeny, []PackSource{{Root: priorRoot, Manifest: priorManifest}})
	if err != nil {
		t.Fatal(err)
	}

	cas := &lifecycleCAS{}
	// Identity mismatch is refused: adopt is only for an exact durable match.
	mismatch := NewPackLifecycle("other@9", ModeDeny, cas)
	if _, err := mismatch.StageSources([]PackSource{{Root: root, Manifest: manifest}}); err != nil {
		t.Fatal(err)
	}
	if err := mismatch.AdoptStaged("user.prior@1", priorHook); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("staged/current mismatch must be refused, got %v", err)
	}
	if cas.from != "" {
		t.Fatalf("adopt must not run the CAS, got %q -> %q", cas.from, cas.to)
	}

	adopt := NewPackLifecycle("user.alpha@1", ModeDeny, cas)
	if err := adopt.AdoptStaged("user.prior@1", priorHook); err == nil || !strings.Contains(err.Error(), "no staged pack") {
		t.Fatalf("adopt without a staged pack must be refused, got %v", err)
	}
	if _, err := adopt.StageSources([]PackSource{{Root: root, Manifest: manifest}}); err != nil {
		t.Fatal(err)
	}
	// A pack-labelled previous without a loaded chain is refused: the
	// rollback would otherwise serve built-ins under that version label.
	if err := adopt.AdoptStaged("user.prior@1", nil); err == nil || !strings.Contains(err.Error(), "no loaded hook chain") {
		t.Fatalf("unloaded previous pack must be refused, got %v", err)
	}
	if err := adopt.AdoptStaged("user.prior@1", priorHook); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if cas.from != "" {
		t.Fatalf("adopt must not run the CAS, got %q -> %q", cas.from, cas.to)
	}
	if _, hits, err := adopt.ActiveHook().Apply("ALPHA_ADOPT_VALUE"); err != ErrDenied || len(hits) == 0 {
		t.Fatalf("adopted candidate not active: %#v, %v", hits, err)
	}
	if got := adopt.StagedVersion(); got != "" {
		t.Fatalf("adopt must consume the staged candidate, StagedVersion = %q", got)
	}
	// The re-anchored history makes the follow-up rollback CAS the durable
	// transition the row expects (current -> durable previous) ...
	if err := adopt.Rollback(context.Background()); err != nil {
		t.Fatalf("rollback after adopt: %v", err)
	}
	if cas.from != "user.alpha@1" || cas.to != "user.prior@1" {
		t.Fatalf("post-adopt rollback CAS = %q -> %q, want user.alpha@1 -> user.prior@1", cas.from, cas.to)
	}
	// ... and restore the REAL prior chain: the previous pack's detector
	// denies its pattern where the built-in chain would let it through.
	if _, _, err := adopt.ActiveHook().Apply("PRIOR_ADOPT_VALUE"); !errors.Is(err, ErrDenied) {
		t.Fatalf("rollback must restore the loaded prior hook, got %v", err)
	}
	if _, _, err := adopt.ActiveHook().Apply("ALPHA_ADOPT_VALUE"); err != nil {
		t.Fatalf("rollback must stop enforcing the adopted candidate: %v", err)
	}
}
