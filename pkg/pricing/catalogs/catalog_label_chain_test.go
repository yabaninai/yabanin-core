package catalogs

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/pricing"
)

// labelPattern is the REF-04 preview label contract as a grammar: source
// token, catalog version, generated date, sha256 digest.
var labelPattern = regexp.MustCompile(`^yabanin-catalog@([^/\s]+) (\d{4}-\d{2}-\d{2}) sha256:([0-9a-f]{64})$`)

// TestProvenanceLabelContract pins the label over the committed catalog:
// exact grammar, exact identity parts, deterministic across rebuilds.
func TestProvenanceLabelContract(t *testing.T) {
	committed := readCorpusFile(t, committedCatalogRel)
	loaded, err := LoadCatalog(committed)
	if err != nil {
		t.Fatalf("load committed: %v", err)
	}
	label, err := ProvenanceLabel(loaded)
	if err != nil {
		t.Fatalf("ProvenanceLabel: %v", err)
	}

	m := labelPattern.FindStringSubmatch(label)
	if m == nil {
		t.Fatalf("label %q does not match the REF-04 contract grammar", label)
	}
	if m[1] != "0.1.0" {
		t.Fatalf("label version = %q, want 0.1.0", m[1])
	}
	if m[2] != "2026-11-02" {
		t.Fatalf("label date = %q, want 2026-11-02", m[2])
	}
	d, err := pricing.CatalogDigest(loaded)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if m[3] != d {
		t.Fatalf("label digest %q does not match the catalog digest %q", m[3], d)
	}

	// A rebuild sealed by MarshalCatalog produces the same label.
	rebuilt := mustBuild(t, corpusInputs(t))
	rebuilt, err = pricing.SealCatalog(rebuilt)
	if err != nil {
		t.Fatalf("seal rebuild: %v", err)
	}
	rbytes, err := MarshalCatalog(rebuilt)
	if err != nil {
		t.Fatalf("marshal rebuild: %v", err)
	}
	if !bytes.Equal(rbytes, committed) {
		t.Fatal("rebuild bytes diverged from the pin (determinism regression)")
	}
	rlabel, err := ProvenanceLabel(rebuilt)
	if err != nil {
		t.Fatalf("ProvenanceLabel(rebuilt): %v", err)
	}
	if rlabel != label {
		t.Fatalf("rebuilt label %q differs from committed label %q", rlabel, label)
	}

	// Source separation: the label cites OUR artifact, never the upstream
	// snapshot; upstream attribution stays at entry level.
	if strings.Contains(label, "litellm") {
		t.Fatalf("label must not name the upstream snapshot: %q", label)
	}
	foundDerived := 0
	for _, mo := range loaded.Models {
		if ClassifyEntry(mo) == ClassLiteLLMDerived {
			foundDerived++
		}
	}
	if foundDerived != 0 {
		t.Fatalf("derived entries in pin = %d, want 0 (no third-party data in shipped catalog)", foundDerived)
	}

	// Structural accessor agrees.
	ld, err := LabelDigest(loaded)
	if err != nil || ld != d {
		t.Fatalf("LabelDigest = %q err=%v, want %q", ld, err, d)
	}
}

// TestProvenanceLabelFailsClosed probes the refusal paths: no label may
// exist for an unsealed or malformed catalog.
func TestProvenanceLabelFailsClosed(t *testing.T) {
	cat := mustBuild(t, corpusInputs(t)) // unsealed: Digest ""
	if _, err := ProvenanceLabel(cat); err == nil || !strings.Contains(err.Error(), "not sealed") {
		t.Fatalf("unsealed catalog must refuse a label, got %v", err)
	}
	if _, err := LabelDigest(cat); err == nil {
		t.Fatal("unsealed catalog must refuse a bare digest")
	}

	// A content change without resealing is refused at load; after
	// resealing the label digest moves (labels pin content, not names).
	sealed, err := pricing.SealCatalog(cat)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	bumped := sealed
	bumped.Version = "9.9.9-mutated"
	if err := pricing.ValidateCatalog(bumped); err == nil {
		t.Fatal("mutated catalog with stale digest must fail validation (digest vs content)")
	}
	resal, err := pricing.SealCatalog(bumped)
	if err != nil {
		t.Fatalf("reseal: %v", err)
	}
	newLabel, err := ProvenanceLabel(resal)
	if err != nil {
		t.Fatalf("ProvenanceLabel(resealed): %v", err)
	}
	baseLabel, err := ProvenanceLabel(sealed)
	if err != nil {
		t.Fatalf("ProvenanceLabel(sealed): %v", err)
	}
	if newLabel == baseLabel {
		t.Fatal("resealing after a content change must move the label digest")
	}
}

// TestChainRollbackBothWays pins the rollback-chain semantics over the
// committed pin: forward, tampered-refusal, and rollback-as-new-snapshot.
func TestChainRollbackBothWays(t *testing.T) {
	committed := readCorpusFile(t, committedCatalogRel)
	v1, err := LoadCatalog(committed)
	if err != nil {
		t.Fatalf("load committed: %v", err)
	}
	d1, err := pricing.CatalogDigest(v1)
	if err != nil {
		t.Fatalf("digest v1: %v", err)
	}

	// Forward: v2 declares supersedes=digest(v1); the chain verifies.
	v2 := v1
	v2.Version = "0.2.0"
	v2.GeneratedAt = "2027-01-15"
	v2.Supersedes = d1
	v2.Digest = ""
	v2, err = pricing.SealCatalog(v2)
	if err != nil {
		t.Fatalf("seal v2: %v", err)
	}
	if err := VerifyChain(v1, v2); err != nil {
		t.Fatalf("forward chain must verify: %v", err)
	}

	// Both directions load independently; v1's digest is unchanged after
	// all operations (snapshots are immutable values).
	v2Bytes, err := MarshalCatalog(v2)
	if err != nil {
		t.Fatalf("marshal v2: %v", err)
	}
	loadedV2, err := LoadCatalog(v2Bytes)
	if err != nil {
		t.Fatalf("load v2: %v", err)
	}
	d1Again, err := pricing.CatalogDigest(v1)
	if err != nil {
		t.Fatalf("digest v1 again: %v", err)
	}
	if d1Again != d1 {
		t.Fatalf("v1 digest moved: %s -> %s", d1, d1Again)
	}

	// Tampered supersedes pointer: re-sealed so the digest matches the
	// forged content (the point is the CHAIN check, not the digest check):
	// the chain must still refuse because the pointer lies about history.
	forged := loadedV2
	forged.Supersedes = strings.Repeat("ab", 32)
	forged, err = pricing.SealCatalog(forged)
	if err != nil {
		t.Fatalf("seal forged: %v", err)
	}
	if err := VerifyChain(v1, forged); err == nil || !strings.Contains(err.Error(), "supersedes") {
		t.Fatalf("forged supersedes must break the chain, got %v", err)
	}

	// An empty supersedes pointer is not a rollback: the chain requires the
	// new snapshot to declare what it replaces (re-sealed so the digest
	// check passes and the chain rule itself fires).
	noPred := loadedV2
	noPred.Supersedes = ""
	noPred, err = pricing.SealCatalog(noPred)
	if err != nil {
		t.Fatalf("seal noPred: %v", err)
	}
	if err := VerifyChain(v2, noPred); err == nil || !strings.Contains(err.Error(), "predecessor") {
		t.Fatalf("snapshot without a predecessor pointer must refuse, got %v", err)
	}

	// Rollback is a NEW snapshot that restores prior content: v3 carries
	// v1's models with its own identity and supersedes digest(v2).
	v3 := v1
	v3.Version = "0.1.1-rollback"
	v3.GeneratedAt = "2027-02-01"
	v3.Supersedes = loadedV2.Digest
	v3.Digest = ""
	v3, err = pricing.SealCatalog(v3)
	if err != nil {
		t.Fatalf("seal v3: %v", err)
	}
	if err := VerifyChain(loadedV2, v3); err != nil {
		t.Fatalf("rollback chain must verify: %v", err)
	}

	// Stale-day boundary sanity for the chain participants: v2 keeps the
	// SLA; StaleModels reports the 3 verified-primary arms after day 91.
	stale := pricing.StaleModels(loadedV2, time.Date(2026, 12, 8, 0, 0, 0, 0, time.UTC))
	if len(stale) != 3 {
		t.Fatalf("stale entries on 2026-12-08 = %v, want the 3 verified arms", stale)
	}
}

// TestPrecedenceDocumented pins the load-bearing statements of
// PRECEDENCE.md (the COREREF-05 R1 ownership split). If the wording moves,
// move the pin with it deliberately — these sentences are what consumers
// and reviewers rely on.
func TestPrecedenceDocumented(t *testing.T) {
	doc := string(readCorpusFile(t, "pkg/pricing/catalogs/PRECEDENCE.md"))
	required := []string{
		"rate authority",
		"routing-config and identity authority",
		"The pricing catalog wins for every priced axis",
		"The models registry wins for which model serves a request",
		"never free",
		"never inherits a price",
		"never serveable",
		"LoadCatalog",
		"VerifyChain",
		"ProvenanceLabel",
		"source citation, not a freshness claim",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) {
			t.Errorf("PRECEDENCE.md must state %q", want)
		}
	}
}

// TestOfflineNoClockPins is a static self-audit of this package: the build
// path must stay offline (no network imports) and wall-clock-free
// (no time.Now outside tests), so output bytes can never depend on the
// machine that runs the build.
func TestOfflineNoClockPins(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	files, err := filepath.Glob(filepath.Dir(thisFile) + "/*.go")
	if err != nil {
		t.Fatalf("glob package sources: %v", err)
	}
	if len(files) < 8 {
		t.Fatalf("package source scan found %d files, unexpectedly few", len(files))
	}
	for _, f := range files {
		isTest := strings.HasSuffix(f, "_test.go")
		// #nosec G304 -- reading this package's own compiled sources (path
		// from runtime.Caller, no user input); the scan IS the pin.
		srcBytes, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		src := string(srcBytes)
		// The offline pin applies to the build path only (non-test
		// sources); scanning test files would self-match this test's own
		// literal ban list.
		if !isTest {
			for _, banned := range []string{`"net/http"`, `"net/url"`, `"net"`} {
				if strings.Contains(src, banned) {
					t.Errorf("%s imports %s: the catalog build path must stay offline", f, banned)
				}
			}
			if strings.Contains(src, "time.Now(") {
				t.Errorf("%s calls time.Now: catalog bytes must never depend on the wall clock", f)
			}
		}
	}
}
