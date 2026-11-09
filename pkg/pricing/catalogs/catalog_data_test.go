package catalogs

import (
	"bytes"
	"flag"
	"path/filepath"
	"testing"
)

// updateCatalog rewrites the committed reference catalog from the corpus
// (golden-file flow):
//
//	go test ./pkg/pricing/catalogs/ -run TestCommittedReferenceCatalog -update
//
// The committed file is a generated pin, never hand-edited: rebuilds must
// reproduce it byte-for-byte, and the loader verifies its digest instead of
// trusting it.
var updateCatalog = flag.Bool("update", false, "rewrite the committed reference catalog from the corpus")

// committedCatalogRel is the repo-root-relative pin location. CORE-REF-03's
// pack envelope embeds this file verbatim and CORE-REF-04's serving flip
// loads it through LoadCatalog; the path is stable so both can reference it.
const committedCatalogRel = "pkg/pricing/catalogs/reference-catalog-v1.json"

// TestCommittedReferenceCatalog rebuilds the v1 catalog from the committed
// corpus and compares bytes with the pin. Determinism makes this an exact
// equality check: any drift (corpus, builder, config) must go through a
// deliberate -update commit, never a silent mismatch.
func TestCommittedReferenceCatalog(t *testing.T) {
	in := corpusInputs(t)
	cat, err := BuildCatalog(in, V1BuildConfig())
	if err != nil {
		t.Fatalf("BuildCatalog: %v", err)
	}
	want, err := MarshalCatalog(cat)
	if err != nil {
		t.Fatalf("MarshalCatalog: %v", err)
	}

	path := filepath.Join(repoRoot(t), filepath.FromSlash(committedCatalogRel))
	if *updateCatalog {
		// #nosec G306 -- generated public catalog pin; world-readable by
		// design (it ships in the repo and the public export).
		if err := writeFile(path, want); err != nil {
			t.Fatalf("write committed catalog: %v", err)
		}
		t.Logf("updated %s (%d bytes)", committedCatalogRel, len(want))
		return
	}

	got := readCorpusFile(t, committedCatalogRel)
	if !bytes.Equal(got, want) {
		t.Fatalf(`committed reference catalog does not match a corpus rebuild
(rebuild %d bytes, pin %d bytes). If the change is intended, regenerate the
pin and commit it together with the change:
  go test ./pkg/pricing/catalogs/ -run TestCommittedReferenceCatalog -update`, len(want), len(got))
	}

	// The pin must load fail-closed: digest recomputed over content.
	loaded, err := LoadCatalog(got)
	if err != nil {
		t.Fatalf("committed catalog must load cleanly: %v", err)
	}
	if loaded.Version != "0.1.0" || loaded.GeneratedAt != "2026-11-02" {
		t.Fatalf("committed catalog identity = %s @ %s, want 0.1.0 @ 2026-11-02", loaded.Version, loaded.GeneratedAt)
	}
	if loaded.Supersedes != "" {
		t.Fatalf("genesis pin must not declare a predecessor, got %q", loaded.Supersedes)
	}
	stats := Coverage(loaded)
	if stats.TotalEntries != 5 || stats.ActiveVerifiedPrimary != 3 || stats.Retired != 2 {
		t.Fatalf("committed catalog coverage drifted: %+v", stats)
	}
}
