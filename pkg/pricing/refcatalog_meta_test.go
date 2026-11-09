package pricing

import (
	"testing"
)

// Lockstep guard for the refcatalog_meta shim: the new
// process-boundary helpers must behave exactly like LoadBundledRefServe on
// the embedded pack. If someone changes the serving gates in refserve.go
// without mirroring ServeCatalogFromPack (or vice versa), this flips.

// TestBundledRefPackJSONIsLoadableCopy pins that the exposed bytes are the
// committed pack (pass every load check) and that mutating the returned
// slice cannot corrupt the embedded original.
func TestBundledRefPackJSONIsLoadableCopy(t *testing.T) {
	b := BundledRefPackJSON()
	if len(b) == 0 {
		t.Fatal("BundledRefPackJSON returned no bytes")
	}
	pack, cat, err := LoadRefPack(b)
	if err != nil {
		t.Fatalf("embedded pack must load: %v", err)
	}
	if pack.CatalogDigest != cat.Digest {
		t.Fatalf("catalog digest mismatch in exposed pack")
	}
	// Mutation isolation.
	b[0] ^= 0xFF
	if _, _, err := LoadRefPack(BundledRefPackJSON()); err != nil {
		t.Fatalf("embedded original was mutated through the copy: %v", err)
	}
}

// TestServeCatalogFromPackMatchesBundledServe pins that seating a pricer
// from the embedded pack bytes produces the identical citation (version,
// generated_at, digest) as the canonical LoadBundledRefServe path.
func TestServeCatalogFromPackMatchesBundledServe(t *testing.T) {
	bundled, err := LoadBundledRefServe()
	if err != nil {
		t.Fatalf("LoadBundledRefServe: %v", err)
	}
	fromPack, err := ServeCatalogFromPack(BundledRefPackJSON())
	if err != nil {
		t.Fatalf("ServeCatalogFromPack: %v", err)
	}
	want, okW := bundled.CatalogProvenance()
	got, okG := fromPack.CatalogProvenance()
	if !okW || !okG {
		t.Fatalf("catalog citations missing: bundled ok=%v, from-pack ok=%v", okW, okG)
	}
	if want != got {
		t.Fatalf("citation drift: bundled %+v, from-pack %+v", want, got)
	}
}

// TestServeCatalogFromPackRefusesGarbage pins the fail-closed path: pack
// bytes that do not pass LoadRefPack must not produce a pricer.
func TestServeCatalogFromPackRefusesGarbage(t *testing.T) {
	if _, err := ServeCatalogFromPack([]byte("not a pack")); err == nil {
		t.Fatal("garbage bytes must be refused")
	}
	if _, err := ServeCatalogFromPack(nil); err == nil {
		t.Fatal("nil bytes must be refused")
	}
}

// TestProjectionFromPackMatchesServeCatalogFromPack pins the promotion
// planning contract: the PriceFile the durable promotion plans against is
// byte-for-byte the projection a pack-seated pricer serves. If the serving
// gates ever drift from the planner projection, the materialized table
// would diverge from served prices — this flips.
func TestProjectionFromPackMatchesServeCatalogFromPack(t *testing.T) {
	pf, err := ProjectionFromPack(BundledRefPackJSON())
	if err != nil {
		t.Fatalf("ProjectionFromPack: %v", err)
	}
	served, err := ServeCatalogFromPack(BundledRefPackJSON())
	if err != nil {
		t.Fatalf("ServeCatalogFromPack: %v", err)
	}
	servedFile := served.File()
	if pf.Source != servedFile.Source || pf.Date != servedFile.Date {
		t.Fatalf("projection metadata drift: source %q/%q date %q/%q",
			pf.Source, servedFile.Source, pf.Date, servedFile.Date)
	}
	if len(pf.Models) != len(servedFile.Models) || len(pf.Models) == 0 {
		t.Fatalf("projection size drift: %d vs %d", len(pf.Models), len(servedFile.Models))
	}
	for i := range pf.Models {
		if pf.Models[i] != servedFile.Models[i] {
			t.Fatalf("projection entry %d drift: %+v vs %+v", i, pf.Models[i], servedFile.Models[i])
		}
	}
}

// TestProjectionFromPackRefusesGarbage pins the same fail-closed path as
// the pricer builder: no valid projection from invalid bytes.
func TestProjectionFromPackRefusesGarbage(t *testing.T) {
	if _, err := ProjectionFromPack([]byte("not a pack")); err == nil {
		t.Fatal("garbage bytes must be refused")
	}
	if _, err := ProjectionFromPack(nil); err == nil {
		t.Fatal("nil bytes must be refused")
	}
}
