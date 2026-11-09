package pricing

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// CORE-REF-04 serving flip: the default file pricer serves the reference
// catalog projection (active + verified + in-window + non-stale entries),
// cites the yabanin-catalog label. No third-party corpus ships. Historical computations are
// never re-rated: provenance is captured per pricer instance, and the
// tenant-override seam (SetDefaultFilePricer) keeps precedence.

const (
	// genesis pin (REF-02 handover contract; TestBundledRefSnapshotPins
	// independently pins the committed file bytes).
	refGenesisDigest = "eeb4d7063d48b8bf7b5d4f4374278259cdff856792755f63d0a92c21f2f651c5"
	refGenesisLabel  = "yabanin-catalog@0.1.0"
	// the committed pack envelope digest (REF-03 snapshot).
	refGenesisPackSHA = "267134c734ebb93d028a73d4f6b1e7f97f3cd5405d756faf8ce51f7b52515968"
)

// TestRefServeEmbedMatchesCommitted pins the embedded reference pack to the
// committed snapshot file byte-for-byte: the serving flip must serve exactly
// the reviewed artifact, not a drifted copy.
func TestRefServeEmbedMatchesCommitted(t *testing.T) {
	committed := filepath.Join(repoRoot(t), committedRefPackRel)
	want, err := os.ReadFile(committed) // #nosec G304 -- repo-relative path from a package-level constant
	if err != nil {
		t.Fatalf("read committed pack: %v", err)
	}
	if string(bundledRefPackBytes) != string(want) {
		t.Fatalf("embedded reference pack drifted from %s", committedRefPackRel)
	}
	// The envelope chain pin: pack_sha256 is the self-referential envelope
	// digest (REF-03), verified by the loader — assert the field explicitly
	// so the pin documents both layers (file bytes above, envelope chain here).
	pack, _, err := LoadRefPack(bundledRefPackBytes)
	if err != nil {
		t.Fatalf("embedded reference pack must pass all loader checks: %v", err)
	}
	if pack.PackSHA256 != refGenesisPackSHA {
		t.Fatalf("embedded pack envelope digest %s, want the REF-03 pin %s", pack.PackSHA256, refGenesisPackSHA)
	}
}

// TestRefServeLoadsGenesisProjection: the flipped default serves the three
// active verified-primary arms with exact cents from the committed RefRate
// amounts, cites the genesis label, and carries the structured catalog info.
// Every active arm also projects under its aliases with identical rates.
// AUD-PRICE-02: pins are driven through the explicit-instant loader at the
// catalog generation date — the pins never go SLA-stale when the shipped
// verified_at (2026-09-08 + 90d) ages past the wall clock, and the alias
// rows stay pinned with the canonical ones.
func TestRefServeLoadsGenesisProjection(t *testing.T) {
	genesisNow := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	p, err := loadBundledRefServeAt(genesisNow)
	if err != nil {
		t.Fatalf("loadBundledRefServeAt: %v", err)
	}
	prov := p.Provenance()
	if prov.Source != refGenesisLabel {
		t.Errorf("source = %q, want %q", prov.Source, refGenesisLabel)
	}
	if prov.Date != "2026-11-02" {
		t.Errorf("date = %q, want 2026-11-02", prov.Date)
	}
	if prov.SHA256 != "sha256:"+refGenesisDigest {
		t.Errorf("sha256 = %q, want the genesis catalog digest", prov.SHA256)
	}
	if prov.ModelCnt != 6 {
		t.Errorf("model count = %d, want the 3 active arms + their 3 aliases", prov.ModelCnt)
	}
	info, ok := p.CatalogProvenance()
	if !ok {
		t.Fatal("catalog provenance missing on the reference-backed pricer")
	}
	if info.Version != "0.1.0" || info.GeneratedAt != "2026-11-02" || info.Digest != refGenesisDigest {
		t.Errorf("catalog info = %+v", info)
	}

	// Exact cents from the committed catalog (R2): every projected model's
	// projected rates must equal the RefRate amounts of the entry it serves —
	// the canonical entry for canonical rows, the target entry for alias rows.
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), genesisCatalogRel))
	if err != nil {
		t.Fatalf("read committed catalog: %v", err)
	}
	var cat Catalog
	if err := json.Unmarshal(raw, &cat); err != nil {
		t.Fatalf("parse committed catalog: %v", err)
	}
	byKey := map[string]*RefModel{}
	aliasOwner := map[string]*RefModel{}
	for i := range cat.Models {
		m := &cat.Models[i]
		byKey[m.Provider+"\x00"+m.Model] = m
		for _, a := range m.Aliases {
			aliasOwner[m.Provider+"\x00"+a] = m
		}
	}
	pf := p.File()
	if len(pf.Models) != 6 {
		t.Fatalf("projected file has %d models, want 3 canonical + 3 alias rows", len(pf.Models))
	}
	for _, pm := range pf.Models {
		key := pm.Provider + "\x00" + pm.Model
		src := byKey[key]
		if src == nil {
			src = aliasOwner[key]
		}
		if src == nil {
			t.Fatalf("projected %s/%s has no catalog entry", pm.Provider, pm.Model)
		}
		if src.Status != RefStatusActive {
			t.Errorf("projected %s/%s is %q, not active", pm.Provider, pm.Model, src.Status)
		}
		if err := refRateAxesMatch(src, pm); err != nil {
			t.Errorf("%s/%s: %v", pm.Provider, pm.Model, err)
		}
	}
	// The draft corpus is out of the serving path: unknown, not free.
	if _, ok := p.Lookup("openai", "gpt-4o"); ok {
		t.Error("draft corpus entry must not serve through the reference projection")
	}
}

// refRateAxesMatch asserts the projected PriceFileModel carries exactly the
// priced RefRate amounts of its catalog entry (token axes), with cache axes
// absent (0 = "not offered" legacy semantics).
func refRateAxesMatch(src *RefModel, pm PriceFileModel) error {
	for _, r := range src.Rates {
		if r.Amount == nil {
			continue
		}
		var got float64
		switch r.Axis {
		case AxisInput:
			got = pm.Input
		case AxisOutput:
			got = pm.Output
		case AxisCacheWrite:
			got = pm.CacheW
		case AxisCacheRead:
			got = pm.CacheR
		default:
			continue // non-token axes are not projected into the file shape
		}
		if got != *r.Amount {
			return fmt.Errorf("axis %s: projected %v != catalog rate %v", r.Axis, got, *r.Amount)
		}
	}
	return nil
}

// TestRefServeServeabilityGate drives the PRECEDENCE §5 gate structurally:
// only active + verified-source + in-window + non-stale entries project.
func TestRefServeServeabilityGate(t *testing.T) {
	now := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	base := refServeEntry()

	cases := []struct {
		name   string
		mutate func(*RefModel, *Catalog)
		wantIn bool
	}{
		{"active verified in-window serves", func(_ *RefModel, _ *Catalog) {}, true},
		{"draft never serves", func(m *RefModel, _ *Catalog) { m.Status = RefStatusDraft }, false},
		{"retired never serves", func(m *RefModel, _ *Catalog) { m.Status = RefStatusRetired }, false},
		{"future effective_from is out of window", func(m *RefModel, _ *Catalog) { m.EffectiveFrom = "2027-01-01" }, false},
		{"expired effective_to is out of window", func(m *RefModel, _ *Catalog) { m.EffectiveTo = "2026-10-01" }, false},
		{"stale beyond the review SLA does not serve", func(m *RefModel, c *Catalog) {
			m.VerifiedAt = "2026-07-01" // 124 days before now, SLA 90
			c.ReviewSLADays = 90
		}, false},
		{"no review SLA means no staleness gate", func(m *RefModel, c *Catalog) {
			m.VerifiedAt = "2026-07-01"
			c.ReviewSLADays = 0
		}, true},
		{"active without a verified source does not serve", func(m *RefModel, _ *Catalog) {
			m.Sources = nil
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cat := Catalog{
				SchemaVersion: RefSchemaVersion,
				Version:       "gate-test",
				GeneratedAt:   "2026-11-02",
				Source:        "refpack test assembly (deterministic fixture)",
				ReviewSLADays: 90,
				Models:        []RefModel{base},
			}
			m := &cat.Models[0]
			if tc.mutate != nil {
				tc.mutate(m, &cat)
			}
			pf, err := projectServeable(cat, now)
			if err != nil {
				t.Fatalf("projectServeable: %v", err)
			}
			if tc.wantIn && len(pf.Models) != 1 {
				t.Fatalf("entry must serve, got %d models", len(pf.Models))
			}
			if !tc.wantIn && len(pf.Models) != 0 {
				t.Fatalf("entry must NOT serve, got %d models", len(pf.Models))
			}
		})
	}
}

// refServeEntry is one active verified in-window entry with input+output
// priced — the minimal serveable shape.
func refServeEntry() RefModel {
	in := 0.14
	out := 0.28
	return RefModel{
		Provider: "gprov", Model: "gate-model",
		Currency: "USD", Status: RefStatusActive,
		EffectiveFrom: "2026-07-01", VerifiedAt: "2026-11-01",
		Rates: []RefRate{
			{Axis: AxisInput, Unit: RefUnitPer1MTokens, Amount: &in},
			{Axis: AxisOutput, Unit: RefUnitPer1MTokens, Amount: &out},
		},
		Sources: []RefSource{{
			Kind: RefSourceInternalEvidence, Ref: "ev-gate-1", VerifiedAt: "2026-11-01",
		}},
		Reviewer: "gate-reviewer",
	}
}

// TestRefServeRefusesUnpriceableActive: an active verified entry without a
// priced input or output amount is refused — the projection must never turn
// an unknown price into a free one.
func TestRefServeRefusesUnpriceableActive(t *testing.T) {
	now := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	cat := Catalog{
		SchemaVersion: RefSchemaVersion,
		Version:       "gate-test",
		GeneratedAt:   "2026-11-02",
		Source:        "refpack test assembly (deterministic fixture)",
		ReviewSLADays: 90,
		Models:        []RefModel{refServeEntry()},
	}
	m := &cat.Models[0]
	for i := range m.Rates {
		if m.Rates[i].Axis == AxisOutput {
			m.Rates[i].Amount = nil
		}
	}
	if _, err := projectServeable(cat, now); err == nil {
		t.Fatal("active entry with an unpriced output axis must be refused, not projected as free")
	}
}

// The compatibility loader must not resurrect the removed corpus.
func TestRefServeLegacyLoaderUsesPrimaryCatalog(t *testing.T) {
	p, err := LoadBundled()
	ref, refErr := LoadBundledRefServe()
	if (err == nil) != (refErr == nil) {
		t.Fatalf("compatibility/reference errors differ: %v / %v", err, refErr)
	}
	if err != nil {
		return
	} // Expired or otherwise unservable catalogs must refuse equally.
	if p.Provenance() != ref.Provenance() {
		t.Fatal("compatibility loader changed provenance")
	}
	if _, ok := p.Lookup("openai", "gpt-4o"); ok {
		t.Fatal("excluded rate reappeared")
	}
	if _, ok := p.CatalogProvenance(); !ok {
		t.Fatal("primary catalog citation missing")
	}
}

// TestRefServe_DefaultFlipsAndOverridesWin: the process default cites the
// reference catalog, an explicit SetDefaultFilePricer (the tenant-override /
// external-snapshot seam) still wins, and flipping never mutates a pricer
// that was captured before — per-computation provenance, no retroactive
// re-rating. The pristine default is rebuilt through the explicit-instant
// seam at the fixed audit instant (package-wide audit02Time): what is under
// test here is flip/override precedence and provenance immutability, not
// the shipped catalog's expiry (pinned separately in
// TestAuditPRICE02_ShippedCatalogExpiryBoundary).
func TestRefServe_DefaultFlipsAndOverridesWin(t *testing.T) {
	defaultFilePricerMu.Lock()
	saved := defaultFilePricer
	defaultFilePricer = nil
	defaultFilePricerMu.Unlock()
	resetFilePricerOnce()
	defer func() {
		defaultFilePricerMu.Lock()
		defaultFilePricer = saved
		firstToucher := saved == nil
		defaultFilePricerMu.Unlock()
		if firstToucher {
			resetFilePricerOnce()
		}
	}()

	// Same fixed instant as the other serving-flip pins, via the production
	// seam: the catalog-citation requirement must not depend on the
	// machine clock.
	fresh, err := loadBundledRefServeAt(audit02Time)
	if err != nil {
		t.Fatalf("loadBundledRefServeAt: %v", err)
	}
	if !strings.HasPrefix(fresh.Provenance().Source, "yabanin-catalog@") {
		t.Fatalf("default pricer must cite the reference catalog, got %+v", fresh.Provenance())
	}

	// A pricer captured before any flip keeps its provenance (value copy,
	// no shared mutable state). captured aliases fresh — the two original
	// DefaultFilePricer calls returned the same singleton instance, so the
	// mutation-precedence semantics are unchanged.
	captured := fresh
	before := captured.Provenance()
	custom, err := NewFilePricer(PriceFile{
		Source: "override", Date: "2026-11-02", Currency: "USD", Units: "per_1m_tokens",
		Models: []PriceFileModel{{Provider: "ovr", Model: "m", Input: 1, Output: 2}},
	}, "sha256:override")
	if err != nil {
		t.Fatalf("NewFilePricer: %v", err)
	}
	SetDefaultFilePricer(custom)
	if got := DefaultFilePricer(); got != custom {
		t.Error("SetDefaultFilePricer override must win over the flipped default")
	}
	if captured.Provenance() != before {
		t.Error("flip must not mutate a previously captured pricer's provenance")
	}
}
