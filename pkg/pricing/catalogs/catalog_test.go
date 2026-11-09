package catalogs

import (
	"bytes"
	"encoding/json"
	"math"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/pricing"
)

// mustBuild builds the v1 catalog or fails the test.
func mustBuild(t *testing.T, in BuildInput) pricing.Catalog {
	t.Helper()
	cat, err := BuildCatalog(in, V1BuildConfig())
	if err != nil {
		t.Fatalf("BuildCatalog: %v", err)
	}
	return cat
}

// TestBuildCatalogFromCorpus assembles the reference catalog from the
// primary record and pins 3 verified arms plus 2 retired identities.
func TestBuildCatalogFromCorpus(t *testing.T) {
	cat := mustBuild(t, corpusInputs(t))

	if err := pricing.ValidateCatalog(cat); err != nil {
		t.Fatalf("built catalog must validate (unsealed): %v", err)
	}

	// Header: genesis snapshot, explicit assembly identity (no wall clock).
	if cat.SchemaVersion != pricing.RefSchemaVersion {
		t.Fatalf("schema_version = %d, want %d", cat.SchemaVersion, pricing.RefSchemaVersion)
	}
	if cat.Version != "0.1.0" || cat.GeneratedAt != "2026-11-02" {
		t.Fatalf("header identity = %s @ %s, want 0.1.0 @ 2026-11-02", cat.Version, cat.GeneratedAt)
	}
	if cat.Supersedes != "" {
		t.Fatalf("genesis snapshot must not declare a predecessor, got %q", cat.Supersedes)
	}
	if cat.Digest != "" {
		t.Fatalf("built catalog must be unsealed (caller seals), got digest %q", cat.Digest)
	}
	if cat.ReviewSLADays != 90 {
		t.Fatalf("review_sla_days = %d, want 90", cat.ReviewSLADays)
	}
	if strings.TrimSpace(cat.Source) == "" {
		t.Fatal("assembly source is required in the header")
	}

	stats := Coverage(cat)
	if stats.TotalEntries != 5 {
		t.Fatalf("total entries = %d, want 5 (3 verified arms + 2 retired entries)", stats.TotalEntries)
	}
	if stats.ActiveVerifiedPrimary != 3 {
		t.Fatalf("active verified-primary = %d, want 3 (nebius arms)", stats.ActiveVerifiedPrimary)
	}
	if stats.Retired != 2 {
		t.Fatalf("retired = %d, want 2 (nebius avoid list)", stats.Retired)
	}
	if stats.DraftLitellmDerived != 0 {
		t.Fatalf("litellm-derived drafts = %d, want 0 (no distributed third-party data)", stats.DraftLitellmDerived)
	}
	if stats.DraftOther != 0 {
		t.Fatalf("draft entries with unexpected provenance = %d, want 0 (every draft must trace to the litellm corpus)", stats.DraftOther)
	}
	// Primary active entries have two known positive token axes each.
	if stats.UnpricedAxes != 0 {
		t.Fatalf("explicitly unpriced axes = %d, want 0 (primary rates only)", stats.UnpricedAxes)
	}
	// Three active entries, two axes each.
	if stats.PricedAxes != 6 {
		t.Fatalf("priced axes = %d, want 6 (two token axes per active arm)", stats.PricedAxes)
	}
	if stats.Aliases != 3 {
		t.Fatalf("aliases = %d, want 3 (nebius billing names)", stats.Aliases)
	}
}

// TestBuildCatalogCorpusSpotValues pins corpus-derived price facts the
// whole delivery relies on: the conversion semantics survive the assembly.
func TestBuildCatalogImportedValues(t *testing.T) {
	cat := mustBuild(t, importedInputs(t))
	m, ok := pricing.ResolveModel(cat, "fixture", "priced")
	if !ok {
		t.Fatal("imported synthetic model missing")
	}
	for axis, want := range map[string]float64{pricing.AxisInput: 17, pricing.AxisOutput: 29, pricing.AxisCacheRead: 5} {
		got, priced := pricing.RateAmount(m, axis)
		if !priced || got != want {
			t.Fatalf("axis %s got %v/%v want %v", axis, got, priced, want)
		}
	}
	if ClassifyEntry(m) != ClassLiteLLMDerived || m.Status != pricing.RefStatusDraft {
		t.Fatalf("import attribution/status lost: %+v", m)
	}
	if pricing.EntryServeable(m, time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("unreviewed import served")
	}
	if !strings.Contains(m.Sources[0].Ref, "@synthetic-test-only") || !strings.Contains(m.Sources[0].Note, "NOT verified by Yabanin") {
		t.Fatal("import provenance lost")
	}
	m, ok = pricing.ResolveModel(cat, "fixture", "unknown-input")
	if !ok {
		t.Fatal("unpriced model missing")
	}
	r, present := pricing.Rate(m, pricing.AxisInput)
	if !present || r.Amount != nil {
		t.Fatal("unknown axis must remain explicit null, not free")
	}
	if _, ok := pricing.ResolveModel(cat, "fixture", "missing"); ok {
		t.Fatal("unknown model resolved")
	}
}

// TestBuildCatalogNebiusOverlay pins the verified-primary slice: the only
// entries in v1 allowed to price production traffic.
func TestBuildCatalogNebiusOverlay(t *testing.T) {
	cat := mustBuild(t, corpusInputs(t))
	at := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)

	m, ok := pricing.ResolveModel(cat, "nebius-token-factory", "zai-org/GLM-5.2")
	if !ok {
		t.Fatal("nebius-token-factory:zai-org/GLM-5.2 must resolve")
	}
	if m.Status != pricing.RefStatusActive || m.Reviewer != NebiusEntryReviewer || m.VerifiedAt != "2026-09-08" {
		t.Fatalf("G1 arm lifecycle = %s/%s@%s, want active/%s@2026-09-08", m.Status, m.Reviewer, m.VerifiedAt, NebiusEntryReviewer)
	}
	if in, priced := pricing.RateAmount(m, pricing.AxisInput); !priced || in != 1.4 {
		t.Fatalf("G1 input = %v priced=%v, want 1.4 true", in, priced)
	}
	if out, priced := pricing.RateAmount(m, pricing.AxisOutput); !priced || out != 4.4 {
		t.Fatalf("G1 output = %v priced=%v, want 4.4 true", out, priced)
	}
	if !pricing.EntryServeable(m, at) {
		t.Fatal("verified-primary arm must be serveable at assembly time")
	}
	if pricing.EntryServeable(m, time.Date(2026, 5, 31, 23, 59, 59, 0, time.UTC)) {
		t.Fatal("arm window opens 2026-06-01; must not be serveable before")
	}
	// Billing name resolves as an alias to the same verified entry.
	a, ok := pricing.ResolveModel(cat, "nebius-token-factory", "GLM-5.2")
	if !ok || a.Model != "zai-org/GLM-5.2" {
		t.Fatalf("billing-name alias must resolve to the arm entry, got %+v ok=%v", a, ok)
	}

	// Every nebius rate carries dated evidence naming the verified record.
	for _, r := range m.Rates {
		if len(r.Evidence) != 1 {
			t.Fatalf("axis %s must carry exactly one dated observation, got %d", r.Axis, len(r.Evidence))
		}
		ev := r.Evidence[0]
		if ev.Ref != NebiusEvidencePrefix+"2026-09-08" || ev.At != "2026-09-08" {
			t.Fatalf("axis %s evidence = %+v, want ref %s... at 2026-09-08", r.Axis, ev, NebiusEvidencePrefix)
		}
	}

	// G2_ALT: the billing line lacks the -0731 suffix; the alias keeps the
	// clean billed string and the caveat is carried in the source note.
	m, ok = pricing.ResolveModel(cat, "nebius-token-factory", "deepseek-ai/DeepSeek-V4-Flash-0731")
	if !ok {
		t.Fatal("G2_ALT arm must resolve")
	}
	aliasOK := false
	for _, a := range m.Aliases {
		if a == "DeepSeek-V4-Flash" {
			aliasOK = true
		}
	}
	if !aliasOK {
		t.Fatalf("G2_ALT must alias its billed string %q, aliases=%v", "DeepSeek-V4-Flash", m.Aliases)
	}
	caveatOK := false
	for _, s := range m.Sources {
		if strings.Contains(s.Note, "billing-name caveat") {
			caveatOK = true
		}
	}
	if !caveatOK {
		t.Fatal("G2_ALT must carry the billing-name caveat in its source note")
	}

	// Avoid list: retired, never serveable at any instant, no rates.
	m, ok = pricing.ResolveModel(cat, "nebius-token-factory", "meta-llama/Llama-3.3-70B-Instruct")
	if !ok {
		t.Fatal("avoid-list model must be present as a retired entry (deprecation is verified fact)")
	}
	if m.Status != pricing.RefStatusRetired {
		t.Fatalf("avoid entry status = %q, want retired", m.Status)
	}
	if len(m.Rates) != 0 {
		t.Fatalf("retired entry must carry no rates, got %d", len(m.Rates))
	}
	if m.EffectiveTo != "2026-08-31" {
		t.Fatalf("retired entry window must close at the stated deprecation date, got %q", m.EffectiveTo)
	}
	for _, ts := range []time.Time{at, time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if pricing.EntryServeable(m, ts) {
			t.Fatalf("retired entry must never be serveable (checked %s)", ts)
		}
	}
}

// TestBuildCatalogDeterministic pins the determinism contract: same corpus
// in any entry order -> same catalog digest and same canonical model order.
func TestBuildCatalogDeterministic(t *testing.T) {
	in := importedInputs(t)
	cat1 := mustBuild(t, in)
	cat2 := mustBuild(t, in)

	d1, err := pricing.CatalogDigest(cat1)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	d2, err := pricing.CatalogDigest(cat2)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if d1 != d2 {
		t.Fatalf("identical inputs produced different digests: %s vs %s", d1, d2)
	}

	// Permute the token corpus (shuffle entry order, re-marshal) and
	// rebuild: the digest must not move.
	pf, _, err := pricing.ParsePriceFile(bytes.NewReader(in.TokenSnapshot))
	if err != nil {
		t.Fatalf("reparse token snapshot: %v", err)
	}
	rnd := rand.New(rand.NewSource(42)) // #nosec G404 -- deterministic test shuffle, not security
	rnd.Shuffle(len(pf.Models), func(i, j int) { pf.Models[i], pf.Models[j] = pf.Models[j], pf.Models[i] })
	permuted, err := json.Marshal(pf)
	if err != nil {
		t.Fatalf("re-marshal permuted corpus: %v", err)
	}
	cat3, err := BuildCatalog(BuildInput{TokenSnapshot: permuted, UnitSnapshot: in.UnitSnapshot, NebiusRecord: in.NebiusRecord}, V1BuildConfig())
	if err != nil {
		t.Fatalf("build from permuted corpus: %v", err)
	}
	d3, err := pricing.CatalogDigest(cat3)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if d1 != d3 {
		t.Fatalf("corpus entry order changed the digest: %s vs %s", d1, d3)
	}

	// Entries are stored in canonical order (5-tuple): byte-stable files.
	for i := 1; i < len(cat1.Models); i++ {
		prev, cur := cat1.Models[i-1], cat1.Models[i]
		if modelLess(cur, prev) {
			t.Fatalf("models not in canonical order at [%d]: %s:%s after %s:%s",
				i, cur.Provider, cur.Model, prev.Provider, prev.Model)
		}
	}
}

// modelLess is the canonical 5-tuple comparison (matches the schema's
// canonical ordering contract).
func modelLess(a, b pricing.RefModel) bool {
	if a.Provider != b.Provider {
		return a.Provider < b.Provider
	}
	if a.Model != b.Model {
		return a.Model < b.Model
	}
	if a.Region != b.Region {
		return a.Region < b.Region
	}
	if a.Tier != b.Tier {
		return a.Tier < b.Tier
	}
	return a.ContextBand < b.ContextBand
}

// TestEnforceNeverFreeGuard probes the builder-side never-free guard
// directly (defense in depth behind the conversion semantics, which already
// map legacy zeros to nil).
func TestEnforceNeverFreeGuard(t *testing.T) {
	zero := 0.0
	NaN := math.NaN()
	c := func(r pricing.RefRate) pricing.Catalog {
		return pricing.Catalog{Models: []pricing.RefModel{{
			Provider: "x", Model: "y", Currency: "USD", Status: pricing.RefStatusDraft,
			Rates: []pricing.RefRate{r},
		}}}
	}
	base := pricing.RefRate{Axis: pricing.AxisInput, Unit: pricing.RefUnitPer1MTokens}

	if err := enforceNeverFree(c(pricing.RefRate{Axis: pricing.AxisInput, Unit: pricing.RefUnitPer1MTokens})); err != nil {
		t.Fatalf("nil amount (explicitly unpriced) must pass: %v", err)
	}
	r := base
	v := 1.4
	r.Amount = &v
	if err := enforceNeverFree(c(r)); err != nil {
		t.Fatalf("positive amount must pass: %v", err)
	}
	r.Amount = &zero
	if err := enforceNeverFree(c(r)); err == nil || !strings.Contains(err.Error(), "never-free") {
		t.Fatalf("zero amount must be refused as never-free, got %v", err)
	}
	r.Amount = &NaN
	if err := enforceNeverFree(c(r)); err == nil {
		t.Fatal("non-finite amount must be refused")
	}
}

func TestOptionalSnapshotsRemainStrict(t *testing.T) {
	for _, tc := range []struct {
		name        string
		token, unit []byte
	}{
		{name: "malformed token", token: []byte("{")},
		{name: "malformed unit", unit: []byte("{")},
		{name: "empty provided token", token: []byte(`{"source":"test","date":"2026-11-09","currency":"USD","units":"per_1m_tokens","models":[]}`)},
		{name: "empty provided unit", unit: []byte(`{"source":"test","date":"2026-11-09","currency":"USD","units":[]}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := corpusInputs(t)
			in.TokenSnapshot = tc.token
			in.UnitSnapshot = tc.unit
			if _, err := BuildCatalog(in, V1BuildConfig()); err == nil {
				t.Fatal("invalid explicitly supplied input accepted")
			}
		})
	}
	for _, kind := range []string{"token", "unit"} {
		t.Run(kind+" only", func(t *testing.T) {
			in := importedInputs(t)
			want := 7
			if kind == "token" {
				in.UnitSnapshot = nil
			} else {
				in.TokenSnapshot = nil
				want = 6
			}
			cat := mustBuild(t, in)
			if len(cat.Models) != want {
				t.Fatalf("lost supplied or primary entries: %d want %d", len(cat.Models), want)
			}
		})
	}
}
