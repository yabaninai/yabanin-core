package pricing

import (
	"strings"
	"testing"
)

// convertPriceFixture is a legacy PriceFile exercising every conversion
// rule: priced input/output, zero input (unknown, not free), cache axes
// present and absent.
func convertPriceFixture() PriceFile {
	return PriceFile{
		Source:   "github.com/example/models@abc123",
		Date:     "2026-09-30",
		Currency: "USD",
		Units:    "per_1m_tokens",
		Models: []PriceFileModel{
			{Provider: "openai", Model: "gpt-a", Input: 0.5, Output: 1.5, CacheW: 0.75, CacheR: 0.05},
			{Provider: "openai", Model: "gpt-free-entry", Input: 0, Output: 2.0, CacheW: 0, CacheR: 0},
		},
	}
}

func TestCatalogFromPriceFileMapping(t *testing.T) {
	c, err := CatalogFromPriceFile(convertPriceFixture())
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if err := ValidateCatalog(c); err != nil {
		t.Fatalf("converted catalog must validate: %v", err)
	}

	if len(c.Models) != 2 {
		t.Fatalf("one entry per legacy model, got %d", len(c.Models))
	}
	m, ok := ResolveModel(c, "openai", "gpt-a")
	if !ok {
		t.Fatal("gpt-a must convert")
	}

	// Header contract.
	if m.Status != RefStatusDraft {
		t.Fatalf("converted entries must be draft, got %q", m.Status)
	}
	if m.Currency != "USD" || m.EffectiveFrom != "2026-09-30" || m.VerifiedAt != "2026-09-30" {
		t.Fatalf("date/currency must carry over, got %+v", m)
	}
	if len(m.Sources) != 1 || m.Sources[0].Ref != convertPriceFixture().Source ||
		m.Sources[0].Kind != RefSourceInternalEvidence {
		t.Fatalf("entry source must name the legacy snapshot, got %+v", m.Sources)
	}

	// Priced axes keep their amounts on the paired unit.
	in, priced := RateAmount(m, AxisInput)
	if !priced || in != 0.5 {
		t.Fatalf("input axis: priced=%v amount=%v", priced, in)
	}
	r, _ := Rate(m, AxisInput)
	if r.Unit != RefUnitPer1MTokens {
		t.Fatalf("token axis must use per_1m_tokens, got %q", r.Unit)
	}
	out, priced := RateAmount(m, AxisOutput)
	if !priced || out != 1.5 {
		t.Fatalf("output axis: priced=%v amount=%v", priced, out)
	}

	// Non-zero cache rates convert to present, priced axes.
	cw, priced := RateAmount(m, AxisCacheWrite)
	if !priced || cw != 0.75 {
		t.Fatalf("cache_write axis: priced=%v amount=%v", priced, cw)
	}
	cr, priced := RateAmount(m, AxisCacheRead)
	if !priced || cr != 0.05 {
		t.Fatalf("cache_read axis: priced=%v amount=%v", priced, cr)
	}

	// Zero input price is explicitly unpriced (nil), NEVER free.
	freeEntry, ok := ResolveModel(c, "openai", "gpt-free-entry")
	if !ok {
		t.Fatal("gpt-free-entry must convert")
	}
	if amount, priced := RateAmount(freeEntry, AxisInput); priced || amount != 0 {
		t.Fatalf("legacy zero must convert to explicitly unpriced, got priced=%v amount=%v", priced, amount)
	}
	if r, ok := Rate(freeEntry, AxisInput); !ok || r.Amount != nil {
		t.Fatalf("legacy zero must keep the axis present with nil amount, got %+v ok=%v", r, ok)
	}
	// The zero cache axes are absent, not nil-noise.
	if _, ok := Rate(freeEntry, AxisCacheWrite); ok {
		t.Fatal("zero legacy cache rate must leave the axis absent")
	}

	// Nothing converted is serveable.
	at, _ := parseRefTime("2026-10-01")
	if EntryServeable(c.Models[0], at) {
		t.Fatal("converted draft entries must never be serveable")
	}
}

func TestCatalogFromPriceFileUnknownDate(t *testing.T) {
	pf := convertPriceFixture()
	pf.Date = "unknown"
	c, err := CatalogFromPriceFile(pf)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if err := ValidateCatalog(c); err != nil {
		t.Fatalf("unknown legacy date must convert to a valid catalog: %v", err)
	}
	m := c.Models[0]
	if m.EffectiveFrom != "" || m.VerifiedAt != "" {
		t.Fatalf("unknown date must map to open window and no verification, got from=%q verified=%q",
			m.EffectiveFrom, m.VerifiedAt)
	}
}

func TestCatalogFromUnitFileGroupsByIdentity(t *testing.T) {
	uf := UnitFile{
		Source:   "github.com/example/models@abc123",
		Date:     "2026-09-30",
		Currency: "USD",
		Units: []UnitEntry{
			{Provider: "openai", Model: "tts-a", Unit: UnitPerCharacter, Rate: 0.000015},
			{Provider: "openai", Model: "tts-a", Unit: UnitPerImage, Rate: 0.02},
			{Provider: "deepgram", Model: "nova", Unit: UnitPerAudioSecond, Rate: 0.0043},
		},
	}
	c, err := CatalogFromUnitFile(uf)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if err := ValidateCatalog(c); err != nil {
		t.Fatalf("converted unit catalog must validate: %v", err)
	}

	// Two entries for the same model merge into one entry with two rates.
	if len(c.Models) != 2 {
		t.Fatalf("entries grouped by identity, got %d models: %+v", len(c.Models), c.Models)
	}
	m, ok := ResolveModel(c, "openai", "tts-a")
	if !ok {
		t.Fatal("tts-a must convert")
	}
	charRate, priced := RateAmount(m, AxisCharacter)
	if !priced || charRate != 0.000015 {
		t.Fatalf("character axis: priced=%v amount=%v", priced, charRate)
	}
	imgRate, priced := RateAmount(m, AxisImage)
	if !priced || imgRate != 0.02 {
		t.Fatalf("image axis: priced=%v amount=%v", priced, imgRate)
	}
	audio, priced := RateAmount(m, AxisAudioSecond)
	if priced || audio != 0 {
		t.Fatal("audio axis must be absent for a TTS entry")
	}
}

func TestCatalogFromUnitFileRejectsUnknownUnit(t *testing.T) {
	uf := UnitFile{
		Source: "s", Date: "2026-09-30", Currency: "USD",
		Units: []UnitEntry{{Provider: "openai", Model: "gpu-box", Unit: "gpu_hour", Rate: 2.0}},
	}
	_, err := CatalogFromUnitFile(uf)
	if err == nil || !strings.Contains(err.Error(), "unknown unit") {
		t.Fatalf("unknown unit must be an error, got %v", err)
	}
}

func TestMergeCatalogs(t *testing.T) {
	tokenCat, err := CatalogFromPriceFile(convertPriceFixture())
	if err != nil {
		t.Fatalf("convert price: %v", err)
	}
	unitCat, err := CatalogFromUnitFile(UnitFile{
		Source:   "github.com/example/models@abc123",
		Date:     "2026-09-30",
		Currency: "USD",
		Units: []UnitEntry{
			// Same identity as a token entry: rates must merge into it.
			{Provider: "openai", Model: "gpt-a", Unit: UnitPerImage, Rate: 0.03},
			// Brand new identity: appended.
			{Provider: "openai", Model: "image-only", Unit: UnitPerImage, Rate: 0.08},
		},
	})
	if err != nil {
		t.Fatalf("convert units: %v", err)
	}

	merged, err := MergeCatalogs(tokenCat, unitCat)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if err := ValidateCatalog(merged); err != nil {
		t.Fatalf("merged catalog must validate: %v", err)
	}

	// Metadata stays with dst.
	if merged.Version != tokenCat.Version || merged.Source != tokenCat.Source {
		t.Fatal("merged metadata must come from dst")
	}

	// Disjoint identity appended.
	if _, ok := ResolveModel(merged, "openai", "image-only"); !ok {
		t.Fatal("src-only identity must be appended")
	}

	// Same identity: rate axes unioned on one entry.
	m, ok := ResolveModel(merged, "openai", "gpt-a")
	if !ok {
		t.Fatal("gpt-a must survive the merge")
	}
	if _, priced := RateAmount(m, AxisInput); !priced {
		t.Fatal("dst token rate must survive")
	}
	if img, priced := RateAmount(m, AxisImage); !priced || img != 0.03 {
		t.Fatalf("src unit rate must merge in, priced=%v amount=%v", priced, img)
	}

	// Inputs unmodified.
	if len(tokenCat.Models) != 2 || len(unitCat.Models) != 2 {
		t.Fatal("MergeCatalogs must not modify its inputs")
	}
}

func TestMergeCatalogsRateDisagreementIsError(t *testing.T) {
	base, err := CatalogFromPriceFile(convertPriceFixture())
	if err != nil {
		t.Fatal(err)
	}
	// A different snapshot prices the same identity differently on input.
	other := convertPriceFixture()
	other.Source = "github.com/example/models@def456"
	other.Models[0].Input = 0.9
	conflict, err := CatalogFromPriceFile(other)
	if err != nil {
		t.Fatal(err)
	}

	_, err = MergeCatalogs(base, conflict)
	if err == nil || !strings.Contains(err.Error(), `axis "input"`) || !strings.Contains(err.Error(), "amounts disagree") {
		t.Fatalf("rate disagreement must be an error, got %v", err)
	}
}

// TestMergeCatalogsNilVersusNumberResolvesToNumber pins the one documented
// merge resolution (SCHEMA.md §Conversion): an explicitly-unpriced axis
// (legacy zero → nil) merged against a verified number resolves to the
// number in both directions, nil-vs-nil stays nil, and only two different
// numbers are an error (pinned by TestMergeCatalogsRateDisagreementIsError).
func TestMergeCatalogsNilVersusNumberResolvesToNumber(t *testing.T) {
	base, err := CatalogFromPriceFile(convertPriceFixture())
	if err != nil {
		t.Fatal(err)
	}
	// gpt-free-entry prices input at legacy zero → Amount=nil in base;
	// the second snapshot carries a verified 0.25 for the same axis.
	verified := convertPriceFixture()
	verified.Source = "github.com/example/models@def456"
	verified.Models[1].Input = 0.25
	verifiedCat, err := CatalogFromPriceFile(verified)
	if err != nil {
		t.Fatal(err)
	}

	merged, err := MergeCatalogs(base, verifiedCat)
	if err != nil {
		t.Fatalf("nil-vs-number must resolve to the number, got %v", err)
	}
	m, ok := ResolveModel(merged, "openai", "gpt-free-entry")
	if !ok {
		t.Fatal("gpt-free-entry must survive the merge")
	}
	if in, priced := RateAmount(m, AxisInput); !priced || in != 0.25 {
		t.Fatalf("verified number must win nil-vs-number (dst=nil), priced=%v amount=%v", priced, in)
	}

	// Mirror direction: dst carries the number, src is the unknown.
	merged, err = MergeCatalogs(verifiedCat, base)
	if err != nil {
		t.Fatalf("number-vs-nil must resolve to the number, got %v", err)
	}
	m, ok = ResolveModel(merged, "openai", "gpt-free-entry")
	if !ok {
		t.Fatal("gpt-free-entry must survive the merge")
	}
	if in, priced := RateAmount(m, AxisInput); !priced || in != 0.25 {
		t.Fatalf("verified number must win nil-vs-number (dst=number), priced=%v amount=%v", priced, in)
	}

	// nil-vs-nil stays nil: both snapshots leave input explicitly unpriced.
	alsoNil := convertPriceFixture()
	alsoNil.Source = "github.com/example/models@000fff"
	alsoNilCat, err := CatalogFromPriceFile(alsoNil)
	if err != nil {
		t.Fatal(err)
	}
	merged, err = MergeCatalogs(base, alsoNilCat)
	if err != nil {
		t.Fatalf("nil-vs-nil must not be an error, got %v", err)
	}
	m, ok = ResolveModel(merged, "openai", "gpt-free-entry")
	if !ok {
		t.Fatal("gpt-free-entry must survive the merge")
	}
	if r, ok := Rate(m, AxisInput); !ok || r.Amount != nil {
		t.Fatalf("nil-vs-nil must stay explicitly unpriced, got %+v ok=%v", r, ok)
	}
}

func TestMergeCatalogsAgreeingAmountsUniteEvidence(t *testing.T) {
	base, err := CatalogFromPriceFile(convertPriceFixture())
	if err != nil {
		t.Fatal(err)
	}
	other := convertPriceFixture()
	other.Source = "github.com/example/models@def456" // same amounts, different snapshot
	agreeing, err := CatalogFromPriceFile(other)
	if err != nil {
		t.Fatal(err)
	}

	merged, err := MergeCatalogs(base, agreeing)
	if err != nil {
		t.Fatalf("agreeing merge must succeed: %v", err)
	}
	m, ok := ResolveModel(merged, "openai", "gpt-a")
	if !ok {
		t.Fatal("entry must survive")
	}
	if len(m.Sources) != 2 {
		t.Fatalf("sources must unite, got %d", len(m.Sources))
	}
	// The legacy adapter emits no per-rate evidence; both rates stay clean.
	r, _ := Rate(m, AxisInput)
	if len(r.Evidence) != 0 {
		t.Fatalf("converted rates carry no evidence, got %+v", r.Evidence)
	}
}

func TestMergeCatalogsCurrencyMismatchIsError(t *testing.T) {
	base, err := CatalogFromPriceFile(convertPriceFixture())
	if err != nil {
		t.Fatal(err)
	}
	eur := convertPriceFixture()
	eur.Currency = "EUR"
	eurCat, err := CatalogFromPriceFile(eur)
	if err != nil {
		t.Fatal(err)
	}
	_, err = MergeCatalogs(base, eurCat)
	if err == nil || !strings.Contains(err.Error(), "currency mismatch") {
		t.Fatalf("currency mismatch must be an error, got %v", err)
	}
}

// TestSyntheticSnapshotsConvertAndValidate checks authored token/unit fixtures
// through conversion, merge, sealing and validation with every identity preserved.
// It also pins the lossy contract: converted entries are draft and none is
// serveable.
func TestSyntheticSnapshotsConvertAndValidate(t *testing.T) {
	// Authored synthetic snapshots exercise the same complete import pipeline.
	fp, err := NewFilePricer(PriceFile{Source: "synthetic token test", Date: "2026-09-30", Currency: "USD", Units: "per_1m_tokens", Models: []PriceFileModel{{Provider: "fixture", Model: "priced", Input: 17, Output: 29}}}, "test")
	if err != nil {
		t.Fatal(err)
	}
	up, err := NewUnitFilePricer(UnitFile{Source: "synthetic unit test", Date: "2026-09-30", Currency: "USD", Units: []UnitEntry{{Provider: "fixture", Model: "image", Unit: UnitPerImage, Rate: 0.123456}}}, "test")
	if err != nil {
		t.Fatal(err)
	}

	tokenCat, err := CatalogFromPriceFile(fp.File())
	if err != nil {
		t.Fatalf("convert token snapshot: %v", err)
	}
	unitCat, err := CatalogFromUnitFile(up.File())
	if err != nil {
		t.Fatalf("convert unit snapshot: %v", err)
	}

	merged, err := MergeCatalogs(tokenCat, unitCat)
	if err != nil {
		t.Fatalf("merge legacy snapshots: %v", err)
	}
	merged, err = SealCatalog(merged)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := ValidateCatalog(merged); err != nil {
		t.Fatalf("merged bundled catalog must validate: %v", err)
	}

	// Identity preservation: distinct (provider, model) pairs across both
	// files must equal the entry count.
	identities := make(map[string]struct{})
	for _, m := range fp.File().Models {
		identities[m.Provider+"\x00"+m.Model] = struct{}{}
	}
	for _, u := range up.File().Units {
		identities[u.Provider+"\x00"+u.Model] = struct{}{}
	}
	if len(merged.Models) != len(identities) {
		t.Fatalf("identity preservation failed: %d entries for %d legacy identities", len(merged.Models), len(identities))
	}

	// Spot-check a known entry against the legacy numbers.
	var gpt4o *PriceFileModel
	for i := range fp.File().Models {
		if fp.File().Models[i].Provider == "fixture" && fp.File().Models[i].Model == "priced" {
			gpt4o = &fp.File().Models[i]
			break
		}
	}
	if gpt4o == nil {
		t.Fatal("bundled snapshot must contain openai:gpt-4o")
	}
	m, ok := ResolveModel(merged, "fixture", "priced")
	if !ok {
		t.Fatal("gpt-4o must convert")
	}
	in, priced := RateAmount(m, AxisInput)
	if !priced || in != gpt4o.Input {
		t.Fatalf("gpt-4o input must convert exactly: priced=%v got %v want %v", priced, in, gpt4o.Input)
	}
	if m.Status != RefStatusDraft {
		t.Fatalf("converted entries must be draft, got %q", m.Status)
	}
	at, _ := parseRefTime("2026-10-01")
	if EntryServeable(m, at) {
		t.Fatal("converted bundled entries must never be serveable")
	}
}
