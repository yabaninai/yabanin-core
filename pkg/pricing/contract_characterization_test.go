package pricing

// Characterization tests for the legacy-debt pricing batch: they pin the
// observable contracts of ImportLiteLLM, ImportLiteLLMUnits, RefDiff and
// PlanCatalogPromotion (classification counts, output formats, error paths,
// identity semantics) independently of the implementations' internal shape,
// with hand-counted oracles, so the complexity decomposition cannot change
// behavior silently.

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- ImportLiteLLM ---

func TestImportLiteLLMContract_ParseRefusals(t *testing.T) {
	cases := []struct{ name, in, wantSub string }{
		{"invalid json", `{`, "parse litellm catalog"},
		{"array top level", `[]`, "parse litellm catalog"},
		{"null top level", `null`, "top level must be a JSON object"},
		{"trailing object", `{} {}`, "trailing data"},
		{"trailing garbage", `{} x`, "trailing data"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := ImportLiteLLM(strings.NewReader(tc.in), "s", "2026-11-12")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantSub)
		})
	}
}

// litellmContractFixture exercises every import classification. Hand-counted
// oracle (15 real keys, sample_spec excluded):
//
//	Imported 5: mixed-case/prov, dp/dup/m (first sorted dup key), tp/x
//	  (tiered, counted not skipped), ip/x (output absent = 0), sp/deep/name
//	  (model is everything after the FIRST "/")
//	SkippedMode 3: nulled/entry (null object → mode ""), rerank/x, nomode/x
//	SkippedNoPrice 1: zero/price
//	SkippedInvalid 5: not/object, neg/price, badtype/price, noprov/x, prov/
//	  (empty model after the slash)
//	Duplicates 1: b/dup/m; TieredIgnored 1: tiered/x
const litellmContractFixture = `{
  "sample_spec": {"mode": "chat", "litellm_provider": "openai"},
  "nulled/entry": null,
  "not/object": 42,
  "rerank/x": {"mode": "rerank", "litellm_provider": "p", "input_cost_per_token": 0.000001, "output_cost_per_token": 0.000002},
  "nomode/x": {"litellm_provider": "p", "input_cost_per_token": 0.000001, "output_cost_per_token": 0.000002},
  "zero/price": {"mode": "chat", "litellm_provider": "p", "input_cost_per_token": 0, "output_cost_per_token": 0},
  "neg/price": {"mode": "chat", "litellm_provider": "p", "input_cost_per_token": -0.000001, "output_cost_per_token": 0.000002},
  "badtype/price": {"mode": "chat", "litellm_provider": "p", "input_cost_per_token": "free", "output_cost_per_token": 0.000002},
  "noprov/x": {"mode": "chat", "litellm_provider": "   ", "input_cost_per_token": 0.000001, "output_cost_per_token": 0.000002},
  "prov/": {"mode": "chat", "litellm_provider": "p", "input_cost_per_token": 0.000001, "output_cost_per_token": 0.000002},
  "Mixed_Case/prov": {"mode": "chat", "litellm_provider": "Mixed_Case", "input_cost_per_token": 0.000002, "output_cost_per_token": 0.000004},
  "a/dup/m": {"mode": "chat", "litellm_provider": "dp", "input_cost_per_token": 0.000003, "output_cost_per_token": 0.000003},
  "b/dup/m": {"mode": "chat", "litellm_provider": "dp", "input_cost_per_token": 0.000009, "output_cost_per_token": 0.000009},
  "tiered/x": {"mode": "chat", "litellm_provider": "tp", "input_cost_per_token": 0.000004, "output_cost_per_token": 0.000004, "input_cost_per_token_above_200k_tokens": 0.000002},
  "inputonly/x": {"mode": "embedding", "litellm_provider": "ip", "input_cost_per_token": 0.00000123456789},
  "slash/deep/name": {"mode": "completion", "litellm_provider": "sp", "input_cost_per_token": 0.000002, "output_cost_per_token": 0.000003, "cache_creation_input_token_cost": 0.0000025, "cache_read_input_token_cost": 0.00000025}
}`

func TestImportLiteLLMContract_Classification(t *testing.T) {
	pf, stats, err := ImportLiteLLM(strings.NewReader(litellmContractFixture),
		"contract-src", "2026-11-12")
	require.NoError(t, err)

	assert.Equal(t, 15, stats.Total)
	assert.Equal(t, 5, stats.Imported)
	assert.Equal(t, 3, stats.SkippedMode)
	assert.Equal(t, 1, stats.SkippedNoPrice)
	assert.Equal(t, 5, stats.SkippedInvalid)
	assert.Equal(t, 1, stats.Duplicates)
	assert.Equal(t, 1, stats.TieredIgnored)

	assert.Equal(t, "contract-src", pf.Source)
	assert.Equal(t, "2026-11-12", pf.Date)
	assert.Equal(t, "USD", pf.Currency)
	assert.Equal(t, "per_1m_tokens", pf.Units)

	// Projection order is (provider, model); the model name keeps every
	// segment after the FIRST "/" of the catalog key.
	var got []string
	for _, m := range pf.Models {
		got = append(got, m.Provider+"/"+m.Model)
	}
	assert.Equal(t, []string{
		"dp/dup/m",
		"ip/x",
		"mixed-case/prov",
		"sp/deep/name",
		"tp/x",
	}, got)

	dp := findModel(t, pf, "dp", "dup/m")
	assert.InDelta(t, 3.0, dp.Input, 1e-9, "first sorted duplicate key wins")
	deep := findModel(t, pf, "sp", "deep/name")
	assert.InDelta(t, 2.0, deep.Input, 1e-9)
	assert.InDelta(t, 3.0, deep.Output, 1e-9)
	assert.InDelta(t, 2.5, deep.CacheW, 1e-9)
	assert.InDelta(t, 0.25, deep.CacheR, 1e-9)

	// Per-token USD → per-1M with 6-decimal rounding; absent output stays 0.
	ip := findModel(t, pf, "ip", "x")
	assert.InDelta(t, 1.234568, ip.Input, 1e-9)
	assert.InDelta(t, 0.0, ip.Output, 1e-9)

	// Provider normalization: lowercase + "_"→"-".
	assert.Equal(t, "mixed-case", findModel(t, pf, "mixed-case", "prov").Provider)
}

func TestImportLiteLLMContract_EmptyCatalog(t *testing.T) {
	pf, stats, err := ImportLiteLLM(strings.NewReader(`{}`), "s", "d")
	require.NoError(t, err)
	assert.Equal(t, 0, stats.Total)
	assert.Empty(t, pf.Models)
	assert.Equal(t, "USD", pf.Currency)
}

// --- ImportLiteLLMUnits ---

func TestImportLiteLLMUnitsContract_ParseRefusals(t *testing.T) {
	cases := []struct{ name, in, wantSub string }{
		{"invalid json", `{`, "parse litellm catalog"},
		{"array top level", `[]`, "parse litellm catalog"},
		{"null top level", `null`, "top level must be a JSON object"},
		{"trailing object", `{} {}`, "trailing data"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := ImportLiteLLMUnits(strings.NewReader(tc.in), "s", "2026-11-12")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantSub)
		})
	}
}

// unitsContractFixture hand-counted oracle (11 real keys):
//
//	Imported 3: sp/ok (12-decimal rounding), gp-pro/mixed (max of both image
//	  axes; provider normalized), dp/img (model = LAST "/" segment; the
//	  second size class raises the kept rate to the max)
//	SkippedMode 1: chat/x
//	SkippedNoPrice 2: tts/nochar (axis field absent), asr/zero (all-zero)
//	SkippedInvalid 4: asr/neg, asr/badstr, img/noprov, img/ (empty model)
//	Duplicates 1: y/high/img
const unitsContractFixture = `{
  "sample_spec": {"mode": "image_generation", "litellm_provider": "openai"},
  "tts/ok": {"mode": "audio_speech", "litellm_provider": "sp", "input_cost_per_character": 0.000034567812345},
  "tts/nochar": {"mode": "audio_speech", "litellm_provider": "sp2", "output_cost_per_token": 0.1},
  "asr/zero": {"mode": "audio_transcription", "litellm_provider": "ap", "input_cost_per_second": 0.0, "output_cost_per_second": 0.0},
  "asr/neg": {"mode": "audio_transcription", "litellm_provider": "ap2", "input_cost_per_second": -0.0001, "output_cost_per_second": 0.0002},
  "asr/badstr": {"mode": "audio_transcription", "litellm_provider": "ap3", "input_cost_per_second": "x"},
  "img/noprov": {"mode": "image_generation", "litellm_provider": "", "input_cost_per_image": 0.1},
  "img/": {"mode": "image_generation", "litellm_provider": "gp", "input_cost_per_image": 0.1},
  "img/mixed": {"mode": "image_generation", "litellm_provider": "GP_Pro", "input_cost_per_image": 0.2, "output_cost_per_image": 0.15},
  "x/low/img": {"mode": "image_generation", "litellm_provider": "dp", "input_cost_per_image": 0.01},
  "y/high/img": {"mode": "image_generation", "litellm_provider": "dp", "input_cost_per_image": 0.02},
  "chat/x": {"mode": "chat", "litellm_provider": "cp", "input_cost_per_token": 0.1}
}`

func TestImportLiteLLMUnitsContract_Classification(t *testing.T) {
	uf, stats, err := ImportLiteLLMUnits(strings.NewReader(unitsContractFixture),
		"contract-src", "2026-11-12")
	require.NoError(t, err)

	assert.Equal(t, 11, stats.Total)
	assert.Equal(t, 3, stats.Imported)
	assert.Equal(t, 1, stats.SkippedMode)
	assert.Equal(t, 2, stats.SkippedNoPrice)
	assert.Equal(t, 4, stats.SkippedInvalid)
	assert.Equal(t, 1, stats.Duplicates)

	assert.Equal(t, "contract-src", uf.Source)
	assert.Equal(t, "2026-11-12", uf.Date)
	assert.Equal(t, "USD", uf.Currency)

	// Sorted by (provider, model); model is the LAST "/" segment.
	var got []string
	for _, e := range uf.Units {
		got = append(got, e.Provider+":"+e.Model+"/"+e.Unit)
	}
	assert.Equal(t, []string{
		"dp:img/" + UnitPerImage,
		"gp-pro:mixed/" + UnitPerImage,
		"sp:ok/" + UnitPerCharacter,
	}, got)

	assert.InDelta(t, 0.02, entryFor(t, uf, "dp", "img").Rate, 1e-15,
		"duplicate collapse keeps the maximum rate")
	assert.InDelta(t, 0.2, entryFor(t, uf, "gp-pro", "mixed").Rate, 1e-15,
		"image rate is the max over both per-image axes")
	assert.InDelta(t, 0.000034567812, entryFor(t, uf, "sp", "ok").Rate, 1e-15,
		"rates round at 12 decimals, not the token import's 6")
}

// --- RefDiff ---

func TestRefDiffContract_ParseRefusals(t *testing.T) {
	good := sealedCatalogJSON(t, refPackTestCatalog())
	unsealed, err := json.Marshal(refPackTestCatalog())
	require.NoError(t, err)

	cases := []struct {
		name, oldSub, newSub, wantSub string
	}{
		{"old invalid json", `{`, string(good), "ref diff: old snapshot"},
		{"old unsealed", string(unsealed), string(good), "ref diff: old snapshot"},
		{"new invalid json", string(good), `nope`, "ref diff: new snapshot"},
		{"new unsealed", string(good), string(unsealed), "ref diff: new snapshot"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := RefDiff([]byte(tc.oldSub), []byte(tc.newSub))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantSub)
		})
	}
}

// contractDiffModel builds one minimal valid draft/active entry priced on
// the input axis.
func contractDiffModel(provider, model string, input float64) RefModel {
	return RefModel{
		Provider: provider, Model: model,
		Currency: "USD", Status: RefStatusDraft,
		VerifiedAt: "2026-11-02", Reviewer: "diff-reviewer",
		Rates: []RefRate{{Axis: AxisInput, Unit: RefUnitPer1MTokens, Amount: &input}},
	}
}

func TestRefDiffContract_OutputFormat(t *testing.T) {
	oldCat := Catalog{
		SchemaVersion: RefSchemaVersion, Version: "1.0.0-old", GeneratedAt: "2026-11-02",
		Source: "contract", ReviewSLADays: 90,
		Models: []RefModel{
			contractDiffModel("aprov", "alpha-model", 3.0),
			contractDiffModel("kprov", "keep-model", 5.0),
			contractDiffModel("uprov", "ups-model", 6.0),
			contractDiffModel("zprov", "zeta-model", 7.5),
		},
	}
	newCat := Catalog{
		SchemaVersion: RefSchemaVersion, Version: "1.0.0-new", GeneratedAt: "2026-11-03",
		Source: "contract", ReviewSLADays: 90,
		Models: []RefModel{
			// alpha-model absent → REMOVED; keep-model promoted with
			// reviewer + primary sources → legal, rendered as CHANGED;
			// ups-model identical → unchanged, no line; zeta-model rate
			// change; beta-model new → ADDED.
			contractDiffModel("bprov", "beta-model", 1.0),
			contractDiffModel("kprov", "keep-model", 5.0),
			contractDiffModel("uprov", "ups-model", 6.0),
			contractDiffModel("zprov", "zeta-model", 8.0),
		},
	}
	keep := &newCat.Models[1]
	keep.Status = RefStatusActive
	keep.VerifiedAt = "2026-11-03"
	keep.Sources = []RefSource{{Kind: RefSourceInternalEvidence, Ref: "ev-keep-1", VerifiedAt: "2026-11-03"}}

	oldSealed, err := SealCatalog(oldCat)
	require.NoError(t, err)
	newSealed, err := SealCatalog(newCat)
	require.NoError(t, err)

	got, err := RefDiff(mustJSON(t, oldSealed), mustJSON(t, newSealed))
	require.NoError(t, err)

	// Hand-rendered oracle: canonical identity order, two-space field
	// indentation, %g amounts, 12-char digest prefix, fixed summary line.
	want := fmt.Sprintf(`ref-diff: 1.0.0-old (%s) -> 1.0.0-new (%s)
REMOVED aprov/alpha-model
ADDED bprov/beta-model
CHANGED kprov/keep-model
  status: draft -> active
  verified_at: 2026-11-02 -> 2026-11-03
  sources: (none) -> ev-keep-1
CHANGED zprov/zeta-model
  rates[input]: 7.5 -> 8
summary: added=1 removed=1 changed=2 unchanged=1
`, oldSealed.Digest[:12], newSealed.Digest[:12])
	assert.Equal(t, want, got)
}

func TestRefDiffContract_IdentityIncludesRegion(t *testing.T) {
	// The diff identity is (provider, model, region, tier, context_band):
	// a region change is a remove+add pair of identically labeled entries,
	// never a CHANGED line.
	mk := func(region string) Catalog {
		m := contractDiffModel("p", "m", 1.0)
		m.Region = region
		return Catalog{
			SchemaVersion: RefSchemaVersion, Version: "1.0.0-" + region,
			GeneratedAt: "2026-11-02", Source: "contract", ReviewSLADays: 90,
			Models: []RefModel{m},
		}
	}
	got, err := RefDiff(sealedCatalogJSON(t, mk("")), sealedCatalogJSON(t, mk("eu")))
	require.NoError(t, err)
	assert.Contains(t, got, "REMOVED p/m\n")
	assert.Contains(t, got, "ADDED p/m\n")
	assert.Contains(t, got, "summary: added=1 removed=1 changed=0 unchanged=0\n")
	assert.NotContains(t, got, "CHANGED")
}

func TestRefDiffContract_ActiveToActiveNotGated(t *testing.T) {
	// The promotion gate covers ONLY draft→active transitions; an entry
	// already active on both sides renders as a plain CHANGED diff.
	active := func(input float64) Catalog {
		m := contractDiffModel("aprov", "alpha-model", input)
		m.Status = RefStatusActive
		m.VerifiedAt = "2026-11-02"
		m.Sources = []RefSource{{Kind: RefSourceInternalEvidence, Ref: "ev-a2a", VerifiedAt: "2026-11-02"}}
		return Catalog{
			SchemaVersion: RefSchemaVersion, Version: "1.0.0-a2a",
			GeneratedAt: "2026-11-02", Source: "contract", ReviewSLADays: 90,
			Models: []RefModel{m},
		}
	}
	got, err := RefDiff(sealedCatalogJSON(t, active(2.0)), sealedCatalogJSON(t, active(3.0)))
	require.NoError(t, err)
	assert.Contains(t, got, "CHANGED aprov/alpha-model")
	assert.Contains(t, got, "rates[input]: 2 -> 3")
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

// --- PlanCatalogPromotion ---

func TestPlanCatalogPromotionContract_CacheAxes(t *testing.T) {
	cat := PriceFile{Source: "cat@1", Models: []PriceFileModel{
		{Provider: "p", Model: "m", Input: 1, Output: 2, CacheW: 3, CacheR: 4},
	}}

	// A cache-write-only difference is a real price change: the plan must
	// supersede the open catalog row, not skip it as unchanged.
	report := PlanCatalogPromotion(cat, map[string]*Day0ActiveRow{
		"p\x00m": {ID: 7, Source: Day0SourceCatalog, InputPerM: 1, OutputPerM: 2, CacheWritePerM: 3.5, CacheReadPerM: 4},
	})
	require.Len(t, report.Ops, 1)
	assert.Equal(t, Day0ActionUpdate, report.Ops[0].Action)
	assert.Equal(t, int64(7), report.Ops[0].CloseID)
	assert.InDelta(t, 3.0, report.Ops[0].Insert.CacheWritePerM, 1e-12)

	// Sub-epsilon drift on any axis stays "unchanged" (no update flapping);
	// above-epsilon drift updates.
	for _, tc := range []struct {
		name  string
		drift float64
		want  string
	}{
		{"within epsilon stays unchanged", 4e-7, Day0ActionSkip},
		{"above epsilon updates", 6e-7, Day0ActionUpdate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := PlanCatalogPromotion(cat, map[string]*Day0ActiveRow{
				"p\x00m": {ID: 9, Source: Day0SourceCatalog, InputPerM: 1, OutputPerM: 2, CacheWritePerM: 3, CacheReadPerM: 4 + tc.drift},
			})
			require.Len(t, report.Ops, 1)
			assert.Equal(t, tc.want, report.Ops[0].Action)
		})
	}
}

func TestPlanCatalogPromotionContract_RangeGuardCoversCacheAxes(t *testing.T) {
	// numeric(10,6) bounds every stored axis: a cache rate above
	// day0PerMMax skips the entry even when the token axes are storable.
	cat := PriceFile{Source: "cat@1", Models: []PriceFileModel{
		{Provider: "r", Model: "o", Input: 1, Output: 1, CacheW: 10000},
	}}
	report := PlanCatalogPromotion(cat, nil)
	require.Len(t, report.Ops, 1)
	assert.Equal(t, Day0ActionSkip, report.Ops[0].Action)
	assert.Equal(t, "price outside numeric(10,6) range", report.Ops[0].Reason)
	assert.Equal(t, 1, report.Skipped)
	assert.Equal(t, 0, report.Added)
}

func TestPlanCatalogPromotionContract_AddProjection(t *testing.T) {
	// A nil active map means no open rows: every projection is an add
	// carrying the full four-axis insert plus the source ref.
	cat := PriceFile{Source: "cat@1", Models: []PriceFileModel{
		{Provider: "q", Model: "n", Input: 5, Output: 6, CacheW: 7, CacheR: 8},
	}}
	report := PlanCatalogPromotion(cat, nil)
	require.Len(t, report.Ops, 1)
	assert.Equal(t, 1, report.Total)
	assert.Equal(t, 1, report.Added)
	op := report.Ops[0]
	assert.Equal(t, Day0ActionAdd, op.Action)
	assert.Empty(t, op.Reason)
	assert.Equal(t, Day0Insert{
		Provider: "q", Model: "n",
		InputPerM: 5, OutputPerM: 6, CacheWritePerM: 7, CacheReadPerM: 8,
		SourceRef: "cat@1#q/n",
	}, op.Insert)
}
