package pricing

import (
	"errors"
	"strings"
	"testing"
)

// unitImportFixture is newly authored synthetic data, not a catalog extract.
// Invented model IDs and amounts exercise every importer classification.
const unitImportFixture = `{
  "sample_spec": {"mode": "chat", "litellm_provider": "openai"},
  "fixture-transcribe": {"mode": "audio_transcription", "litellm_provider": "openai", "input_cost_per_second": 0.000089123},
  "deepgram/fixture-input-second": {"mode": "audio_transcription", "litellm_provider": "deepgram", "input_cost_per_second": 0.0000123456, "output_cost_per_second": 0.0},
  "soniox/fixture-output-second": {"mode": "audio_transcription", "litellm_provider": "soniox", "input_cost_per_second": 0.0, "output_cost_per_second": 0.0000234567},
  "fixture-character": {"mode": "audio_speech", "litellm_provider": "openai", "input_cost_per_character": 0.0000345678},
  "fixture-token-speech": {"mode": "audio_speech", "litellm_provider": "openai", "input_cost_per_token": 0.0000456789, "output_cost_per_token": 0.000056789},
  "aiml/fixture-pixel-or-image": {"mode": "image_generation", "litellm_provider": "aiml", "output_cost_per_image": 0.123},
  "1024-x-1024/fixture-image": {"mode": "image_generation", "litellm_provider": "openai", "input_cost_per_image": 0.234},
  "high/1024-x-1024/fixture-image": {"mode": "image_generation", "litellm_provider": "openai", "input_cost_per_image": 0.345},
  "azure/hd/1024-x-1024/fixture-pixel-or-image": {"mode": "image_generation", "litellm_provider": "azure", "input_cost_per_pixel": 8.765e-08, "output_cost_per_token": 0.0},
  "fixture-chat": {"mode": "chat", "litellm_provider": "openai", "input_cost_per_token": 0.000067891, "output_cost_per_token": 0.000078912},
  "vertex_ai/fixture-wrong-axis": {"mode": "audio_speech", "litellm_provider": "vertex_ai", "output_cost_per_image": 0.02},
  "broken": {"mode": "audio_transcription", "litellm_provider": "openai", "input_cost_per_second": "oops"}
}`

func entryFor(t *testing.T, uf UnitFile, provider, model string) UnitEntry {
	t.Helper()
	for _, e := range uf.Units {
		if e.Provider == provider && e.Model == model {
			return e
		}
	}
	t.Fatalf("unit file has no entry for %s:%s", provider, model)
	return UnitEntry{}
}

func TestImportLiteLLMUnits(t *testing.T) {
	uf, stats, err := ImportLiteLLMUnits(strings.NewReader(unitImportFixture),
		"github.com/BerriAI/litellm@test/model_prices_and_context_window.json", "2026-09-30")
	if err != nil {
		t.Fatalf("ImportLiteLLMUnits: %v", err)
	}

	// 12 real keys (sample_spec excluded): 6 imported, 1 wrong mode, 3
	// without a non-token price, 1 collapsed size class, 1 malformed
	// field: 6+1+3+1+1 = 12.
	if stats.Total != 12 {
		t.Errorf("stats.Total = %d, want 12", stats.Total)
	}
	if stats.Imported != 6 || stats.SkippedMode != 1 || stats.SkippedNoPrice != 3 || stats.SkippedInvalid != 1 || stats.Duplicates != 1 {
		t.Errorf("stats = %+v, want Imported 6 / SkippedMode 1 / SkippedNoPrice 3 / SkippedInvalid 1 / Duplicates 1", stats)
	}

	// Transcription: per input second, verbatim catalog rate; an explicit
	// 0.0 on one per-second axis with the other present is honored.
	if e := entryFor(t, uf, "openai", "fixture-transcribe"); e.Unit != UnitPerAudioSecond || e.Rate != 0.000089123 {
		t.Errorf("fixture-transcribe = %+v", e)
	}
	if e := entryFor(t, uf, "deepgram", "fixture-input-second"); e.Unit != UnitPerAudioSecond || e.Rate != 0.0000123456 {
		t.Errorf("deepgram/fixture-input-second = %+v", e)
	}
	// Output-second billing (input 0.0) still prices the axis.
	if e := entryFor(t, uf, "soniox", "fixture-output-second"); e.Unit != UnitPerAudioSecond || e.Rate != 0.0000234567 {
		t.Errorf("soniox/fixture-output-second = %+v", e)
	}
	// Speech: per character, input_cost_per_character only.
	if e := entryFor(t, uf, "openai", "fixture-character"); e.Unit != UnitPerCharacter || e.Rate != 0.0000345678 {
		t.Errorf("fixture-character = %+v", e)
	}
	// Images: per image; size-class keys collapse onto the last segment
	// with the maximum rate.
	if e := entryFor(t, uf, "openai", "fixture-image"); e.Unit != UnitPerImage || e.Rate != 0.345 {
		t.Errorf("fixture-image = %+v (want max of size classes 0.345)", e)
	}
	if stats.Duplicates != 1 {
		t.Errorf("stats.Duplicates = %d, want 1 (collapsed fixture-image size classes)", stats.Duplicates)
	}

	// Fail-closed exclusions: token-billed TTS, per-pixel azure variants,
	// chat models and misfiled modes must NOT produce entries.
	for _, key := range [][2]string{
		{"openai", "fixture-token-speech"},
		{"openai", "fixture-chat"},
		{"azure", "fixture-pixel-or-image"},
		{"vertex", "fixture-wrong-axis"},
	} {
		for _, e := range uf.Units {
			if e.Provider == key[0] && e.Model == key[1] {
				t.Errorf("unexpected entry %s:%s (%s %v) — must stay unpriced", e.Provider, e.Model, e.Unit, e.Rate)
			}
		}
	}

	// Deterministic order.
	for i := 1; i < len(uf.Units); i++ {
		prev, cur := uf.Units[i-1], uf.Units[i]
		if prev.Provider > cur.Provider || (prev.Provider == cur.Provider && prev.Model > cur.Model) {
			t.Fatalf("units not sorted at %d: %s:%s after %s:%s", i, cur.Provider, cur.Model, prev.Provider, prev.Model)
		}
	}
	if uf.Source != "github.com/BerriAI/litellm@test/model_prices_and_context_window.json" || uf.Date != "2026-09-30" || uf.Currency != "USD" {
		t.Errorf("provenance = %s / %s / %s", uf.Source, uf.Date, uf.Currency)
	}
}

func TestImportLiteLLMUnitsDuplicateMaxRate(t *testing.T) {
	// A later size class with a HIGHER rate must win the collapse: the
	// bound covers the most expensive catalog variant of the model.
	cat := `{
	  "low/1024-x-1024/m": {"mode": "image_generation", "litellm_provider": "p", "input_cost_per_image": 0.01},
	  "high/1024-x-1024/m": {"mode": "image_generation", "litellm_provider": "p", "input_cost_per_image": 0.02}
	}`
	uf, stats, err := ImportLiteLLMUnits(strings.NewReader(cat), "s", "2026-09-30")
	if err != nil {
		t.Fatalf("ImportLiteLLMUnits: %v", err)
	}
	if len(uf.Units) != 1 || uf.Units[0].Rate != 0.02 {
		t.Fatalf("units = %+v, want single entry at max 0.02", uf.Units)
	}
	if stats.Duplicates != 1 || stats.Imported != 1 {
		t.Errorf("stats = %+v, want Imported 1 / Duplicates 1", stats)
	}
}

func TestValidateUnitFile(t *testing.T) {
	valid := UnitFile{
		Source: "s", Date: "2026-09-30", Currency: "USD",
		Units: []UnitEntry{{Provider: "openai", Model: "fixture-character", Unit: UnitPerCharacter, Rate: 0.0000345678}},
	}
	if err := ValidateUnitFile(valid); err != nil {
		t.Fatalf("ValidateUnitFile(valid) = %v", err)
	}

	cases := []struct {
		name string
		mut  func(*UnitFile)
		want string
	}{
		{"empty source", func(f *UnitFile) { f.Source = " " }, "source is required"},
		{"empty date", func(f *UnitFile) { f.Date = "" }, "date is required"},
		{"currency", func(f *UnitFile) { f.Currency = "EUR" }, "currency must be USD"},
		{"empty units", func(f *UnitFile) { f.Units = nil }, "units list is empty"},
		{"provider", func(f *UnitFile) { f.Units[0].Provider = "" }, "provider is required"},
		{"model", func(f *UnitFile) { f.Units[0].Model = "" }, "model is required"},
		{"unknown unit", func(f *UnitFile) { f.Units[0].Unit = "per_pixel" }, `unknown unit kind "per_pixel"`},
		{"negative rate", func(f *UnitFile) { f.Units[0].Rate = -1 }, "negative rate"},
		{"nan rate", func(f *UnitFile) { f.Units[0].Rate = nan() }, "not a finite number"},
		{"duplicate", func(f *UnitFile) {
			f.Units = append(f.Units, f.Units[0])
		}, "duplicate entry for openai:fixture-character"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := UnitFile{
				Source: "s", Date: "2026-09-30", Currency: "USD",
				Units: []UnitEntry{{Provider: "openai", Model: "fixture-character", Unit: UnitPerCharacter, Rate: 0.0000345678}},
			}
			tc.mut(&f)
			err := ValidateUnitFile(f)
			if err == nil {
				t.Fatalf("ValidateUnitFile = nil, want %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidateUnitFile = %q, want it to contain %q", err.Error(), tc.want)
			}
			var ufe *UnitFileError
			if !errors.As(err, &ufe) {
				t.Fatalf("error is %T, want *UnitFileError", err)
			}
		})
	}
}

// nan/abs keep this file free of a direct math import for one literal.
func nan() float64 {
	zero := 0.0
	return zero / zero
}

func TestParseUnitFile(t *testing.T) {
	body := `{"source":"s","date":"2026-09-30","currency":"USD","units":[
	  {"provider":"openai","model":"fixture-character","unit":"per_character","rate":0.0000345678}]}`
	uf, sum, err := ParseUnitFile(strings.NewReader(body))
	if err != nil {
		t.Fatalf("ParseUnitFile: %v", err)
	}
	if !strings.HasPrefix(sum, "sha256:") || len(sum) != len("sha256:")+64 {
		t.Errorf("sha256 = %q", sum)
	}
	if len(uf.Units) != 1 {
		t.Errorf("units = %+v", uf.Units)
	}

	if _, _, err := ParseUnitFile(strings.NewReader("{not json")); err == nil {
		t.Error("ParseUnitFile(bad json) = nil error")
	}
	if _, _, err := ParseUnitFile(strings.NewReader(`{"source":"s"}`)); err == nil {
		t.Error("ParseUnitFile(invalid file) = nil error")
	}
}

func TestUnitFilePricer(t *testing.T) {
	uf := UnitFile{
		Source: "s", Date: "2026-09-30", Currency: "USD",
		Units: []UnitEntry{
			{Provider: "openai", Model: "fixture-character", Unit: UnitPerCharacter, Rate: 0.0000345678},
			{Provider: "azure", Model: "fixture-character", Unit: UnitPerCharacter, Rate: 0.0000789126},
		},
	}
	p, err := NewUnitFilePricer(uf, "sha256:abc")
	if err != nil {
		t.Fatalf("NewUnitFilePricer: %v", err)
	}

	e, ok := p.LookupUnit("openai", "fixture-character")
	if !ok || e.Rate != 0.0000345678 || e.Unit != UnitPerCharacter {
		t.Errorf("LookupUnit(openai, fixture-character) = %+v, %v", e, ok)
	}
	// Provider alias fallback: azure-openai resolves to the azure entry.
	e, ok = p.LookupUnit("azure-openai", "fixture-character")
	if !ok || e.Rate != 0.0000789126 {
		t.Errorf("LookupUnit(azure-openai, fixture-character) = %+v, %v", e, ok)
	}
	if _, ok := p.LookupUnit("openai", "unknown"); ok {
		t.Error("LookupUnit(openai, unknown) = ok, want miss")
	}

	prov := p.Provenance()
	if prov.SHA256 != "sha256:abc" || prov.Entries != 2 || prov.Currency != "USD" {
		t.Errorf("Provenance = %+v", prov)
	}

	// NewUnitFilePricer re-validates defensively.
	uf.Units[0].Rate = -1
	if _, err := NewUnitFilePricer(uf, "sha256:abc"); err == nil {
		t.Error("NewUnitFilePricer(negative rate) = nil error")
	}
}

// No unit dataset ships; known former names and aliases are unpriced.
func TestLoadBundledUnits(t *testing.T) {
	p, err := LoadBundledUnits()
	if err != nil {
		t.Fatal(err)
	}
	if len(p.File().Units) != 0 || p.Provenance().Entries != 0 || p.Provenance().Source != "" {
		t.Fatal("empty default invented data or provenance")
	}
	for _, key := range [][2]string{{"openai", "tts-1"}, {"openai", "whisper-1"}, {"openai", "gpt-image-1"}, {"azure-openai", "tts-1"}} {
		if _, ok := p.LookupUnit(key[0], key[1]); ok {
			t.Fatalf("default unit price reappeared: %v", key)
		}
	}
	if _, err := NewUnitFilePricer(UnitFile{}, ""); err == nil {
		t.Fatal("empty imported files must still fail validation")
	}
}

func TestDefaultUnitPricer(t *testing.T) {
	p := DefaultUnitPricer()
	if p == nil {
		t.Fatal("DefaultUnitPricer = nil")
	}
	if _, ok := p.LookupUnit("openai", "tts-1"); ok {
		t.Error("default unit pricer must not invent a rate")
	}
	// Replacement swaps the process-wide instance; restore the bundled
	// default so later tests observe the shipped snapshot.
	custom := &UnitFilePricer{}
	SetDefaultUnitPricer(custom)
	if DefaultUnitPricer() != custom {
		t.Error("SetDefaultUnitPricer did not replace the default")
	}
	bundled, err := LoadBundledUnits()
	if err != nil {
		t.Fatalf("LoadBundledUnits: %v", err)
	}
	SetDefaultUnitPricer(bundled)
	if DefaultUnitPricer() != bundled {
		t.Error("SetDefaultUnitPricer(bundled) did not stick")
	}
}
