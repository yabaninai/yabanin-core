package pricing

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLiteLLMFormatPin_MatchesImporter proves the pin cannot drift from the
// importer: every token mode the pin admits is really admitted by
// ImportLiteLLM, one probed unsupported mode is really skipped, the pinned
// source unit and the snapshot denominator stay as documented, and the
// pinned price scale describes the actual USD/token → per-1M conversion.
func TestLiteLLMFormatPin_MatchesImporter(t *testing.T) {
	pin := LiteLLMFormatPin()
	require.NotEmpty(t, pin.SupportedModes)
	require.Equal(t, "model_prices_and_context_window.json", pin.Catalog)
	require.Equal(t, "usd_per_token", pin.Unit, "the source catalog is quoted in USD per token")

	var b bytes.Buffer
	b.WriteString(`{"sample_spec": {}`) // object stays open until every entry is appended
	for i, mode := range pin.SupportedModes {
		fmt.Fprintf(&b, `, "m%d": {"litellm_provider": "pinprov", "mode": %q, "input_cost_per_token": 1e-06, "output_cost_per_token": 2e-06}`, i, mode)
	}
	// Control: a mode the pin does NOT claim must be skipped.
	b.WriteString(`, "ctrl": {"litellm_provider": "pinprov", "mode": "rerank", "input_cost_per_token": 1e-06, "output_cost_per_token": 2e-06}}`)

	pf, stats, err := ImportLiteLLM(bytes.NewReader(b.Bytes()), "pin", "2026-10-28")
	require.NoError(t, err)
	assert.Zero(t, stats.SkippedInvalid)
	assert.Equal(t, len(pin.SupportedModes), stats.Imported, "every pinned mode is admitted")
	assert.Equal(t, 1, stats.SkippedMode, "the unpinned control mode is explicitly skipped")
	assert.Equal(t, "per_1m_tokens", pf.Units, "the snapshot denominator")

	for _, m := range pf.Models {
		require.Equal(t, "pinprov", m.Provider)
		assert.InDelta(t, pin.PriceScale*1e-6, m.Input, 1e-9, "1e-6 USD/token × pin.PriceScale = per-1M price")
		assert.InDelta(t, 2*pin.PriceScale*1e-6, m.Output, 1e-9)
	}
}

// TestLiteLLMProviderAliases_MatchPin exercises the alias table through the
// real normalization path (uppercase + '_' input, i.e. the raw catalog
// spelling), plus the vertex_ai_<region> family and the passthrough.
func TestLiteLLMProviderAliases_MatchPin(t *testing.T) {
	pin := LiteLLMFormatPin()
	require.NotEmpty(t, pin.ProviderAliases)
	for raw, want := range pin.ProviderAliases {
		catalogSpelling := strings.ToUpper(strings.ReplaceAll(raw, "-", "_"))
		assert.Equal(t, want, normalizeLiteLLMProvider(catalogSpelling), "alias %q via raw spelling %q", raw, catalogSpelling)
	}
	assert.Equal(t, "vertex", normalizeLiteLLMProvider("vertex_ai_europe-west4"))
	assert.Equal(t, "vertex", normalizeLiteLLMProvider("VERTEX_AI_US"))
	assert.Equal(t, "anthropic", normalizeLiteLLMProvider("Anthropic"))
	// An alias must match exactly, not as a prefix.
	assert.Equal(t, "together-ai-2", normalizeLiteLLMProvider("together_ai_2"))
}

// TestLiteLLMUnitModePin_MatchesUnitsImporter proves each pinned non-token
// mode imports into exactly the pinned unit kind through the pinned fields.
func TestLiteLLMUnitModePin_MatchesUnitsImporter(t *testing.T) {
	pin := LiteLLMUnitModePin()
	require.NotEmpty(t, pin)

	var b bytes.Buffer
	b.WriteString(`{"sample_spec": {}`)
	for i, m := range pin {
		fmt.Fprintf(&b, `, "u%d": {"litellm_provider": "unitprov", "mode": %q, %q: 0.01, %q: 0.02}`,
			i, m.Mode, m.Fields[0], m.Fields[len(m.Fields)-1])
	}
	b.WriteString(`}`)

	uf, stats, err := ImportLiteLLMUnits(strings.NewReader(b.String()), "pin", "2026-10-28")
	require.NoError(t, err)
	assert.Equal(t, len(pin), stats.Imported)
	assert.Zero(t, stats.SkippedMode)
	assert.Zero(t, stats.SkippedInvalid)

	byUnit := make(map[string]string) // unit → model
	for _, e := range uf.Units {
		require.Equal(t, "unitprov", e.Provider)
		byUnit[e.Unit] = e.Model
	}
	for i, m := range pin {
		assert.Equal(t, fmt.Sprintf("u%d", i), byUnit[m.Unit], "mode %q prices %q via its pinned fields", m.Mode, m.Unit)
	}
}

// TestLiteLLMPins_DeepCopy: callers must not be able to mutate package
// state through the returned pin slices/maps.
func TestLiteLLMPins_DeepCopy(t *testing.T) {
	pin := LiteLLMFormatPin()
	pin.SupportedModes[0] = "MUTATED"
	pin.ProviderAliases["MUTATED"] = "MUTATED"
	pin.Limitations[0] = "MUTATED"

	fresh := LiteLLMFormatPin()
	assert.NotContains(t, fresh.SupportedModes, "MUTATED")
	assert.NotContains(t, fresh.ProviderAliases, "MUTATED")
	assert.NotContains(t, fresh.Limitations, "MUTATED")

	modes := LiteLLMUnitModePin()
	require.NotEmpty(t, modes)
	modes[0].Mode = "MUTATED"
	modes[0].Fields[0] = "MUTATED"
	freshModes := LiteLLMUnitModePin()
	assert.NotEqual(t, "MUTATED", freshModes[0].Mode)
	assert.NotEqual(t, "MUTATED", freshModes[0].Fields[0])
}

// TestLiteLLMFieldMap_Stable: mapped fields come first, refusals last,
// statuses are from the closed set and every field is named once — the
// ordering contract reports rely on for deterministic rendering.
func TestLiteLLMFieldMap_Stable(t *testing.T) {
	fm := LiteLLMFieldMap()
	require.NotEmpty(t, fm)

	seenRefused := false
	names := make(map[string]struct{}, len(fm))
	for _, m := range fm {
		require.Contains(t, []string{LiteLLMFieldMapped, LiteLLMFieldRefused}, m.Status)
		require.NotEmpty(t, m.Field)
		assert.NotContains(t, names, m.Field, "each field is documented once")
		names[m.Field] = struct{}{}
		if m.Status == LiteLLMFieldRefused {
			seenRefused = true
			assert.NotEmpty(t, m.Note, "a refusal must say why")
			assert.Empty(t, m.Target, "a refusal has no target")
		} else if seenRefused {
			t.Fatal("mapped field after a refusal breaks the deterministic order")
		}
	}
	assert.True(t, seenRefused, "the map must document refusals, not only mappings")
}

// TestLiteLLMFieldMap_CredentialsRefused is the §14 negative as a test:
// the pin refuses credential fields explicitly.
func TestLiteLLMFieldMap_CredentialsRefused(t *testing.T) {
	for _, m := range LiteLLMFieldMap() {
		if strings.Contains(m.Field, "api_key") {
			require.Equal(t, LiteLLMFieldRefused, m.Status)
			return
		}
	}
	t.Fatal("no explicit credential refusal in the field map")
}

// Third-party format edge cases (empty / malformed / unicode), pinned so a
// refactor of the importers cannot silently change their disposition.

func TestImportLiteLLM_EmptyCatalog(t *testing.T) {
	pf, stats, err := ImportLiteLLM(strings.NewReader(`{}`), "fixture", "2026-10-28")
	require.NoError(t, err)
	assert.Zero(t, stats.Total)
	assert.Empty(t, pf.Models)
	assert.Equal(t, "per_1m_tokens", pf.Units)
}

func TestImportLiteLLM_MalformedInput(t *testing.T) {
	for _, bad := range []string{`{`, `[]`, `null`, `"scalar"`, `42`} {
		_, _, err := ImportLiteLLM(strings.NewReader(bad), "fixture", "2026-10-28")
		require.Error(t, err, "input %q", bad)
		assert.Contains(t, err.Error(), "parse litellm catalog")
	}
	// Decode consumes only the first JSON value: trailing data must be an
	// error, never a silently truncated import.
	for _, bad := range []string{`{"a": {}} {"b": {}}`, `{"a": {}} garbage`, `{"a": {}} []`} {
		_, _, err := ImportLiteLLM(strings.NewReader(bad), "fixture", "2026-10-28")
		require.Error(t, err, "input %q", bad)
		assert.Contains(t, err.Error(), "trailing data after the top-level object")
	}
	// A scalar entry value is a per-entry unmarshal failure: skipped, not
	// fatal — one bad entry must not kill the whole catalog.
	pf, stats, err := ImportLiteLLM(strings.NewReader(
		`{"a": "scalar", "b/x": {"litellm_provider": "openai", "mode": "chat", "input_cost_per_token": 1e-06, "output_cost_per_token": 1e-06}}`),
		"f", "2026-10-28")
	require.NoError(t, err)
	assert.Equal(t, 1, stats.SkippedInvalid, "scalar entry is SkippedInvalid")
	assert.Equal(t, 1, stats.Imported)
	assert.Len(t, pf.Models, 1)
}

func TestImportLiteLLM_UnicodeAndSpecialKeys(t *testing.T) {
	raw := `{
		"openai/модель-👀": {"litellm_provider": "openai", "mode": "chat", "input_cost_per_token": 1e-06, "output_cost_per_token": 2e-06},
		"provider-япошка/узел": {"litellm_provider": "provider-япошка", "mode": "chat", "input_cost_per_token": 3e-06, "output_cost_per_token": 4e-06},
		"openai/with space v2": {"litellm_provider": "openai", "mode": "responses", "input_cost_per_token": 5e-06, "output_cost_per_token": 6e-06}
	}`
	pf, stats, err := ImportLiteLLM(strings.NewReader(raw), "fixture", "2026-10-28")
	require.NoError(t, err)
	assert.Equal(t, 3, stats.Imported)
	assert.Zero(t, stats.SkippedInvalid)

	byKey := make(map[string]PriceFileModel, len(pf.Models))
	for _, m := range pf.Models {
		byKey[m.Provider+"/"+m.Model] = m
	}
	assert.Contains(t, byKey, "openai/модель-👀", "unicode model ids are preserved verbatim")
	assert.Contains(t, byKey, "provider-япошка/узел", "unicode providers pass through normalization untouched")
	assert.Contains(t, byKey, "openai/with space v2", "internal spaces are preserved")
}

func TestImportLiteLLM_EmptyProviderAndKeySkipped(t *testing.T) {
	raw := `{
		"": {"litellm_provider": "openai", "mode": "chat", "input_cost_per_token": 1e-06, "output_cost_per_token": 2e-06},
		"no-provider": {"mode": "chat", "input_cost_per_token": 1e-06, "output_cost_per_token": 2e-06},
		"blank-provider": {"litellm_provider": "  ", "mode": "chat", "input_cost_per_token": 1e-06, "output_cost_per_token": 2e-06},
		"slash-only/": {"litellm_provider": "openai", "mode": "chat", "input_cost_per_token": 1e-06, "output_cost_per_token": 2e-06},
		"good": {"litellm_provider": "openai", "mode": "chat", "input_cost_per_token": 1e-06, "output_cost_per_token": 2e-06}
	}`
	pf, stats, err := ImportLiteLLM(strings.NewReader(raw), "fixture", "2026-10-28")
	require.NoError(t, err)
	assert.Equal(t, 4, stats.SkippedInvalid, "empty key, missing/blank provider and empty model are explicit SkippedInvalid")
	assert.Equal(t, 1, stats.Imported)
	require.Len(t, pf.Models, 1)
	assert.Equal(t, "good", pf.Models[0].Model)
	require.NoError(t, ValidatePriceFile(pf), "the surviving snapshot must validate")
}

// detLCG is a tiny deterministic pseudo-random source (fixed seed at the
// call site): enough to fuzz catalog shapes repeatably without math/rand.
type detLCG struct{ state uint64 }

func (g *detLCG) next(n int) int {
	g.state = g.state*6364136223846793005 + 1442695040888963407
	if n <= 0 {
		panic("detLCG.next: n must be positive")
	}
	return int((g.state >> 33) % uint64(n)) //nolint:gosec // G115: guarded positive n; deterministic test LCG
}

// TestImportLiteLLM_RandomizedInvariants is the cheap randomized sweep
// (fixed seed, repeatable): a synthetic catalog built from the pinned
// alphabet must always produce sorted, deduplicated, validating output whose
// stats partition the total — no silent disposition.
func TestImportLiteLLM_RandomizedInvariants(t *testing.T) {
	pin := LiteLLMFormatPin()
	rng := detLCG{state: 20261028}

	var b bytes.Buffer
	b.WriteString(`{"sample_spec": {}`)
	const n = 200
	for i := 0; i < n; i++ {
		mode := pin.SupportedModes[rng.next(len(pin.SupportedModes))]
		if rng.next(10) == 0 {
			mode = "rerank" // probed unsupported mode
		}
		prov := fmt.Sprintf("prov-%d", rng.next(20))
		if rng.next(20) == 0 {
			prov = "" // probed invalid provider
		}
		fmt.Fprintf(&b, `, "k%03d/x": {"litellm_provider": %q, "mode": %q, "input_cost_per_token": %de-06, "output_cost_per_token": %de-06}`,
			i, prov, mode, rng.next(50), rng.next(50))
	}
	b.WriteString(`}`)

	pf, stats, err := ImportLiteLLM(strings.NewReader(b.String()), "fixture", "2026-10-28")
	require.NoError(t, err)
	assert.Equal(t, stats.Imported+stats.SkippedMode+stats.SkippedNoPrice+stats.SkippedInvalid+stats.Duplicates, stats.Total,
		"stats must partition the total")
	require.NoError(t, ValidatePriceFile(pf), "emitted snapshot must validate")
	seen := make(map[string]struct{}, len(pf.Models))
	for i, m := range pf.Models {
		key := m.Provider + "\x00" + m.Model
		assert.NotContains(t, seen, key, "no duplicate (provider, model) pairs emitted")
		seen[key] = struct{}{}
		if i > 0 {
			prev := pf.Models[i-1]
			assert.LessOrEqual(t, prev.Provider+"\x00"+prev.Model, key, "output sorted by (provider, model)")
		}
	}
}

// TestImportLiteLLMUnits_NonObjectRejected pins the same layout rules for
// the unit importer (parity with the token importer): non-object payloads
// and trailing data are errors, never silent.
func TestImportLiteLLMUnits_NonObjectRejected(t *testing.T) {
	_, _, err := ImportLiteLLMUnits(strings.NewReader(`null`), "fixture", "2026-10-28")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "top level must be a JSON object")
	for _, bad := range []string{`{"a": {}} {"b": {}}`, `{"a": {}} garbage`} {
		_, _, err := ImportLiteLLMUnits(strings.NewReader(bad), "fixture", "2026-10-28")
		require.Error(t, err, "input %q", bad)
		assert.Contains(t, err.Error(), "trailing data after the top-level object")
	}
}
