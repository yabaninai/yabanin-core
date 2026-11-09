package trcli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/pricing"
)

// TestPricingLiteLLMFormat drives the format-pin subcommand: the emitted
// document parses, pins the historical format reference and carries the
// explicit credential refusal from the field map.
func TestPricingLiteLLMFormat(t *testing.T) {
	root := RootCommand()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"pricing", "litellm-format"})

	require.NoError(t, root.Execute())
	require.Empty(t, stderr.String())

	var doc struct {
		Format    pricing.LiteLLMFormat         `json:"format"`
		UnitModes []pricing.LiteLLMUnitMode     `json:"unit_modes"`
		FieldMap  []pricing.LiteLLMFieldMapping `json:"field_map"`
	}
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &doc))
	require.Equal(t, "model_prices_and_context_window.json", doc.Format.Catalog)
	require.Contains(t, doc.Format.PinnedUpstream, "61a73c59b049a8cd6c559168d7f3a2557a1a8cf7",
		"the pin must cite the historical format reference")
	require.Contains(t, doc.Format.SupportedModes, "chat")
	require.NotEmpty(t, doc.UnitModes)
	require.NotEmpty(t, doc.FieldMap)

	refused := false
	for _, m := range doc.FieldMap {
		if m.Status == "refused" && strings.Contains(m.Field, "api_key") {
			refused = true
		}
	}
	require.True(t, refused, "the printed field map must refuse credential fields explicitly")
}

func TestPricingImportLiteLLM(t *testing.T) {
	root := RootCommand()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"pricing", "import-litellm",
		"--in", "../pricing/testdata/litellm_sample.json",
		"--source", "fixture",
		"--date", "2026-09-30",
	})

	require.NoError(t, root.Execute())
	require.Contains(t, stderr.String(), "imported=8")

	var pf pricing.PriceFile
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &pf))
	require.NoError(t, pricing.ValidatePriceFile(pf))
	require.Equal(t, "fixture", pf.Source)
}

// TestPricingImportLiteLLMUnits drives the unit side-catalog subcommand end
// to end against a dedicated audio/image fixture: the emitted unit file
// validates, keeps the max rate on duplicates and carries the provenance.
func TestPricingImportLiteLLMUnits(t *testing.T) {
	root := RootCommand()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"pricing", "import-litellm-units",
		"--in", "../pricing/testdata/litellm_units_sample.json",
		"--source", "fixture",
		"--date", "2026-09-30",
	})

	require.NoError(t, root.Execute())
	require.Equal(t,
		"total=8 imported=3 skipped_mode=1 skipped_no_price=2 skipped_invalid=1 duplicates=1\n",
		stderr.String())

	var uf pricing.UnitFile
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &uf))
	require.NoError(t, pricing.ValidateUnitFile(uf))
	require.Equal(t, "fixture", uf.Source)
	require.Len(t, uf.Units, 3)

	byKey := make(map[string]pricing.UnitEntry, len(uf.Units))
	for _, e := range uf.Units {
		byKey[e.Provider+":"+e.Model] = e
	}
	// per_character = input only; per_second_audio/per_image = max of the
	// present fields; the duplicate keeps the max rate.
	require.InDelta(t, 0.0000321, byKey["openai:tts"].Rate, 1e-15)
	require.Equal(t, pricing.UnitPerCharacter, byKey["openai:tts"].Unit)
	require.InDelta(t, 0.034567, byKey["deepgram:fixture-audio"].Rate, 1e-15)
	require.InDelta(t, 0.0789, byKey["openai:fixture-image"].Rate, 1e-15)
	require.Equal(t, pricing.UnitPerImage, byKey["openai:fixture-image"].Unit)
}
