package pricing

import "strings"

// The LiteLLM migration pin exists so the catalog contract consumed by
// ImportLiteLLM and ImportLiteLLMUnits is data, not tribal knowledge.
// PRODUCT-CONTRACT.md §14 (migration wizard) and owner decision I65 require
// the supported source formats to be pinned and every unsupported field to
// have an explicit, non-silent disposition. The mapping below is the
// price/unit importer slice of that contract; the config-level dry-run
// report and apply remain with the wizard tasks (N16-P02-T03+).

// LiteLLM field mapping statuses.
const (
	LiteLLMFieldMapped  = "mapped"
	LiteLLMFieldRefused = "refused"
)

// LiteLLMFieldMapping records the disposition of one LiteLLM catalog field:
// where it lands in a Yabanin snapshot, or why it is refused.
type LiteLLMFieldMapping struct {
	Field  string `json:"field"`
	Status string `json:"status"` // LiteLLMFieldMapped or LiteLLMFieldRefused
	Target string `json:"target,omitempty"`
	Note   string `json:"note,omitempty"`
}

// LiteLLMUnitMode pins one non-token metering mode of the same catalog:
// which unit kind it prices and which catalog fields carry the rate.
type LiteLLMUnitMode struct {
	Mode   string   `json:"mode"`
	Unit   string   `json:"unit"`
	Fields []string `json:"fields"`
	Note   string   `json:"note,omitempty"`
}

// LiteLLMFormat is the pinned description of the LiteLLM price-catalog
// format this package imports.
type LiteLLMFormat struct {
	Catalog         string            `json:"catalog"`
	Layout          string            `json:"layout"`
	Unit            string            `json:"unit"`
	PriceScale      float64           `json:"price_scale"`
	SupportedModes  []string          `json:"supported_modes"`
	ProviderAliases map[string]string `json:"provider_aliases"`
	PinnedUpstream  string            `json:"pinned_upstream"`
	Notice          string            `json:"notice"`
	Limitations     []string          `json:"limitations"`
}

// liteLLMProviderAliases is the exact-match provider normalization table
// applied after lowercasing and '_'→'-' folding. normalizeLiteLLMProvider
// consults it, so the pin and the importer cannot drift apart silently.
var liteLLMProviderAliases = map[string]string{
	"text-completion-openai": "openai",
	"together-ai":            "together",
	"fireworks-ai":           "fireworks",
}

// liteLLMVertexPrefix marks the vertex_ai_<region> provider family, which
// collapses to the "vertex" provider regardless of region suffix.
const liteLLMVertexPrefix = "vertex-ai-"

// liteLLMSupportedModes mirrors the token-price mode allow-list enforced by
// ImportLiteLLM. Kept next to the pin so the format contract documents
// exactly what is admitted and everything else is SkippedMode.
var liteLLMSupportedModes = []string{"chat", "completion", "responses", "embedding"}

// liteLLMUnitModePin mirrors the mode→unit mapping enforced by
// ImportLiteLLMUnits (litellmUnitFields). Kept next to the pin so the
// format contract documents the non-token axes without drift.
var liteLLMUnitModePin = []LiteLLMUnitMode{
	{Mode: "audio_transcription", Unit: UnitPerAudioSecond,
		Fields: []string{"input_cost_per_second", "output_cost_per_second"},
		Note:   "rate is the maximum of the present fields; a repeated (provider, model) keeps the max"},
	{Mode: "audio_speech", Unit: UnitPerCharacter,
		Fields: []string{"input_cost_per_character"},
		Note:   "token-billed TTS (no per-character field) stays unpriced, never re-priced from token rates"},
	{Mode: "image_generation", Unit: UnitPerImage,
		Fields: []string{"input_cost_per_image", "output_cost_per_image"},
		Note:   "model name is the text after the last '/' so size-class keys collapse onto one entry"},
}

// LiteLLMFormatPin returns the pinned LiteLLM catalog contract. The returned
// value is a copy; callers cannot mutate package state through it.
func LiteLLMFormatPin() LiteLLMFormat {
	modes := make([]string, len(liteLLMSupportedModes))
	copy(modes, liteLLMSupportedModes)
	aliases := make(map[string]string, len(liteLLMProviderAliases))
	for k, v := range liteLLMProviderAliases {
		aliases[k] = v
	}
	return LiteLLMFormat{
		Catalog: "model_prices_and_context_window.json",
		Layout:  "flat JSON object keyed by LiteLLM model id",
		Unit:    "usd_per_token",
		// ImportLiteLLM multiplies every token price by this scale to
		// produce the per_1m_tokens snapshot; keep in sync with roundPrice.
		PriceScale:      1e6,
		SupportedModes:  modes,
		ProviderAliases: aliases,
		PinnedUpstream:  "github.com/BerriAI/litellm model_prices_and_context_window.json @ 61a73c59b049a8cd6c559168d7f3a2557a1a8cf7 (import-format reference)",
		Notice:          "upstream/import-format attribution in pkg/pricing/NOTICE-litellm.txt",
		Limitations: []string{
			"compatibility covers the documented flat model_prices layout; compatibility is not guaranteed for every upstream version",
			"catalogs are untrusted input: malformed JSON entries and entries with an empty provider or model id are counted in SkippedInvalid, never emitted",
			"tiered per-token fields (*_above_*_tokens) are counted in LiteLLMImportStats.TieredIgnored, never converted",
			"no user accounts, request logs, or financial history are carried by design (PRODUCT-CONTRACT.md §14 negative)",
			"credential fields are refused and never appear in imports, previews, or reports",
			"router limits and config-level routes/limits transfer is the migration wizard scope (N16-P02-T03+), not this importer",
			"Bifrost migration is a separate packet (N16-P03)",
		},
	}
}

// LiteLLMUnitModePin returns the pinned non-token metering modes. The
// returned value is a deep copy; callers cannot mutate package state
// through it.
func LiteLLMUnitModePin() []LiteLLMUnitMode {
	out := make([]LiteLLMUnitMode, len(liteLLMUnitModePin))
	for i, m := range liteLLMUnitModePin {
		m.Fields = append([]string(nil), m.Fields...)
		out[i] = m
	}
	return out
}

// LiteLLMFieldMap returns the field-by-field mapping between the pinned
// LiteLLM catalog and the Yabanin price snapshot. Order is stable: mapped
// fields first, then refusals, so reports render deterministically.
func LiteLLMFieldMap() []LiteLLMFieldMapping {
	return []LiteLLMFieldMapping{
		{Field: "model id (catalog key)", Status: LiteLLMFieldMapped,
			Target: "PriceFileModel.Model",
			Note:   "text after the first '/' keeps the model name; the key prefix is informational only"},
		{Field: "litellm_provider", Status: LiteLLMFieldMapped,
			Target: "PriceFileModel.Provider",
			Note:   "lowercased, '_'→'-', exact aliases applied, vertex_ai_<region> collapses to vertex; empty/whitespace value is SkippedInvalid"},
		{Field: "mode", Status: LiteLLMFieldMapped,
			Target: "admission gate",
			Note:   "chat/completion/responses/embedding admitted for token prices; audio_transcription/audio_speech/image_generation for unit rates; every other value is SkippedMode, never silently kept"},
		{Field: "input_cost_per_token", Status: LiteLLMFieldMapped,
			Target: "PriceFileModel.Input", Note: "USD/token scaled ×1e6 to per_1m_tokens"},
		{Field: "output_cost_per_token", Status: LiteLLMFieldMapped,
			Target: "PriceFileModel.Output", Note: "USD/token scaled ×1e6 to per_1m_tokens"},
		{Field: "cache_creation_input_token_cost", Status: LiteLLMFieldMapped,
			Target: "PriceFileModel.CacheW", Note: "optional; absent → 0"},
		{Field: "cache_read_input_token_cost", Status: LiteLLMFieldMapped,
			Target: "PriceFileModel.CacheR", Note: "optional; absent → 0"},
		{Field: "input/output_cost_per_second, _per_character, _per_image (non-token axes)", Status: LiteLLMFieldMapped,
			Target: "UnitEntry.Rate via ImportLiteLLMUnits",
			Note:   "rates are verbatim USD-per-unit (rounded at 1e-12); see LiteLLMUnitModePin for the mode→unit mapping"},
		{Field: "*_above_*_tokens (tiered per-token fields)", Status: LiteLLMFieldRefused,
			Note: "tiered pricing is not representable in the flat per-1M snapshot; entry counted in LiteLLMImportStats.TieredIgnored"},
		{Field: "max_input_tokens / max_output_tokens (context window)", Status: LiteLLMFieldRefused,
			Note: "model limits are not part of the price snapshot; config-level limits belong to the wizard report (N16-P02-T03+)"},
		{Field: "tpm / rpm / model_info / litellm_params (router limits)", Status: LiteLLMFieldRefused,
			Note: "router/runtime configuration is outside the catalog contract of this importer"},
		{Field: "api_key / api_base / api_type (credentials)", Status: LiteLLMFieldRefused,
			Note: "credentials are never imported, previewed, logged, or reported (PRODUCT-CONTRACT.md §14)"},
	}
}

// normalizeLiteLLMProvider maps a raw litellm_provider string to the
// canonical Yabanin provider id using the pinned alias table.
func normalizeLiteLLMProvider(provider string) string {
	provider = strings.ToLower(provider)
	provider = strings.ReplaceAll(provider, "_", "-")
	if mapped, ok := liteLLMProviderAliases[provider]; ok {
		return mapped
	}
	if strings.HasPrefix(provider, liteLLMVertexPrefix) {
		return "vertex"
	}
	return provider
}
