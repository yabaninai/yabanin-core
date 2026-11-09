package pricing

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
)

// LiteLLMImportStats counts how ImportLiteLLM classified each catalog entry.
type LiteLLMImportStats struct {
	Total, Imported, SkippedMode, SkippedNoPrice, SkippedInvalid, Duplicates, TieredIgnored int
}

// ImportLiteLLM converts LiteLLM's model_prices_and_context_window.json
// (USD per token) into a PriceFile (USD per 1M tokens).
func ImportLiteLLM(r io.Reader, source, date string) (PriceFile, LiteLLMImportStats, error) {
	var root map[string]json.RawMessage
	dec := json.NewDecoder(r)
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return PriceFile{}, LiteLLMImportStats{}, fmt.Errorf("parse litellm catalog: %w", err)
	}
	if root == nil {
		// Valid JSON that is not a flat object (null) is a layout
		// violation, not an empty catalog: silence here would bless any
		// non-object payload.
		return PriceFile{}, LiteLLMImportStats{}, fmt.Errorf("parse litellm catalog: top level must be a JSON object")
	}
	if _, err := dec.Token(); err != io.EOF {
		// Decode consumes only the FIRST JSON value; without this check a
		// catalog with trailing data imports silently truncated.
		return PriceFile{}, LiteLLMImportStats{}, fmt.Errorf("parse litellm catalog: trailing data after the top-level object")
	}

	keys := make([]string, 0, len(root))
	for key := range root {
		if key == "sample_spec" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var stats LiteLLMImportStats
	stats.Total = len(keys)
	seen := make(map[string]struct{}, len(keys))
	models := make([]PriceFileModel, 0, len(keys))

	for _, key := range keys {
		var obj map[string]any
		if err := json.Unmarshal(root[key], &obj); err != nil {
			stats.SkippedInvalid++
			continue
		}
		mode, _ := obj["mode"].(string)
		switch mode {
		case "chat", "completion", "responses", "embedding":
		default:
			stats.SkippedMode++
			continue
		}
		if litellmTiered(obj) {
			stats.TieredIgnored++
		}

		input, okIn := litellmUSD(obj, "input_cost_per_token")
		output, okOut := litellmUSD(obj, "output_cost_per_token")
		cacheW, okW := litellmUSD(obj, "cache_creation_input_token_cost")
		cacheR, okR := litellmUSD(obj, "cache_read_input_token_cost")
		if !okIn || !okOut || !okW || !okR {
			stats.SkippedInvalid++
			continue
		}
		if input == 0 && output == 0 {
			stats.SkippedNoPrice++
			continue
		}

		provider := normalizeLiteLLMProvider(stringField(obj, "litellm_provider"))
		if strings.TrimSpace(provider) == "" {
			// ValidatePriceFile rejects an empty provider; skipping here
			// keeps the whole-file import alive and the disposition
			// explicit (parity with ImportLiteLLMUnits).
			stats.SkippedInvalid++
			continue
		}
		model := key
		if i := strings.IndexByte(key, '/'); i >= 0 {
			model = key[i+1:]
		}
		if strings.TrimSpace(model) == "" {
			// An empty catalog key would emit a model-less entry that
			// only fails later validation; count it as invalid instead.
			stats.SkippedInvalid++
			continue
		}
		id := provider + "\x00" + model
		if _, dup := seen[id]; dup {
			stats.Duplicates++
			continue
		}
		seen[id] = struct{}{}
		models = append(models, PriceFileModel{
			Provider: provider,
			Model:    model,
			Input:    roundPrice(input * 1e6),
			Output:   roundPrice(output * 1e6),
			CacheW:   roundPrice(cacheW * 1e6),
			CacheR:   roundPrice(cacheR * 1e6),
		})
		stats.Imported++
	}

	sort.Slice(models, func(i, j int) bool {
		if models[i].Provider != models[j].Provider {
			return models[i].Provider < models[j].Provider
		}
		return models[i].Model < models[j].Model
	})

	return PriceFile{
		Source:   source,
		Date:     date,
		Currency: "USD",
		Units:    "per_1m_tokens",
		Models:   models,
	}, stats, nil
}

func litellmTiered(obj map[string]any) bool {
	for key := range obj {
		if strings.Contains(key, "_above_") && strings.Contains(key, "tokens") {
			return true
		}
	}
	return false
}

func litellmUSD(obj map[string]any, key string) (float64, bool) {
	raw, ok := obj[key]
	if !ok || raw == nil {
		return 0, true
	}
	switch v := raw.(type) {
	case json.Number:
		f, err := v.Float64()
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 {
			return 0, false
		}
		return f, true
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
			return 0, false
		}
		return v, true
	default:
		return 0, false
	}
}

func stringField(obj map[string]any, key string) string {
	s, _ := obj[key].(string)
	return s
}

func roundPrice(v float64) float64 {
	return math.Round(v*1e6) / 1e6
}
