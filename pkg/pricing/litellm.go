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

// litellmEntryClass is how an importer disposed of one catalog entry; the
// importer maps the class onto its stats counters.
type litellmEntryClass int

const (
	litellmEntryImport litellmEntryClass = iota
	litellmEntryInvalid
	litellmEntryMode
	litellmEntryNoPrice
	litellmEntryDuplicate
)

// ImportLiteLLM converts LiteLLM's model_prices_and_context_window.json
// (USD per token) into a PriceFile (USD per 1M tokens).
func ImportLiteLLM(r io.Reader, source, date string) (PriceFile, LiteLLMImportStats, error) {
	root, err := parseLiteLLMCatalog(r)
	if err != nil {
		return PriceFile{}, LiteLLMImportStats{}, err
	}
	keys := litellmCatalogKeys(root)

	var stats LiteLLMImportStats
	stats.Total = len(keys)
	seen := make(map[string]struct{}, len(keys))
	models := make([]PriceFileModel, 0, len(keys))
	for _, key := range keys {
		m, class, tiered := litellmTokenEntry(key, root[key], seen)
		if tiered {
			stats.TieredIgnored++
		}
		switch class {
		case litellmEntryImport:
			models = append(models, m)
			stats.Imported++
		case litellmEntryInvalid:
			stats.SkippedInvalid++
		case litellmEntryMode:
			stats.SkippedMode++
		case litellmEntryNoPrice:
			stats.SkippedNoPrice++
		case litellmEntryDuplicate:
			stats.Duplicates++
		}
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

// parseLiteLLMCatalog decodes the top level of LiteLLM's
// model_prices_and_context_window.json. The payload must be exactly one
// flat JSON object with no trailing data: null is a layout violation, not
// an empty catalog (silence here would bless any non-object payload), and
// Decode consumes only the first JSON value, so trailing data would
// otherwise import silently truncated.
func parseLiteLLMCatalog(r io.Reader) (map[string]json.RawMessage, error) {
	var root map[string]json.RawMessage
	dec := json.NewDecoder(r)
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf("parse litellm catalog: %w", err)
	}
	if root == nil {
		return nil, fmt.Errorf("parse litellm catalog: top level must be a JSON object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("parse litellm catalog: trailing data after the top-level object")
	}
	return root, nil
}

// litellmCatalogKeys returns the sorted entry keys, excluding the
// sample_spec documentation entry.
func litellmCatalogKeys(root map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(root))
	for key := range root {
		if key == "sample_spec" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// litellmTokenEntry classifies one catalog entry for the token import and,
// for an importable entry, registers its identity in seen (the first
// sorted key wins; later duplicates keep the earlier prices). tiered
// reports a tiered-pricing entry independently of its final class — the
// disposition is counted even when the entry is then skipped.
func litellmTokenEntry(key string, raw json.RawMessage, seen map[string]struct{}) (PriceFileModel, litellmEntryClass, bool) {
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return PriceFileModel{}, litellmEntryInvalid, false
	}
	mode, _ := obj["mode"].(string)
	switch mode {
	case "chat", "completion", "responses", "embedding":
	default:
		return PriceFileModel{}, litellmEntryMode, false
	}
	tiered := litellmTiered(obj)
	in, out, cacheW, cacheR, priced, ok := litellmTokenPrices(obj)
	if !ok {
		return PriceFileModel{}, litellmEntryInvalid, tiered
	}
	if !priced {
		return PriceFileModel{}, litellmEntryNoPrice, tiered
	}
	provider, model, ok := litellmTokenIdentity(key, obj)
	if !ok {
		return PriceFileModel{}, litellmEntryInvalid, tiered
	}
	id := provider + "\x00" + model
	if _, dup := seen[id]; dup {
		return PriceFileModel{}, litellmEntryDuplicate, tiered
	}
	seen[id] = struct{}{}
	return PriceFileModel{
		Provider: provider,
		Model:    model,
		Input:    roundPrice(in * 1e6),
		Output:   roundPrice(out * 1e6),
		CacheW:   roundPrice(cacheW * 1e6),
		CacheR:   roundPrice(cacheR * 1e6),
	}, litellmEntryImport, tiered
}

// litellmTokenPrices reads the four token price axes (USD per token). An
// absent axis reads as 0 — absence is not an error. ok=false marks a
// malformed axis; priced=false marks input and output both zero (cache-only
// pricing is not importable).
func litellmTokenPrices(obj map[string]any) (in, out, cacheW, cacheR float64, priced, ok bool) {
	in, okIn := litellmUSD(obj, "input_cost_per_token")
	out, okOut := litellmUSD(obj, "output_cost_per_token")
	cacheW, okW := litellmUSD(obj, "cache_creation_input_token_cost")
	cacheR, okR := litellmUSD(obj, "cache_read_input_token_cost")
	return in, out, cacheW, cacheR,
		in != 0 || out != 0,
		okIn && okOut && okW && okR
}

// litellmTokenIdentity names the token entry: normalized provider plus
// every key segment after the FIRST "/" (region-scoped keys keep their
// inner segments). ok=false for an empty provider or model — such an entry
// could only fail later validation, so the import counts it as invalid
// instead and keeps importing the rest of the file.
func litellmTokenIdentity(key string, obj map[string]any) (provider, model string, ok bool) {
	provider = normalizeLiteLLMProvider(stringField(obj, "litellm_provider"))
	if strings.TrimSpace(provider) == "" {
		return "", "", false
	}
	model = key
	if i := strings.IndexByte(key, '/'); i >= 0 {
		model = key[i+1:]
	}
	if strings.TrimSpace(model) == "" {
		return "", "", false
	}
	return provider, model, true
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
