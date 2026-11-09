// Package locales holds the message catalog for the audit report renderers
// (I18N-12). Each locale file contributes a `map[string]string` of
// user-facing render templates. English (en) is the canonical locale and
// reproduces the historical hardcoded strings byte-for-byte, so a report
// rendered with no locale (or an unknown one) is identical to the pre-I18N-12
// output — the existing English-asserting tests keep passing and the
// markdown/JSON/HTML contracts are unchanged.
//
// Only the RENDER templates are localized (document title, section headings,
// labels, banners, table captions, money). The report's DATA fields — Finding
// names/details, Recommendation rules/details, the pricing note — are built in
// report.go and stay English: they are the JSON payload (stable contract) and
// localizing pre-formatted prose would break determinism and the --format json
// schema. This matches the card: "шаблоны рендера на языке клиента".
package locales

import (
	"fmt"
	"sort"

	"github.com/reireirei/yabanin/pkg/i18n"
)

// keys is the closed set of template keys every locale must define. A locale
// missing any key falls back to the en value for that key (see Get), so an
// incomplete translation degrades per-key rather than failing the render.
// This list is the single source of truth for catalog completeness; the
// TestCatalogCompleteness test enforces it.
var keys = []string{
	// document / banner
	"docTitle", "generated", "insuffBanner", "source", "pricingBlk", "simUnavail",
	"unknownWindow", "htmlInsuffBanner", "htmlSource", "htmlPricingBlk",
	"htmlSimUnavail", "htmlUnknown", "htmlScrollSuffix",
	// section 1 — summary
	"summaryHeading", "summaryNum", "summaryRequests", "summaryTotalCost",
	"summaryUnpriced", "summaryWindow", "modelHead", "providerHead", "yes",
	"modelTableLabel", "providerTableLabel",
	// section 2 — findings
	"findingsHeading", "findingsNum", "noFindings",
	// section 3 — cache
	"cacheHeading", "cacheNum", "cacheHitRate", "cacheTokensAvoid",
	"cacheDollarsAvoid", "cacheCaveat", "cacheModelHead", "cacheTableLabel",
	// section 4 — routing
	"routingHeading", "routingNum", "routingClassHead", "routingOnly",
	"routingOnMisses", "routingUnpricedDrop", "routingCombined",
	"routingTableLabel",
	// section 5 — data quality
	"qualityHeading", "qualityNum", "qualityParsed", "qualityDenominator",
	"qualityCap", "qualityRealTokens", "qualityTimestamps", "qualityUnpriced",
	"qualityUnpricedModels",
	// section 6 — recommendations
	"recsHeading", "recsNum", "noRecs",
}

// Catalog is one locale's render templates (a flat key->template map).
type Catalog struct {
	lang string
	strs map[string]string
}

// en is the canonical catalog — byte-identical to the pre-I18N-12 strings.
var en = Catalog{
	lang: "en",
	strs: map[string]string{
		"docTitle":      "Yabanin Spend Audit",
		"generated":     "_generated: %s_",
		"insuffBanner":  "> **Insufficient sample.** %d requests over %s. Figures below are indicative, not statistically reliable.",
		"source":        "Source: `%s`",
		"pricingBlk":    "Pricing source: %s\n\nVersion: `%s`\n\nAs of: %s\n\n%s\n\n",
		"simUnavail":    "> **Simulation unavailable:** %s",
		"unknownWindow": "an unknown window",

		"htmlInsuffBanner": "<div class=\"banner\"><strong>Insufficient sample.</strong> %d requests over %s. Figures are indicative, not statistically reliable.</div>",
		"htmlSource":       "<p>Source: <code>%s</code></p>",
		"htmlPricingBlk":   "<p>Pricing source: %s</p><p>Version: <code style=\"overflow-wrap:anywhere\">%s</code></p><p>As of: %s</p><p>%s</p>",
		"htmlSimUnavail":   "<p class=\"banner\">Simulation unavailable: %s</p>",
		"htmlUnknown":      `<span class="unknown">Unknown</span>`,
		"htmlScrollSuffix": " — horizontally scrollable",

		"summaryHeading":     "Summary",
		"summaryNum":         "1.",
		"summaryRequests":    "Requests: %d",
		"summaryTotalCost":   "Total cost: %s (input %s, output %s)",
		"summaryUnpriced":    "Unpriced requests (no known price, excluded from $ totals): %d",
		"summaryWindow":      "Window: %s",
		"modelHead":          "| Model | Requests | Cost | Share | Unpriced |",
		"providerHead":       "| Provider | Requests | Share |",
		"yes":                "yes",
		"modelTableLabel":    "Top models",
		"providerTableLabel": "Top providers",

		"findingsHeading": "What we found",
		"findingsNum":     "2.",
		"noFindings":      "No findings above threshold for this sample.",

		"cacheHeading":      "Cache simulation (%s)",
		"cacheNum":          "3.",
		"cacheHitRate":      "Hit rate: %.1f%%",
		"cacheTokensAvoid":  "Tokens avoided: %d",
		"cacheDollarsAvoid": "Dollars avoided: %s",
		"cacheCaveat":       "_Caveat: %s._",
		"cacheModelHead":    "| Model | Requests | Hit rate |",
		"cacheTableLabel":   "Cache hit rate by model",

		"routingHeading":      "Routing simulation (%s)",
		"routingNum":          "4.",
		"routingClassHead":    "| Class | Requests |",
		"routingOnly":         "Routing-only savings (all requests): %s",
		"routingOnMisses":     "Routing-on-misses savings (production order): %s",
		"routingUnpricedDrop": "Unpriced targets dropped: %d",
		"routingCombined":     "**Combined savings (cache + routing on misses): %s** (overlap %s not double-counted)",
		"routingTableLabel":   "Routing class distribution",

		"qualityHeading":        "Data quality",
		"qualityNum":            "5.",
		"qualityParsed":         "Parsed: %d, skipped: %d",
		"qualityDenominator":    "Ingestion denominator: %d lines (parsed + skipped)",
		"qualityCap":            "Ingestion cap: %d records",
		"qualityRealTokens":     "Rows with real token counts: %.1f%%",
		"qualityTimestamps":     "Rows with timestamps: %.1f%%",
		"qualityUnpriced":       "Unpriced requests: %d",
		"qualityUnpricedModels": "Unpriced models: %s",

		"recsHeading": "Recommendations",
		"recsNum":     "6.",
		"noRecs":      "No recommendations fired for this sample.",
	},
}

// registry maps a locale tag to its catalog. Unknown tags resolve to en via
// Get, so a bad --lang degrades to English rather than failing the render.
var registry = map[string]Catalog{
	"en": en,
}

func init() {
	// Locale files register themselves here (see ru.go, de.go, ...).
}

// register adds a locale catalog. Called from each locale file's init().
func register(c Catalog) { registry[c.lang] = c }

// Available returns the sorted list of registered locale tags.
func Available() []string {
	out := make([]string, 0, len(registry))
	for tag := range registry {
		out = append(out, tag)
	}
	sort.Strings(out)
	return out
}

// Get returns the catalog for lang, falling back to en for empty/unknown tags.
func Get(lang string) Catalog {
	if c, ok := registry[lang]; ok {
		return c
	}
	return en
}

// Lang returns the locale tag (e.g. "en", "ru") used for <html lang> and the
// money/number formatters.
func (c Catalog) Lang() string { return c.lang }

// T returns the template for key in lang, falling back to the en value when the
// locale omits the key (per-key graceful degradation).
func (c Catalog) T(key string) string {
	if s, ok := c.strs[key]; ok {
		return s
	}
	if s, ok := en.strs[key]; ok {
		return s
	}
	return key
}

// F applies a template with args (a thin fmt.Sprintf wrapper so renderers read
// naturally: cat.T("summaryRequests", r.S1.Requests)).
func (c Catalog) F(key string, a ...any) string {
	return fmt.Sprintf(c.T(key), a...)
}

// Money renders a USD amount in this locale via pkg/i18n (CLDR currency). For
// en this matches the legacy "$%.2f" shape, so en output is unchanged.
func (c Catalog) Money(v float64) string {
	return i18n.FormatMoney(c.lang, "USD", v)
}
