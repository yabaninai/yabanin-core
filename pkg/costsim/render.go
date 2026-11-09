package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/reireirei/yabanin/pkg/costsim/locales"
)

// RenderMarkdown renders the full six-section report as Markdown. Output is
// deterministic for a given report except the single "generated" line, which
// carries GeneratedAt and is the only value that changes between runs.
func RenderMarkdown(r AuditReport) string {
	return RenderMarkdownLang(r, "")
}

// RenderMarkdownLang renders the report as Markdown with the report's render
// templates taken from the locale `lang` (I18N-12). Empty/unknown `lang` uses
// English (the canonical locale), which is byte-identical to the historical
// hardcoded output — so the no-locale path is unchanged. Money is formatted
// with the locale's CLDR data via the catalog.
func RenderMarkdownLang(r AuditReport, lang string) string {
	cat := locales.Get(lang)
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", cat.T("docTitle"))
	fmt.Fprintf(&b, cat.T("generated"), r.GeneratedAt.Format("2006-01-02 15:04:05 UTC"))
	b.WriteString("\n\n")
	if r.InsufficientSample() {
		fmt.Fprintf(&b, cat.T("insuffBanner"), r.S1.Requests, windowLabel(r, cat))
		b.WriteString("\n\n")
	}
	if r.Source != "" {
		fmt.Fprintf(&b, cat.T("source"), r.Source)
		b.WriteString("\n\n")
	}
	fmt.Fprintf(&b, cat.T("pricingBlk"), r.Pricing.Source, r.Pricing.Version, r.Pricing.AsOf, r.Pricing.Note)
	if r.SimulationError != "" {
		fmt.Fprintf(&b, cat.T("simUnavail"), r.SimulationError)
		b.WriteString("\n\n")
	}
	renderSummary(&b, r, cat)
	renderFindings(&b, r, cat)
	renderCache(&b, r, cat)
	renderRouting(&b, r, cat)
	renderQuality(&b, r, cat)
	renderRecommendations(&b, r, cat)
	return b.String()
}

// RenderJSON renders the report as canonical JSON. Struct fields marshal in
// declaration order and maps are sorted by key, so the output is byte-stable for
// a given report (GeneratedAt is the one field that changes between runs).
func RenderJSON(r AuditReport) (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data) + "\n", nil
}

// RenderHTML renders the report as a self-contained HTML document with no
// external assets (no CDN, no JS — the site may embed it on any host). It is
// deterministic for a given report except the single generated-at line.
//
// AVR-04 (F04): every table lives in its own labeled overflow-x:auto scroll
// container (role=region, aria-label, tabindex=0) so a wide table scrolls
// locally instead of widening the document on 360/390px viewports; the
// unknown-price cells render "Unknown" instead of "$0.00"; and the palette is
// the Astra v2 Paper & Olive set (standards/design.md), inlined for autonomy.
// The hex literals are the verified snapshot of the canon required by the
// offline report (design/lint-design.sh [render] pin) — do not add new ones.
const htmlStyle = `body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:#f2efe6;color:#292d24;margin:0;padding:0;overflow-wrap:anywhere}
main{max-width:900px;margin:2rem auto;padding:0 1rem}
h1{font-size:1.5rem;margin:0 0 .5rem}h2{font-size:1.2rem;border-bottom:1px solid #d2d3c4;padding-bottom:.3rem;margin-top:2rem}
p{line-height:1.5}
code{background:#e8e5d9;padding:.1rem .3rem;overflow-wrap:anywhere}
.banner{background:#f3ecd8;border:1px solid #d2d3c4;padding:.6rem .8rem;margin:1rem 0}
.scroll{overflow-x:auto;margin:1rem 0;border:1px solid #d2d3c4;border-radius:4px}
.scroll:focus-visible{outline:2px solid #4c6236;outline-offset:1px}
table{border-collapse:collapse;width:100%;min-width:420px;margin:0}
th,td{border-bottom:1px solid #d2d3c4;padding:.45rem .6rem;text-align:left;font-size:.9rem}
th{background:#e8e5d9;border-bottom:2px solid #808570}
tr:last-child td{border-bottom:0}
.unknown{color:#626657;font-style:italic}`

// RenderHTML renders the audit report as a self-contained HTML document.
// RenderHTML.
func RenderHTML(r AuditReport) string {
	return RenderHTMLLang(r, "")
}

// RenderHTMLLang renders the report as a self-contained HTML document with the
// render templates from locale `lang` (I18N-12). Empty/unknown `lang` uses
// English (byte-identical to the historical output, including <html lang="en">).
// AVR-04 (F04) invariants are preserved: every table is in its own labeled
// overflow-x:auto scroll container, unknown-price cells render the localized
// "Unknown" (never "$0.00"), and the palette is inlined.
func RenderHTMLLang(r AuditReport, lang string) string {
	cat := locales.Get(lang)
	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html lang=\"")
	b.WriteString(html.EscapeString(cat.Lang()))
	b.WriteString("\">\n<head>\n")
	b.WriteString("<meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>")
	b.WriteString(html.EscapeString(cat.T("docTitle")))
	b.WriteString("</title>\n")
	b.WriteString("<style>")
	b.WriteString(htmlStyle)
	b.WriteString("</style>\n</head>\n<body>\n<main>\n")
	fmt.Fprintf(&b, "<h1>%s</h1>\n", html.EscapeString(cat.T("docTitle")))
	fmt.Fprintf(&b, "<p><em>%s</em></p>\n", html.EscapeString(fmt.Sprintf(cat.T("generated"), r.GeneratedAt.Format("2006-01-02 15:04:05 UTC"))))
	if r.InsufficientSample() {
		fmt.Fprintf(&b, cat.T("htmlInsuffBanner"), r.S1.Requests, html.EscapeString(windowLabel(r, cat)))
		b.WriteString("\n")
	}
	if r.Source != "" {
		fmt.Fprintf(&b, cat.T("htmlSource"), html.EscapeString(r.Source))
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, cat.T("htmlPricingBlk"), html.EscapeString(r.Pricing.Source), html.EscapeString(r.Pricing.Version), html.EscapeString(r.Pricing.AsOf), html.EscapeString(r.Pricing.Note))
	if r.SimulationError != "" {
		fmt.Fprintf(&b, cat.T("htmlSimUnavail"), html.EscapeString(r.SimulationError))
	}
	renderHTMLSummary(&b, r, cat)
	renderHTMLFindings(&b, r, cat)
	renderHTMLCache(&b, r, cat)
	renderHTMLRouting(&b, r, cat)
	renderHTMLQuality(&b, r, cat)
	renderHTMLRecommendations(&b, r, cat)
	b.WriteString("</main>\n</body>\n</html>\n")
	return b.String()
}

// --- helpers -----------------------------------------------------------------

func windowLabel(r AuditReport, cat locales.Catalog) string {
	if !r.S1.HasWindow || r.S1.Window == "" {
		return cat.T("unknownWindow")
	}
	return r.S1.Window
}

func renderSummary(b *strings.Builder, r AuditReport, cat locales.Catalog) {
	fmt.Fprintf(b, "## %s %s\n\n", cat.T("summaryNum"), cat.T("summaryHeading"))
	fmt.Fprintf(b, "- %s\n", cat.F("summaryRequests", r.S1.Requests))
	fmt.Fprintf(b, "- %s\n", cat.F("summaryTotalCost", cat.Money(r.S1.TotalCost), cat.Money(r.S1.InputCost), cat.Money(r.S1.OutputCost)))
	fmt.Fprintf(b, "- %s\n", cat.F("summaryUnpriced", r.S1.UnpricedRequests))
	fmt.Fprintf(b, "- %s\n", cat.F("summaryWindow", windowLabel(r, cat)))
	b.WriteString("\n")
	if len(r.S1.TopModels) > 0 {
		b.WriteString(cat.T("modelHead"))
		b.WriteString("\n|---|---|---|---|---|\n")
		for _, m := range r.S1.TopModels {
			up := ""
			if m.Unpriced {
				up = cat.T("yes")
			}
			fmt.Fprintf(b, "| %s | %d | %s | %.1f%% | %s |\n", m.Name, m.Requests, cat.Money(m.CostUSD), m.SharePct, up)
		}
		b.WriteString("\n")
	}
	if len(r.S1.TopProviders) > 0 {
		b.WriteString(cat.T("providerHead"))
		b.WriteString("\n|---|---|---|\n")
		for _, p := range r.S1.TopProviders {
			fmt.Fprintf(b, "| %s | %d | %.1f%% |\n", p.Name, p.Requests, p.SharePct)
		}
		b.WriteString("\n")
	}
}

func renderFindings(b *strings.Builder, r AuditReport, cat locales.Catalog) {
	fmt.Fprintf(b, "## %s %s\n\n", cat.T("findingsNum"), cat.T("findingsHeading"))
	if len(r.S2) == 0 {
		b.WriteString(cat.T("noFindings"))
		b.WriteString("\n\n")
		return
	}
	for _, f := range r.S2 {
		fmt.Fprintf(b, "- **%s** — %s\n", f.Name, f.Detail)
	}
	b.WriteString("\n")
}

func renderCache(b *strings.Builder, r AuditReport, cat locales.Catalog) {
	fmt.Fprintf(b, "## %s %s\n\n", cat.T("cacheNum"), cat.F("cacheHeading", r.S3.Mode))
	fmt.Fprintf(b, "- %s\n", cat.F("cacheHitRate", r.S3.HitRatePct))
	fmt.Fprintf(b, "- %s\n", cat.F("cacheTokensAvoid", r.S3.TokensAvoided))
	fmt.Fprintf(b, "- %s\n", cat.F("cacheDollarsAvoid", cat.Money(r.S3.DollarsAvoided)))
	if r.S3.Caveat != "" {
		fmt.Fprintf(b, "- %s\n", cat.F("cacheCaveat", r.S3.Caveat))
	}
	if len(r.S3.PerModel) > 0 {
		b.WriteString("\n")
		b.WriteString(cat.T("cacheModelHead"))
		b.WriteString("\n|---|---|---|\n")
		for _, m := range r.S3.PerModel {
			fmt.Fprintf(b, "| %s | %d | %.1f%% |\n", m.Name, m.Requests, m.SharePct)
		}
		b.WriteString("\n")
	}
}

func renderRouting(b *strings.Builder, r AuditReport, cat locales.Catalog) {
	fmt.Fprintf(b, "## %s %s\n\n", cat.T("routingNum"), cat.F("routingHeading", r.S4.Classifier))
	keys := sortedKeys(r.S4.ClassDistribution)
	if len(keys) > 0 {
		b.WriteString(cat.T("routingClassHead"))
		b.WriteString("\n|---|---|\n")
		for _, k := range keys {
			fmt.Fprintf(b, "| %s | %d |\n", k, r.S4.ClassDistribution[k])
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(b, "- %s\n", cat.F("routingOnly", cat.Money(r.S4.RoutingOnly)))
	fmt.Fprintf(b, "- %s\n", cat.F("routingOnMisses", cat.Money(r.S4.RoutingOnMisses)))
	if r.S4.UnpricedDropped > 0 {
		fmt.Fprintf(b, "- %s\n", cat.F("routingUnpricedDrop", r.S4.UnpricedDropped))
	}
	fmt.Fprintf(b, "- %s\n\n", cat.F("routingCombined", cat.Money(r.Savings.Combined), cat.Money(r.Savings.Overlap)))
}

func renderQuality(b *strings.Builder, r AuditReport, cat locales.Catalog) {
	fmt.Fprintf(b, "## %s %s\n\n", cat.T("qualityNum"), cat.T("qualityHeading"))
	fmt.Fprintf(b, "- %s\n", cat.F("qualityParsed", r.S5.Parsed, r.S5.Skipped))
	fmt.Fprintf(b, "- %s\n", cat.F("qualityDenominator", r.S5.Denominator))
	if r.S5.Cap > 0 {
		fmt.Fprintf(b, "- %s\n", cat.F("qualityCap", r.S5.Cap))
	}
	fmt.Fprintf(b, "- %s\n", cat.F("qualityRealTokens", r.S5.RealTokenSharePct))
	fmt.Fprintf(b, "- %s\n", cat.F("qualityTimestamps", r.S5.TimestampedPct))
	fmt.Fprintf(b, "- %s\n", cat.F("qualityUnpriced", r.S5.UnpricedCount))
	if len(r.S5.UnpricedModels) > 0 {
		fmt.Fprintf(b, "- %s\n", cat.F("qualityUnpricedModels", strings.Join(r.S5.UnpricedModels, ", ")))
	}
	b.WriteString("\n")
}

func renderRecommendations(b *strings.Builder, r AuditReport, cat locales.Catalog) {
	fmt.Fprintf(b, "## %s %s\n\n", cat.T("recsNum"), cat.T("recsHeading"))
	if len(r.S6) == 0 {
		b.WriteString(cat.T("noRecs"))
		b.WriteString("\n\n")
		return
	}
	for i, rec := range r.S6 {
		fmt.Fprintf(b, "%d. **%s** — %s\n", i+1, rec.Rule, rec.Detail)
	}
	b.WriteString("\n")
}

// --- HTML section renderers ---------------------------------------------------

// htmlTable wraps a table in its own labeled scroll container (AVR-04 / F04).
// The container is a focusable region so keyboard users can scroll it; the
// label makes the scrolling affordance discoverable to assistive technology.
func htmlTable(b *strings.Builder, cat locales.Catalog, label string, head string, rows []string) {
	fmt.Fprintf(b, "<div class=\"scroll\" role=\"region\" aria-label=\"%s%s\" tabindex=\"0\">\n<table>\n%s\n",
		html.EscapeString(label), html.EscapeString(cat.T("htmlScrollSuffix")), head)
	for _, row := range rows {
		b.WriteString(row + "\n")
	}
	b.WriteString("</table>\n</div>\n")
}

func renderHTMLSummary(b *strings.Builder, r AuditReport, cat locales.Catalog) {
	fmt.Fprintf(b, "<h2>%s %s</h2>\n<ul>\n", html.EscapeString(cat.T("summaryNum")), html.EscapeString(cat.T("summaryHeading")))
	fmt.Fprintf(b, "<li>%s</li>\n", html.EscapeString(cat.F("summaryRequests", r.S1.Requests)))
	fmt.Fprintf(b, "<li>%s</li>\n", html.EscapeString(cat.F("summaryTotalCost", cat.Money(r.S1.TotalCost), cat.Money(r.S1.InputCost), cat.Money(r.S1.OutputCost))))
	fmt.Fprintf(b, "<li>%s</li>\n", html.EscapeString(cat.F("summaryUnpriced", r.S1.UnpricedRequests)))
	fmt.Fprintf(b, "<li>%s</li>\n", html.EscapeString(cat.F("summaryWindow", windowLabel(r, cat))))
	b.WriteString("</ul>\n")
	if len(r.S1.TopModels) > 0 {
		rows := make([]string, 0, len(r.S1.TopModels))
		for _, m := range r.S1.TopModels {
			up := ""
			if m.Unpriced {
				up = cat.T("yes")
			}
			// AVR-04 (F04): an unpriced model has no known cost — the localized
			// "Unknown", never "$0.00" (unknown is not free).
			cost := cat.Money(m.CostUSD)
			if m.Unpriced {
				cost = cat.T("htmlUnknown")
			}
			rows = append(rows, fmt.Sprintf("<tr><td>%s</td><td>%d</td><td>%s</td><td>%.1f%%</td><td>%s</td></tr>",
				html.EscapeString(m.Name), m.Requests, cost, m.SharePct, html.EscapeString(up)))
		}
		htmlTable(b, cat, cat.T("modelTableLabel"), "<tr><th>Model</th><th>Requests</th><th>Cost</th><th>Share</th><th>Unpriced</th></tr>", rows)
	}
	if len(r.S1.TopProviders) > 0 {
		rows := make([]string, 0, len(r.S1.TopProviders))
		for _, p := range r.S1.TopProviders {
			rows = append(rows, fmt.Sprintf("<tr><td>%s</td><td>%d</td><td>%.1f%%</td></tr>",
				html.EscapeString(p.Name), p.Requests, p.SharePct))
		}
		htmlTable(b, cat, cat.T("providerTableLabel"), "<tr><th>Provider</th><th>Requests</th><th>Share</th></tr>", rows)
	}
}

func renderHTMLFindings(b *strings.Builder, r AuditReport, cat locales.Catalog) {
	fmt.Fprintf(b, "<h2>%s %s</h2>\n", html.EscapeString(cat.T("findingsNum")), html.EscapeString(cat.T("findingsHeading")))
	if len(r.S2) == 0 {
		fmt.Fprintf(b, "<p>%s</p>\n", html.EscapeString(cat.T("noFindings")))
		return
	}
	b.WriteString("<ul>\n")
	for _, f := range r.S2 {
		fmt.Fprintf(b, "<li><strong>%s</strong> — %s</li>\n", html.EscapeString(f.Name), html.EscapeString(f.Detail))
	}
	b.WriteString("</ul>\n")
}

func renderHTMLCache(b *strings.Builder, r AuditReport, cat locales.Catalog) {
	fmt.Fprintf(b, "<h2>%s %s</h2>\n<ul>\n", html.EscapeString(cat.T("cacheNum")), html.EscapeString(cat.F("cacheHeading", r.S3.Mode)))
	fmt.Fprintf(b, "<li>%s</li>\n", html.EscapeString(cat.F("cacheHitRate", r.S3.HitRatePct)))
	fmt.Fprintf(b, "<li>%s</li>\n", html.EscapeString(cat.F("cacheTokensAvoid", r.S3.TokensAvoided)))
	fmt.Fprintf(b, "<li>%s</li>\n", html.EscapeString(cat.F("cacheDollarsAvoid", cat.Money(r.S3.DollarsAvoided))))
	if r.S3.Caveat != "" {
		fmt.Fprintf(b, "<li>%s</li>\n", html.EscapeString(cat.F("cacheCaveat", r.S3.Caveat)))
	}
	b.WriteString("</ul>\n")
	if len(r.S3.PerModel) > 0 {
		rows := make([]string, 0, len(r.S3.PerModel))
		for _, m := range r.S3.PerModel {
			rows = append(rows, fmt.Sprintf("<tr><td>%s</td><td>%d</td><td>%.1f%%</td></tr>",
				html.EscapeString(m.Name), m.Requests, m.SharePct))
		}
		htmlTable(b, cat, cat.T("cacheTableLabel"), "<tr><th>Model</th><th>Requests</th><th>Hit rate</th></tr>", rows)
	}
}

func renderHTMLRouting(b *strings.Builder, r AuditReport, cat locales.Catalog) {
	fmt.Fprintf(b, "<h2>%s %s</h2>\n", html.EscapeString(cat.T("routingNum")), html.EscapeString(cat.F("routingHeading", r.S4.Classifier)))
	keys := sortedKeys(r.S4.ClassDistribution)
	if len(keys) > 0 {
		rows := make([]string, 0, len(keys))
		for _, k := range keys {
			rows = append(rows, fmt.Sprintf("<tr><td>%s</td><td>%d</td></tr>", html.EscapeString(k), r.S4.ClassDistribution[k]))
		}
		htmlTable(b, cat, cat.T("routingTableLabel"), "<tr><th>Class</th><th>Requests</th></tr>", rows)
	}
	b.WriteString("<ul>\n")
	fmt.Fprintf(b, "<li>%s</li>\n", html.EscapeString(cat.F("routingOnly", cat.Money(r.S4.RoutingOnly))))
	fmt.Fprintf(b, "<li>%s</li>\n", html.EscapeString(cat.F("routingOnMisses", cat.Money(r.S4.RoutingOnMisses))))
	if r.S4.UnpricedDropped > 0 {
		fmt.Fprintf(b, "<li>%s</li>\n", html.EscapeString(cat.F("routingUnpricedDrop", r.S4.UnpricedDropped)))
	}
	fmt.Fprintf(b, "<li>%s</li>\n", html.EscapeString(cat.F("routingCombined", cat.Money(r.Savings.Combined), cat.Money(r.Savings.Overlap))))
	b.WriteString("</ul>\n")
}

func renderHTMLQuality(b *strings.Builder, r AuditReport, cat locales.Catalog) {
	fmt.Fprintf(b, "<h2>%s %s</h2>\n<ul>\n", html.EscapeString(cat.T("qualityNum")), html.EscapeString(cat.T("qualityHeading")))
	fmt.Fprintf(b, "<li>%s</li>\n", html.EscapeString(cat.F("qualityParsed", r.S5.Parsed, r.S5.Skipped)))
	fmt.Fprintf(b, "<li>%s</li>\n", html.EscapeString(cat.F("qualityDenominator", r.S5.Denominator)))
	if r.S5.Cap > 0 {
		fmt.Fprintf(b, "<li>%s</li>\n", html.EscapeString(cat.F("qualityCap", r.S5.Cap)))
	}
	fmt.Fprintf(b, "<li>%s</li>\n", html.EscapeString(cat.F("qualityRealTokens", r.S5.RealTokenSharePct)))
	fmt.Fprintf(b, "<li>%s</li>\n", html.EscapeString(cat.F("qualityTimestamps", r.S5.TimestampedPct)))
	fmt.Fprintf(b, "<li>%s</li>\n", html.EscapeString(cat.F("qualityUnpriced", r.S5.UnpricedCount)))
	if len(r.S5.UnpricedModels) > 0 {
		fmt.Fprintf(b, "<li>%s</li>\n", html.EscapeString(cat.F("qualityUnpricedModels", strings.Join(r.S5.UnpricedModels, ", "))))
	}
	b.WriteString("</ul>\n")
}

func renderHTMLRecommendations(b *strings.Builder, r AuditReport, cat locales.Catalog) {
	fmt.Fprintf(b, "<h2>%s %s</h2>\n", html.EscapeString(cat.T("recsNum")), html.EscapeString(cat.T("recsHeading")))
	if len(r.S6) == 0 {
		fmt.Fprintf(b, "<p>%s</p>\n", html.EscapeString(cat.T("noRecs")))
		return
	}
	b.WriteString("<ol>\n")
	for _, rec := range r.S6 {
		fmt.Fprintf(b, "<li><strong>%s</strong> — %s</li>\n", html.EscapeString(rec.Rule), html.EscapeString(rec.Detail))
	}
	b.WriteString("</ol>\n")
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// RegenerateSample writes the current renderer's HTML output for the bundled
// sample traffic fixture (datasets/audit/sample_traffic.jsonl) to path. The
// source line is pinned to the fixture's repo-relative path (as the published
// sample shows it) and the quality account matches the CLI audit pipeline.
// With banner true a synthetic-data banner is inserted after <main> (the
// published example carries it; the datasets/ artifact does not). It exists so
// web/site/static/examples/audit-sample.html and datasets/audit/
// sample_report.html are always produced by the same code that ships, never
// hand-edited. Run it via:
//
//	go test ./pkg/costsim -run TestRegenerateSampleHTML -args -sample.out <file> [-sample.banner]
func RegenerateSample(path string, banner bool) error {
	// Resolve the fixture from the repo root regardless of the caller's
	// working directory (go test runs from the package dir, pkg/costsim).
	root, err := filepath.Abs("../..")
	if err != nil {
		return fmt.Errorf("resolve repo root: %w", err)
	}
	fixture := filepath.Join(root, "datasets", "audit", "sample_traffic.jsonl")
	recs, stats, err := Ingest(context.Background(), fixture, IngestOptions{})
	if err != nil {
		return fmt.Errorf("ingest sample fixture: %w", err)
	}
	rep := GenerateReport(recs, ModeExact)
	rep.Source = fixture
	rep.S5.Skipped = stats.ParseErrorCount
	rep.S5.Cap = stats.Cap
	rep.S5.Denominator = stats.Parsed + stats.ParseErrorCount
	out := RenderHTML(rep)
	if banner {
		bannerHTML := `<div class="banner"><strong>Synthetic sample — not customer results.</strong> Generated from the bundled 600-request fixture. Estimates depend on historical bundled prices and do not establish answer quality.</div>
`
		out = strings.Replace(out, "<main>\n", "<main>\n"+bannerHTML, 1)
	}
	// 0600: the output path is operator-chosen (a repo artifact or a temp
	// file), not a published world-readable destination.
	return os.WriteFile(path, []byte(out), 0o600)
}
