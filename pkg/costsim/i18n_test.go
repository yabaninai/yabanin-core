package audit

import (
	"strings"
	"testing"
)

// These tests pin the I18N-12 behavior: render templates are localized by
// --lang (md + html), the default (empty/unknown) locale stays byte-identical
// to English, and the data fields (finding names/details) remain the stable
// JSON contract.

// TestRenderMarkdownLang_Russian asserts the section headings and labels render
// in Russian when lang=ru, while the data fields (built in report.go) stay the
// English contract values.
func TestRenderMarkdownLang_Russian(t *testing.T) {
	rep := fixtureReportForI18N()
	out := RenderMarkdownLang(rep, "ru")

	// Localized render templates.
	for _, want := range []string{
		"# Yabanin — аудит расходов",
		"## 1. Сводка",
		"- Запросы: ",
		"## 2. Что обнаружено",
		"## 3. Симуляция кэша",
		"## 4. Симуляция маршрутизации",
		"## 5. Качество данных",
		"## 6. Рекомендации",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ru markdown missing %q\n--- output ---\n%s", want, out)
		}
	}
	// Data fields (finding name + recommendation rule) are the JSON contract —
	// they render verbatim (English) even in the ru locale.
	if !strings.Contains(out, "Spend concentration") {
		t.Errorf("ru markdown should still contain the data field \"Spend concentration\"")
	}
}

// TestRenderMarkdownLang_UnknownFallsBackToEn ensures an unknown locale tag
// degrades to English rather than failing or rendering empty.
func TestRenderMarkdownLang_UnknownFallsBackToEn(t *testing.T) {
	rep := fixtureReportForI18N()
	out := RenderMarkdownLang(rep, "xx-NOPE")
	for _, want := range []string{
		"# Yabanin Spend Audit",
		"## 1. Summary",
		"## 6. Recommendations",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("unknown-locale markdown missing en string %q", want)
		}
	}
}

// TestRenderMarkdownLang_EmptyIsEnglish pins the backward-compat contract: no
// locale (the historical default) is byte-identical to the canonical en render.
func TestRenderMarkdownLang_EmptyIsEnglish(t *testing.T) {
	rep := fixtureReportForI18N()
	if got := RenderMarkdown(rep); got != RenderMarkdownLang(rep, "") {
		t.Fatalf("RenderMarkdown (no lang) != RenderMarkdownLang(\"\")")
	}
	if got := RenderMarkdownLang(rep, "en"); got != RenderMarkdown(rep) {
		t.Fatalf("RenderMarkdownLang(\"en\") != RenderMarkdown (en must be canonical)")
	}
}

// TestRenderHTMLLang_Russian asserts the HTML document's lang attribute and
// section headings follow the locale, and unknown cells stay the localized
// "Unknown" (never "$0.00").
func TestRenderHTMLLang_Russian(t *testing.T) {
	rep := fixtureReportForI18N()
	out := RenderHTMLLang(rep, "ru")

	if !strings.Contains(out, `<html lang="ru">`) {
		t.Errorf("ru HTML missing <html lang=\"ru\">")
	}
	for _, want := range []string{
		"<h2>1. Сводка</h2>",
		"<h2>5. Качество данных</h2>",
		"<h2>6. Рекомендации</h2>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ru HTML missing %q", want)
		}
	}
	// AVR-04 (F04) invariant preserved under localization: an unpriced model
	// renders the localized Unknown, never a $0.00.
	if !strings.Contains(out, `class="unknown">Неизвестно`) {
		t.Errorf("ru HTML missing localized Unknown cell")
	}
}

// TestRenderHTMLLang_UnknownFallsBackToEn pins that an unknown locale yields the
// English document (lang="en") — the historical default.
func TestRenderHTMLLang_UnknownFallsBackToEn(t *testing.T) {
	rep := fixtureReportForI18N()
	out := RenderHTMLLang(rep, "zz")
	if !strings.Contains(out, `<html lang="en">`) {
		t.Errorf("unknown-locale HTML should fall back to <html lang=\"en\">")
	}
}

// fixtureReportForI18N builds a minimal, deterministic report that exercises
// every section (including an unpriced model for the Unknown-cell invariant and
// a fired finding + recommendation for the data-field check).
func fixtureReportForI18N() AuditReport {
	rep := AuditReport{}
	rep.S1.Requests = 10
	rep.S1.TotalCost = 12.5
	rep.S1.InputCost = 7.5
	rep.S1.OutputCost = 5.0
	rep.S1.UnpricedRequests = 2
	rep.S1.Window = "2026-09-01..2026-09-07"
	rep.S1.HasWindow = true
	rep.S1.TopModels = []ModelRow{
		{Name: "model-a", Requests: 8, CostUSD: 10.0, SharePct: 80.0},
		{Name: "model-b", Requests: 2, CostUSD: 0, SharePct: 20.0, Unpriced: true},
	}
	rep.S1.TopProviders = []NameShare{{Name: "prov-1", Requests: 10, SharePct: 100.0}}
	rep.S2 = []Finding{{Name: "Spend concentration", Detail: "p50=$0.10 top 1% hold 80.0% of spend."}}
	rep.S3 = CacheBlock{Mode: ModeExact, HitRatePct: 40.0, TokensAvoided: 1000, DollarsAvoided: 2.5}
	rep.S4 = RoutingBlock{Classifier: "ml", ClassDistribution: map[string]int{"easy": 8, "hard": 2}, RoutingOnly: 1.0, RoutingOnMisses: 0.5}
	rep.Savings = CombinedSavings{CacheOnly: 2.5, RoutingOnly: 0.5, Combined: 2.8, Overlap: 0.2}
	rep.S5 = QualityBlock{Parsed: 10, Skipped: 0, Denominator: 10, RealTokenSharePct: 100.0, TimestampedPct: 100.0, UnpricedCount: 2, UnpricedModels: []string{"model-b"}}
	rep.S6 = []Recommendation{{Rule: "Investigate the top spenders", Detail: "top 1% hold 80% of spend."}}
	return rep
}
