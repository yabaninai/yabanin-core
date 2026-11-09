package audit

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

// fixtureRecords builds a deterministic, in-memory record set that exercises
// every section: multiple models, one unpriced model, repeats for cache, a
// retry storm, an error response, and timestamps spanning >24h so the
// insufficient-sample banner does not fire.
func fixtureRecords() []Record {
	recs := make([]Record, 0, 120)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	easy := "Please summarize this text for me."
	hard := "Please debug this failing function and explain why."
	for i := 0; i < 60; i++ {
		recs = append(recs, Record{
			Timestamp:        now.Add(time.Duration(i) * time.Hour),
			Model:            "gpt-4o",
			Provider:         "openai",
			Prompt:           easy,
			PromptTokens:     1200,
			CompletionTokens: 300,
		})
	}
	for i := 0; i < 20; i++ {
		recs = append(recs, Record{
			Timestamp:        now.Add(time.Duration(i) * time.Hour),
			Model:            "gpt-4o",
			Provider:         "openai",
			Prompt:           hard,
			PromptTokens:     4000,
			CompletionTokens: 900,
			StatusCode:       500, // error waste
			DurationMS:       9000,
		})
	}
	// A handful of unpriced requests (model with no price) — must be excluded
	// from $ totals, never silently priced at $0.
	for i := 0; i < 10; i++ {
		recs = append(recs, Record{
			Timestamp:        now.Add(time.Duration(i) * 30 * time.Minute),
			Model:            "totally-unknown-model",
			Provider:         "openai",
			Prompt:           "unpriced request " + string(rune('a'+i%26)),
			PromptTokens:     500,
			CompletionTokens: 100,
		})
	}
	return recs
}

func stripGeneratedLine(s string) string {
	// Remove the single "generated" line (the only non-deterministic value).
	re := regexp.MustCompile(`(?m)^_?generated.*$`)
	return re.ReplaceAllString(s, "")
}

func TestRenderMarkdown_Deterministic(t *testing.T) {
	recs := fixtureRecords()
	a := RenderMarkdown(GenerateReport(recs, ModeExact))
	b := RenderMarkdown(GenerateReport(recs, ModeExact))
	if stripGeneratedLine(a) != stripGeneratedLine(b) {
		t.Fatalf("markdown render is not deterministic (ignoring generated line)")
	}
}

func TestRenderJSON_Deterministic(t *testing.T) {
	recs := fixtureRecords()
	ra := GenerateReport(recs, ModeExact)
	rb := GenerateReport(recs, ModeExact)
	// JSON includes GeneratedAt; normalize it to a fixed value for comparison.
	ra.GeneratedAt = time.Time{}
	rb.GeneratedAt = time.Time{}
	ja, err := RenderJSON(ra)
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	jb, err := RenderJSON(rb)
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	if ja != jb {
		t.Fatalf("json render is not deterministic")
	}
}

func TestRenderHTML_Deterministic(t *testing.T) {
	// In HTML the timestamp sits inside <p><em>_generated…</em></p>, so the
	// markdown-oriented stripGeneratedLine regex never matched it and the
	// test only passed while both renders landed in the same wall-clock
	// second. Pin GeneratedAt instead of stripping.
	recs := fixtureRecords()
	a := RenderHTML(withFixedGeneratedAt(GenerateReport(recs, ModeExact)))
	b := RenderHTML(withFixedGeneratedAt(GenerateReport(recs, ModeExact)))
	if a != b {
		t.Fatalf("html render is not deterministic for a fixed GeneratedAt")
	}
}

func withFixedGeneratedAt(r AuditReport) AuditReport {
	r.GeneratedAt = time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	return r
}

// TestAuditPipeline_NoNetwork confirms the whole audit runs fully in-memory
// with no network, no Postgres, no Redis, no embedder (exact mode).
func TestAuditPipeline_NoNetwork(t *testing.T) {
	recs := fixtureRecords()
	rep := GenerateReport(recs, ModeExact)
	if rep.S1.Requests != len(recs) {
		t.Errorf("Requests = %d, want %d", rep.S1.Requests, len(recs))
	}
	// Unpriced requests must be excluded from the $ total (never priced at $0).
	if rep.S1.UnpricedRequests != 10 {
		t.Errorf("UnpricedRequests = %d, want 10", rep.S1.UnpricedRequests)
	}
	if rep.S1.TotalCost <= 0 {
		t.Errorf("TotalCost = %v, want > 0", rep.S1.TotalCost)
	}
	// The combined savings identity must hold in the rendered report.
	if rep.Savings.Combined != rep.Savings.CacheOnly+routeMisses(rep) {
		t.Errorf("combined identity broken: combined=%v cache=%v", rep.Savings.Combined, rep.Savings.CacheOnly)
	}
	// Insufficient-sample banner must NOT fire for this >24h, >=50-request set.
	if rep.InsufficientSample() {
		t.Errorf("fixture is 90 requests over >24h; InsufficientSample should be false")
	}
}

// routeMisses extracts the routing-on-misses figure from the report's S4 block.
func routeMisses(rep AuditReport) float64 {
	return rep.S4.RoutingOnMisses
}

// TestRenderHTML_Avr04_TableScrollContainers (AVR-04 / F04): every HTML table
// must live in its own labeled, focusable overflow-x:auto scroll container so a
// wide table scrolls locally instead of widening the document on mobile.
func TestRenderHTML_Avr04_TableScrollContainers(t *testing.T) {
	recs := fixtureRecords()
	out := RenderHTML(GenerateReport(recs, ModeExact))
	// Every table sits in exactly one scroll container: counts must match,
	// and no raw <table may appear outside a .scroll div.
	tables := strings.Count(out, "<table>")
	containers := strings.Count(out, `<div class="scroll" role="region"`)
	if tables != containers {
		t.Fatalf("table count (%d) != scroll-container count (%d)", tables, containers)
	}
	if tables == 0 {
		t.Fatalf("fixture report expected to contain tables")
	}
	if !strings.Contains(htmlStyle, "overflow-x:auto") {
		t.Fatalf("scroll container style missing overflow-x:auto")
	}
	// Every </table> must be closed by its scroll container </div>.
	if got := strings.Count(out, "</table>\n</div>"); got != strings.Count(out, "<table>") {
		t.Fatalf("tables not each closed by a scroll container: %d of %d", got, strings.Count(out, "<table>"))
	}
	// Every table is preceded by its scroll container open tag.
	if i := strings.Index(out, "<table>"); i < 0 || !strings.HasSuffix(out[:i], `tabindex="0">
`) {
		t.Fatalf("first table is not inside a scroll container")
	}
}

// TestRenderHTML_Avr04_UnknownNotZero (AVR-04 / F04): an unpriced model's cost
// cell must read "Unknown", never "$0.00" — unknown price is not free.
func TestRenderHTML_Avr04_UnknownNotZero(t *testing.T) {
	rep := GenerateReport(fixtureRecords(), ModeExact)
	// Force an unpriced top model row so the branch is exercised.
	for i := range rep.S1.TopModels {
		rep.S1.TopModels[i].Unpriced = true
		rep.S1.TopModels[i].CostUSD = 0
	}
	out := RenderHTML(rep)
	if !strings.Contains(out, `<span class="unknown">Unknown</span>`) {
		t.Fatalf("expected an Unknown cost cell for unpriced rows")
	}
	// The Unknown cell must not be accompanied by a $0.00 in the same row.
	for _, row := range strings.Split(out, "\n") {
		if strings.Contains(row, `class="unknown"`) {
			if strings.Contains(row, "$0.00") {
				t.Fatalf("unpriced row still shows $0.00: %s", row)
			}
		}
	}
}

// TestRenderHTML_Avr04_NoExternalAssets (AVR-04 / F04): the report stays
// self-contained — no http(s) references, no @import, no script tags.
func TestRenderHTML_Avr04_NoExternalAssets(t *testing.T) {
	out := RenderHTML(GenerateReport(fixtureRecords(), ModeExact))
	if strings.Contains(out, "http://") || strings.Contains(out, "https://") {
		t.Fatalf("report references external URLs; it must stay self-contained")
	}
	if strings.Contains(strings.ToLower(out), "@import") || strings.Contains(strings.ToLower(out), "<script") {
		t.Fatalf("report uses @import or script; it must stay self-contained")
	}
}

func TestInsufficientSample_SmallSet(t *testing.T) {
	recs := []Record{
		{Timestamp: time.Now(), Model: "gpt-4o", Provider: "openai", Prompt: "hi", PromptTokens: 10, CompletionTokens: 5},
	}
	rep := GenerateReport(recs, ModeExact)
	if !rep.InsufficientSample() {
		t.Errorf("1 request must be an insufficient sample")
	}
}

func TestRenderMarkdown_InsufficientBanner(t *testing.T) {
	recs := []Record{
		{Timestamp: time.Now(), Model: "gpt-4o", Provider: "openai", Prompt: "hi", PromptTokens: 10, CompletionTokens: 5},
	}
	out := RenderMarkdown(GenerateReport(recs, ModeExact))
	if !strings.Contains(out, "Insufficient sample") {
		t.Errorf("expected insufficient-sample banner in:\n%s", out)
	}
}
