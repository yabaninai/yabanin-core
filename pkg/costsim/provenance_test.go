package audit

import (
	"strings"
	"testing"
)

func TestPricingProvenanceAllFormats(t *testing.T) {
	report := GenerateReport(nil, ModeExact)
	j, err := RenderJSON(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{RenderMarkdown(report), RenderHTML(report), j} {
		// A03: the report cites the actual price-file snapshot provenance —
		// a SHA256 fingerprint and a source/date. The legacy "upstream
		// verification date not recorded" note only appears when the file
		// pricer is unavailable, so assert the fingerprint + source instead.
		if !strings.Contains(out, "sha256:") || !strings.Contains(out, "source") {
			t.Fatal("price provenance absent")
		}
	}
	if report.S1.TotalCost != 0 || report.S1.UnpricedRequests != 0 {
		t.Fatal("metadata changed totals")
	}
}
func TestSemanticReportDisclosesMissingEmbedder(t *testing.T) {
	report := GenerateReport([]Record{{Model: "gpt-4o", Provider: "openai", PromptTokens: 100}}, ModeSemantic)
	if report.SimulationError == "" || !strings.Contains(RenderHTML(report), "Simulation unavailable") {
		t.Fatal("missing embedder error hidden")
	}
}
