package audit

import (
	"math"
	"strings"
	"testing"
	"time"
)

// gpt-4o prices: InputPerM 2.5, OutputPerM 10.0 (from pkg/pricing table).
func gpt4o(in, out int) Record {
	return Record{
		Model:            "gpt-4o",
		Provider:         "openai",
		PromptTokens:     in,
		CompletionTokens: out,
	}
}

func TestAnalyze_SpendTotalsAndSplit(t *testing.T) {
	recs := []Record{
		gpt4o(1_000_000, 0),         // $2.50 input
		gpt4o(0, 1_000_000),         // $10.00 output
		gpt4o(1_000_000, 1_000_000), // $2.50 + $10.00
	}
	a := Analyze(recs, AnalyzeOptions{})
	if !approx(a.InputTotal, 5.0) {
		t.Errorf("InputTotal = %v, want 5.0", a.InputTotal)
	}
	if !approx(a.OutputTotal, 20.0) {
		t.Errorf("OutputTotal = %v, want 20.0", a.OutputTotal)
	}
	if !approx(a.SpendTotal, 25.0) {
		t.Errorf("SpendTotal = %v, want 25.0", a.SpendTotal)
	}
	if a.PricedRequests != 3 || a.RequestCount != 3 {
		t.Errorf("Priced=%d Count=%d, want 3/3", a.PricedRequests, a.RequestCount)
	}
}

func TestAnalyze_UnpricedExcludedFromTotals(t *testing.T) {
	recs := []Record{
		gpt4o(1_000_000, 0), // $2.50 priced
		{Model: "totally-unknown", PromptTokens: 1_000_000, CompletionTokens: 1_000_000}, // unpriced
	}
	a := Analyze(recs, AnalyzeOptions{})
	if !approx(a.SpendTotal, 2.5) {
		t.Errorf("SpendTotal = %v, want 2.5 (unpriced excluded)", a.SpendTotal)
	}
	if a.PricedRequests != 1 {
		t.Errorf("PricedRequests = %d, want 1", a.PricedRequests)
	}
	if len(a.Quality.UnpricedModels) != 1 || a.Quality.UnpricedModels[0] != "totally-unknown" {
		t.Errorf("UnpricedModels = %v", a.Quality.UnpricedModels)
	}
}

func TestAnalyze_EmptyInputSafe(t *testing.T) {
	a := Analyze(nil, AnalyzeOptions{})
	if a.SpendTotal != 0 || a.RequestCount != 0 {
		t.Errorf("empty input should yield zeros, got %+v", a)
	}
	if a.ConcentrationP50 != 0 || a.Top1PctShare != 0 {
		t.Errorf("empty input percentiles should be 0")
	}
	// PerDay/PerModel should be empty, not nil-panic.
	if len(a.PerDay) != 0 || len(a.PerModel) != 0 {
		t.Errorf("empty input should have no breakdowns")
	}
}

func TestAnalyze_WindowAndPerDay(t *testing.T) {
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	recs := []Record{
		{Model: "gpt-4o", Provider: "openai", PromptTokens: 1_000_000, CompletionTokens: 0, Timestamp: base},
		{Model: "gpt-4o", Provider: "openai", PromptTokens: 1_000_000, CompletionTokens: 0, Timestamp: base.Add(2 * time.Hour)},
		{Model: "gpt-4o", Provider: "openai", PromptTokens: 1_000_000, CompletionTokens: 0, Timestamp: base.AddDate(0, 0, 1)}, // next day
	}
	a := Analyze(recs, AnalyzeOptions{})
	if !a.HasWindow {
		t.Fatal("HasWindow should be true")
	}
	if !a.WindowStart.Equal(base) || !a.WindowEnd.Equal(base.AddDate(0, 0, 1)) {
		t.Errorf("window = %v..%v, want %v..%v", a.WindowStart, a.WindowEnd, base, base.AddDate(0, 0, 1))
	}
	if len(a.PerDay) != 2 {
		t.Fatalf("PerDay = %d days, want 2", len(a.PerDay))
	}
	if a.PerDay[0].Requests != 2 || a.PerDay[1].Requests != 1 {
		t.Errorf("PerDay requests = %d,%d, want 2,1", a.PerDay[0].Requests, a.PerDay[1].Requests)
	}
}

func TestAnalyze_ErrorWaste(t *testing.T) {
	recs := []Record{
		{Model: "gpt-4o", Provider: "openai", PromptTokens: 1_000_000, CompletionTokens: 100_000, StatusCode: 500},
		{Model: "gpt-4o", Provider: "openai", PromptTokens: 1_000_000, CompletionTokens: 100_000, StatusCode: 200},
		{Model: "gpt-4o", Provider: "openai", PromptTokens: 0, CompletionTokens: 0, StatusCode: 429}, // no tokens -> not waste
	}
	a := Analyze(recs, AnalyzeOptions{})
	if a.ErrorWasteRequests != 1 {
		t.Errorf("ErrorWasteRequests = %d, want 1", a.ErrorWasteRequests)
	}
	want := 2.5 + 1.0 // 1M in * 2.5/M + 100k out * 10/M = 2.5 + 1.0
	if !approx(a.ErrorWasteCost, want) {
		t.Errorf("ErrorWasteCost = %v, want %v", a.ErrorWasteCost, want)
	}
}

func TestAnalyze_MaxTokensOverProvision(t *testing.T) {
	recs := []Record{
		{Model: "gpt-4o", Provider: "openai", PromptTokens: 100, CompletionTokens: 10, MaxTokens: 1000},  // 10 < 250 -> under
		{Model: "gpt-4o", Provider: "openai", PromptTokens: 100, CompletionTokens: 900, MaxTokens: 1000}, // 900 >= 250 -> used
		{Model: "gpt-4o", Provider: "openai", PromptTokens: 100, CompletionTokens: 50},                   // no max
	}
	a := Analyze(recs, AnalyzeOptions{})
	if a.MaxTokensSet != 2 {
		t.Errorf("MaxTokensSet = %d, want 2", a.MaxTokensSet)
	}
	if !approx(a.MaxTokensOverProvision, 0.5) {
		t.Errorf("MaxTokensOverProvision = %v, want 0.5", a.MaxTokensOverProvision)
	}
}

func TestAnalyze_RetryStorms(t *testing.T) {
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	samePrompt := "the exact same prompt text"
	recs := []Record{
		{Model: "gpt-4o", Provider: "openai", Prompt: samePrompt, PromptTokens: 100, CompletionTokens: 10, Timestamp: base},
		{Model: "gpt-4o", Provider: "openai", Prompt: samePrompt, PromptTokens: 100, CompletionTokens: 10, Timestamp: base.Add(10 * time.Second)}, // within 60s -> storm
		{Model: "gpt-4o", Provider: "openai", Prompt: samePrompt, PromptTokens: 100, CompletionTokens: 10, Timestamp: base.Add(5 * time.Minute)},  // >60s -> not storm
	}
	a := Analyze(recs, AnalyzeOptions{}) // default 60s window
	if a.RetryStormCount != 1 {
		t.Errorf("RetryStormCount = %d, want 1", a.RetryStormCount)
	}
}

func TestAnalyze_PerModelBreakdown(t *testing.T) {
	recs := []Record{
		gpt4o(1_000_000, 0),
		{Model: "claude-3-5-sonnet-latest", Provider: "anthropic", PromptTokens: 1_000_000, CompletionTokens: 0}, // 3.0/M input
	}
	a := Analyze(recs, AnalyzeOptions{})
	if len(a.PerModel) != 2 {
		t.Fatalf("PerModel = %d, want 2", len(a.PerModel))
	}
	// Sorted by cost desc: gpt-4o 2.5 then claude 3.0? Actually claude input is 3.0 > gpt 2.5.
	if a.PerModel[0].Model != "claude-3-5-sonnet-latest" {
		t.Errorf("top model = %q, want claude (higher cost)", a.PerModel[0].Model)
	}
}

func TestAnalyze_EstimationFlagPropagates(t *testing.T) {
	recs := []Record{
		{Model: "gpt-4o", Provider: "openai", Prompt: strings.Repeat("x", 40), TokensEstimated: true}, // estimated 10 tokens
		gpt4o(1_000_000, 0), // real
	}
	a := Analyze(recs, AnalyzeOptions{})
	// real-token share = 1 of 2 = 0.5
	if !approx(a.Quality.RealTokenShare, 0.5) {
		t.Errorf("RealTokenShare = %v, want 0.5", a.Quality.RealTokenShare)
	}
}

func TestPercentilesKnownSeries(t *testing.T) {
	// series 1..10
	series := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	got := percentiles(series, 50, 90, 99)
	// Linear-interpolation percentile: p50 -> rank .5*9=4.5 -> (5+6)/2=5.5
	if !approx(got[0], 5.5) {
		t.Errorf("p50 = %v, want 5.5", got[0])
	}
	// p90 -> rank .9*9=8.1 -> 9 + .1*(10-9)=9.1
	if math.Abs(got[1]-9.1) > 1e-9 {
		t.Errorf("p90 = %v, want 9.1", got[1])
	}
	// single element
	if got1 := percentiles([]float64{42}, 50); got1[0] != 42 {
		t.Errorf("single p50 = %v, want 42", got1[0])
	}
	// empty
	if gotE := percentiles(nil, 50); gotE[0] != 0 {
		t.Errorf("empty p50 = %v, want 0", gotE[0])
	}
}

func approx(a, b float64) bool { return math.Abs(a-b) < 1e-9 }
