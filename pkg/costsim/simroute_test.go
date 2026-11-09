package audit

import (
	"testing"

	"github.com/reireirei/yabanin/pkg/classifier"
)

// easyPrompt classifies as easy (contains "summarize", short, no code fence).
const easyPrompt = "Please summarize this text for me."

// hardPrompt classifies as hard (contains "debug").
const hardPrompt = "Please debug this failing function and explain why."

// mediumPrompt has no easy/hard keywords -> medium.
const mediumPrompt = "Tell me about the history of France in detail."

func TestSimRoute_ClassDistribution(t *testing.T) {
	recs := []Record{
		{Model: "gpt-4o", Provider: "openai", Prompt: easyPrompt, PromptTokens: 50, CompletionTokens: 5},
		{Model: "gpt-4o", Provider: "openai", Prompt: hardPrompt, PromptTokens: 50, CompletionTokens: 5},
		{Model: "gpt-4o", Provider: "openai", Prompt: mediumPrompt, PromptTokens: 50, CompletionTokens: 5},
	}
	res, err := SimulateRouting(recs, SimRouteOptions{})
	if err != nil {
		t.Fatalf("SimulateRouting: %v", err)
	}
	if res.ClassDistribution["easy"] != 1 || res.ClassDistribution["hard"] != 1 || res.ClassDistribution["medium"] != 1 {
		t.Errorf("ClassDistribution = %v, want easy/hard/medium each 1", res.ClassDistribution)
	}
	if res.ClassifierName != "rule_tier" {
		t.Errorf("ClassifierName = %q, want rule_tier", res.ClassifierName)
	}
}

func TestSimRoute_SavingOnlyWhenCheaper(t *testing.T) {
	// gpt-4o -> gpt-4o-mini is cheaper. 1M input tokens: orig 2.5, target 0.15.
	recs := []Record{
		{Model: "gpt-4o", Provider: "openai", Prompt: easyPrompt, PromptTokens: 1_000_000, CompletionTokens: 0},
	}
	res, err := SimulateRouting(recs, SimRouteOptions{})
	if err != nil {
		t.Fatalf("SimulateRouting: %v", err)
	}
	if res.RoutingOnly != 2.35 {
		t.Errorf("RoutingOnly = %v, want 2.35 (gpt-4o -> gpt-4o-mini exact input price delta)", res.RoutingOnly)
	}
	if res.RoutedCount != 1 {
		t.Errorf("RoutedCount = %d, want 1", res.RoutedCount)
	}
}

func TestSimRoute_UnknownSourceIsUnpricedNotZero(t *testing.T) {
	recs := []Record{
		{Model: "private-unknown-model", Provider: "openai", Prompt: easyPrompt, PromptTokens: 1_000_000},
	}
	res, err := SimulateRouting(recs, SimRouteOptions{})
	if err != nil {
		t.Fatalf("SimulateRouting: %v", err)
	}
	if res.RoutingOnly != 0 {
		t.Errorf("RoutingOnly = %v, unknown source must not be treated as zero-cost", res.RoutingOnly)
	}
	if res.UnpricedDropped != 1 {
		t.Errorf("UnpricedDropped = %d, want 1 for QuoteUnknown semantics", res.UnpricedDropped)
	}
}

func TestSimRoute_NoSavingWhenAlreadyTarget(t *testing.T) {
	// If the request is already on the cheap model, routing to it is no change.
	recs := []Record{
		{Model: "gpt-4o-mini", Provider: "openai", Prompt: easyPrompt, PromptTokens: 1_000_000, CompletionTokens: 0},
	}
	res, _ := SimulateRouting(recs, SimRouteOptions{})
	if res.RoutingOnly != 0 || res.RoutedCount != 0 {
		t.Errorf("already-on-target should yield no saving, got %+v", res)
	}
}

func TestSimRoute_NoNegativeSavings(t *testing.T) {
	// Route easy (cheap) -> a more expensive model: must NOT claim a saving.
	custom := map[string]string{"easy": "gpt-4o", "medium": "gpt-4o", "hard": ""}
	recs := []Record{
		{Model: "gpt-4o-mini", Provider: "openai", Prompt: easyPrompt, PromptTokens: 1_000_000, CompletionTokens: 0},
	}
	res, _ := SimulateRouting(recs, SimRouteOptions{TierMap: custom})
	if res.RoutingOnly != 0 {
		t.Errorf("routing to a more expensive model must not yield savings, got %v", res.RoutingOnly)
	}
}

func TestSimRoute_UnpricedTargetDropped(t *testing.T) {
	// Target model with no price -> no saving, counted as unpriced drop.
	custom := map[string]string{"easy": "totally-unknown-model", "medium": "totally-unknown-model", "hard": ""}
	recs := []Record{
		{Model: "gpt-4o", Provider: "openai", Prompt: easyPrompt, PromptTokens: 1_000_000, CompletionTokens: 0},
	}
	res, _ := SimulateRouting(recs, SimRouteOptions{TierMap: custom})
	if res.RoutingOnly != 0 {
		t.Errorf("unpriced target must not yield savings, got %v", res.RoutingOnly)
	}
	if res.UnpricedDropped != 1 {
		t.Errorf("UnpricedDropped = %d, want 1", res.UnpricedDropped)
	}
}

func TestComputeCombined_ArithmeticIdentity(t *testing.T) {
	// combined == cache + routing-on-misses, and overlap == routing-all - routing-misses.
	cacheRes := SimCacheResult{DollarsAvoided: 10.0}
	routingAll := SimRouteResult{RoutingOnly: 30.0}
	routingMisses := SimRouteResult{RoutingOnMisses: 20.0}
	comb := ComputeCombined(cacheRes, routingAll, routingMisses)
	if comb.CacheOnly != 10.0 {
		t.Errorf("CacheOnly = %v, want 10", comb.CacheOnly)
	}
	if comb.RoutingOnly != 30.0 {
		t.Errorf("RoutingOnly = %v, want 30", comb.RoutingOnly)
	}
	if comb.Combined != 30.0 { // 10 cache + 20 routing-on-misses
		t.Errorf("Combined = %v, want 30 (10 + 20)", comb.Combined)
	}
	if comb.Overlap != 10.0 { // 30 - 20
		t.Errorf("Overlap = %v, want 10 (30 - 20)", comb.Overlap)
	}
}

func TestParseTierMap(t *testing.T) {
	m, err := ParseTierMap([]string{"easy=gpt-4o-mini", "medium=claude-3-5-haiku-latest", "hard="})
	if err != nil {
		t.Fatalf("ParseTierMap: %v", err)
	}
	if m["easy"] != "gpt-4o-mini" || m["medium"] != "claude-3-5-haiku-latest" || m["hard"] != "" {
		t.Errorf("tier map = %v", m)
	}
}

func TestParseTierMap_RejectsMalformed(t *testing.T) {
	// Note: "easy=" (empty model) is VALID — it means "keep original". Only
	// missing '=', empty class, or unknown class are rejected.
	for _, bad := range []string{"easy", "=gpt-4o", "bogus=gpt-4o"} {
		if _, err := ParseTierMap([]string{bad}); err == nil {
			t.Errorf("ParseTierMap(%q) should error", bad)
		}
	}
}

func TestSimRoute_CombinedEndToEnd(t *testing.T) {
	// Two identical easy prompts: cache hits the second, so routing applies to
	// the first (a miss) only in combined.
	recs := []Record{
		{Model: "gpt-4o", Provider: "openai", Prompt: easyPrompt, PromptTokens: 1_000_000, CompletionTokens: 0},
		{Model: "gpt-4o", Provider: "openai", Prompt: easyPrompt, PromptTokens: 1_000_000, CompletionTokens: 0},
	}
	cacheRes, hitSet, err := SimulateCacheWithHits(recs, SimCacheOptions{Mode: ModeExact})
	if err != nil {
		t.Fatalf("SimulateCache: %v", err)
	}
	routingAll, _ := SimulateRouting(recs, SimRouteOptions{})
	routingMisses, _ := SimulateRoutingOnMisses(recs, SimRouteOptions{}, hitSet)
	comb := ComputeCombined(cacheRes, routingAll, routingMisses)
	// The identity must hold: combined == cache + routing-on-misses.
	if comb.Combined != cacheRes.DollarsAvoided+routingMisses.RoutingOnMisses {
		t.Errorf("identity violated: combined=%v, cache+routing-misses=%v",
			comb.Combined, cacheRes.DollarsAvoided+routingMisses.RoutingOnMisses)
	}
	if routingMisses.RoutingOnMisses > routingAll.RoutingOnly {
		t.Errorf("routing-on-misses (%v) cannot exceed routing-all (%v)", routingMisses.RoutingOnMisses, routingAll.RoutingOnly)
	}
	_ = classifier.ClassMedium // keep the import used if unused elsewhere
}
