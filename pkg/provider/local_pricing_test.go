package provider

// N08-P04-T04 «Локальные модели: offline pricing»: pricing data is
// offline-only (embedded snapshot, zero network) and a local/self-hosted
// runtime has no per-token cloud price. These tests pin the deterministic
// fallback contract:
//
//   - a local runtime provider (vllm/ollama/llamacpp/tgi) is NEVER priced
//     from any table — not even when a snapshot row collides under a local
//     provider key; the result is fail-closed (PriceKnown=false, exactly
//     zero cost: unknown, not free);
//   - cloud models keep pricing normally (the guard must not leak);
//   - a model absent from the offline data gets the identical fail-closed
//     answer on every call (deterministic, no network, no invention);
//   - the predicate follows discovery exactly (trimmed canonical names;
//     wrong-case names are not local runtimes — those rows cannot render
//     as installed/working either, see local_discovery tests).
//
// The global default pricer is swapped per the azure_openai_test.go
// precedent and restored via t.Cleanup; these tests stay sequential (no
// t.Parallel) because the pricer is process-global.

import (
	"reflect"
	"testing"

	"github.com/reireirei/yabanin/pkg/pricing"
)

// mapPricer is a stub table simulating offline pricing data that (against
// all hygiene) carries rows under local runtime provider keys and a cloud
// row — the collision case the guard must refuse.
type mapPricer map[string]pricing.Price

func (m mapPricer) Lookup(providerName, model string) (pricing.Price, bool) {
	p, ok := m[providerName+":"+model]
	return p, ok
}

func localPricingStub() mapPricer {
	return mapPricer{
		"ollama:llama3":       {InputPerM: 5, OutputPerM: 15},
		"llamacpp:local-qwen": {InputPerM: 5, OutputPerM: 15},
		"vllm:vllm-model":     {InputPerM: 5, OutputPerM: 15},
		"tgi:tgi-model":       {InputPerM: 5, OutputPerM: 15},
		"openai:gpt-4o":       {InputPerM: 2.5, OutputPerM: 10},
		"LLamaCpp:wrongcased": {InputPerM: 5, OutputPerM: 15},
	}
}

func localPricingUsage() Usage {
	return Usage{PromptTokens: 1_000_000, CompletionTokens: 500_000, TotalTokens: 1_500_000}
}

func TestLocalPricing_LocalRuntimeCollisionNeverPriced(t *testing.T) {
	pricing.SetDefaultPricer(localPricingStub())
	t.Cleanup(func() { pricing.SetDefaultPricer(pricing.StaticPricer()) })

	for _, providerName := range LocalRuntimeProviders() {
		model := providerName + "-model"
		if providerName == "ollama" {
			model = "llama3"
		}
		if providerName == "llamacpp" {
			model = "local-qwen"
		}
		ext := ComputeCost(localPricingUsage(), providerName, model)
		if ext.PriceKnown {
			t.Fatalf("%s:%s must not be priced from a table row under a local provider key (invented cloud price), got %+v",
				providerName, model, ext)
		}
		if ext.EstimatedCostUSD != 0 {
			t.Fatalf("%s:%s cost must be exactly zero when pricing is unknown, got %v",
				providerName, model, ext.EstimatedCostUSD)
		}
		if ext.ProviderName != providerName || ext.ModelName != model {
			t.Fatalf("ComputeCost must preserve the (provider, model) context, got %q/%q",
				ext.ProviderName, ext.ModelName)
		}
	}

	// Boundary: surrounding whitespace is tolerated by the shared discovery
	// predicate (trimmed canonical name), so the guard fires for it too.
	trimmed := ComputeCost(localPricingUsage(), "  ollama  ", "llama3")
	if trimmed.PriceKnown || trimmed.EstimatedCostUSD != 0 {
		t.Fatalf("a whitespace-padded local provider name must hit the same offline guard, got %+v", trimmed)
	}
}

func TestLocalPricing_CloudModelStillPricedUnderSameStub(t *testing.T) {
	pricing.SetDefaultPricer(localPricingStub())
	t.Cleanup(func() { pricing.SetDefaultPricer(pricing.StaticPricer()) })

	ext := ComputeCost(localPricingUsage(), "openai", "gpt-4o")
	if !ext.PriceKnown {
		t.Fatal("the guard must not leak: a cloud model under a cloud provider key stays priced")
	}
	// 1M input @ $2.5/M + 0.5M output @ $10/M
	if ext.EstimatedCostUSD != 2.5+5.0 {
		t.Fatalf("cloud cost formula changed: got %v, want %v", ext.EstimatedCostUSD, 2.5+5.0)
	}
}

func TestLocalPricing_AbsentModelFailClosedDeterministic(t *testing.T) {
	// Default pricer (static table + embedded offline snapshot): the model
	// is absent from every offline source. No network fetch exists on this
	// path at all; the answer must be identical on every call.
	first := ComputeCost(localPricingUsage(), "openai", "no-such-model-anywhere")
	second := ComputeCost(localPricingUsage(), "openai", "no-such-model-anywhere")

	if first.PriceKnown || second.PriceKnown {
		t.Fatal("an absent model must fail closed: unknown, never invented")
	}
	if first.EstimatedCostUSD != 0 || second.EstimatedCostUSD != 0 {
		t.Fatalf("absent model cost must be zero-with-known-flag-false, got %v / %v",
			first.EstimatedCostUSD, second.EstimatedCostUSD)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("offline fallback must be deterministic (identical answers), got %+v vs %+v", first, second)
	}
}

func TestLocalPricing_CaseBoundaryFollowsDiscovery(t *testing.T) {
	pricing.SetDefaultPricer(localPricingStub())
	t.Cleanup(func() { pricing.SetDefaultPricer(pricing.StaticPricer()) })

	// "LLamaCpp" is NOT a canonical local runtime name — discovery refuses
	// such a row as not-installed, so the pricing guard must not treat it
	// as local either: the two predicates share one table and one rule.
	ext := ComputeCost(localPricingUsage(), "LLamaCpp", "wrongcased")
	if !ext.PriceKnown {
		t.Fatal("non-canonical provider names are not local runtimes (discovery-consistent): the stub row under that name prices normally")
	}
}
