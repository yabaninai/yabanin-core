package sovereign

import "testing"

func TestClassify_CNFlagged_AlwaysForeign(t *testing.T) {
	m := ModelMeta{Country: "JP", CNFlagged: true, Provider: "sakana"}
	if got := Classify(m, "JP"); got != TierForeign {
		t.Fatalf("CN-flagged must be foreign even for CN buyer; got %s", got)
	}
}

func TestClassify_SelfHosted_OpenWeights(t *testing.T) {
	m := ModelMeta{Provider: "vllm", WeightsURL: "https://hf.co/llama", Country: "US"}
	if got := Classify(m, "FR"); got != TierOpenWeights {
		t.Fatalf("self-hosted open-weights must be open_weights; got %s", got)
	}
}

func TestClassify_SameCountry_Full(t *testing.T) {
	m := ModelMeta{Country: "JP", Provider: "sakana"}
	if got := Classify(m, "JP"); got != TierFull {
		t.Fatalf("same country -> full; got %s", got)
	}
}

func TestClassify_EUBlockCrossCountry_Full(t *testing.T) {
	m := ModelMeta{Country: "FR", Jurisdiction: "EU", Provider: "mistral"}
	if got := Classify(m, "DE"); got != TierFull {
		t.Fatalf("EU block cross-country -> full; got %s", got)
	}
}

func TestClassify_VendorHQMatch_Full(t *testing.T) {
	m := ModelMeta{Country: "US", VendorHQ: "FR", Provider: "x"}
	if got := Classify(m, "FR"); got != TierFull {
		t.Fatalf("vendor HQ match -> full; got %s", got)
	}
}

func TestClassify_Default_Partial(t *testing.T) {
	m := ModelMeta{Country: "BR", Jurisdiction: "BR", VendorHQ: "BR", Provider: "x"}
	if got := Classify(m, "JP"); got != TierPartial {
		t.Fatalf("no match -> partial; got %s", got)
	}
}

func TestClassify_OpenWeightsRequiresSelfHostedProvider(t *testing.T) {
	// weights_url set but provider NOT self-hosted -> NOT open_weights.
	m := ModelMeta{WeightsURL: "https://hf.co/x", Provider: "openai", Country: "US"}
	if got := Classify(m, "JP"); got == TierOpenWeights {
		t.Fatal("must not be open_weights when provider is not self-hosted")
	}
}
