// Package sovereign classifies models by data-residency posture and enforces
// per-org routing policy that constrains which jurisdictions may serve a
// given tenant. It is the policy layer on top of PB4.1 schema metadata.
package sovereign

// Tier classifies a model's sovereignty posture, ordered from weakest to
// strongest: foreign < partial < open_weights < full.
type Tier string

const (
	// TierForeign vendor HQ outside buyer's trusted jurisdictions.
	TierForeign Tier = "foreign"
	// TierPartial vendor HQ trusted, inference/data partially external.
	TierPartial Tier = "partial"
	// TierOpenWeights buyer self-hosts weights (Llama/Mistral via vLLM).
	TierOpenWeights Tier = "open_weights"
	// TierFull vendor HQ + inference + data inside trusted jurisdiction.
	TierFull Tier = "full"
)

// ModelMeta is the sovereignty-relevant subset of models_registry. Loaded by
// the resolver and passed to Policy.Allows for routing decisions (PB4.5).
type ModelMeta struct {
	ModelName    string
	Country      string
	Jurisdiction string
	Tier         Tier
	VendorHQ     string
	CNFlagged    bool
	WeightsURL   string
	Provider     string // canonical provider name ("sakana","vllm",...)
}

// Rank orders tiers weakest→strongest. Used by Policy.Allows to enforce a
// minimum acceptable tier.
func Rank(t Tier) int {
	switch t {
	case TierForeign:
		return 0
	case TierPartial:
		return 1
	case TierOpenWeights:
		return 2
	case TierFull:
		return 3
	}
	return 0
}
