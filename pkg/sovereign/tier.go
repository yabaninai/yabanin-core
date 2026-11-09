package sovereign

// Classify assigns a sovereignty tier to a model relative to a buyer's
// jurisdiction. Rules are deterministic and documented:
//
//  1. CN-flagged models are ALWAYS TierForeign, regardless of buyer. This is
//     the CN-off default (PB4.8) — even a CN buyer sees CN models as foreign
//     so the CNGuard defensive layer applies uniformly.
//  2. Self-hosted open-weights (weights_url set AND provider in
//     {vllm,ollama,tgi,llamacpp}) → TierOpenWeights. Highest practical sovereignty:
//     buyer physically controls inference.
//  3. Model country == buyer jurisdiction → TierFull.
//  4. Model jurisdiction in the same block as buyer (EU / GCC / ASEAN) →
//     TierFull (block-level parity).
//  5. Model vendor HQ == buyer jurisdiction → TierFull.
//  6. Otherwise → TierPartial (trusted-ish but not same-jurisdiction).
func Classify(m ModelMeta, buyerJurisdiction string) Tier {
	if m.CNFlagged {
		return TierForeign
	}
	if m.WeightsURL != "" && isSelfHostedProvider(m.Provider) {
		return TierOpenWeights
	}
	if m.Country == buyerJurisdiction {
		return TierFull
	}
	if sameBlock(m.Jurisdiction, buyerJurisdiction) {
		return TierFull
	}
	if m.VendorHQ == buyerJurisdiction {
		return TierFull
	}
	return TierPartial
}

func isSelfHostedProvider(p string) bool {
	switch p {
	case "vllm", "ollama", "tgi", "llamacpp":
		return true
	}
	return false
}

// sameBlock reports whether modelJuris and buyerJuris fall in the same
// regional jurisdiction block. Member sets are deliberately conservative.
func sameBlock(modelJuris, buyerJuris string) bool {
	blocks := [][]string{
		{"EU", "FR", "DE", "NL", "IE", "ES", "IT", "PT", "AT", "BE", "FI"},
		{"GCC", "AE", "SA", "QA", "BH", "KW", "OM"},
		{"ASEAN", "SG", "MY", "ID", "TH", "VN", "PH"},
	}
	for _, members := range blocks {
		if contains(members, modelJuris) && contains(members, buyerJuris) {
			return true
		}
	}
	return false
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
