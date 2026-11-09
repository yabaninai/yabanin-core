package sovereign

// N09-P01-T10 [risk] — rights/data verification for pkg/sovereign. Test-only
// card: zero production changes.
//
//	permissions — the CN refusal is independent of tier and metadata: forged
//	self-hosted metadata cannot re-classify a CN-flagged model out of
//	TierForeign, the lowest rank cannot be beaten by metadata, and the
//	two-layer defense (Allows + CNGuard) refuses in both layers;
//	data — one documented observation probe: Policy.Allows compares
//	exclusion-list entries exactly while CheckEgress normalizes case and
//	whitespace. Both sides of that comparison are admin-controlled
//	(org_sovereignty_policy row and model registry), so this is recorded as
//	a consistency observation for the policy-owner lane, not a defect claim.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestN09P1T10_Risk_CNGuardIndependentOfTierAndMetadata: a CN-flagged model
// stays TierForeign even when the registry metadata forges the strongest
// self-hosted posture (vllm + weights URL), and neither an org policy with
// the highest tier requirement nor the default tier can admit it through
// either defense layer.
func TestN09P1T10_Risk_CNGuardIndependentOfTierAndMetadata(t *testing.T) {
	t.Parallel()

	// Forged self-hosted open-weights metadata on a CN-flagged model: the
	// CN rule wins over the open-weights rule (rule order in Classify).
	forged := ModelMeta{
		ModelName:  "cn-model",
		Country:    "CN",
		CNFlagged:  true,
		Provider:   "vllm",
		WeightsURL: "https://hf.example/cn-model",
	}
	assert.Equal(t, TierForeign, Classify(forged, "CN"),
		"CN flag must dominate forged self-hosted metadata")

	// The same metadata WITHOUT the CN flag classifies as open-weights —
	// proving the flag, not the metadata shape, is what forces TierForeign.
	unflagged := forged
	unflagged.CNFlagged = false
	assert.Equal(t, TierOpenWeights, Classify(unflagged, "CN"))

	for _, policy := range []Policy{
		DefaultPolicy(), // TierForeign, CNAllowed=false: the org with no row
		{RequiredTier: TierOpenWeights, CNAllowed: false, BuyerJurisdiction: "CN"},
		{RequiredTier: TierForeign, CNAllowed: false, ExcludedCountries: nil},
	} {
		assert.False(t, policy.Allows(forged),
			"%+v must refuse a CN-flagged model", policy)
		require.Error(t, CNGuard(policy, forged),
			"CNGuard must refuse independently of Allows")
		var blocked ErrCNModelBlocked
		require.ErrorAs(t, CNGuard(policy, forged), &blocked)
		assert.Equal(t, "cn-model", blocked.Model)
	}

	// With explicit CN opt-in both layers pass — the refusal is the flag
	// rule, not accidental strictness.
	optIn := Policy{RequiredTier: TierForeign, CNAllowed: true}
	assert.True(t, optIn.Allows(forged))
	assert.NoError(t, CNGuard(optIn, forged))
}

// TestN09P1T10_Risk_AllowsExactCountryComparisonObservation: documents the
// current Allows() country comparison as exact-match (case- and
// whitespace-sensitive), in contrast to CheckEgress which normalizes. The
// registry and the policy row are both admin-controlled, so a casing drift
// between them is a configuration-consistency risk, not a caller-controlled
// bypass. Recorded here so the observation is reproducible; flagged in the
// card record for the policy-owner lane.
func TestN09P1T10_Risk_AllowsExactCountryComparisonObservation(t *testing.T) {
	t.Parallel()

	policy := Policy{
		RequiredTier:      TierForeign,
		ExcludedCountries: []string{"AU"},
	}

	// Exact match refuses the exact spelling.
	assert.False(t, policy.Allows(ModelMeta{ModelName: "m", Country: "AU"}))
	assert.False(t, policy.Allows(ModelMeta{ModelName: "m", VendorHQ: "AU"}))

	// Case drift on the registry side currently passes the org-wide
	// exclusion (CheckEgress would normalize this and refuse).
	assert.True(t, policy.Allows(ModelMeta{ModelName: "m", Country: "au"}),
		"observation: Allows is case-sensitive where CheckEgress normalizes")
	assert.True(t, policy.Allows(ModelMeta{ModelName: "m", VendorHQ: " au "}),
		"observation: Allows is whitespace-sensitive where CheckEgress normalizes")
}
