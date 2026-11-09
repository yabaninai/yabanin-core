// Package asiapacks contains concrete residency policy-packs for Asian
// jurisdictions (SG, IN, ID, JP). Each pack hard-codes the regulatory defaults;
// per-org overrides are loaded from the DB in PA.6.
package asiapacks

import "github.com/reireirei/yabanin/pkg/policy"

// regionAllowed reports whether r is in the allowed jurisdiction list.
func regionAllowed(r policy.Region, allowed []policy.Region) bool {
	return policy.RegionIn(r, allowed)
}

// familyAllowed reports whether f is in the allowed model-family list.
func familyAllowed(f string, allowed []string) bool {
	return policy.FamilyIn(f, allowed)
}

// blacklisted reports whether r is on the negative-list.
func blacklisted(r policy.Region, list []policy.Region) bool {
	return policy.RegionIn(r, list)
}
