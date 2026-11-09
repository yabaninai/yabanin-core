package lineage

import (
	"strings"
)

// Policy defines residency policy rules used by the gateway enforcement hook.
type Policy struct {
	// AllowedRegions lists jurisdictions where inference is permitted.
	AllowedRegions []string
	// BlockedCountries are hard-denied regions (e.g. DPDP blacklist).
	BlockedCountries []string
}

// IsRegionAllowed reports whether region is permitted by this policy.
func (p *Policy) IsRegionAllowed(region string) bool {
	for _, r := range p.BlockedCountries {
		if strings.EqualFold(r, region) {
			return false
		}
	}
	if len(p.AllowedRegions) == 0 {
		return true // no restrictions
	}
	for _, r := range p.AllowedRegions {
		if strings.EqualFold(r, region) {
			return true
		}
	}
	return false
}

// DefaultSGPolicy returns the Singapore PDPA+MAS policy.
func DefaultSGPolicy() *Policy {
	return &Policy{
		AllowedRegions:   []string{"SG", "EU"},
		BlockedCountries: nil,
	}
}

// DefaultINPolicy returns the India DPDP+RBI policy.
func DefaultINPolicy() *Policy {
	return &Policy{
		AllowedRegions:   []string{"IN", "SG"},
		BlockedCountries: []string{"CN"},
	}
}

// DefaultIDPolicy returns the Indonesia UU PDP policy.
func DefaultIDPolicy() *Policy {
	return &Policy{
		AllowedRegions:   []string{"ID", "SG"},
		BlockedCountries: nil,
	}
}
