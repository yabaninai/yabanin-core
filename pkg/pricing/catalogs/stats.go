package catalogs

import (
	"strings"

	"github.com/reireirei/yabanin/pkg/pricing"
)

// ProvenanceClass is the honest-labeling class of a catalog entry: where
// its facts come from and how much trust a consumer may put in them.
// Classes never lie in either direction — derived data is never re-labeled
// as verified, and owner-verified data keeps its verification record.
type ProvenanceClass string

const (
	// ClassVerifiedPrimary means facts verified by the owner against a
	// primary provider source (dated console record, internal evidence ID).
	ClassVerifiedPrimary ProvenanceClass = "verified-primary"
	// ClassLiteLLMDerived means facts converted from the third-party
	// LiteLLM snapshot. Draft by construction; carries upstream attribution
	// (NOTICE-litellm.txt) and must never be presented as Yabanin-verified.
	ClassLiteLLMDerived ProvenanceClass = "litellm-derived"
	// ClassDraft means any other assembled-but-unverified entry.
	ClassDraft ProvenanceClass = "draft"
)

// litellmSourceMarker identifies the corpus's upstream snapshot inside a
// source ref (the pinned commit-scoped path of the bundled header).
const litellmSourceMarker = "github.com/BerriAI/litellm"

// ClassifyEntry reports the provenance class of one entry from its source
// records. Verified-primary wins over derived markers (an entry citing the
// owner-verified evidence record is verified even if other sources exist).
func ClassifyEntry(m pricing.RefModel) ProvenanceClass {
	verified := false
	derived := false
	for _, s := range m.Sources {
		if s.Kind == pricing.RefSourceInternalEvidence && strings.HasPrefix(s.Ref, NebiusEvidencePrefix) {
			verified = true
		}
		if strings.Contains(s.Ref, litellmSourceMarker) {
			derived = true
		}
	}
	switch {
	case verified:
		return ClassVerifiedPrimary
	case derived:
		return ClassLiteLLMDerived
	default:
		return ClassDraft
	}
}

// CoverageStats is the provenance/coverage accounting of one catalog: what
// it contains, where every entry's facts came from, and how many axes are
// priced versus explicitly unpriced. The release record pins these numbers;
// the pin test refuses a record that drifts from the artifact.
type CoverageStats struct {
	// TotalEntries is the number of catalog entries (all statuses).
	TotalEntries int
	// ActiveVerifiedPrimary is the count of active entries whose class is
	// verified-primary — the only entries eligible to price production
	// traffic under the preview policy.
	ActiveVerifiedPrimary int
	// Retired is the count of retired entries (never serveable).
	Retired int
	// DraftTotal is the count of draft entries (never serveable).
	DraftTotal int
	// DraftLitellmDerived is the count of draft entries converted from the
	// third-party corpus.
	DraftLitellmDerived int
	// DraftOther is the count of draft entries that are NOT litellm-derived.
	// A nonzero value here must be explained entry-by-entry in the release
	// record (unexpected provenance in the corpus).
	DraftOther int
	// PricedAxes is the count of rates carrying a verified amount.
	PricedAxes int
	// UnpricedAxes is the count of rates explicitly marked unpriced
	// (amount: null — known axis, no verified price; never treated as
	// free).
	UnpricedAxes int
	// Aliases is the total alias count across entries.
	Aliases int
}

// Coverage computes the provenance/coverage accounting of c.
func Coverage(c pricing.Catalog) CoverageStats {
	var s CoverageStats
	s.TotalEntries = len(c.Models)
	for i := range c.Models {
		m := &c.Models[i]
		s.Aliases += len(m.Aliases)
		switch m.Status {
		case pricing.RefStatusActive:
			if ClassifyEntry(*m) == ClassVerifiedPrimary {
				s.ActiveVerifiedPrimary++
			}
			// An active non-verified entry would be a provenance bug; it
			// counts nowhere and the release tests flag it via DraftOther's
			// sibling rule (activeVerifiedPrimary == 3 expected for v1).
		case pricing.RefStatusRetired:
			s.Retired++
		default: // draft (and anything else counts as not-serveable draft)
			s.DraftTotal++
			if ClassifyEntry(*m) == ClassLiteLLMDerived {
				s.DraftLitellmDerived++
			} else {
				s.DraftOther++
			}
		}
		for j := range m.Rates {
			if m.Rates[j].Amount == nil {
				s.UnpricedAxes++
			} else {
				s.PricedAxes++
			}
		}
	}
	return s
}
