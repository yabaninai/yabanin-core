package sovereign

import (
	"fmt"
	"strings"
)

// EgressKind classifies the data category that crosses (or risks crossing) a
// jurisdictional boundary. N09-P05-T02 binds a country profile to EACH kind:
// model inference, embeddings, logs, export and tool results carry their own
// residency constraints, because the same org may lawfully serve inference
// from one country while its logs must never leave another. The set is
// closed; policy checks for an unknown kind resolve against org-wide rules
// only, so a newly added kind can never silently bypass those.
type EgressKind string

const (
	// EgressInference is prompt/completion traffic to a model endpoint.
	EgressInference EgressKind = "inference"
	// EgressEmbeddings is text/vector representation data sent to an
	// embedding endpoint or vector store.
	EgressEmbeddings EgressKind = "embeddings"
	// EgressLogs is request/response logging, tracing and audit data
	// shipped to (or retained in) another jurisdiction.
	EgressLogs EgressKind = "logs"
	// EgressExport is dataset/admin export out of the home region.
	EgressExport EgressKind = "export"
	// EgressTools is tool/MCP call payloads and results leaving the boundary.
	EgressTools EgressKind = "tools"
)

// EgressKinds is the closed, canonical set of egress kinds.
var EgressKinds = []EgressKind{EgressInference, EgressEmbeddings, EgressLogs, EgressExport, EgressTools}

// Valid reports whether k is one of the five defined egress kinds.
func (k EgressKind) Valid() bool {
	for _, v := range EgressKinds {
		if k == v {
			return true
		}
	}
	return false
}

// EgressProfile is the per-kind country profile. Its rules compose with the
// org-wide Policy.ExcludedCountries, which always apply on top.
type EgressProfile struct {
	// AllowedCountries restricts the kind to these countries. Empty means no
	// allowlist; org-wide rules still apply. Comparison is case-insensitive.
	AllowedCountries []string
	// ExcludedCountries hard-denies these countries for this kind. It wins
	// over the allowlist and over any broader permission (fail-closed).
	ExcludedCountries []string
}

// DenialReason explains why an egress was denied. N09-P05 requires the
// exclusion reason to be explainable, never a bare refusal.
type DenialReason string

const (
	// DenialKindExcluded — country is on the per-kind exclusion list.
	DenialKindExcluded DenialReason = "kind_excluded"
	// DenialKindNotAllowed — the kind has an allowlist and the country is
	// not on it.
	DenialKindNotAllowed DenialReason = "kind_not_allowed"
	// DenialOrgExcluded — country is on the org-wide exclusion list.
	DenialOrgExcluded DenialReason = "org_excluded"
)

// CheckEgress evaluates whether data of kind `kind` may go to `country`
// under the policy. Returns ok=true, or ok=false with the structured reason.
// Resolution order (first match wins):
//
//  1. per-kind profile ExcludedCountries → DenialKindExcluded
//  2. per-kind profile non-empty AllowedCountries without country → DenialKindNotAllowed
//  3. org-wide ExcludedCountries → DenialOrgExcluded
//  4. allow
//
// The check is fail-closed for allowlisted kinds: an empty/unknown country
// never satisfies a non-empty allowlist. Country codes are normalized
// (trim + upper) before comparison. Unknown kinds have no per-kind profile
// by construction and resolve against org-wide rules only; callers must
// pass EgressKind constants.
func (p Policy) CheckEgress(kind EgressKind, country string) (bool, DenialReason) {
	c := normalizeCountry(country)
	if prof, ok := p.Egress[kind]; ok {
		if containsCountry(prof.ExcludedCountries, c) {
			return false, DenialKindExcluded
		}
		if len(prof.AllowedCountries) > 0 && !containsCountry(prof.AllowedCountries, c) {
			return false, DenialKindNotAllowed
		}
	}
	if containsCountry(p.ExcludedCountries, c) {
		return false, DenialOrgExcluded
	}
	return true, ""
}

// AllowsEgress is the boolean convenience form of CheckEgress.
func (p Policy) AllowsEgress(kind EgressKind, country string) bool {
	ok, _ := p.CheckEgress(kind, country)
	return ok
}

// normalizeCountry canonicalizes a country code: trim + uppercase. An empty
// input stays empty (and can therefore never match an allowlist entry).
func normalizeCountry(c string) string {
	return strings.ToUpper(strings.TrimSpace(c))
}

// containsCountry reports whether the normalized country is in the list.
// List entries are normalized the same way, so config casing is irrelevant.
func containsCountry(list []string, country string) bool {
	for _, c := range list {
		if normalizeCountry(c) == country {
			return true
		}
	}
	return false
}

// ErrEgressDenied carries the structured exclusion reason so logs, alerts
// and admin surfaces can explain WHY a region was not used, satisfying the
// N09-P05 facet "explanation of the exclusion reason".
type ErrEgressDenied struct {
	OrgID   string
	Kind    EgressKind
	Country string
	Rule    DenialReason
}

func (e ErrEgressDenied) Error() string {
	return fmt.Sprintf("egress denied for org %s: kind=%s country=%s rule=%s",
		e.OrgID, e.Kind, e.Country, e.Rule)
}
