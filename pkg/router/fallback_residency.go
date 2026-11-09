package router

import (
	"fmt"
	"strings"

	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/sovereign"
)

// Provider exclusion reasons for the fallback chain (N09-P05-T04 «Добавить
// объяснение причины исключения provider»): a candidate that the org's
// sovereignty policy excludes is NEVER dialed — not as the primary, and not
// as a failover hop after an outage of the preceding candidates — and every
// exclusion carries a machine-readable reason. This file is a pre-chain
// filter; it composes with (does not replace) the per-attempt policy gate:
// the executor still re-gates every candidate it dials, so a stale filter
// can never widen what the policy allows.

// CandidateMeta resolves the sovereignty-relevant metadata for one fallback
// chain candidate (typically built from the tier pool's registry metadata via
// TierMetaLookup). ok=false means the metadata was not resolvable — the
// filter records that candidate explicitly (fail-closed under a restrictive
// policy, kept-and-marked under a permissive one), it never guesses.
type CandidateMeta func(info resolver.ModelInfo) (sovereign.ModelMeta, bool)

// TierMetaLookup builds a CandidateMeta from the tier pool's registry
// metadata (router.ModelInfo → sovereign.ModelMeta via ToModelMeta), keyed
// by registry model name. Candidates whose name has no metadata entry
// resolve as ok=false. The returned lookup is a pure map read and safe for
// concurrent use.
func TierMetaLookup(models []ModelInfo) CandidateMeta {
	byName := make(map[string]sovereign.ModelMeta, len(models))
	for _, m := range models {
		byName[m.Name] = m.ToModelMeta()
	}
	return func(info resolver.ModelInfo) (sovereign.ModelMeta, bool) {
		mm, ok := byName[info.ModelName]
		return mm, ok
	}
}

// ExcludedCandidate records one fallback-chain candidate excluded BEFORE any
// attempt, with the reason it was excluded (N09-P05-T04). Region is the
// resolver-level jurisdiction label of the candidate ("" when unset); Denial
// carries the model/provider identity and the matched exclusion reason.
type ExcludedCandidate struct {
	Region string
	Denial sovereign.ProviderDenial
}

// FilteredChain is the outcome of applying the org's sovereignty policy to a
// resolved fallback chain.
//
// Invariants:
//   - Chain is the policy-permitted subsequence of the input chain, relative
//     order preserved — an excluded candidate can never be re-admitted by a
//     later failure of the kept candidates (N09-P05 acceptance: a denied
//     provider is not used even when the primary route is down).
//   - Excluded lists every dropped candidate in input order with its
//     exclusion reason — the refusal is explainable per provider.
//   - MetaUnknown lists candidates whose sovereignty metadata was
//     unavailable but that were kept because the policy is permissive
//     (nothing to violate). Under a restrictive policy such candidates are
//     fail-closed exclusions (reason meta_unknown) and appear in Excluded
//     instead — unknown posture must not silently route.
//   - Filtering is read-only: no metrics, no breaker state, no attempt
//     side effects. Policy enforcement at dial time stays with the caller's
//     per-attempt gate.
type FilteredChain struct {
	Chain       []resolver.ModelInfo
	Excluded    []ExcludedCandidate
	MetaUnknown []string
}

// restrictivePolicy reports whether the policy is able to deny ANY
// candidate: CN models disallowed (that includes DefaultPolicy — CN-off is
// the default posture and cannot confirm an unknown candidate is not
// CN-flagged), any org-wide country exclusion, or a required tier above
// foreign. Only a restrictive policy fail-closes on unknown metadata — a
// fully permissive policy (CN allowed, no exclusions, foreign floor) has
// nothing the unknown posture could hide, so the candidate is kept and
// marked instead of dropped.
func restrictivePolicy(pol sovereign.Policy) bool {
	if !pol.CNAllowed {
		return true
	}
	if len(pol.ExcludedCountries) > 0 {
		return true
	}
	return sovereign.Rank(pol.RequiredTier) > sovereign.Rank(sovereign.TierForeign)
}

// FilterChainByPolicy applies the org's sovereignty policy to a resolved
// fallback chain and returns the permitted subsequence plus per-candidate
// exclusion records (N09-P05-T04).
//
// A nil meta function cannot evaluate the policy and returns the chain
// unchanged with nothing excluded — policy enforcement then stays entirely
// with the caller's per-attempt gate. This degenerate case is explicit (not
// a silent deny-all) so wiring the filter without metadata cannot strand
// legacy chains; callers that hold registry metadata should always pass a
// lookup (TierMetaLookup).
func FilterChainByPolicy(pol sovereign.Policy, chain []resolver.ModelInfo, meta CandidateMeta) FilteredChain {
	out := FilteredChain{Chain: make([]resolver.ModelInfo, 0, len(chain))}
	if meta == nil {
		out.Chain = append(out.Chain, chain...)
		return out
	}
	restrictive := restrictivePolicy(pol)
	for _, info := range chain {
		mm, ok := meta(info)
		if !ok {
			if restrictive {
				// Fail closed: a restrictive policy plus unknown posture may
				// hide a violation — drop the candidate with an explicit
				// meta_unknown exclusion, never dial it speculatively.
				out.Excluded = append(out.Excluded, ExcludedCandidate{
					Region: info.Region,
					Denial: sovereign.ProviderDenial{
						ModelName: info.ModelName,
						Provider:  info.Provider,
						Reason:    sovereign.DenialProviderMetaUnknown,
					},
				})
				continue
			}
			out.Chain = append(out.Chain, info)
			out.MetaUnknown = append(out.MetaUnknown, info.ModelName)
			continue
		}
		if allowed, denial := pol.AllowsExplain(mm); !allowed {
			// The tier-pool metadata carries no provider name; the chain
			// candidate does. Enrich the record so every exclusion is
			// attributable to a provider (N09-P05-T04).
			if denial.Provider == "" {
				denial.Provider = info.Provider
			}
			out.Excluded = append(out.Excluded, ExcludedCandidate{Region: info.Region, Denial: denial})
			continue
		}
		out.Chain = append(out.Chain, info)
	}
	return out
}

// Err returns *ErrNoPermittedProvider when the filter left no permitted
// candidate AND the reason is the policy (at least one exclusion). An empty
// INPUT chain yields no error here — an empty requested chain is the
// caller's shape, not a policy refusal.
func (fc FilteredChain) Err() error {
	if len(fc.Chain) > 0 || len(fc.Excluded) == 0 {
		return nil
	}
	return &ErrNoPermittedProvider{Excluded: fc.Excluded}
}

// ErrNoPermittedProvider reports that the org's sovereignty policy excluded
// every candidate of the fallback chain: the routing layer refuses the
// request instead of dialing a denied provider, and the error carries one
// reason per excluded candidate (model=provider/region/reason) so logs and
// admin surfaces can explain the refusal. The message always carries the
// residency disclosure — a country-scoped exclusion is a technical routing
// control, not a legal residency guarantee.
type ErrNoPermittedProvider struct {
	Excluded []ExcludedCandidate
}

func (e *ErrNoPermittedProvider) Error() string {
	excluded := "none"
	if len(e.Excluded) > 0 {
		parts := make([]string, 0, len(e.Excluded))
		for _, x := range e.Excluded {
			parts = append(parts, fmt.Sprintf("%s=%s/%s/%s",
				x.Denial.ModelName, x.Denial.Provider, x.Region, x.Denial.Reason))
		}
		excluded = strings.Join(parts, ",")
	}
	return fmt.Sprintf("router: no policy-permitted provider in fallback chain, excluded=[%s]: %s",
		excluded, sovereign.ResidencyDisclosure)
}
