package regionrouter

import (
	"context"
	"fmt"
	"log/slog"
	"sort"

	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/sovereign"
)

// PolicySource supplies the per-org sovereignty policy. *sovereign.PolicyStore
// satisfies it. Optional: without a source the evaluator keeps its previous
// behavior (failover filtered by health and pinning only).
type PolicySource interface {
	Get(ctx context.Context, orgID string) sovereign.Policy
}

// FailoverEvaluator decides whether to keep serving locally or redirect.
type FailoverEvaluator struct {
	router      *Router
	checker     *HealthChecker
	regions     config.RegionMap
	logger      *slog.Logger
	localRegion string
	// policySrc, when set, gates failover peers by the org's per-egress-kind
	// country profile (N09-P05-T02): a region whose country is denied for the
	// evaluator's egress kind is never chosen, even when it is the only
	// healthy peer — the org gets a 503 instead of a residency violation.
	policySrc  PolicySource
	egressKind sovereign.EgressKind
}

// NewFailoverEvaluator creates an evaluator for org-level failover decisions.
// Failover filtering defaults to the inference egress kind; attach a policy
// source via WithPolicySource to enable per-kind country filtering.
func NewFailoverEvaluator(router *Router, checker *HealthChecker, regions config.RegionMap, localRegion string, logger *slog.Logger) *FailoverEvaluator {
	return &FailoverEvaluator{
		router:      router,
		checker:     checker,
		regions:     regions,
		logger:      logger,
		localRegion: localRegion,
		egressKind:  sovereign.EgressInference,
	}
}

// WithPolicySource attaches the per-org sovereignty policy used to filter
// failover peers per egress kind. A nil source is ignored.
func (f *FailoverEvaluator) WithPolicySource(src PolicySource) *FailoverEvaluator {
	if src != nil {
		f.policySrc = src
	}
	return f
}

// WithEgressKind overrides the egress kind used for failover filtering
// (default inference — the request-serving path). Invalid kinds are ignored.
func (f *FailoverEvaluator) WithEgressKind(kind sovereign.EgressKind) *FailoverEvaluator {
	if kind.Valid() {
		f.egressKind = kind
	}
	return f
}

// Decide returns the action for an org request. Returns a PeerRedirect when
// failover is needed, or nil to serve locally.
func (f *FailoverEvaluator) Decide(ctx context.Context, orgID string) error {
	assign := f.router.Resolve(ctx, orgID)

	// If org is pinned to this region, always serve locally (even if degraded).
	if assign.HomeRegion == f.localRegion {
		return nil
	}

	// Non-pinned org: check if home region is healthy.
	healthy := f.checker.HealthyRegions(ctx)
	homeHealthy := false
	for _, r := range healthy {
		if r == assign.HomeRegion {
			homeHealthy = true
			break
		}
	}

	if !homeHealthy && !assign.ResidencyPinned {
		// Failover: route to next best healthy region, but never into a
		// region the org's egress policy denies (N09-P05 acceptance: a
		// denied region is not used even during a primary-route outage).
		pol := f.policyFor(ctx, orgID)
		best, denials := f.selectBestPeer(ctx, orgID, healthy, assign.HomeRegion, pol)
		if best != "" {
			if rc, ok := f.regions.Lookup(best); ok {
				return redirectError(best, rc.GatewayURL)
			}
		}
		if len(denials) > 0 {
			// Every healthy peer was policy-denied: refuse with the
			// per-region exclusion reasons (N09-P05-T04) instead of a bare
			// count — the 503 must be explainable per denied peer.
			return &ErrFailoverPeersDenied{
				OrgID:  orgID,
				Home:   assign.HomeRegion,
				Kind:   f.egressKind,
				Denied: denials,
			}
		}
		if !f.egressKind.Valid() {
			// Defensive (unreachable via the constructors, which pin a valid
			// kind): the fail-closed blanket denial keeps its historical
			// count-shaped message.
			return fmt.Errorf("regionrouter: failover peers for home region %s denied by egress policy (org=%s kind=%s denied=%d)",
				assign.HomeRegion, orgID, f.egressKind, len(healthy))
		}
		// No peer available — 503.
		return fmt.Errorf("regionrouter: no healthy peer for home region %s", assign.HomeRegion)
	}

	if assign.ResidencyPinned && !homeHealthy {
		return fmt.Errorf("regionrouter: pinned org cannot failover from down region %s", assign.HomeRegion)
	}

	return nil
}

// policyFor resolves the org policy; without a source (or for unknown orgs)
// the default policy applies no additional egress constraints.
func (f *FailoverEvaluator) policyFor(ctx context.Context, orgID string) sovereign.Policy {
	if f.policySrc == nil || orgID == "" {
		return sovereign.DefaultPolicy()
	}
	return f.policySrc.Get(ctx, orgID)
}

// redirectError composes the surfaced redirect decision for a country-bound
// endpoint. The non-legal-guarantee disclosure is part of the format
// itself (N09-P05 negative criterion): no caller — even one that skips
// gateway-side sanitization — can present the endpoint as a residency
// guarantee.
func redirectError(region, gatewayURL string) error {
	return fmt.Errorf("regionrouter: redirect to %s (%s) [%s]", region, gatewayURL, ResidencyDisclosure)
}

// selectBestPeer picks the lowest-priority healthy peer that the org's
// per-egress-kind country profile permits. It returns the chosen region (or
// "") and one EgressDenial record per policy-denied candidate — each denial
// is counted in residency_egress_denied_total, logged with its rule, and
// carried back so the refusal is explainable per peer (N09-P05-T04). The
// kind is consulted through its routing class (DataClassForKind), so
// single-kind classes enforce exactly that kind's profile.
func (f *FailoverEvaluator) selectBestPeer(ctx context.Context, orgID string, healthy []string, exclude string, pol sovereign.Policy) (string, []EgressDenial) {
	class, ok := DataClassForKind(f.egressKind)
	if !ok {
		// Constructor guarantees a valid kind; an invalid one must not open
		// a policy bypass — deny every peer (fail-closed). No per-peer
		// records here (there is no kind to name a rule with); Decide keeps
		// the historical blanket message for this defensive branch.
		if f.logger != nil {
			f.logger.Warn("failover disabled: invalid egress kind", "org_id", orgID, "kind", string(f.egressKind))
		}
		return "", nil
	}
	// Filter out the excluded home region and pick lowest-priority healthy peer.
	type candidate struct {
		name     string
		priority int
	}
	var cands []candidate
	var denials []EgressDenial
	for _, r := range healthy {
		if r == exclude {
			continue
		}
		rc, ok := f.regions.Lookup(r)
		if !ok {
			continue
		}
		if allowed, kind, reason := CheckClass(pol, class, rc.Country); !allowed {
			denials = append(denials, EgressDenial{
				Region: r, Country: rc.Country, Kind: kind, Rule: reason,
			})
			metrics.ResidencyEgressDeniedTotal.WithLabelValues(
				string(kind), countryLabel(rc.Country), string(reason)).Inc()
			if f.logger != nil {
				f.logger.Warn("failover peer denied by residency policy",
					"org_id", orgID, "region", r, "country", rc.Country,
					"kind", string(kind), "rule", string(reason))
			}
			continue
		}
		cands = append(cands, candidate{name: r, priority: rc.Priority})
	}
	if len(cands) == 0 {
		return "", denials
	}
	best := cands[0]
	for _, c := range cands[1:] {
		if c.priority < best.priority || (c.priority == best.priority && c.name < best.name) {
			best = c
		}
	}
	return best.name, denials
}

// AllowsClass reports whether `region` may carry the org's data of the
// given class under the org's egress policy (embeddings, logs, tools,
// detectors, ... — unlike Decide, this also covers non-inference serving
// and export surfaces, and it evaluates LOCAL regions too). The returned
// denial explains a negative answer; on allow, Kind and Rule are empty.
// An invalid class denies with empty kind/rule (fail-closed).
func (f *FailoverEvaluator) AllowsClass(ctx context.Context, orgID string, class DataClass, region string) (bool, EgressDenial) {
	return allowsClassRegion(f.policyFor(ctx, orgID), class, region, f.regions)
}

// allowsClassRegion is the policy-only region permission check.
func allowsClassRegion(pol sovereign.Policy, class DataClass, region string, regions config.RegionMap) (bool, EgressDenial) {
	country := ""
	if rc, ok := regions.Lookup(region); ok {
		country = rc.Country
	}
	if allowed, kind, reason := CheckClass(pol, class, country); !allowed {
		return false, EgressDenial{Region: region, Country: country, Kind: kind, Rule: reason}
	}
	return true, EgressDenial{Region: region, Country: country}
}

// PlanFailoverChain resolves the full residency-safe fallback chain for the
// org and data class (N09-P05-T03: routing accounts for detectors,
// embeddings, logs, tools and fallbacks). The plan lists the home region
// (policy permission only) and every healthy peer the policy permits,
// priority-ordered; peers denied by policy are recorded with their rule and
// excluded from the ENTIRE chain regardless of health — a denied region is
// never used, not even as the Nth fallback during a primary-route outage.
// Pinned orgs never fail over (empty Fallbacks). Planning is read-only:
// denial counters increment on the serving decision path (Decide), not here.
func (f *FailoverEvaluator) PlanFailoverChain(ctx context.Context, orgID string, class DataClass) FallbackPlan {
	plan := FallbackPlan{OrgID: orgID, Class: class}
	if !class.Valid() {
		// Fail-closed: an unknown data class yields an empty (denying)
		// plan — Err() explains instead of opening a policy bypass.
		return plan
	}

	assign := f.router.Resolve(ctx, orgID)
	plan.Home = assign.HomeRegion
	pol := f.policyFor(ctx, orgID)
	if rc, ok := f.regions.Lookup(assign.HomeRegion); ok {
		plan.HomeCountry = rc.Country
	}
	allowed, denial := allowsClassRegion(pol, class, assign.HomeRegion, f.regions)
	plan.HomeAllowed = allowed
	if !allowed {
		d := denial
		plan.HomeDenial = &d
	}

	if assign.ResidencyPinned {
		// Pinned orgs never fail over (Router contract): the chain is the
		// home region only; peers are not even consulted.
		return plan
	}

	var healthy []string
	if f.checker != nil {
		healthy = f.checker.HealthyRegions(ctx)
	}
	var hops []FallbackHop
	for _, r := range healthy {
		if r == assign.HomeRegion {
			continue
		}
		rc, ok := f.regions.Lookup(r)
		if !ok {
			continue
		}
		if allowed, kind, reason := CheckClass(pol, class, rc.Country); !allowed {
			plan.Denied = append(plan.Denied, EgressDenial{
				Region: r, Country: rc.Country, Kind: kind, Rule: reason,
			})
			continue
		}
		hops = append(hops, FallbackHop{
			Region: r, Country: rc.Country, GatewayURL: rc.GatewayURL, Priority: rc.Priority,
		})
	}
	sort.Slice(hops, func(i, j int) bool {
		if hops[i].Priority != hops[j].Priority {
			return hops[i].Priority < hops[j].Priority
		}
		return hops[i].Region < hops[j].Region
	})
	plan.Fallbacks = hops
	sortDenialsByRegion(plan.Denied)
	return plan
}
