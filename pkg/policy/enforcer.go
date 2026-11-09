package policy

import (
	"context"
	"log/slog"
)

// RegionResolver returns the residency region for an org (cached upstream).
// Returning "" means the org is global (no enforcement).
type RegionResolver func(ctx context.Context, orgID string) Region

// ModelCandidate describes an in-region model usable for remap.
type ModelCandidate struct {
	Name   string
	Region Region
	Family string
}

// ModelPool returns candidate in-region models for remap when the requested
// model is denied. A nil-returning / nil pool simply means "no remap, deny".
type ModelPool interface {
	ModelsForRegion(ctx context.Context, region Region) []ModelCandidate
}

// Enforcer is invoked by the gateway per request to enforce residency policy.
//
// Semantics:
//   - org region == "" (global)         → free-pass Allowed.
//   - region has no registered pack     → FAIL-CLOSED (regulated region must
//     not silently bypass policy).
//   - pack denies                       → try remap to an in-region candidate;
//     if none, the deny stands.
type Enforcer struct {
	registry *Registry
	regionOf RegionResolver
	pool     ModelPool
	log      *slog.Logger
}

// NewEnforcer builds an Enforcer. pool may be nil (remap disabled, deny only).
func NewEnforcer(reg *Registry, rr RegionResolver, pool ModelPool, l *slog.Logger) *Enforcer {
	if l == nil {
		l = slog.Default()
	}
	return &Enforcer{registry: reg, regionOf: rr, pool: pool, log: l}
}

// Enforce evaluates residency for one request and returns a Decision.
func (e *Enforcer) Enforce(ctx context.Context, orgID, requestedModel string, modelRegion Region, family string) Decision {
	region := e.regionOf(ctx, orgID)
	if region == "" || region == RegionGlobal {
		return Decision{Allowed: true, Region: RegionGlobal, PackID: "none"}
	}

	pack := e.registry.Get(region)
	if pack == nil {
		// Regulated region without a pack → fail-closed.
		e.log.Warn("residency: regulated region has no pack (fail-closed)",
			"org_id", orgID, "region", region)
		return Decision{
			Allowed: false,
			Region:  region,
			PackID:  "missing",
			Reason:  "no policy pack registered for regulated region",
		}
	}

	dec := pack.Evaluate(ctx, EvalContext{
		OrgID:          orgID,
		ModelRequested: requestedModel,
		ModelRegion:    modelRegion,
		UpstreamFamily: family,
	}, nil) // override loading wired in PA.6; nil = defaults

	if !dec.Allowed && e.pool != nil {
		for _, c := range e.pool.ModelsForRegion(ctx, region) {
			trial := pack.Evaluate(ctx, EvalContext{
				OrgID:          orgID,
				ModelRequested: c.Name,
				ModelRegion:    c.Region,
				UpstreamFamily: c.Family,
			}, nil)
			if trial.Allowed {
				dec.Allowed = true
				dec.RemappedModel = c.Name
				dec.Reason = "remapped to in-region model"
				dec.Violations = nil
				return dec
			}
		}
	}
	return dec
}
