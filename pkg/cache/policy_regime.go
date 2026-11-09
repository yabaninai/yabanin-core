package cache

import (
	"context"
	"strings"
)

// PolicyRegimeResolver returns a short, stable fingerprint of the tenant
// policy regime that currently governs an org's completions (N03-P02-T03:
// bind the cache identity to the tenant policy). Whenever the governing
// policy changes — a tighten included — the fingerprint must change, so warm
// entries stored under the earlier regime degrade to misses instead of being
// served.
//
// The fingerprint contract: an answer must be non-empty and must not contain
// the unit separator U+001F the identity composition joins on. "" answers
// "policy enforcement is off or unverifiable for this org"; a fingerprint
// carrying the separator could alias another regime's composed identity and
// is refused exactly like "". The cache validates every answer at the
// boundary — a resolver that cannot keep the contract silences the org's
// cache instead of storing or serving under an ambiguous identity.
//
// The resolver is optional infrastructure: with a nil resolver the cache
// keeps the plain RT-05 behavior of stands without a policy runtime (no
// gating, no tagging).
//
// N03-P02-T04: once armed, an empty fingerprint answers "policy enforcement
// is off or unverifiable for this org" — the runtime is unwired,
// cold-unavailable, runs with policy mode off, or no snapshot could be
// loaded. The cache then performs NO lookup and NO write for the org at all
// (enforcement-off is preserved without reads and writes, not "read and
// filter"): a lookup degrades to a miss before any cache layer is touched,
// and a write stores nothing on any layer or queue. Every gated operation is
// counted in CacheEnforcementOffSkippedTotal so the silenced traffic stays
// distinguishable from organic misses in the metrics (N03-P02-T05). This
// closes the bypass window where an untagged entry written while off could later be served by
// a lookup whose regime resolution transiently failed — a replay with no
// re-governance at all.
type PolicyRegimeResolver func(ctx context.Context, orgID string) string

const (
	// policyRegimeTag joins the regime fingerprint onto existing generation
	// parameters. The composition stays unambiguous because neither side of
	// the join can carry the unit separator (\x1f): the gateway composes
	// GenParams from the effort values ("low"/"medium"/"high"), and the
	// resolver's fingerprint is validated separator-free before joining
	// (validRegimeFingerprint).
	policyRegimeTag  = "\x1fpolreg:"
	policyRegimeBare = "polreg:"
)

// SetPolicyRegimeResolver arms regime-bound cache identity for this service.
// Wire once at startup, before the service serves traffic; passing nil
// disarms the binding (plain RT-05 identity, cache fully active). Once
// armed, an empty fingerprint silences the cache for that org entirely —
// no lookups, no writes. The same explicit refusal covers an org-less
// operation (no tenant the cache could resolve a governing regime for) and
// a fingerprint that breaks the composition contract.
func (cs *CacheService) SetPolicyRegimeResolver(resolve PolicyRegimeResolver) {
	cs.regime = resolve
}

// regimeResolve resolves the org's tenant-policy regime ONCE for one cache
// operation. It returns the identity to operate under and whether the
// operation is refused: an armed resolver answering outside the fingerprint
// contract means the operation cannot be governed — enforcement is off or
// unverifiable for the org, the identity names no org to resolve a regime
// for, or the fingerprint could alias another regime's identity — and the
// caller must skip the operation entirely: no cache lookup, no write on any
// layer or queue. Every refusal ticks CacheEnforcementOffSkippedTotal.
//
// A nil resolver (binding disarmed) keeps the plain pre-binding behavior:
// the operation proceeds under the unmodified RT-05 identity, whatever org
// it carries. This is the old-configuration compatibility surface — a stand
// without a policy runtime never consults the gate at all.
//
// With the binding armed, the gate decides BEFORE consulting the resolver
// that the operation is governable at all: an org-less identity names no
// tenant whose policy could govern the replay, so it is refused without a
// resolver round-trip instead of passing ungoverned. The gateway refuses an
// org-less chat request before the cache is reached; the refusal here is the
// boundary's own defense so a future caller cannot reintroduce an ungoverned
// lookup or write by skipping that pre-check.
//
// Callers must pass the plain gateway-built identity; the composition is
// applied exactly here, identically on the lookup and the write path, so an
// entry is always served from and stored under the same regime-bound
// identity.
func (cs *CacheService) regimeResolve(ctx context.Context, ri RouteIdentity) (RouteIdentity, bool) {
	if cs.regime == nil {
		return ri, false
	}
	if ri.OrgID == "" {
		// Armed binding and no org: the operation cannot name the tenant
		// policy regime that would govern it. Refuse it before any resolver
		// call (the resolver contract is per-org) and before any cache layer
		// is touched — fail closed, not pass-through.
		RecordEnforcementOffSkip()
		return ri, true
	}
	regime := cs.regime(ctx, ri.OrgID)
	if !validRegimeFingerprint(regime) {
		// Enforcement off/unverifiable, or a fingerprint that cannot join
		// the identity unambiguously: refuse the whole operation (no
		// lookup, no write), never compose a potentially ambiguous identity.
		RecordEnforcementOffSkip()
		return ri, true
	}
	ri.GenParams = composeRegimeGenParams(ri.GenParams, regime)
	return ri, false
}

// regimeIdentity returns the route identity extended with the org's current
// policy regime fingerprint. The fingerprint rides in the generation
// parameters slot, so the strict GenParams equality of the provenance match
// (RT-05) is what turns a regime change into a miss on every layer — exact,
// pg exact and semantic — with no new key layout and no migration.
//
// This is the composition-only view of regimeResolve for direct identity
// inspection; the LookupWithResult/Write paths call regimeResolve themselves
// so the resolver runs exactly once per operation and the gated state is
// honored.
func (cs *CacheService) regimeIdentity(ctx context.Context, ri RouteIdentity) RouteIdentity {
	composed, _ := cs.regimeResolve(ctx, ri)
	return composed
}

// composeRegimeGenParams folds the regime fingerprint into the generation
// parameters slot. The fingerprint must already satisfy the resolver
// contract (regimeResolve validates before composing): the join is plain
// concatenation, so only a separator-free fingerprint keeps the mapping
// (parameters, fingerprint) → composed identity injective.
func composeRegimeGenParams(params, regime string) string {
	if regime == "" {
		return params
	}
	if params == "" {
		return policyRegimeBare + regime
	}
	return params + policyRegimeTag + regime
}

// validRegimeFingerprint reports whether a resolver answer may join the
// regime composition. It accepts only non-empty fingerprints without the
// unit separator U+001F: "" is the enforcement-off/unverifiable answer the
// gate must refuse, and a fingerprint carrying the composition separator
// would break the injectivity of composeRegimeGenParams — two different
// (parameters, fingerprint) pairs could compose to the same identity string,
// so an entry sealed under one regime could be served by a lookup whose
// regime resolved differently (a tighten aliasing back onto the loosened
// identity). Rather than trying to sanitize an untrusted fingerprint, the
// gate treats a contract-breaking answer like any other unverifiable
// enforcement state: the org's operations are refused until the resolver
// answers a composable fingerprint again. The production fingerprint is a
// hexadecimal digest and always valid; the check defends the boundary for
// every other PolicyRegimeResolver implementation.
func validRegimeFingerprint(regime string) bool {
	return regime != "" && !strings.ContainsRune(regime, '\x1f')
}
