package cli

import (
	"context"
	"time"

	"github.com/reireirei/yabanin/pkg/classifier"
	"github.com/reireirei/yabanin/pkg/router"
)

//
//   - D1: the quality source is the versioned agenteval run results, read by
//     the read-only adapter in pkg/agenteval/results. No runtime writes.
//   - D2: application is owner-approved only. The runtime consumes exclusively
//     the owner-approved snapshot (approvals registry); a accepted
//     Recommendation becomes that snapshot out-of-band. Nothing here auto-applies.
//   - D3: the surface is the EXISTING per-org routing_mode — orgs opt in by
//     setting routing_mode="quality"; threshold/loader stay the same surface.
//   - D4: router.CompareQualitySnapshots is the vN/vN+1 overlap evidence
//     required before any traffic shift; it is a proof-harness hook, never an
//     auto-switch.
//
// Off by default everywhere: quality routing participates only when the org's
// routing_mode is "quality" AND a quality source is wired (config-gated).

// routing_mode surface (organizations.routing_mode).
const routingModeQuality = "quality"

// qualitySnapshotMaxAge bounds snapshot freshness. Eval runs are periodic; a
// dated snapshot is an explicit fallback (decision Reason
// "quality_fallback:stale_snapshot"), so a forgotten approval cannot steer
// traffic forever.
const qualitySnapshotMaxAge = 30 * 24 * time.Hour

// selectTierModel is the auto-branch model selection. Unless the org's
// routing_mode is "quality" AND a quality source is wired, it is exactly
// SelectModelWithAffinity with a zero QualityOutcome — no behavior change.
// In quality mode an unavailable, missing or stale source degrades to the
// unchanged classifier selection and the outcome names the fallback reason;
// the sovereignty filter, residency and reservation gates are identical on
// every path (the quality ranking only reorders the already-filtered pool).
func (gw *gateway) selectTierModel(ctx context.Context, cls classifier.Class, orgID, preferredModel, sessionID, routingMode string) (router.ModelInfo, router.QualityOutcome, router.CanaryDecision, error) {
	if routingMode != routingModeQuality || gw.qualitySource == nil {
		m, dec, err := gw.tierRouter.SelectModelForSession(ctx, cls, orgID, preferredModel, sessionID)
		return m, router.QualityOutcome{}, dec, err
	}

	snap, err := gw.qualitySource.QualitySnapshot(ctx, orgID)
	if err != nil || snap == nil {
		reason := router.QualityFallbackSourceUnavailable
		if err == nil {
			reason = router.QualityFallbackNoSnapshot
		}
		gw.log.Debug("quality routing fallback: no usable snapshot", "org_id", orgID, "reason", reason)
		m, dec, selErr := gw.tierRouter.SelectModelForSession(ctx, cls, orgID, preferredModel, sessionID)
		return m, router.QualityOutcome{FallbackReason: reason}, dec, selErr
	}
	if !snap.Fresh(qualitySnapshotMaxAge, gw.now()) {
		gw.log.Debug("quality routing fallback: snapshot stale", "org_id", orgID, "version", snap.Version)
		m, dec, selErr := gw.tierRouter.SelectModelForSession(ctx, cls, orgID, preferredModel, sessionID)
		return m, router.QualityOutcome{Version: snap.Version, FallbackReason: router.QualityFallbackStale}, dec, selErr
	}
	// routing_mode=quality uses the versioned quality ranking; canary
	// rollouts target orgs in the default affinity mode. The quality path
	// therefore returns an inactive canary decision by construction.
	m, qOutcome, qerr := gw.tierRouter.SelectModelWithQuality(ctx, cls, orgID, preferredModel, snap)
	return m, qOutcome, router.CanaryDecision{}, qerr
}

// applyQualityOutcome folds the quality outcome into the routing decision:
// source=quality_eval with the snapshot version when the ranking decided, or
// an explicit "quality_fallback:<reason>" when the classifier path decided
// instead. Visible in X-Yabanin-Decision and the routing_decision event field.
func applyQualityOutcome(dec *routingDecision, qo router.QualityOutcome) {
	if qo.Used {
		dec.Source = decisionSourceQualityEval
		dec.QualityVersion = qo.Version
		return
	}
	if qo.FallbackReason != "" {
		dec.Reason = "quality_fallback:" + qo.FallbackReason
	}
}
