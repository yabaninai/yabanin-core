package cli

import (
	"context"
	"fmt"
	"net/http"

	apierrors "github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/logctx"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/policy"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/router"
)

// RT-02: shared final-candidate policy gate.
//
// Pre-routing admission (chatCompletions head, admit) checks the model the
// CLIENT named. Classifier/tier routing, org rule overrides, time-window
// downgrade, unknown-model fallback and residency remap may each replace that
// candidate afterwards. gateCandidate re-checks the candidate that will
// actually be called, under the trusted identity the auth middleware resolved
// (it strips client copies of the identity headers before injecting the
// resolved key's org/team/key id — never read a client-supplied identity here).
//
// Contract:
//   - pure with respect to HTTP: never writes a response, never touches the
//     upstream. Callers translate the outcome into exactly one terminal error.
//   - gateDenied  → 403 before upstream; terminal: no retry, no fallback hop.
//   - gateUnavailable (access/policy store failure) → 503; terminal as well —
//     a degraded policy store must not be routed around.
//   - Existing contracts preserved: whitelist alias semantics (an alias is
//     checked as its canonical target), residency ZAI/data-boundary rules.
//   - Optional shadow/evalgate work sits strictly after the first upstream
//     byte; a denied/unavailable gate returns before them, so they are
//     skipped with the logged reason and never produce a call or verdict.

// candidateIdentity is the trusted request identity (auth middleware output).
type candidateIdentity struct {
	OrgID    string
	TeamID   string
	APIKeyID string
}

// gateOutcome classifies the gate decision.
type gateOutcome int

const (
	gateAllowed     gateOutcome = iota
	gateDenied                  // 403: candidate is not permitted for this identity
	gateUnavailable             // 503: access/policy check could not be evaluated
)

// gateResult is the explicit gate outcome plus the terminal wire error the
// caller must write when the outcome is not allowed. The wire fields mirror
// the pre-routing admission envelopes exactly.
type gateResult struct {
	Outcome gateOutcome
	Status  int
	ErrType string
	ErrCode string // optional machine-readable code (ZAI contracts)
	Message string
}

// gateCandidate evaluates the final canonical candidate. The whitelist is
// checked against info.ModelName — the registry model that will actually be
// called — so alias targets, rule/routing overrides, unknown-model fallbacks
// and residency remaps all re-enter the same access contract the requested
// model passed at admission.
func (gw *gateway) gateCandidate(ctx context.Context, id candidateIdentity, requestedModel string, info resolver.ModelInfo) gateResult {
	if gw.wl != nil {
		candidate := info.ModelName
		if candidate == "" {
			candidate = requestedModel
		}
		allowed, err := gw.wl.Check(ctx, id.APIKeyID, id.TeamID, candidate)
		if err != nil {
			metrics.WlCheckErrors.Inc()
			return gateResult{
				Outcome: gateUnavailable,
				Status:  http.StatusServiceUnavailable,
				ErrType: "whitelist_check_unavailable",
				Message: "whitelist check temporarily unavailable",
			}
		}
		if !allowed {
			return gateResult{
				Outcome: gateDenied,
				Status:  http.StatusForbidden,
				ErrType: apierrors.ErrorCodePermissionDenied,
				Message: fmt.Sprintf("model %q is not allowed for this API key", candidate),
			}
		}
	}
	if res, blocked := zaiCodingViolation(gw.cfg.ZAICodingEnabled, requestedModel, info); blocked {
		return res
	}
	return gateResult{Outcome: gateAllowed}
}

// enforceFinalCandidateGate runs gateCandidate and, when the candidate does
// not pass, writes the single terminal error response. It returns false when
// the caller must stop (response already written).
func (gw *gateway) enforceFinalCandidateGate(w http.ResponseWriter, r *http.Request, id candidateIdentity, requestedModel string, info resolver.ModelInfo) bool {
	res := gw.gateCandidate(r.Context(), id, requestedModel, info)
	if res.Outcome == gateAllowed {
		return true
	}
	l := logctx.From(r.Context(), gw.log)
	if res.Outcome == gateUnavailable {
		l.Warn("final-candidate policy check unavailable, denying request",
			"org_id", id.OrgID, "requested", requestedModel, "candidate", info.ModelName, "reason", res.Message)
	} else {
		l.Warn("final-candidate policy gate denied request",
			"org_id", id.OrgID, "requested", requestedModel, "candidate", info.ModelName, "reason", res.Message)
	}
	writeGateDenial(w, res)
	return false
}

// writeGateDenial emits the terminal error for a non-allowed gate outcome.
// Callers invoke it exactly once per request.
func writeGateDenial(w http.ResponseWriter, res gateResult) {
	if res.ErrCode != "" {
		apierrors.WriteWithCode(w, res.Status, res.ErrType, res.Message, res.ErrCode)
		return
	}
	apierrors.Write(w, res.Status, res.ErrType, res.Message)
}

// gateAttemptCandidate is the RT-03 per-provider-attempt gate: it re-runs the
// shared final-candidate gate (access whitelist + ZAI/data-boundary) plus the
// residency contract for ONE concrete candidate about to be called — a
// fallback hop, or an optional secondary call (shadow target, evalgate
// premium comparison). The policy that allowed the primary never
// automatically allows the next candidate.
//
// Returns the candidate that must actually be called. A residency remap on a
// secondary attempt is followed (and the remapped candidate re-gated), so the
// caller never sends traffic to a model the enforcer rejected; the loop is
// bounded and production wiring is deny-only (no remap pool).
//
// A non-nil *router.PolicyError is chain-terminal: no transport retry, no
// next candidate, no secondary call. Cancellation is NOT handled here —
// callers must check ctx.Err() before gating so a dead context is not
// misreported as a policy-store outage.
func (gw *gateway) gateAttemptCandidate(ctx context.Context, id candidateIdentity, requestedModel string, mi resolver.ModelInfo) (resolver.ModelInfo, *router.PolicyError) {
	for hops := 0; ; hops++ {
		res := gw.gateCandidate(ctx, id, requestedModel, mi)
		if res.Outcome != gateAllowed {
			gw.logGateAttempt(ctx, id, requestedModel, mi, res)
			return mi, policyOutcomeFromGate(res)
		}
		if gw.residencyEnforcer == nil || id.OrgID == "" {
			return mi, nil
		}
		resDec := gw.residencyEnforcer.Enforce(ctx, id.OrgID, mi.ModelName, policy.Region(mi.Region), mi.Provider)
		if !resDec.Allowed {
			metrics.ResidencyEnforcementTotal.WithLabelValues(string(resDec.Region), "denied").Inc()
			res := gateResult{
				Outcome: gateDenied,
				Status:  http.StatusForbidden,
				ErrType: "residency_policy_violation",
				Message: "request violates organization residency policy: " + resDec.Reason,
			}
			gw.logGateAttempt(ctx, id, requestedModel, mi, res)
			return mi, policyOutcomeFromGate(res)
		}
		if resDec.RemappedModel == "" || resDec.RemappedModel == mi.ModelName || hops >= 2 {
			return mi, nil
		}
		// Follow the residency remap to the in-region candidate and re-gate
		// it under the same access + ZAI contracts (bounded to 2 follows).
		// RT-06: resolution runs under the request context — a registry
		// outage is an explicit unavailable outcome (terminal), never a
		// silent degrade to a half-populated candidate.
		nfo, nerr := gw.resolveModelInfo(ctx, resDec.RemappedModel)
		if nerr != nil {
			res := gateResult{
				Outcome: gateUnavailable,
				Status:  http.StatusServiceUnavailable,
				ErrType: "model_registry_unavailable",
				Message: "model registry temporarily unavailable",
			}
			gw.logGateAttempt(ctx, id, requestedModel, mi, res)
			return mi, policyOutcomeFromGate(res)
		}
		mi = nfo
	}
}

// logGateAttempt records why a secondary candidate was not called.
func (gw *gateway) logGateAttempt(ctx context.Context, id candidateIdentity, requestedModel string, mi resolver.ModelInfo, res gateResult) {
	l := logctx.From(ctx, gw.log)
	if res.Outcome == gateUnavailable {
		l.Warn("candidate policy check unavailable, stopping before provider call",
			"org_id", id.OrgID, "requested", requestedModel, "candidate", mi.ModelName, "reason", res.Message)
		return
	}
	l.Warn("candidate policy gate denied provider call",
		"org_id", id.OrgID, "requested", requestedModel, "candidate", mi.ModelName, "reason", res.Message)
}

// policyOutcomeFromGate converts a gate decision into the terminal
// *router.PolicyError consumed by the fallback executor.
func policyOutcomeFromGate(res gateResult) *router.PolicyError {
	return &router.PolicyError{
		Status:  res.Status,
		ErrType: res.ErrType,
		ErrCode: res.ErrCode,
		Message: res.Message,
	}
}

// gateResultFromPolicy converts a terminal *router.PolicyError back into the
// gate envelope shape for writeGateDenial.
func gateResultFromPolicy(pe *router.PolicyError) gateResult {
	outcome := gateDenied
	if pe.Status == http.StatusServiceUnavailable {
		outcome = gateUnavailable
	}
	return gateResult{
		Outcome: outcome,
		Status:  pe.Status,
		ErrType: pe.ErrType,
		ErrCode: pe.ErrCode,
		Message: pe.Message,
	}
}
