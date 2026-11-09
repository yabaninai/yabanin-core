package router

// N09-P04-T03 — evidence-only automatic rollback recommendation.
//
// The advisor computes a recommendation from measured canary-vs-baseline
// outcomes, but the only rollback that exists is the MANUAL one (PUT
// enabled=false — atomic, version-key bump, resolver reload). Nothing in
// this file mutates rollout state; the recommendation is evidence for a
// human decision. A measured/imported evaluation result never implies an
// automatically approved production routing change, and whatever the
// verdict, the exact reasons (rates, deltas, sample sizes) ride the advice
// so a downgrade/rollback is never unexplained.
//
// The rules are explicit domain semantics in code (I37 keeps Expr for the
// shared condition language; routing decisions keep explicitly defined
// domain semantics). The evaluator is pure and deterministic — inject the
// clock, feed it counters, get the same advice every time.

import (
	"fmt"
	"time"
)

// Canary advice action vocabulary. The recommendation action name contains
// "manual" by design: the system never rolls back by itself (D3), the
// advice only names the manual action it recommends.
const (
	CanaryAdviceHold           = "hold"
	CanaryAdviceManualRollback = "manual-rollback"
)

// CanaryArmOutcome is one arm's observed traffic over the evaluation window.
// Counters are monotonic window deltas computed by the caller (request_logs
// or metrics scrape); the advisor never reads clocks or stores.
type CanaryArmOutcome struct {
	Requests   int64
	Failures   int64
	LatencySum time.Duration // total observed request latency; mean = Sum/Requests
}

// CanaryAdviceInput is one evaluation: rollout identity plus both arms'
// outcomes over the SAME window.
type CanaryAdviceInput struct {
	RolloutID string
	Name      string
	Version   int
	Base      CanaryArmOutcome
	Canary    CanaryArmOutcome
}

// CanaryAdvice is the evidence-only recommendation. Recommended=false is
// still evidence: Reasons always carry the numbers behind the verdict.
type CanaryAdvice struct {
	RolloutID string
	Name      string
	Version   int

	Action       string // CanaryAdviceHold | CanaryAdviceManualRollback
	Recommended  bool   // true = manual rollback recommended (never executed)
	Insufficient bool   // sample evidence below the configured thresholds

	Reasons []string

	BaseFailureRate   float64
	CanaryFailureRate float64
	BaseLatencyMean   time.Duration
	CanaryLatencyMean time.Duration

	EvaluatedAt time.Time
}

// CanaryRolloutAdvisor evaluates canary outcomes against the baseline and
// produces the manual-rollback recommendation. Safe for concurrent use
// (immutable after construction).
type CanaryRolloutAdvisor struct {
	// MinCanaryRequests / MinBaseRequests are the per-arm sample floors:
	// below them the advice is hold+insufficient, never a verdict.
	MinCanaryRequests int64
	MinBaseRequests   int64
	// MaxFailureRateDelta is the absolute failure-rate gap (canary − base)
	// at which the canary arm recommends rollback: 0.05 = five percentage
	// points. Must be exceeded (>=) together with MinFailureRate.
	MaxFailureRateDelta float64
	// MinFailureRate is the absolute canary failure-rate floor: a noisy
	// near-zero baseline must not amplify tiny absolute gaps into a
	// rollback recommendation.
	MinFailureRate float64
	// MaxLatencyRatio is the canary/base mean-latency ratio (>=) that
	// recommends rollback: 1.5 = canary 50% slower than baseline.
	MaxLatencyRatio float64

	now func() time.Time
}

const (
	canaryAdvisorMinCanaryRequests = 30
	canaryAdvisorMinBaseRequests   = 30
	canaryAdvisorMaxFailureDelta   = 0.05
	canaryAdvisorMinFailureRate    = 0.02
	canaryAdvisorMaxLatencyRatio   = 1.5
)

// NewCanaryRolloutAdvisor applies defaults for zero/negative values:
// minCanary=30, minBase=30, failureDelta=0.05 (5pp), failureFloor=0.02,
// latencyRatio=1.5.
func NewCanaryRolloutAdvisor(minCanary, minBase int64, maxFailureDelta, minFailureRate, maxLatencyRatio float64) *CanaryRolloutAdvisor {
	a := &CanaryRolloutAdvisor{
		MinCanaryRequests:   minCanary,
		MinBaseRequests:     minBase,
		MaxFailureRateDelta: maxFailureDelta,
		MinFailureRate:      minFailureRate,
		MaxLatencyRatio:     maxLatencyRatio,
		now:                 time.Now,
	}
	if a.MinCanaryRequests <= 0 {
		a.MinCanaryRequests = canaryAdvisorMinCanaryRequests
	}
	if a.MinBaseRequests <= 0 {
		a.MinBaseRequests = canaryAdvisorMinBaseRequests
	}
	if a.MaxFailureRateDelta <= 0 {
		a.MaxFailureRateDelta = canaryAdvisorMaxFailureDelta
	}
	if a.MinFailureRate <= 0 {
		a.MinFailureRate = canaryAdvisorMinFailureRate
	}
	if a.MaxLatencyRatio <= 0 {
		a.MaxLatencyRatio = canaryAdvisorMaxLatencyRatio
	}
	return a
}

// failureRate guards the divide: a zero-request arm has no measurable rate
// (the sample floors keep this from masking real traffic in practice).
func failureRate(o CanaryArmOutcome) float64 {
	if o.Requests <= 0 {
		return 0
	}
	return float64(o.Failures) / float64(o.Requests)
}

// latencyMean guards the divide like failureRate.
func latencyMean(o CanaryArmOutcome) time.Duration {
	if o.Requests <= 0 {
		return 0
	}
	return o.LatencySum / time.Duration(o.Requests)
}

// Recommend evaluates one rollout's canary against its baseline. Invalid
// evidence (negative counters) is never silently clamped to a verdict — the
// advice is hold with an explicit reason; I51-style: a precise reason or no
// recommendation at all.
func (a *CanaryRolloutAdvisor) Recommend(in CanaryAdviceInput) CanaryAdvice {
	adv := CanaryAdvice{
		RolloutID:   in.RolloutID,
		Name:        in.Name,
		Version:     in.Version,
		Action:      CanaryAdviceHold,
		EvaluatedAt: a.now(),
	}

	if in.Canary.Requests < 0 || in.Canary.Failures < 0 || in.Base.Requests < 0 || in.Base.Failures < 0 {
		adv.Insufficient = true
		adv.Reasons = append(adv.Reasons,
			fmt.Sprintf("invalid evidence: negative counters (canary requests=%d failures=%d, base requests=%d failures=%d)",
				in.Canary.Requests, in.Canary.Failures, in.Base.Requests, in.Base.Failures))
		return adv
	}

	adv.BaseFailureRate = failureRate(in.Base)
	adv.CanaryFailureRate = failureRate(in.Canary)
	adv.BaseLatencyMean = latencyMean(in.Base)
	adv.CanaryLatencyMean = latencyMean(in.Canary)

	if in.Canary.Requests < a.MinCanaryRequests || in.Base.Requests < a.MinBaseRequests {
		adv.Insufficient = true
		adv.Reasons = append(adv.Reasons,
			fmt.Sprintf("insufficient samples: canary %d/%d requests, base %d/%d requests (thresholds)",
				in.Canary.Requests, a.MinCanaryRequests, in.Base.Requests, a.MinBaseRequests))
		return adv
	}

	delta := adv.CanaryFailureRate - adv.BaseFailureRate
	if delta >= a.MaxFailureRateDelta && adv.CanaryFailureRate >= a.MinFailureRate {
		adv.Recommended = true
		adv.Reasons = append(adv.Reasons,
			fmt.Sprintf("failure rate: canary %.4f vs base %.4f (delta %.4f >= %.4f, floor %.4f)",
				adv.CanaryFailureRate, adv.BaseFailureRate, delta, a.MaxFailureRateDelta, a.MinFailureRate))
	}

	if adv.BaseLatencyMean > 0 && adv.CanaryLatencyMean > 0 {
		ratio := float64(adv.CanaryLatencyMean) / float64(adv.BaseLatencyMean)
		if ratio >= a.MaxLatencyRatio {
			adv.Recommended = true
			adv.Reasons = append(adv.Reasons,
				fmt.Sprintf("latency: canary mean %s vs base mean %s (ratio %.3f >= %.3f)",
					adv.CanaryLatencyMean, adv.BaseLatencyMean, ratio, a.MaxLatencyRatio))
		}
	}

	if adv.Recommended {
		adv.Action = CanaryAdviceManualRollback
		adv.Reasons = append(adv.Reasons,
			"recommendation only: run the manual rollback (PUT enabled=false — atomic, bumps the version key); the system never rolls back by itself")
		return adv
	}

	adv.Reasons = append(adv.Reasons,
		fmt.Sprintf("within thresholds: failure delta %.4f < %.4f (or below floor %.4f), latency ratio within %.3f",
			delta, a.MaxFailureRateDelta, a.MinFailureRate, a.MaxLatencyRatio))
	return adv
}
