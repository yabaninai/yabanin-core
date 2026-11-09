package cli

import (
	"encoding/json"
	"net/http"

	"github.com/reireirei/yabanin/pkg/router"
)

// Routing-decision explainability (v18 R1, whitepaper ch.4 Real-time
// Explainability Layer). The gateway answers "why was THIS model chosen for
// THIS request" with a machine-readable payload, exposed as:
//
//   - response header X-Yabanin-Decision (default on, YABANIN_DECISION_HEADER)
//   - event field routing_decision (default on, YABANIN_DECISION_EVENT)
//
// The header is set on the wire; the event field is consumed by loggerd into
// request_logs.routing_decision (G2).

// Decision header / event field name.
const decisionHeaderKey = "X-Yabanin-Decision"

// Decision sources.
const (
	decisionSourceCacheExact    = "cache_exact"
	decisionSourceCacheSemantic = "cache_semantic"
	decisionSourceTierRouter    = "tier_router"
	decisionSourceRuleOverride  = "rule_override"
	decisionSourcePassthrough   = "passthrough"
	// inside the policy-filtered pool (routing_mode=quality orgs with an
	// owner-approved snapshot).
	decisionSourceQualityEval = "quality_eval"
)

// routingDecision is the wire payload. All fields are omitempty where a zero
// value is meaningful ("not set"), so the compact JSON stays small on the
// common passthrough path.
type routingDecision struct {
	// Source of the final model choice: cache_exact, cache_semantic,
	// tier_router, rule_override, or passthrough (client model kept).
	Source string `json:"source"`
	// classifier class: easy|medium|hard (empty when no classifier ran).
	Class string `json:"class,omitempty"`
	// classifier confidence [0..1] (0 when no classifier ran).
	Confidence float64 `json:"confidence,omitempty"`
	// per-org routing threshold the confidence was compared against
	// (0 when no classifier ran).
	Threshold float64 `json:"threshold,omitempty"`
	// KV-cache-aware session affinity outcome: "used" | "miss" | "".
	Affinity string `json:"affinity,omitempty"`
	// the session's preferred (warm) model when affinity was consulted.
	Preferred string `json:"preferred,omitempty"`
	// model the decision moved FROM (client-requested or pre-override).
	From string `json:"from,omitempty"`
	// model the decision moved TO ("" when passthrough).
	To string `json:"to,omitempty"`
	// reasoning_effort injected for this request (v15 E1), when applicable.
	Effort string `json:"effort,omitempty"`
	// matched this request's selected model (omitempty keeps every
	// non-rollout payload byte-for-byte unchanged).
	// Arm of the hash-sticky split: "canary" | "base".
	Arm string `json:"arm,omitempty"`
	// RolloutID is the rollout row id (analytics join key; the per-rollout
	// measured share and the auto-Recommendation evidence query on it).
	RolloutID string `json:"rollout_id,omitempty"`
	// RolloutVersion is the active version that produced this decision.
	RolloutVersion int `json:"rollout_version,omitempty"`
	// CanaryPercent is the configured whole percent of the active version.
	CanaryPercent int `json:"canary_percent,omitempty"`
	// free-form reason for non-typical outcomes (e.g.
	// "time_window_downgrade" once R2 lands, "always_premium", or
	// unavailable/stale/insufficient and the classifier path decided).
	Reason string `json:"reason,omitempty"`
	// choice was based on; set only when Source == quality_eval.
	QualityVersion string `json:"quality_version,omitempty"`
	// Downgrade is the typed downgrade report: "time_window" when the R2
	// cheap-hours/batch path moved the request to a cheaper tier, empty
	// otherwise. Machine-readable twin of Reason — consumers branch on
	// this field instead of parsing reason strings.
	Downgrade string `json:"downgrade,omitempty"`
	// Rule identifies the exact routing rule version that produced a
	// rule_override decision (CORE-TRACE-04): namespace "routing", the
	// rule id, and a content hash of the rule's configuration captured at
	// match time — so later rule edits/deletes keep the ORIGINAL version in
	// request history. nil (and thus absent from the wire) for every other
	// source and for unstamped rule_override decisions: a decision must
	// never carry a fabricated rule identity.
	Rule *DecisionRuleRef `json:"rule,omitempty"`
}

// DecisionRuleRef is the rule-trace identity triple stamped onto a
// rule_override decision (CORE-TRACE-04). The vocabulary matches
// CORE-TRACE-05 (namespaces policy/step/routing/tool-policy).
type DecisionRuleRef struct {
	Namespace string `json:"namespace"`
	ID        string `json:"id"`
	Version   string `json:"version"`
}

// set writes the decision as a compact JSON header (no spaces).
func (d routingDecision) set(w http.ResponseWriter) {
	b, err := json.Marshal(d)
	if err != nil {
		return
	}
	w.Header().Set(decisionHeaderKey, string(b))
}

// accumulator: an inactive decision (no rollout matched — the common path)
// leaves the payload untouched; an active one adds arm/rollout_id/
// rollout_version/canary_percent to the header and the analytics event. The
// decision itself was already applied to the model choice by the router.
func (cc *chatContext) stampCanary(d router.CanaryDecision) {
	cc.canary = d
	if !d.Active() {
		return
	}
	cc.dec.Arm = d.Arm
	cc.dec.RolloutID = d.RolloutID
	cc.dec.RolloutVersion = d.Version
	cc.dec.CanaryPercent = d.Percent
}

// decisionSourceCacheHit maps a cache hit source type ("exact" | "semantic")
// to the decision source vocabulary.
func decisionSourceCacheHit(sourceType string) string {
	if sourceType == "semantic" {
		return decisionSourceCacheSemantic
	}
	return decisionSourceCacheExact
}
