package cli

import (
	"encoding/json"
	"strings"

	"github.com/reireirei/yabanin/pkg/classifier"
	"github.com/reireirei/yabanin/pkg/resolver"
)

// classEffort maps classifier classes to OpenAI reasoning_effort values.
var classEffort = map[classifier.Class]string{
	classifier.ClassEasy:   "low",
	classifier.ClassMedium: "medium",
	classifier.ClassHard:   "high",
}

// injectReasoningEffort sets "reasoning_effort" in an OpenAI-format request
// body. Best-effort: any unmarshal/marshal error returns body unchanged.
//
// The patch goes through map[string]json.RawMessage (not
// map[string]interface{}): a float64 round-trip would silently corrupt
// extension integers beyond 2^53 in the same body it patches (N07-P01-T04
// explicit pass-through). Only the injected key is rewritten; every other
// field keeps its exact encoded value (same idiom as upstream.OverrideModelRaw).
func injectReasoningEffort(body []byte, effort string) []byte {
	if effort == "" || len(body) == 0 {
		return body
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(body, &root); err != nil {
		return body
	}
	enc, err := json.Marshal(effort)
	if err != nil {
		return body
	}
	root["reasoning_effort"] = enc
	out, err := json.Marshal(root)
	if err != nil {
		return body
	}
	return out
}

// effortForCandidate returns the reasoning_effort value that
// maybeInjectEffort would inject for this candidate ("" when none). It is
// the single source of the eligibility decision — the cache route identity
// (RT-05) uses the same helper so a stored entry's generation parameters can
// be compared against what the current route would inject.
func (gw *gateway) effortForCandidate(mi resolver.ModelInfo, cls classifier.Class) string {
	if !gw.cfg.EffortRoutingEnabled || mi.Provider == "anthropic" {
		return ""
	}
	effort := classEffort[cls]
	if effort == "" {
		return ""
	}
	model := strings.ToLower(mi.ModelName)
	for _, frag := range gw.effortModels { // prepared []string, lowercase
		if frag != "" && strings.Contains(model, frag) {
			return effort
		}
	}
	return ""
}

// maybeInjectEffort applies the mapping when effort routing is enabled, the
// attempt's provider is OpenAI-compat, and the model matches the configured
// reasoning-model list. Anthropic is excluded: its thinking API uses a
// different field (follow-up).
func (gw *gateway) maybeInjectEffort(body []byte, mi resolver.ModelInfo, cls classifier.Class) []byte {
	effort := gw.effortForCandidate(mi, cls)
	if effort == "" {
		return body
	}
	return injectReasoningEffort(body, effort)
}
