package pipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// EffectivePolicyHash computes the stable identity of a loaded policy
// snapshot. JSON's deterministic map-key ordering makes rules and prompt pins
// reproducible across consumers. A nil prompt-pin map and an empty one are
// the same state: both marshal as an empty object so runtime, simulator and
// CLI callers never diverge on absent pins.
func EffectivePolicyHash(version int, policy Policy, promptPins map[string]string) string {
	if promptPins == nil {
		promptPins = map[string]string{}
	}
	canonical := struct {
		Version    int               `json:"version"`
		Policy     Policy            `json:"policy"`
		PromptPins map[string]string `json:"prompt_pins"`
	}{Version: version, Policy: policy, PromptPins: promptPins}
	b, err := json.Marshal(canonical)
	if err != nil {
		// Policy consists only of JSON-compatible values; keep this helper
		// total if a caller supplies an unsupported Params value.
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
