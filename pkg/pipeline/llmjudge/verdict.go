package llmjudge

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// DefaultThreshold is the confidence above which a judge finding raises a
// deny (documented in README.md §Threshold choice).
const DefaultThreshold = 0.8

// JudgeFinding is one violation claim in the judge model's answer.
type JudgeFinding struct {
	Category string `json:"category"`
	// Severity is the judge's qualitative scale (low|medium|high expected;
	// passed through verbatim — it is informational, the action mapping
	// uses confidence + threshold).
	Severity string `json:"severity,omitempty"`
	// Confidence in [0,1]; nil means the judge omitted it, which maps to
	// 1.0 (fail-closed: a claimed violation without a score still counts).
	Confidence *float64 `json:"confidence,omitempty"`
	Evidence   string   `json:"evidence,omitempty"`
	Span       string   `json:"span,omitempty"`
}

// JudgeVerdict is the parsed judge answer. An empty findings list is the
// "clean" verdict.
type JudgeVerdict struct {
	Findings []JudgeFinding `json:"findings"`
	Summary  string         `json:"summary,omitempty"`
}

// confidence returns the effective confidence of a finding: clamped to
// [0,1]; omitted values count as 1.0 (fail-closed, see JudgeFinding).
func (f JudgeFinding) confidence() float64 {
	if f.Confidence == nil {
		return 1
	}
	return clamp01(*f.Confidence)
}

// findingAction maps one finding to its strictness: confidence >= threshold
// denies, anything below raises a flag. The threshold is the policy's tuning
// knob between false denies and missed violations (README.md).
func findingAction(confidence, threshold float64) pipeline.Action {
	if confidence >= threshold {
		return pipeline.ActionDeny
	}
	return pipeline.ActionFlag
}

// clamp01 bounds f to [0,1] (judge models drift outside the range).
func clamp01(f float64) float64 {
	switch {
	case f < 0:
		return 0
	case f > 1:
		return 1
	default:
		return f
	}
}

// ParseVerdict converts the raw judge completion into a JudgeVerdict.
//
// Parsing is strictly bounded: (1) markdown fences are stripped, (2) the
// whole text must be valid JSON — on failure (3) the substring from the
// first '{' to the last '}' is retried (models prepend stray prose despite
// instructions). Anything still unparsable is a malformed verdict and the
// step returns an error, so the policy's on_error mode decides the outcome
// (fail_open+flag is the recommended default for judge steps).
//
// Shape validation: every finding MUST name a category; unknown severity
// strings pass through; confidence outside [0,1] is clamped. maxEvidence
// caps the stored evidence length in runes (decision-log hygiene — evidence
// quotes user content).
func ParseVerdict(content string, maxEvidence int) (JudgeVerdict, error) {
	s := stripFences(content)
	v, err := decodeVerdict(s)
	if err != nil {
		l, r := strings.Index(s, "{"), strings.LastIndex(s, "}")
		if l < 0 || r <= l {
			return JudgeVerdict{}, fmt.Errorf("judge answer is not a JSON verdict: %w", err)
		}
		v, err = decodeVerdict(s[l : r+1])
		if err != nil {
			return JudgeVerdict{}, fmt.Errorf("judge answer is not a JSON verdict: %w", err)
		}
	}
	for i := range v.Findings {
		if strings.TrimSpace(v.Findings[i].Category) == "" {
			return JudgeVerdict{}, fmt.Errorf("judge verdict finding %d: empty category", i)
		}
		if maxEvidence > 0 {
			v.Findings[i].Evidence = truncateRunes(v.Findings[i].Evidence, maxEvidence)
		}
	}
	return v, nil
}

// decodeVerdict unmarshals one candidate JSON document leniently (unknown
// fields allowed — judge models add commentary keys despite instructions).
func decodeVerdict(s string) (JudgeVerdict, error) {
	var v JudgeVerdict
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return JudgeVerdict{}, err
	}
	return v, nil
}

// stripFences removes a wrapping ```...``` block if the model added one.
func stripFences(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "```") {
		return s
	}
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	if i := strings.LastIndex(s, "```"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// truncateRunes caps s to max runes, appending an ellipsis when truncated.
func truncateRunes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}
