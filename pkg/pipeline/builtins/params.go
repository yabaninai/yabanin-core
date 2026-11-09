package builtins

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// Severity vocabulary of the builtin detectors (see package doc).
const (
	sevHigh   = "high"
	sevMedium = "medium"
	sevLow    = "low"
)

// maxEvidence bounds the Evidence excerpt a builtin finding may quote from
// user content. Decision-log persistence (OP-9) hashes evidence anyway; the
// cap keeps the in-memory result bounded even for huge payloads.
const maxEvidence = 64

// maxEvidenceLong bounds evidence that carries detector-rendered diagnostics
// (e.g. schema validation messages) rather than raw user content.
const maxEvidenceLong = 512

// allKindsList is the default "kinds" set: every defined payload kind.
func allKindsList() []pipeline.PayloadKind {
	return []pipeline.PayloadKind{
		pipeline.KindRequest, pipeline.KindResponse,
		pipeline.KindStreamPrefix, pipeline.KindStreamFinal,
		pipeline.KindToolArgs, pipeline.KindToolResult,
	}
}

// findingActions is the set of actions a detector finding may carry.
// "allow" is intentionally absent: an allowing detector finding is inert
// noise — an inert run is expressed by shadow mode, not by fake findings.
var findingActions = map[pipeline.Action]bool{
	pipeline.ActionFlag: true,
	pipeline.ActionMask: true,
	pipeline.ActionDeny: true,
}

// parseKinds resolves the optional "kinds" param (list of payload kind
// strings). A nil/absent param yields def, defaulting to ALL kinds when no
// def is given. Unknown kinds are factory errors so a typo can never
// silently drop a payload kind from inspection.
func parseKinds(params map[string]any, def ...pipeline.PayloadKind) (map[pipeline.PayloadKind]bool, error) {
	raw, ok := params["kinds"]
	if !ok || raw == nil {
		if len(def) == 0 {
			def = allKindsList()
		}
		set := make(map[pipeline.PayloadKind]bool, len(def))
		for _, k := range def {
			set[k] = true
		}
		return set, nil
	}
	items, err := anyToStrings(raw)
	if err != nil {
		return nil, fmt.Errorf("params.kinds: %w", err)
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("params.kinds: at least one payload kind is required")
	}
	set := make(map[pipeline.PayloadKind]bool, len(items))
	for _, it := range items {
		k := pipeline.PayloadKind(it)
		if !k.Valid() {
			return nil, fmt.Errorf("params.kinds: unknown payload kind %q", it)
		}
		set[k] = true
	}
	return set, nil
}

// parseAction resolves the optional "action" param; default flag. Values
// outside flag|mask|deny (including "allow") are factory errors.
func parseAction(params map[string]any) (pipeline.Action, error) {
	raw, ok := params["action"]
	if !ok || raw == nil {
		return pipeline.ActionFlag, nil
	}
	s, err := anyToString(raw)
	if err != nil {
		return "", fmt.Errorf("params.action: %w", err)
	}
	a := pipeline.Action(s)
	if !findingActions[a] {
		return "", fmt.Errorf("params.action: %q: want flag|mask|deny (allow is not a detector action)", s)
	}
	return a, nil
}

// paramStrings resolves a required list-of-strings param. Accepts []any and
// []string (YAML decodes lists as []any).
func paramStrings(params map[string]any, key string) ([]string, error) {
	raw, ok := params[key]
	if !ok || raw == nil {
		return nil, fmt.Errorf("params.%s: required", key)
	}
	items, err := anyToStrings(raw)
	if err != nil {
		return nil, fmt.Errorf("params.%s: %w", key, err)
	}
	for _, it := range items {
		if it == "" {
			return nil, fmt.Errorf("params.%s: empty entries are not allowed", key)
		}
	}
	return items, nil
}

// paramString resolves a required non-empty string param.
func paramString(params map[string]any, key string) (string, error) {
	raw, ok := params[key]
	if !ok || raw == nil {
		return "", fmt.Errorf("params.%s: required", key)
	}
	s, err := anyToString(raw)
	if err != nil {
		return "", fmt.Errorf("params.%s: %w", key, err)
	}
	if s == "" {
		return "", fmt.Errorf("params.%s: must not be empty", key)
	}
	return s, nil
}

// paramInt resolves an int param; when absent, def is returned.
func paramInt(params map[string]any, key string, def int) (int, error) {
	raw, ok := params[key]
	if !ok || raw == nil {
		return def, nil
	}
	switch v := raw.(type) {
	case int:
		return v, nil
	case int64:
		return int(v), nil
	case float64:
		if v != float64(int(v)) {
			return 0, fmt.Errorf("params.%s: %v: must be an integer", key, v)
		}
		return int(v), nil
	case string:
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0, fmt.Errorf("params.%s: %q: must be an integer", key, v)
		}
		return n, nil
	default:
		return 0, fmt.Errorf("params.%s: %T: must be an integer", key, raw)
	}
}

// paramBool resolves a bool param; when absent, def is returned.
func paramBool(params map[string]any, key string, def bool) (bool, error) {
	raw, ok := params[key]
	if !ok || raw == nil {
		return def, nil
	}
	switch v := raw.(type) {
	case bool:
		return v, nil
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "yes", "on":
			return true, nil
		case "false", "no", "off":
			return false, nil
		default:
			return false, fmt.Errorf("params.%s: %q: must be a boolean", key, v)
		}
	default:
		return false, fmt.Errorf("params.%s: %T: must be a boolean", key, raw)
	}
}

// anyToStrings flattens []any / []string / single-string params.
func anyToStrings(raw any) ([]string, error) {
	switch v := raw.(type) {
	case []string:
		return append([]string(nil), v...), nil
	case []any:
		out := make([]string, 0, len(v))
		for i, it := range v {
			s, err := anyToString(it)
			if err != nil {
				return nil, fmt.Errorf("[%d]: %w", i, err)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		s, err := anyToString(raw)
		if err != nil {
			return nil, err
		}
		return []string{s}, nil
	}
}

// anyToString renders one param element as a string.
func anyToString(raw any) (string, error) {
	switch v := raw.(type) {
	case string:
		return v, nil
	case fmt.Stringer:
		return v.String(), nil
	default:
		return "", fmt.Errorf("%T: must be a string", raw)
	}
}

// payloadText extracts the inspected text of a payload: all message contents
// joined with "\n"; when no message has content, Body; when both are absent,
// StreamChunk. Detectors treat the result as read-only.
func payloadText(p *pipeline.Payload) string {
	var sb strings.Builder
	for _, m := range p.Messages {
		if m.Content == "" {
			continue
		}
		if sb.Len() > 0 {
			sb.WriteByte('\n')
		}
		sb.WriteString(m.Content)
	}
	if sb.Len() > 0 {
		return sb.String()
	}
	if len(p.Body) > 0 {
		return string(p.Body)
	}
	return p.StreamChunk
}

// jsonText is the JSON-step target: Body first (structured payloads carry the
// document there), falling back to the message text (an LLM output message
// may itself be the JSON document).
func jsonText(p *pipeline.Payload) string {
	if len(p.Body) > 0 {
		return string(p.Body)
	}
	return payloadText(p)
}

// finding assembles one builtin pipeline.Finding.
func finding(stepID, category, severity, span, evidence string, action pipeline.Action) pipeline.Finding {
	return pipeline.Finding{
		Step:     stepID,
		Category: category,
		Severity: severity,
		Span:     span,
		Evidence: evidence,
		Action:   action,
	}
}

// span renders "start:end" byte offsets (the convention documented on
// pipeline.Finding.Span).
func span(start, end int) string {
	return strconv.Itoa(start) + ":" + strconv.Itoa(end)
}

// clipEvidence bounds a quoted excerpt to max bytes on a rune boundary,
// marking truncation with "…".
func clipEvidence(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max - 1
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}
