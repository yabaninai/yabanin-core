// Package redact provides the shared credential scrubber used at every
// durable boundary: the producer (before the event reaches the Redis stream)
// and the consumer (before SQL persistence). One implementation keeps the
// producer and consumer redaction guarantees identical.
package redact

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
)

var (
	secretAssignment = regexp.MustCompile(`(?i)(\b(?:authorization|bearer|api[-_]?key|access[-_]?token|refresh[-_]?token|token|password|passwd|secret|private[-_]?key)\b\s*["']?\s*[:=]\s*["']?)([^\s"',;}]+)`)
	bearerSecret     = regexp.MustCompile(`(?i)(\bbearer\s+)([a-z0-9._~+/=-]{8,})`)
	awkSecretKey     = regexp.MustCompile(`(?i)(\b(?:aws_access_key_id|aws_secret_access_key|aws_session_token)\b\s*[=:]\s*)([^\s,;]+)`)
)

// ScrubSecrets redacts credential-shaped assignments and bearer values while
// retaining surrounding diagnostic prose; JSON-aware (nested keys, base64-wrapped
// JSON) and safe to apply repeatedly.
func ScrubSecrets(text string) string {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return text
	}
	var value any
	if json.Unmarshal([]byte(trimmed), &value) == nil {
		if scrubbed, changed := scrubJSON(value); changed {
			if encoded, err := json.Marshal(scrubbed); err == nil {
				return string(encoded)
			}
		}
	}
	if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil && json.Valid(decoded) {
		var wrapped any
		if json.Unmarshal(decoded, &wrapped) == nil {
			if scrubbed, changed := scrubJSON(wrapped); changed {
				encoded, marshalErr := json.Marshal(scrubbed)
				if marshalErr == nil {
					return base64.StdEncoding.EncodeToString(encoded)
				}
			}
		}
	}
	text = bearerSecret.ReplaceAllString(text, `${1}[REDACTED]`)
	text = secretAssignment.ReplaceAllString(text, `${1}[REDACTED]`)
	return awkSecretKey.ReplaceAllString(text, `${1}[REDACTED]`)
}

func scrubJSON(value any) (any, bool) {
	switch node := value.(type) {
	case map[string]any:
		changed := false
		for key, child := range node {
			if secretKeyName.MatchString(key) {
				node[key] = "[REDACTED]"
				changed = true
				continue
			}
			clean, childChanged := scrubJSON(child)
			node[key] = clean
			changed = changed || childChanged
		}
		return node, changed
	case []any:
		changed := false
		for i, child := range node {
			clean, childChanged := scrubJSON(child)
			node[i] = clean
			changed = changed || childChanged
		}
		return node, changed
	case string:
		clean := ScrubSecrets(node)
		return clean, clean != node
	default:
		return value, false
	}
}

var secretKeyName = regexp.MustCompile(`(?i)^(authorization|bearer|api[-_]?key|access[-_]?token|refresh[-_]?token|token|password|passwd|secret|private[-_]?key|aws_secret_access_key|aws_session_token)$`)

// debugLogResponse returns true when YABANIN_DEBUG_LOG_RESPONSE=true.
