package auditlog

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
)

var (
	auditSecretKey = regexp.MustCompile(`(?i)^(authorization|bearer|api[-_]?key|access[-_]?token|refresh[-_]?token|token|password|passwd|secret|private[-_]?key|aws_secret_access_key|aws_session_token)$`)
	auditSecretKV  = regexp.MustCompile(`(?i)(\b(?:authorization|bearer|api[-_]?key|access[-_]?token|refresh[-_]?token|token|password|passwd|secret|private[-_]?key|aws_secret_access_key|aws_session_token)\b\s*["']?\s*[:=]\s*["']?)([^\s"',;}]+)`)
	auditBearer    = regexp.MustCompile(`(?i)(\bbearer\s+)([a-z0-9._~+/=-]{8,})`)
)

// scrubAuditSecrets is applied before hash calculation and durable insertion.
// Recognized values are masked while ordinary audit prose remains readable.
func scrubAuditSecrets(text string) string {
	if strings.TrimSpace(text) == "" {
		return text
	}
	var value any
	if json.Unmarshal([]byte(text), &value) == nil {
		if clean, changed := scrubAuditJSON(value); changed {
			if encoded, err := json.Marshal(clean); err == nil {
				return string(encoded)
			}
		}
	}
	trimmed := strings.TrimSpace(text)
	if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil && json.Valid(decoded) {
		var wrapped any
		if json.Unmarshal(decoded, &wrapped) == nil {
			if clean, changed := scrubAuditJSON(wrapped); changed {
				if encoded, marshalErr := json.Marshal(clean); marshalErr == nil {
					return base64.StdEncoding.EncodeToString(encoded)
				}
			}
		}
	}
	text = auditBearer.ReplaceAllString(text, `${1}[REDACTED]`)
	return auditSecretKV.ReplaceAllString(text, `${1}[REDACTED]`)
}

func scrubAuditJSON(value any) (any, bool) {
	switch node := value.(type) {
	case map[string]any:
		changed := false
		for key, child := range node {
			if auditSecretKey.MatchString(key) {
				node[key] = "[REDACTED]"
				changed = true
				continue
			}
			clean, childChanged := scrubAuditJSON(child)
			node[key] = clean
			changed = changed || childChanged
		}
		return node, changed
	case []any:
		changed := false
		for i, child := range node {
			clean, childChanged := scrubAuditJSON(child)
			node[i] = clean
			changed = changed || childChanged
		}
		return node, changed
	case string:
		clean := scrubAuditSecrets(node)
		return clean, clean != node
	default:
		return value, false
	}
}
