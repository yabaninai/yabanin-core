package handlers

// AUX-14b: sanitized before/after snapshots for audit entries.
//
// A snapshot is the JSON encoding of the entity state an admin action
// observed. Before it is stored on the journal entry it is walked and every
// value whose key looks secret-bearing (key_hash, password_hash, token,
// authorization, …) is replaced with a fixed placeholder — the journal must
// never become a side channel for credentials, even though its HTTP surface
// is root-only today. Nested objects and arrays are sanitized recursively;
// scalar arrays are left untouched.
//
// Size is capped: a pathological payload cannot balloon the in-memory
// journal (cap 2000→1000 entries) — an oversized snapshot degrades to a
// {"truncated":true} marker instead of being stored.

import (
	"encoding/json"
	"strings"
)

const (
	// auditSnapshotMaxBytes caps one serialized snapshot after sanitization.
	auditSnapshotMaxBytes = 16 * 1024
	// redactedPlaceholder replaces every secret-like value.
	redactedPlaceholder = "[redacted]"
	// auditTruncatedMarker replaces a snapshot that exceeded the size cap.
	auditTruncatedMarker = `{"truncated":true}`
)

// auditSecretKeyFragments are matched against lowercased map keys. A key is
// secret-bearing when any fragment occurs in it (so key_hash, password_hash,
// upstream_api_key, Authorization, X-Api-Token all match).
var auditSecretKeyFragments = []string{
	"password",
	"passwd",
	"secret",
	"token",
	"hash",
	"credential",
	"api_key",
	"apikey",
	"authorization",
	"private_key",
	"session_key",
}

// auditSnapshot sanitizes and encodes v for the audit journal. A nil v (or
// anything that fails to round-trip through JSON) yields nil, and the field
// is omitted from the entry.
func auditSnapshot(v any) json.RawMessage {
	if v == nil {
		return nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var node any
	if err := json.Unmarshal(raw, &node); err != nil {
		return nil
	}
	sanitized := maskAuditNode(node)
	out, err := json.Marshal(sanitized)
	if err != nil {
		return nil
	}
	if len(out) > auditSnapshotMaxBytes {
		return json.RawMessage(auditTruncatedMarker)
	}
	return out
}

// maskAuditNode walks decoded JSON and returns a copy with secret-like map
// values replaced. Non-map containers are copied element-wise; scalars pass
// through.
func maskAuditNode(node any) any {
	switch typed := node.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, value := range typed {
			if isAuditSecretKey(key) {
				out[key] = redactedPlaceholder
				continue
			}
			out[key] = maskAuditNode(value)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, value := range typed {
			out[i] = maskAuditNode(value)
		}
		return out
	default:
		return node
	}
}

// isAuditSecretKey reports whether a JSON object key looks secret-bearing.
func isAuditSecretKey(key string) bool {
	lowered := strings.ToLower(key)
	for _, fragment := range auditSecretKeyFragments {
		if strings.Contains(lowered, fragment) {
			return true
		}
	}
	return false
}
