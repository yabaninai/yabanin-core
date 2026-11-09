// Package cache provides semantic cache storage with Redis and pgvector backends.
package cache

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
	"unicode"
)

// NormalizationPolicy controls how aggressively prompts are normalized for caching.
type NormalizationPolicy int

const (
	// PolicyStrict produces a hash identical to the raw JSON (sorted keys only).
	PolicyStrict NormalizationPolicy = iota
	// PolicyNormalized trims whitespace, strips volatile fields (request_id, timestamp),
	// and sorts keys — the default balanced policy.
	PolicyNormalized
	// PolicyAggressive applies lowercasing and punctuation stripping on top of normalized.
	PolicyAggressive
)

// NormalizeMessagesJSON canonicalizes a JSON body containing a "messages" array
// so that semantically equivalent prompts produce identical byte sequences.
// Uses PolicyNormalized by default.
func NormalizeMessagesJSON(body []byte) ([]byte, error) {
	return NormalizeWithPolicy(body, PolicyNormalized)
}

// NormalizeWithPolicy applies the given normalization policy to a JSON body.
func NormalizeWithPolicy(body []byte, policy NormalizationPolicy) ([]byte, error) {
	raw, err := decodeNumberPreserving(body)
	if err != nil {
		return nil, err
	}

	messages, ok := raw["messages"].([]interface{})
	if !ok {
		return body, nil
	}

	for _, m := range messages {
		msg, ok := m.(map[string]interface{})
		if !ok {
			continue
		}
		normalizeMessage(msg, policy)
	}

	// Remove empty or nil messages.
	var filtered []interface{}
	for _, m := range messages {
		if m == nil {
			continue
		}
		if msg, ok := m.(map[string]interface{}); ok && len(msg) == 0 {
			continue
		}
		filtered = append(filtered, m)
	}
	raw["messages"] = filtered

	// Strip volatile top-level keys for normalized/aggressive policies.
	switch policy {
	case PolicyNormalized, PolicyAggressive:
		delete(raw, "request_id")
		delete(raw, "timestamp")
		delete(raw, "cache_control")
	}

	return sortedJSON(raw)
}

// normalizeMessage applies per-message canonicalization based on the policy.
func normalizeMessage(msg map[string]interface{}, policy NormalizationPolicy) {
	// CACHE-02: PolicyStrict is documented as raw-JSON fidelity (sorted keys
	// only). String fields — content, name, role, and tool-call argument
	// strings — are payload bytes, not tokens to clean: no TrimSpace, no
	// arguments re-serialization. Whitespace-normalizing spelling belongs to
	// the balanced policies below.
	if policy == PolicyStrict {
		return
	}

	content, _ := msg["content"].(string)
	if content != "" {
		msg["content"] = strings.TrimSpace(content)
		if policy == PolicyAggressive {
			msg["content"] = strings.ToLower(msg["content"].(string))
			msg["content"] = stripPunctuation(msg["content"].(string))
		}
	}

	name, _ := msg["name"].(string)
	if name != "" {
		msg["name"] = strings.TrimSpace(name)
	}

	if tools, ok := msg["tool_calls"].([]interface{}); ok {
		for _, t := range tools {
			tc, ok := t.(map[string]interface{})
			if !ok {
				continue
			}
			if args, ok := tc["function"].(map[string]interface{}); ok {
				if a := args["arguments"]; a != nil {
					if s, ok := a.(string); ok {
						parsed, err := decodeNumberPreserving([]byte(s))
						if err == nil {
							sorted, serr := sortedJSON(parsed)
							if serr == nil {
								args["arguments"] = string(sorted)
							}
						}
					}
				}
			}
		}
	}

	if role, ok := msg["role"].(string); ok {
		msg["role"] = strings.TrimSpace(role)
	}
}

// stripPunctuation removes non-alphanumeric characters except spaces.
func stripPunctuation(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == ' ' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// decodeNumberPreserving decodes a JSON object keeping every number literal
// verbatim (CACHE-02). A plain Unmarshal round-trips numbers through float64,
// which silently rewrote beyond-precision integers (2^53+1 became 2^53) and
// re-spelled literals (1e3 became 1000): two distinguishable upstream requests
// normalized onto one byte sequence and shared an exact-cache response. With
// UseNumber the literals survive decoding and json.Marshal re-emits them
// byte-verbatim, so differently spelled numbers stay distinct in the key
// space — the safe direction (a lower hit rate, never a wrong hit). Only
// decoded values flow through here: every json.Number is a syntactically
// valid literal, so marshalling cannot fail on input-produced numbers.
func decodeNumberPreserving(data []byte) (map[string]interface{}, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var raw map[string]interface{}
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// sortedJSON produces a deterministic JSON byte representation with keys sorted alphabetically.
func sortedJSON(v interface{}) ([]byte, error) {
	return json.Marshal(sortValue(v))
}

// sortValue recursively sorts map keys for deterministic serialization.
func sortValue(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		sorted := make(map[string]interface{}, len(keys))
		for _, k := range keys {
			sorted[k] = sortValue(val[k])
		}
		return sorted
	case []interface{}:
		for i, elem := range val {
			val[i] = sortValue(elem)
		}
		return val
	default:
		return v
	}
}

// NormalizePromptHash is a convenience that normalizes the body and computes its SHA-256.
func NormalizePromptHash(body []byte) (string, error) {
	normalized, err := NormalizeMessagesJSON(body)
	if err != nil {
		return "", err
	}
	return ComputePromptHash(normalized), nil
}

// ---------------------------------------------------------------------------
// Benchmark helpers for normalization.
// ---------------------------------------------------------------------------

// FastHash computes SHA-256 of the normalized prompt without full JSON marshalling.
// Used in hot paths where we already have a string body.
func FastHash(body []byte) string {
	return ComputePromptHash(body)
}
