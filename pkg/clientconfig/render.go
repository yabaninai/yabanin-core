package clientconfig

import (
	"encoding/json"
	"strings"

	"github.com/reireirei/yabanin/pkg/labels"
)

func withV1(base string) string {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if strings.HasSuffix(base, "/v1") {
		return base
	}
	return base + "/v1"
}

func encodeLabels(set map[string]string) string {
	if len(set) == 0 {
		return ""
	}
	return labels.Encode(labels.Set(set))
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

func mustJSON(v any) string {
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "{}\n"
	}
	return string(body) + "\n"
}

func yamlQuote(value string) string {
	if value == "" {
		return `""`
	}
	if strings.ContainsAny(value, ":#{}[]&*!|>'\"%@`") || strings.Contains(value, " ") {
		return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
	}
	return value
}
