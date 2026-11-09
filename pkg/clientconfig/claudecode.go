package clientconfig

import (
	"encoding/json"
	"strings"
)

// ClaudeSettings is the desired Claude Code settings fragment.
type ClaudeSettings struct {
	BaseURL       string
	APIKeyHelper  string
	AuthTokenEnv  string
	CustomHeaders string
}

// ClaudeCode builds Claude Code settings. helper uses apiKeyHelper; env names ANTHROPIC_AUTH_TOKEN's source.
func ClaudeCode(p Params) ClaudeSettings {
	settings := ClaudeSettings{BaseURL: strings.TrimRight(p.BaseURL, "/")}
	if p.helper() {
		settings.APIKeyHelper = "yb harness key --tool claude-code"
	} else {
		settings.AuthTokenEnv = p.keyEnv()
	}
	if len(p.Labels) > 0 {
		settings.CustomHeaders = "X-Yabanin-Labels: " + encodeLabels(p.Labels)
	}
	return settings
}

// RenderJSON renders settings.json fields. The key value is not included.
func (c ClaudeSettings) RenderJSON() string {
	env := map[string]string{
		"ANTHROPIC_BASE_URL":               c.BaseURL,
		"CLAUDE_CODE_GATEWAY_HINT_HEADERS": "1",
	}
	if c.CustomHeaders != "" {
		env["ANTHROPIC_CUSTOM_HEADERS"] = c.CustomHeaders
	}
	doc := map[string]any{"env": env}
	if c.APIKeyHelper != "" {
		doc["apiKeyHelper"] = c.APIKeyHelper
	}
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "{}\n"
	}
	return string(body) + "\n"
}

// RenderEnv renders a shell snippet that points ANTHROPIC_AUTH_TOKEN at the env name.
func (c ClaudeSettings) RenderEnv() string {
	var b strings.Builder
	b.WriteString("export ANTHROPIC_BASE_URL=" + shellQuote(c.BaseURL) + "\n")
	b.WriteString("export CLAUDE_CODE_GATEWAY_HINT_HEADERS=1\n")
	if c.AuthTokenEnv != "" {
		b.WriteString("export ANTHROPIC_AUTH_TOKEN=\"$" + c.AuthTokenEnv + "\"\n")
	}
	if c.CustomHeaders != "" {
		b.WriteString("export ANTHROPIC_CUSTOM_HEADERS=" + shellQuote(c.CustomHeaders) + "\n")
	}
	return b.String()
}
