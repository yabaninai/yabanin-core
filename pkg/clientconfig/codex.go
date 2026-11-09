package clientconfig

import (
	"fmt"
	"strings"
)

// CodexConfig is the desired Codex provider block.
type CodexConfig struct {
	Model    string
	Provider string
	BaseURL  string
	KeyEnv   string
	Helper   bool
}

// Codex builds a Codex config. The key is an env name or a helper command.
func Codex(p Params) CodexConfig {
	return CodexConfig{
		Model:    p.Model,
		Provider: p.providerID(),
		BaseURL:  withV1(p.BaseURL),
		KeyEnv:   p.keyEnv(),
		Helper:   p.helper(),
	}
}

// RenderTOML renders the managed Codex provider.
func (c CodexConfig) RenderTOML() string {
	var b strings.Builder
	fmt.Fprintf(&b, "model_provider = %q\n", c.Provider)
	if c.Model != "" {
		fmt.Fprintf(&b, "model = %q\n", c.Model)
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "[model_providers.%s]\n", c.Provider)
	b.WriteString("name = \"Yabanin\"\n")
	fmt.Fprintf(&b, "base_url = %q\n", c.BaseURL)
	b.WriteString("wire_api = \"responses\"\n")
	fmt.Fprintf(&b, "env_http_headers = { \"X-Yabanin-Labels\" = %q }\n", "YABANIN_LABELS")
	if c.Helper {
		fmt.Fprintf(&b, "\n[model_providers.%s.auth]\n", c.Provider)
		b.WriteString("command = \"yb\"\n")
		b.WriteString("args = [\"harness\", \"key\", \"--tool\", \"codex\"]\n")
		b.WriteString("refresh_interval_ms = 300000\n")
		b.WriteString("timeout_ms = 5000\n")
		return b.String()
	}
	fmt.Fprintf(&b, "env_key = %q\n", c.KeyEnv)
	return b.String()
}
