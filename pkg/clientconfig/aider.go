package clientconfig

import "strings"

// AiderConfig is the desired Aider config. The key stays in AIDER_OPENAI_API_KEY.
type AiderConfig struct {
	BaseURL string
	Model   string
	KeyEnv  string
	Helper  bool
}

// Aider builds an Aider config.
func Aider(p Params) AiderConfig {
	return AiderConfig{BaseURL: withV1(p.BaseURL), Model: p.Model, KeyEnv: p.keyEnv(), Helper: p.helper()}
}

// RenderYAML renders ~/.aider.conf.yml without a secret.
func (c AiderConfig) RenderYAML() string {
	var b strings.Builder
	b.WriteString("openai-api-base: " + yamlQuote(c.BaseURL) + "\n")
	if c.Model != "" {
		b.WriteString("model: " + yamlQuote(c.Model) + "\n")
	}
	return b.String()
}

// RenderEnv renders the shell line that points Aider at the key env or the helper.
func (c AiderConfig) RenderEnv() string {
	if c.Helper {
		return "export AIDER_OPENAI_API_KEY=\"$(yb harness key --tool aider)\"\n"
	}
	return "export AIDER_OPENAI_API_KEY=\"$" + c.KeyEnv + "\"\n"
}
