package clientconfig

// OpenCodeModel is one model entry advertised to OpenCode.
type OpenCodeModel struct {
	Name string `json:"name"`
}

// OpenCodeProvider is the yabanin provider object.
type OpenCodeProvider struct {
	NPM     string                   `json:"npm"`
	Name    string                   `json:"name"`
	Options OpenCodeOptions          `json:"options"`
	Models  map[string]OpenCodeModel `json:"models,omitempty"`
}

// OpenCodeOptions is the OpenAI-compatible provider options. APIKey is an env reference.
type OpenCodeOptions struct {
	BaseURL string            `json:"baseURL"`
	APIKey  string            `json:"apiKey"`
	Headers map[string]string `json:"headers,omitempty"`
}

// OpenCode builds the provider. apiKey is always {env:KEY}, never a secret.
func OpenCode(p Params, models []string) OpenCodeProvider {
	provider := OpenCodeProvider{
		NPM:  "@ai-sdk/openai-compatible",
		Name: "Yabanin",
		Options: OpenCodeOptions{
			BaseURL: withV1(p.BaseURL),
			APIKey:  "{env:" + p.keyEnv() + "}",
		},
		Models: map[string]OpenCodeModel{},
	}
	if len(p.Labels) > 0 {
		provider.Options.Headers = map[string]string{"X-Yabanin-Labels": encodeLabels(p.Labels)}
	}
	seen := map[string]bool{}
	add := func(id string) {
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		provider.Models[id] = OpenCodeModel{Name: id}
	}
	for _, id := range models {
		add(id)
	}
	add(p.Model)
	if len(provider.Models) == 0 {
		provider.Models = nil
	}
	return provider
}

// RenderJSON renders the provider object.
func (o OpenCodeProvider) RenderJSON() string { return mustJSON(o) }
