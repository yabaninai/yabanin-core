package clientconfig

import "strings"

// ContinueModel is one Continue model entry.
type ContinueModel struct {
	Name     string
	Provider string
	APIBase  string
	APIKey   string
	Headers  map[string]string
}

// ContinueModels is the desired Continue model list.
type ContinueModels struct {
	Models []ContinueModel
	Note   string
}

// Continue builds Continue models. The API key field references an env name.
func Continue(p Params) ContinueModels {
	headers := map[string]string{}
	if len(p.Labels) > 0 {
		headers["X-Yabanin-Labels"] = encodeLabels(p.Labels)
	}
	chat := ContinueModel{
		Name:     firstNonEmpty(p.Model, "yabanin"),
		Provider: "openai",
		APIBase:  withV1(p.BaseURL),
		APIKey:   "${" + p.keyEnv() + "}",
		Headers:  headers,
	}
	out := ContinueModels{Models: []ContinueModel{chat}}
	if p.AutocompleteModel != "" {
		out.Models = append(out.Models, ContinueModel{
			Name:     p.AutocompleteModel,
			Provider: "openai",
			APIBase:  withV1(p.BaseURL),
			APIKey:   "${" + p.keyEnv() + "}",
			Headers:  headers,
		})
	}
	if p.helper() {
		out.Note = "Continue cannot call a key helper; export " + p.keyEnv() + " instead of pasting the key"
	}
	return out
}

// RenderYAML renders ~/.continue/config.yaml models.
func (c ContinueModels) RenderYAML() string {
	var b strings.Builder
	if c.Note != "" {
		b.WriteString("# " + c.Note + "\n")
	}
	b.WriteString("models:\n")
	for _, model := range c.Models {
		b.WriteString("  - name: " + yamlQuote(model.Name) + "\n")
		b.WriteString("    provider: openai\n")
		b.WriteString("    apiBase: " + yamlQuote(model.APIBase) + "\n")
		b.WriteString("    apiKey: " + yamlQuote(model.APIKey) + "\n")
		if len(model.Headers) > 0 {
			b.WriteString("    requestOptions:\n      headers:\n")
			b.WriteString("        X-Yabanin-Labels: " + yamlQuote(model.Headers["X-Yabanin-Labels"]) + "\n")
		}
	}
	return b.String()
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
