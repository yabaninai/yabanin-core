package clientconfig

import "strings"

// Cline returns setup instructions. Cline stores settings in the VS Code extension, so this is not applied automatically.
func Cline(p Params) string {
	var b strings.Builder
	b.WriteString("Cline stores its provider in VS Code extension state, so yb does not edit it.\n")
	b.WriteString("In Cline, choose an OpenAI-compatible provider.\n")
	b.WriteString("Base URL: " + withV1(p.BaseURL) + "\n")
	if p.Model != "" {
		b.WriteString("Model: " + p.Model + "\n")
	}
	if p.helper() {
		b.WriteString("Do not paste the API key. Put the output of `yb key print` into Cline's key field, or export " + p.keyEnv() + ".\n")
	} else {
		b.WriteString("Do not paste the API key. Set the key field from the environment variable " + p.keyEnv() + ".\n")
	}
	if len(p.Labels) > 0 {
		b.WriteString("Custom header: X-Yabanin-Labels: " + encodeLabels(p.Labels) + "\n")
	}
	return b.String()
}
