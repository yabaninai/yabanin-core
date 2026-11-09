package llmjudge

import (
	"context"
	"embed"
	"fmt"
	"strings"
	"text/template"
)

//go:embed judges
var judgesFS embed.FS

// Prompt is one immutable judge prompt version. Body is the raw template
// (text/template); at run time the step renders it with promptData.
type Prompt struct {
	// Ref is the canonical reference the prompt was loaded with
	// ("judges/toxicity@2").
	Ref string
	// Version is the template version identifier the source resolved this
	// responses via X-Policy-Judge-Version). Embedded sources report the
	// ref's <version> part; store-backed sources report the immutable
	// version number the label pointed at resolve time. "" when a source
	// does not version its templates. It never affects rendering or
	// verdicts.
	Version string
	// Body is the template text.
	Body string
}

// PromptSource supplies versioned judge prompts. The pipeline core treats a
// prompt as a versioned RESOURCE: refs are immutable (name@version), so a
// policy always renders byte-identical instructions — this is the property
// that makes verdicts auditable across policy versions.
//
// replaces it via Deps.Prompts with a store-backed implementation. The
type PromptSource interface {
	// Load returns the prompt for ref ("judges/toxicity@2"). Implementations
	// must return an error for unknown refs or malformed ref syntax — the
	// step factory surfaces it as a policy load error.
	Load(ctx context.Context, ref string) (Prompt, error)
}

// ParseRef splits a prompt reference "judges/toxicity@2" into its name and
// version parts. The version is REQUIRED — "latest" style resolution would
// break the immutability a policy load depends on. Name must live in the
// "judges/" namespace and contain no whitespace or further '@'.
func ParseRef(ref string) (name, version string, err error) {
	at := strings.LastIndex(ref, "@")
	if at <= 0 || at == len(ref)-1 {
		return "", "", fmt.Errorf("prompt ref %q: want <judges/<name>@<version>>", ref)
	}
	name, version = ref[:at], ref[at+1:]
	if !strings.HasPrefix(name, "judges/") || strings.TrimPrefix(name, "judges/") == "" ||
		strings.TrimSpace(name) != name ||
		strings.ContainsAny(name, " \t\n@") || strings.ContainsAny(version, " \t\n@/") {
		return "", "", fmt.Errorf("prompt ref %q: want <judges/<name>@<version>>", ref)
	}
	return name, version, nil
}

// EmbeddedPromptSource serves the judge prompts compiled into this package:
// judges/<name>/<version>.md. Version directories keep every shipped version
// readable and diffable in review.
type EmbeddedPromptSource struct{}

// Load resolves ref against the embedded judges/ filesystem.
func (EmbeddedPromptSource) Load(_ context.Context, ref string) (Prompt, error) {
	name, version, err := ParseRef(ref)
	if err != nil {
		return Prompt{}, err
	}
	body, err := judgesFS.ReadFile(name + "/" + version + ".md")
	if err != nil {
		return Prompt{}, fmt.Errorf("prompt ref %q: not found in embedded judges: %w", ref, err)
	}
	return Prompt{Ref: ref, Version: version, Body: string(body)}, nil
}

// promptData is the template payload rendered into a judge prompt. Categories
// is the comma-joined taxonomy from step params (empty when the policy does
// not pin one — the prompt then falls back to its own default taxonomy).
type promptData struct {
	Input      string
	Categories string
}

// compilePromptTemplate parses a prompt body once (factory time). Executed
// per run with missingkey=error so a template/step contract drift fails the
// step loudly instead of sending half-rendered instructions to a judge.
func compilePromptTemplate(ref, body string) (*template.Template, error) {
	tpl, err := template.New(ref).Option("missingkey=error").Parse(body)
	if err != nil {
		return nil, fmt.Errorf("prompt ref %q: template parse: %w", ref, err)
	}
	return tpl, nil
}

// renderPrompt executes tpl against data; any execution error is a step
// error (on_error semantics apply).
func renderPrompt(tpl *template.Template, data promptData) (string, error) {
	var sb strings.Builder
	if err := tpl.Execute(&sb, data); err != nil {
		return "", fmt.Errorf("judge prompt render: %w", err)
	}
	return sb.String(), nil
}
