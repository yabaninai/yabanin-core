package llmjudge

import (
	"context"
	"strings"
	"testing"
)

func TestParseRef(t *testing.T) {
	for _, tc := range []struct {
		ref, wantName, wantVer string
	}{
		{"judges/toxicity@2", "judges/toxicity", "2"},
		{"judges/pii.v2@10", "judges/pii.v2", "10"},
	} {
		name, ver, err := ParseRef(tc.ref)
		if err != nil || name != tc.wantName || ver != tc.wantVer {
			t.Errorf("ParseRef(%q) = %q, %q, %v", tc.ref, name, ver, err)
		}
	}
	for _, bad := range []string{
		"",
		"judges/toxicity",       // no version
		"toxicity@2",            // not in the judges/ namespace
		"judges/@2",             // empty name
		"judges/toxicity@",      // empty version
		"judges/tox city@2",     // whitespace
		"judges/toxicity@la st", // whitespace in version
		"@2",
	} {
		if _, _, err := ParseRef(bad); err == nil {
			t.Errorf("ParseRef(%q) must fail", bad)
		}
	}
}

func TestEmbeddedPromptSource_LoadsShippedVersions(t *testing.T) {
	src := EmbeddedPromptSource{}
	for _, ref := range []string{"judges/toxicity@1", "judges/toxicity@2"} {
		p, err := src.Load(context.Background(), ref)
		if err != nil {
			t.Fatalf("Load(%q): %v", ref, err)
		}
		if p.Ref != ref || len(p.Body) == 0 {
			t.Fatalf("Load(%q) = %+v", ref, p)
		}
		// gateway's X-Policy-Judge-Version header input).
		if want := strings.TrimPrefix(ref, "judges/toxicity@"); p.Version != want {
			t.Errorf("Load(%q).Version = %q, want %q", ref, p.Version, want)
		}
		if !strings.Contains(p.Body, "{{.Input}}") {
			t.Errorf("prompt %q does not render {{.Input}}", ref)
		}
	}
	if _, err := src.Load(context.Background(), "judges/ghost@9"); err == nil {
		t.Error("unknown ref must fail")
	}
}

func TestRenderPrompt_MissingKeyFailsLoudly(t *testing.T) {
	tpl, err := compilePromptTemplate("r", "in={{.Input}} cats={{.Missing}}")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if _, err := renderPrompt(tpl, promptData{Input: "x"}); err == nil {
		t.Fatal("rendering with a missing key must fail (missingkey=error)")
	}
}

func TestRenderPrompt_Categories(t *testing.T) {
	tpl, err := compilePromptTemplate("r", "cats={{.Categories}}")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	out, err := renderPrompt(tpl, promptData{Categories: "toxicity, pii"})
	if err != nil || out != "cats=toxicity, pii" {
		t.Fatalf("render = %q, %v", out, err)
	}
}
