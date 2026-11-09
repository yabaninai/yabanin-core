package clientconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/labels"
)

func TestRenderGoldens(t *testing.T) {
	params := Params{BaseURL: "https://gw.example", Model: "gpt", Labels: labels.Set{"team": "payments"}}
	cases := []struct {
		name string
		mode string
		got  string
	}{
		{"codex", "env", Codex(withMode(params, "env")).RenderTOML()},
		{"codex", "helper", Codex(withMode(params, "helper")).RenderTOML()},
		{"claude-code", "env", ClaudeCode(withMode(params, "env")).RenderEnv()},
		{"claude-code", "helper", ClaudeCode(withMode(params, "helper")).RenderJSON()},
		{"opencode", "env", OpenCode(withMode(params, "env"), []string{"gpt"}).RenderJSON()},
		{"opencode", "helper", OpenCode(withMode(params, "helper"), []string{"gpt"}).RenderJSON()},
		{"continue", "env", Continue(withMode(params, "env")).RenderYAML()},
		{"continue", "helper", Continue(withMode(params, "helper")).RenderYAML()},
		{"cline", "env", Cline(withMode(params, "env"))},
		{"cline", "helper", Cline(withMode(params, "helper"))},
		{"aider", "env", Aider(withMode(params, "env")).RenderYAML() + Aider(withMode(params, "env")).RenderEnv()},
		{"aider", "helper", Aider(withMode(params, "helper")).RenderYAML() + Aider(withMode(params, "helper")).RenderEnv()},
	}
	for _, tc := range cases {
		t.Run(tc.name+"_"+tc.mode, func(t *testing.T) {
			if strings.Contains(tc.got, "sk-") || strings.Contains(tc.got, "super-secret") {
				t.Fatalf("secret leaked:\n%s", tc.got)
			}
			path := filepath.Join("testdata", tc.name+"_"+tc.mode+".golden")
			want, err := os.ReadFile(path) //nolint:gosec // G304: path is a testdata golden name, not user input
			if err != nil {
				t.Fatal(err)
			}
			if tc.got != string(want) {
				t.Fatalf("got\n%s\nwant\n%s", tc.got, want)
			}
		})
	}
}

func TestCodexTOMLStrings(t *testing.T) {
	env := Codex(Params{BaseURL: "https://gw.example", KeyMode: "env"}).RenderTOML()
	if !strings.Contains(env, `wire_api = "responses"`) || !strings.Contains(env, `env_key = "YABANIN_API_KEY"`) || strings.Contains(env, "[model_providers.yabanin.auth]") {
		t.Fatalf("%s", env)
	}
	helper := Codex(Params{BaseURL: "https://gw.example/v1", KeyMode: "helper", Model: "gpt"}).RenderTOML()
	for _, needle := range []string{`model_provider = "yabanin"`, `model = "gpt"`, `base_url = "https://gw.example/v1"`, `command = "yb"`, `args = ["harness", "key", "--tool", "codex"]`} {
		if !strings.Contains(helper, needle) {
			t.Fatalf("missing %s\n%s", needle, helper)
		}
	}
}

func withMode(p Params, mode string) Params {
	p.KeyMode = mode
	return p
}
