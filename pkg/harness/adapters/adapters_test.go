package adapters

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/harness"
	"github.com/reireirei/yabanin/pkg/labels"
)

func testParams() ConnectParams {
	return ConnectParams{
		GatewayURL:   "https://gw.example",
		Model:        "gpt",
		LabelsMode:   "static",
		StaticLabels: labels.Set{"team": "payments"},
		Experimental: true,
	}
}

func TestAdapterLifecycles(t *testing.T) {
	t.Setenv("CODEX_HOME", "")
	t.Setenv("SHELL", "/bin/zsh")
	foreign := map[string]string{
		"codex":       "owner = \"me\"\nmodel_provider = \"openai\"\n",
		"claude-code": "{\n  \"theme\": \"dark\",\n  \"env\": {\n    \"ANTHROPIC_API_KEY\": \"foreign-token\"\n  }\n}\n",
		"opencode":    "{\n  \"plugin\": [\"other\"]\n}\n",
		"continue":    "name: foreign\n",
		"aider":       "theme: dark\n",
		"shell":       "alias ll='ls'\n",
	}
	for _, id := range []string{"codex", "claude-code", "opencode", "continue", "aider", "shell"} {
		t.Run(id, func(t *testing.T) {
			adapter := mustAdapter(t, id)
			t.Run("clean", func(t *testing.T) {
				home := t.TempDir()
				plan := mustPlan(t, adapter, home, testParams())
				if len(plan.Changes) == 0 {
					t.Fatal("empty plan")
				}
				eng := &harness.Engine{Home: home}
				if _, err := eng.Apply(plan); err != nil {
					t.Fatal(err)
				}
				again := mustPlan(t, adapter, home, testParams())
				if len(again.Changes) != 0 {
					t.Fatalf("second plan has %d changes", len(again.Changes))
				}
				if _, err := eng.Rollback(plan.Tool, adapter.Unapply); err != nil {
					t.Fatal(err)
				}
				for _, change := range plan.Changes {
					if _, err := os.Stat(change.Path); !os.IsNotExist(err) {
						t.Fatalf("created file remains %s", change.Path)
					}
				}
			})
			t.Run("foreign", func(t *testing.T) {
				home := t.TempDir()
				det := adapter.Detect(home, nil)
				before := []byte(foreign[id])
				if err := os.MkdirAll(filepath.Dir(det.ConfigPath), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(det.ConfigPath, before, 0o600); err != nil {
					t.Fatal(err)
				}
				plan := mustPlan(t, adapter, home, testParams())
				primary := changeByPath(t, plan, det.ConfigPath)
				if bytes.Equal(primary.Before, primary.After) {
					t.Fatal("plan did not change the foreign file")
				}
				matchGolden(t, id, "before", primary.Before)
				matchGolden(t, id, "after", primary.After)
				eng := &harness.Engine{Home: home}
				if _, err := eng.Apply(plan); err != nil {
					t.Fatal(err)
				}
				if _, err := eng.Rollback(id, adapter.Unapply); err != nil {
					t.Fatal(err)
				}
				got, err := readTemp(det.ConfigPath)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, before) {
					t.Fatalf("exact rollback\n%s", got)
				}
			})
			t.Run("surgical", func(t *testing.T) {
				home := t.TempDir()
				det := adapter.Detect(home, nil)
				before := []byte(foreign[id])
				if err := os.MkdirAll(filepath.Dir(det.ConfigPath), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(det.ConfigPath, before, 0o600); err != nil {
					t.Fatal(err)
				}
				plan := mustPlan(t, adapter, home, testParams())
				eng := &harness.Engine{Home: home}
				if _, err := eng.Apply(plan); err != nil {
					t.Fatal(err)
				}
				edited := mutate(id, planChange(t, plan, det.ConfigPath).After)
				if err := os.WriteFile(det.ConfigPath, edited, 0o600); err != nil {
					t.Fatal(err)
				}
				report, err := eng.Rollback(id, adapter.Unapply)
				if err != nil {
					t.Fatal(err)
				}
				if report.Status != "rolled_back" && report.Status != "partially_rolled_back" {
					t.Fatalf("status %s %+v", report.Status, report.Files)
				}
				got, err := readTemp(det.ConfigPath)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Contains(got, []byte("user-kept")) {
					t.Fatalf("lost the manual edit\n%s", got)
				}
				if bytes.Contains(got, []byte("yabanin:"+id+":")) || bytes.Contains(got, []byte("yb harness key")) {
					t.Fatalf("managed content remains\n%s", got)
				}
				matchGolden(t, id, "rolledback", got)
			})
		})
	}
}

func TestConflictsAndLimits(t *testing.T) {
	t.Setenv("CODEX_HOME", "")
	t.Setenv("SHELL", "/bin/zsh")
	home := t.TempDir()
	codex := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(codex), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(codex, []byte("[model_providers.yabanin]\nname = \"x\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := mustAdapter(t, "codex").Plan(home, testParams()); err == nil || !strings.Contains(err.Error(), "--provider-id") {
		t.Fatalf("%v", err)
	}
	settings := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte("{\"apiKeyHelper\":\"other\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	claude := mustAdapter(t, "claude-code")
	if _, err := claude.Plan(home, testParams()); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("%v", err)
	}
	forced := testParams()
	forced.Force = true
	if _, err := claude.Plan(home, forced); err != nil {
		t.Fatal(err)
	}
	jsonc := filepath.Join(home, ".config", "opencode", "opencode.jsonc")
	if err := os.MkdirAll(filepath.Dir(jsonc), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jsonc, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := mustAdapter(t, "opencode").Plan(home, testParams()); err == nil || !strings.Contains(err.Error(), "opencode.jsonc") {
		t.Fatalf("%v", err)
	}
	plain := testParams()
	plain.Experimental = false
	if _, err := mustAdapter(t, "continue").Plan(t.TempDir(), plain); err == nil || !strings.Contains(err.Error(), "verify with the tool's current docs") {
		t.Fatalf("%v", err)
	}
	if _, err := mustAdapter(t, "aider").Plan(t.TempDir(), plain); err == nil || !strings.Contains(err.Error(), "--experimental") {
		t.Fatalf("%v", err)
	}
	warnHome := t.TempDir()
	warnPath := filepath.Join(warnHome, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(warnPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(warnPath, []byte("{\"env\":{\"ANTHROPIC_API_KEY\":\"foreign-token\",\"ANTHROPIC_CUSTOM_HEADERS\":\"X-Existing: 1\"}}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	warned, err := claude.Plan(warnHome, testParams())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(warned.Warnings, " "), "ANTHROPIC_API_KEY") {
		t.Fatalf("warnings %v", warned.Warnings)
	}
	after := string(changeByPath(t, warned, warnPath).After)
	if !strings.Contains(after, "X-Existing: 1\\nX-Yabanin-Labels: team=payments") && !strings.Contains(after, "X-Existing: 1\nX-Yabanin-Labels: team=payments") {
		t.Fatalf("%s", after)
	}
}

func TestShellSyntax(t *testing.T) {
	t.Setenv("CODEX_HOME", "")
	home := t.TempDir()
	t.Setenv("SHELL", "/bin/zsh")
	plan := mustPlan(t, mustAdapter(t, "shell"), home, testParams())
	body := string(plan.Changes[0].After)
	if strings.Contains(body, "OPENAI_BASE_URL") || !strings.Contains(body, `YABANIN_API_KEY="$(yb key print 2>/dev/null)"`) {
		t.Fatalf("%s", body)
	}
	global := testParams()
	global.GlobalEnv = true
	plan = mustPlan(t, mustAdapter(t, "shell"), t.TempDir(), global)
	if !strings.Contains(string(plan.Changes[0].After), "OPENAI_BASE_URL") {
		t.Fatalf("%s", plan.Changes[0].After)
	}
	t.Setenv("SHELL", "/usr/bin/fish")
	plan = mustPlan(t, mustAdapter(t, "shell"), t.TempDir(), testParams())
	if !strings.Contains(string(plan.Changes[0].After), "set -gx YABANIN_GATEWAY_URL") {
		t.Fatalf("%s", plan.Changes[0].After)
	}
}

func TestUnsupportedList(t *testing.T) {
	for _, id := range []string{"cursor", "cline", "roo-code", "kilo-code", "zed", "jetbrains", "copilot", "gemini-cli"} {
		adapter := mustAdapter(t, id)
		ok, reason := adapter.Supported()
		if ok || reason == "" {
			t.Fatalf("%s supported %v %q", id, ok, reason)
		}
		if _, err := adapter.Plan(t.TempDir(), testParams()); err == nil {
			t.Fatalf("%s plan succeeded", id)
		}
	}
}

func mustAdapter(t *testing.T, id string) Adapter {
	t.Helper()
	adapter, ok := ByID(id)
	if !ok {
		t.Fatalf("missing %s", id)
	}
	return adapter
}

func mustPlan(t *testing.T, adapter Adapter, home string, p ConnectParams) harness.Plan {
	t.Helper()
	plan, err := adapter.Plan(home, p)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func changeByPath(t *testing.T, plan harness.Plan, path string) harness.Change {
	t.Helper()
	change := planChange(t, plan, path)
	return *change
}

func planChange(t *testing.T, plan harness.Plan, path string) *harness.Change {
	t.Helper()
	for i := range plan.Changes {
		if plan.Changes[i].Path == path {
			return &plan.Changes[i]
		}
	}
	t.Fatalf("no change for %s", path)
	return nil
}

func mutate(id string, body []byte) []byte {
	if id == "claude-code" || id == "opencode" {
		return bytes.Replace(body, []byte("{"), []byte("{\n  \"user-kept\": true,"), 1)
	}
	return append(append([]byte{}, body...), []byte("# user-kept\n")...)
}

func matchGolden(t *testing.T, tool, name string, body []byte) {
	t.Helper()
	path := filepath.Join("testdata", tool, name+".txt")
	existing, err := readTemp(path)
	if err != nil {
		t.Fatalf("golden %s: %v", path, err)
	}
	if !bytes.Equal(existing, body) {
		t.Fatalf("%s mismatch\n%s", path, body)
	}
}

func readTemp(path string) ([]byte, error) {
	return os.ReadFile(path) //nolint:gosec // G304: test reads a temp config or a testdata golden, not a user path
}
