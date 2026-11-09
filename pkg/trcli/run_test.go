package trcli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("YB_CI_HELPER") == "1" {
		ciHelperMain()
	}
	if os.Getenv("YB_RUN_HELPER") == "1" {
		helperMain()
	}
	os.Exit(m.Run())
}

func helperMain() {
	var b strings.Builder
	for _, key := range []string{"YABANIN_LABELS", "ANTHROPIC_CUSTOM_HEADERS", "OPENCODE_CONFIG_CONTENT"} {
		if value, ok := os.LookupEnv(key); ok {
			fmt.Fprintf(&b, "%s=%s\n", key, value)
		}
	}
	if path := os.Getenv("YB_RUN_HELPER_OUT"); path != "" {
		_ = os.WriteFile(path, []byte(b.String()), 0o600) //nolint:gosec // G304: path is the test helper output file
	}
	code := 0
	if raw := os.Getenv("YB_RUN_HELPER_EXIT"); raw != "" {
		code, _ = strconv.Atoi(raw)
	}
	os.Exit(code)
}

func TestRunLabelsPerTool(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITLAB_CI", "")
	t.Setenv("YABANIN_PROFILE", "")
	t.Setenv("YABANIN_LABELS", "")
	_ = os.Unsetenv("YABANIN_LABELS")
	t.Setenv("ANTHROPIC_CUSTOM_HEADERS", "")
	_ = os.Unsetenv("ANTHROPIC_CUSTOM_HEADERS")
	t.Setenv("OPENCODE_CONFIG_CONTENT", "")
	_ = os.Unsetenv("OPENCODE_CONFIG_CONTENT")
	t.Setenv("YB_RUN_HELPER", "1")
	t.Setenv("YB_RUN_HELPER_EXIT", "0")
	dir := t.TempDir()
	home := t.TempDir()
	restore := swapCredentialHome(t, home)
	defer restore()
	if err := os.MkdirAll(filepath.Join(home, ".yabanin"), 0o750); err != nil {
		t.Fatal(err)
	}
	cfg := []byte("{\"version\":1,\"profiles\":{\"default\":{\"labels\":{\"cost_center\":\"CC-42\"}}}}\n")
	if err := os.WriteFile(filepath.Join(home, ".yabanin", "config.json"), cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	settings := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte("{\"env\":{\"ANTHROPIC_CUSTOM_HEADERS\":\"X-From-Settings: 1\"}}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	codex := runHelper(t, dir, "codex")
	if value, ok := envValue(codex, "YABANIN_LABELS"); !ok || !strings.Contains(value, "team=payments") || !strings.Contains(value, "cost_center=CC-42") {
		t.Fatalf("%s", codex)
	}
	if _, ok := envValue(codex, "ANTHROPIC_CUSTOM_HEADERS"); ok {
		t.Fatalf("%s", codex)
	}
	if _, ok := envValue(codex, "OPENCODE_CONFIG_CONTENT"); ok {
		t.Fatalf("%s", codex)
	}

	t.Setenv("ANTHROPIC_CUSTOM_HEADERS", "X-Existing: 1")
	claudeOut, claude := runHelperCapture(t, dir, "claude-code")
	if !strings.Contains(claudeOut, "--labels-mode dynamic") {
		t.Fatalf("%s", claudeOut)
	}
	if !strings.Contains(claude, "ANTHROPIC_CUSTOM_HEADERS=X-Existing: 1\nX-Yabanin-Labels:") || !strings.Contains(claude, "team=payments") {
		t.Fatalf("%s", claude)
	}
	if strings.Contains(claude, "YABANIN_LABELS=") {
		t.Fatalf("%s", claude)
	}

	t.Setenv("OPENCODE_CONFIG_CONTENT", `{"provider":{"other":{"name":"kept"},"yabanin":{"options":{"baseURL":"https://gw.example"}}}}`)
	open := runHelper(t, dir, "opencode")
	payload, ok := envValue(open, "OPENCODE_CONFIG_CONTENT")
	if !ok {
		t.Fatalf("%s", open)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(payload), &doc); err != nil {
		t.Fatalf("%v\n%s", err, open)
	}
	providers, _ := doc["provider"].(map[string]any)
	if _, ok := providers["other"]; !ok {
		t.Fatalf("lost provider\n%s", open)
	}
	yabanin, _ := providers["yabanin"].(map[string]any)
	options, _ := yabanin["options"].(map[string]any)
	if options["baseURL"] != "https://gw.example" {
		t.Fatalf("%s", open)
	}
	headers, _ := options["headers"].(map[string]any)
	header, _ := headers["X-Yabanin-Labels"].(string)
	if !strings.Contains(header, "team=payments") || !strings.Contains(header, "cost_center=CC-42") {
		t.Fatalf("%s", header)
	}

	_ = os.Unsetenv("OPENCODE_CONFIG_CONTENT")
	_ = os.Unsetenv("ANTHROPIC_CUSTOM_HEADERS")
	other := runHelper(t, dir, "shell")
	if _, ok := envValue(other, "YABANIN_LABELS"); !ok {
		t.Fatalf("%s", other)
	}
	if _, ok := envValue(other, "OPENCODE_CONFIG_CONTENT"); ok {
		t.Fatalf("%s", other)
	}
}

func TestRunExitCode(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITLAB_CI", "")
	t.Setenv("YABANIN_PROFILE", "")
	t.Setenv("YB_RUN_HELPER", "1")
	t.Setenv("YB_RUN_HELPER_EXIT", "7")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "child.txt")
	t.Setenv("YB_RUN_HELPER_OUT", out)
	_, err = runTr(t, "run", "--dir", dir, "--label", "team=payments", "codex", "--", exe)
	var child *ChildExit
	if !errors.As(err, &child) || child.Code != 7 {
		t.Fatalf("%v", err)
	}
}

func envValue(body, key string) (string, bool) {
	prefix := key + "="
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix), true
		}
	}
	return "", false
}

func runHelper(t *testing.T, dir, tool string) string {
	t.Helper()
	_, body := runHelperCapture(t, dir, tool)
	return body
}

func runHelperCapture(t *testing.T, dir, tool string) (string, string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "child.txt")
	t.Setenv("YB_RUN_HELPER_OUT", out)
	text, err := runTr(t, "run", "--dir", dir, "--label", "team=payments", tool, "--", exe)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(out) //nolint:gosec // G304: path is a temp file created by this test
	if err != nil {
		t.Fatal(err)
	}
	return text, string(body)
}
