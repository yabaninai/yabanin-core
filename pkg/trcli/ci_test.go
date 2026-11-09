package trcli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func ciHelperMain() {
	if os.Getenv("YB_CI_SIGNAL") == "1" {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGTERM)
		if delay, err := time.ParseDuration(os.Getenv("YB_CI_READY_DELAY")); err == nil && delay > 0 {
			time.Sleep(delay)
		}
		path := os.Getenv("YB_CI_PID_FILE")
		if path == "" {
			fmt.Fprintln(os.Stderr, "SIGTERM helper readiness path is empty")
			os.Exit(10)
		}
		if err := os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil { //nolint:gosec // G304: readiness file is the test pid file
			fmt.Fprintf(os.Stderr, "write SIGTERM helper readiness file: %v\n", err)
			os.Exit(10)
		}
		select {
		case <-sigs:
			_ = os.WriteFile(os.Getenv("YB_CI_OUT"), []byte("signaled\n"), 0o600) //nolint:gosec // G304: path is the test output file
			os.Exit(0)
		case <-time.After(3 * time.Second):
			os.Exit(9)
		}
	}
	if path := os.Getenv("YB_CI_PID_FILE"); path != "" {
		_ = os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0o600) //nolint:gosec // G304: path is the test pid file
	}
	var b strings.Builder
	for _, key := range []string{
		"YABANIN_GATEWAY_URL", "YABANIN_LABELS", "ANTHROPIC_BASE_URL", "ANTHROPIC_CUSTOM_HEADERS",
		"OPENAI_BASE_URL", "OPENAI_API_KEY", "ANTHROPIC_AUTH_TOKEN", "YABANIN_API_KEY", "YABANIN_SESSION_KEY_ID",
		"CODEX_HOME", "OPENCODE_CONFIG_CONTENT", "CLAUDE_CONFIG_DIR",
	} {
		if value, ok := os.LookupEnv(key); ok {
			fmt.Fprintf(&b, "%s=%s\n", key, value)
		}
	}
	if home := os.Getenv("CODEX_HOME"); home != "" {
		if body, err := os.ReadFile(filepath.Join(home, "config.toml")); err == nil { //nolint:gosec // G304: path is CODEX_HOME/config.toml created for this test
			fmt.Fprintf(&b, "CODEX_CONFIG=%s\n", strings.ReplaceAll(string(body), "\n", `\n`))
		}
	}
	if path := os.Getenv("YB_CI_OUT"); path != "" {
		_ = os.WriteFile(path, []byte(b.String()), 0o600) //nolint:gosec // G304: path is the test output file
	}
	if os.Getenv("YB_CI_HTTP") == "1" {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, strings.TrimRight(os.Getenv("OPENAI_BASE_URL"), "/")+"/models", nil) //nolint:gosec // G704: URL is the httptest server this test started
		if err != nil {
			os.Exit(8)
		}
		req.Header.Set("Authorization", "Bearer "+os.Getenv("YABANIN_API_KEY"))
		req.Header.Set("X-Yabanin-Labels", os.Getenv("YABANIN_LABELS"))
		resp, err := http.DefaultClient.Do(req) //nolint:gosec // G704: request targets the httptest server, not a user-supplied host
		if err != nil {
			os.Exit(8)
		}
		_ = resp.Body.Close()
	}
	code := 0
	if raw := os.Getenv("YB_CI_HELPER_EXIT"); raw != "" {
		code, _ = strconv.Atoi(raw)
	}
	os.Exit(code)
}

func TestCIEnvFormats(t *testing.T) {
	clearCIEnv(t)
	t.Setenv("YABANIN_GATEWAY_URL", "https://gw.example")
	t.Setenv("YABANIN_CI_KEY", "ci-test-key")
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_PIPELINE_ID", "4242")
	t.Setenv("CI_PROJECT_PATH", "org/repo")
	t.Setenv("CI_MERGE_REQUEST_IID", "7")
	t.Setenv("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME", "feature")
	t.Setenv("ANTHROPIC_CUSTOM_HEADERS", "X-Existing: 1")
	dir := t.TempDir()

	out, err := runTr(t, "ci", "env", "--dir", dir, "--format", "github", "--with-key", "--openai-env")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "ci.pipeline=4242") || !strings.Contains(out, "<<EOF_") {
		t.Fatalf("%s", out)
	}
	for _, name := range []string{"OPENAI_API_KEY", "ANTHROPIC_AUTH_TOKEN", "YABANIN_API_KEY"} {
		if !strings.Contains(out, "::add-mask::ci-test-key\n"+name+"=ci-test-key") {
			t.Fatalf("missing mask before %s\n%s", name, out)
		}
	}

	_, err = runTr(t, "ci", "env", "--dir", dir, "--format", "gitlab-dotenv", "--with-key")
	if err == nil || !strings.Contains(err.Error(), "yb ci exec") {
		t.Fatalf("%v", err)
	}

	t.Setenv("GITLAB_CI", "")
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_RUN_ID", "99")
	t.Setenv("GITHUB_REPOSITORY", "org/repo")
	t.Setenv("GITHUB_SHA", "abc123")
	t.Setenv("GITHUB_REF", "refs/pull/12/merge")
	t.Setenv("GITHUB_EVENT_PATH", "")
	gh, err := runTr(t, "ci", "env", "--dir", dir, "--format", "shell")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gh, "ci.pipeline=99") || !strings.Contains(gh, "ci.system=github") {
		t.Fatalf("%s", gh)
	}
}

func TestCIExecAndFinish(t *testing.T) {
	clearCIEnv(t)
	prev := toolOnPath
	toolOnPath = func(name string) (string, error) {
		if name == "codex" || name == "opencode" {
			return name, nil
		}
		return "", errors.New("not on PATH")
	}
	t.Cleanup(func() { toolOnPath = prev })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("X-Yabanin-Labels"), "ci.pipeline=4242") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.Header.Get("Authorization") != "Bearer ci-test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	t.Setenv("YABANIN_GATEWAY_URL", srv.URL)
	t.Setenv("YABANIN_CI_KEY", "ci-test-key")
	t.Setenv("YABANIN_API_KEY", "parent-key")
	t.Setenv("CODEX_HOME", "parent-codex")
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_PIPELINE_ID", "4242")
	t.Setenv("CI_PROJECT_PATH", "org/repo")
	t.Setenv("YB_CI_HELPER", "1")
	t.Setenv("YB_CI_HTTP", "1")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "child.txt")
	report := filepath.Join(dir, "report.json")
	t.Setenv("YB_CI_OUT", out)
	text, err := runTr(t, "ci", "exec", "--dir", dir, "--openai-env", "--isolate", "--codex-model", "gpt", "--report", report, "--", exe)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text, "ci-test-key") {
		t.Fatalf("exec printed the key\n%s", text)
	}
	if os.Getenv("YABANIN_API_KEY") != "parent-key" || os.Getenv("CODEX_HOME") != "parent-codex" {
		t.Fatal("parent environment changed")
	}
	body, err := os.ReadFile(out) //nolint:gosec // G304: path is a temp file created by this test
	if err != nil {
		t.Fatal(err)
	}
	child := string(body)
	codexHome, ok := envValue(child, "CODEX_HOME")
	if !ok || codexHome == "" || codexHome == "parent-codex" {
		t.Fatalf("%s", child)
	}
	if _, err := os.Stat(codexHome); !os.IsNotExist(err) { //nolint:gosec // G703: path is the temp CODEX_HOME this test created
		t.Fatal("temporary CODEX_HOME remains")
	}
	claudeDir, ok := envValue(child, "CLAUDE_CONFIG_DIR")
	if !ok || claudeDir == "" {
		t.Fatalf("%s", child)
	}
	if _, err := os.Stat(claudeDir); !os.IsNotExist(err) { //nolint:gosec // G703: path is the temp CLAUDE_CONFIG_DIR this test created
		t.Fatal("temporary CLAUDE_CONFIG_DIR remains")
	}
	config, ok := envValue(child, "OPENCODE_CONFIG_CONTENT")
	if !ok || !strings.Contains(config, "ci.pipeline=4242") || !strings.Contains(config, "{env:YABANIN_API_KEY}") {
		t.Fatalf("%s", child)
	}
	if !strings.Contains(child, `env_key = "YABANIN_API_KEY"`) || !strings.Contains(child, "YABANIN_LABELS") || !strings.Contains(child, `model = "gpt"`) {
		t.Fatalf("%s", child)
	}
	if envValueMust(t, child, "YABANIN_API_KEY") != "ci-test-key" {
		t.Fatalf("%s", child)
	}
	raw, err := os.ReadFile(report) //nolint:gosec // G304: path is a temp report created by this test
	if err != nil {
		t.Fatal(err)
	}
	var parsed ciReport
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Usage != nil || parsed.ExitCode == nil || *parsed.ExitCode != 0 || parsed.Labels["ci.pipeline"] != "4242" {
		t.Fatalf("%s", raw)
	}

	finish := filepath.Join(dir, "finish.json")
	if _, err := runTr(t, "ci", "finish", "--dir", dir, "--report", finish); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(finish) //nolint:gosec // G304: path is a temp report created by this test
	if err != nil {
		t.Fatal(err)
	}
	parsed = ciReport{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Usage != nil || parsed.Labels["ci.pipeline"] != "4242" {
		t.Fatalf("%s", raw)
	}
}

func TestCIExecExitAndSignal(t *testing.T) {
	clearCIEnv(t)
	usage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(usage.Close)
	t.Setenv("YABANIN_GATEWAY_URL", usage.URL)
	t.Setenv("YABANIN_CI_KEY", "ci-test-key")
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_PIPELINE_ID", "4242")
	t.Setenv("YB_CI_HELPER", "1")
	t.Setenv("YB_CI_HELPER_EXIT", "7")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	_, err = runTr(t, "ci", "exec", "--session", "off", "--dir", dir, "--report", filepath.Join(dir, "report.json"), "--", exe)
	var child *ChildExit
	if !errors.As(err, &child) || child.Code != 7 {
		t.Fatalf("%v", err)
	}

	t.Setenv("YB_CI_HELPER_EXIT", "")
	t.Setenv("YB_CI_SIGNAL", "1")
	t.Setenv("YB_CI_READY_DELAY", "2200ms")
	pidFile := filepath.Join(dir, "pid")
	out := filepath.Join(dir, "signal.txt")
	t.Setenv("YB_CI_PID_FILE", pidFile)
	t.Setenv("YB_CI_OUT", out)
	watchCtx, stopWatcher := context.WithCancel(context.Background())
	signalResult := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		timeout := time.NewTimer(10 * time.Second)
		defer timeout.Stop()
		for {
			select {
			case <-watchCtx.Done():
				return
			case <-timeout.C:
				signalResult <- fmt.Errorf("helper did not announce SIGTERM readiness within 10s")
				return
			case <-ticker.C:
				if _, err := os.Stat(pidFile); err == nil {
					signalResult <- syscall.Kill(os.Getpid(), syscall.SIGTERM)
					return
				} else if !os.IsNotExist(err) {
					signalResult <- fmt.Errorf("stat helper readiness file: %w", err)
					return
				}
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	root := RootCommand()
	root.SilenceErrors = true
	root.SilenceUsage = true
	var commandOutput strings.Builder
	root.SetOut(&commandOutput)
	root.SetErr(&commandOutput)
	root.SetArgs([]string{"ci", "exec", "--session", "off", "--dir", dir, "--report", filepath.Join(dir, "signal-report.json"), "--", exe})
	err = root.ExecuteContext(ctx)
	stopWatcher()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-signalResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatalf("SIGTERM readiness wait ended before signal delivery: %v", ctx.Err())
	}
	got, err := os.ReadFile(out) //nolint:gosec // G304: path is a temp file created by this test
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "signaled\n" {
		t.Fatalf("%q", got)
	}
}

func clearCIEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"GITLAB_CI", "GITHUB_ACTIONS", "YABANIN_PROFILE", "GITHUB_EVENT_PATH",
		"ANTHROPIC_CUSTOM_HEADERS", "OPENCODE_CONFIG_CONTENT", "YB_CI_HTTP", "YB_CI_SIGNAL",
		"YB_CI_HELPER_EXIT", "YB_CI_READY_DELAY", "YB_RUN_HELPER",
	} {
		t.Setenv(key, "")
		_ = os.Unsetenv(key)
	}
}

func envValueMust(t *testing.T, body, key string) string {
	t.Helper()
	value, ok := envValue(body, key)
	if !ok {
		t.Fatalf("missing %s\n%s", key, body)
	}
	return value
}
