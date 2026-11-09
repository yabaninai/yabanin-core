package trcli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHarnessConnectDisconnect(t *testing.T) {
	t.Setenv("SHELL", "/bin/zsh")
	t.Setenv("CODEX_HOME", "")
	t.Setenv("YABANIN_API_KEY", "test-key")
	srv := harnessGateway(t, false)
	home := t.TempDir()
	restore := swapCredentialHome(t, home)
	defer restore()
	tools := []struct {
		id   string
		path string
		args []string
	}{
		{"codex", filepath.Join(home, ".codex", "config.toml"), nil},
		{"claude-code", filepath.Join(home, ".claude", "settings.json"), nil},
		{"opencode", filepath.Join(home, ".config", "opencode", "opencode.json"), nil},
		{"continue", filepath.Join(home, ".continue", "config.yaml"), []string{"--experimental"}},
		{"aider", filepath.Join(home, ".aider.conf.yml"), []string{"--experimental"}},
		{"shell", filepath.Join(home, ".zshrc"), nil},
	}
	for _, tool := range tools {
		t.Run(tool.id, func(t *testing.T) {
			args := []string{"harness", "connect", tool.id, "--yes", "--gateway-url", srv.URL, "--model", "gpt"}
			args = append(args, tool.args...)
			out, err := runTr(t, args...)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out, "undo: yb harness disconnect "+tool.id) {
				t.Fatalf("%s", out)
			}
			if _, err := os.Stat(tool.path); err != nil {
				t.Fatal(err)
			}
			statusOut, err := runTr(t, "harness", "status")
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(statusOut, tool.id+"\tapplied") {
				t.Fatalf("%s", statusOut)
			}
			out, err = runTr(t, "harness", "disconnect", tool.id, "--yes")
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out, "rolled_back") {
				t.Fatalf("%s", out)
			}
			if _, err := os.Stat(tool.path); !os.IsNotExist(err) {
				t.Fatalf("file remains %s", tool.path)
			}
		})
	}
}

func TestHarnessRefusesMissingEndpointAndNonTTY(t *testing.T) {
	t.Setenv("SHELL", "/bin/zsh")
	t.Setenv("CODEX_HOME", "")
	t.Setenv("YABANIN_API_KEY", "test-key")
	home := t.TempDir()
	restore := swapCredentialHome(t, home)
	defer restore()
	missing := harnessGateway(t, true)
	_, err := runTr(t, "harness", "connect", "codex", "--yes", "--gateway-url", missing.URL)
	if err == nil || !strings.Contains(err.Error(), "/v1/responses") {
		t.Fatalf("%v", err)
	}
	out, err := runTr(t, "harness", "connect", "codex", "--yes", "--force", "--gateway-url", missing.URL, "--model", "gpt")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "undo: yb harness disconnect codex") {
		t.Fatalf("%s", out)
	}
	ready := harnessGateway(t, false)
	_, err = runTr(t, "harness", "connect", "shell", "--gateway-url", ready.URL)
	if err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("%v", err)
	}
	if _, statErr := os.Stat(filepath.Join(home, ".zshrc")); !os.IsNotExist(statErr) {
		t.Fatal("dry refusal wrote the shell file")
	}
}

func TestHarnessKeyAndDoctor(t *testing.T) {
	t.Setenv("SHELL", "/bin/zsh")
	t.Setenv("CODEX_HOME", "")
	t.Setenv("YABANIN_API_KEY", "test-key")
	home := t.TempDir()
	restore := swapCredentialHome(t, home)
	defer restore()
	out, err := runTr(t, "harness", "key", "--tool", "claude-code")
	if err != nil {
		t.Fatal(err)
	}
	if out != "test-key" {
		t.Fatalf("%q", out)
	}
	srv := harnessGateway(t, false)
	out, err = runTr(t, "harness", "doctor", "shell", "--gateway-url", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "ok") || strings.Contains(out, "test-key") {
		t.Fatalf("%s", out)
	}
	t.Setenv("ANTHROPIC_API_KEY", "foreign-token")
	out, err = runTr(t, "harness", "doctor", "shell", "--gateway-url", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "ANTHROPIC_API_KEY") || strings.Contains(out, "foreign-token") {
		t.Fatalf("%s", out)
	}
	settings := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = runTr(t, "harness", "doctor", "claude-code", "--gateway-url", srv.URL)
	if err == nil || !strings.Contains(err.Error(), "not JSON") {
		t.Fatalf("%v", err)
	}
	broken := harnessGateway(t, true)
	_, err = runTr(t, "harness", "doctor", "--gateway-url", broken.URL)
	if err == nil {
		t.Fatal("doctor accepted a gateway without the endpoints")
	}
}

func TestHarnessList(t *testing.T) {
	t.Setenv("SHELL", "/bin/zsh")
	t.Setenv("CODEX_HOME", "")
	home := t.TempDir()
	restore := swapCredentialHome(t, home)
	defer restore()
	out, err := runTr(t, "harness", "list")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "codex") || !strings.Contains(out, "cursor") || !strings.Contains(out, "not connected") {
		t.Fatalf("%s", out)
	}
}

func harnessGateway(t *testing.T, missingEndpoints bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[{"id":"gpt"}]}`))
			return
		}
		if !missingEndpoints && (r.URL.Path == "/v1/responses" || r.URL.Path == "/v1/messages") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return srv
}
