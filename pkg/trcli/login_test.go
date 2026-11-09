package trcli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/trcli/credstore"
)

func TestLoginGatewayOutcomes(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("login stores through a credential helper on darwin and linux; " + runtime.GOOS + " only has the file fallback")
	}
	home := t.TempDir()
	restore := swapCredentialHome(t, home)
	defer restore()
	// Announce secret-tool so the linux store selection picks the helper
	// path: the key must reach the helper on stdin, which is exactly what
	// the runner assertions below check. The file fallback would write the
	// key straight to disk and never invoke the runner.
	run := &recordingRunner{found: "secret-tool"}
	credentialOpen = func(home string) (credstore.Store, error) {
		return credstore.Open(home, run)
	}

	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" && r.Header.Get("Authorization") == "Bearer stdin-secret" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer okSrv.Close()
	out, err := runTrIn(t, "stdin-secret\n", "login", "--gateway-url", okSrv.URL, "--key-stdin")
	if err != nil {
		t.Fatal(err, out)
	}
	if len(run.args) == 0 {
		t.Fatal("credential helper was never invoked")
	}
	if strings.Contains(strings.Join(run.args, " "), "stdin-secret") {
		t.Fatalf("key in argv %q stdin %q", run.args, run.stdin)
	}
	if !strings.Contains(run.stdin, "stdin-secret") {
		t.Fatalf("stdin %q", run.stdin)
	}
	wantRef := "secret-tool:default"
	if runtime.GOOS == "darwin" {
		wantRef = "keychain:default"
	}
	cfg := readClientConfig(t, home)
	if cfg.Profiles["default"].KeyRef != wantRef || cfg.Profiles["default"].GatewayURL != okSrv.URL {
		t.Fatalf("%+v", cfg.Profiles["default"])
	}

	old := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer old.Close()
	out, err = runTrIn(t, "stdin-secret\n", "login", "--gateway-url", old.URL, "--key-stdin")
	if err != nil || !strings.Contains(out, "gateway without /v1/models (RM-13)") {
		t.Fatalf("out %q err %v", out, err)
	}

	denied := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer denied.Close()
	if _, err = runTrIn(t, "stdin-secret\n", "login", "--gateway-url", denied.URL, "--key-stdin"); err == nil {
		t.Fatal("expected 401")
	}
}

func TestKeyPrintPrefersEnv(t *testing.T) {
	t.Setenv("YABANIN_API_KEY", "from-env")
	out, err := runTr(t, "key", "print")
	if err != nil || out != "from-env" {
		t.Fatalf("out %q err %v", out, err)
	}
}

func TestGatewayURLEnvOverridesStored(t *testing.T) {
	t.Setenv("YABANIN_GATEWAY_URL", "https://override.example")
	if got := GatewayURL("https://stored.example"); got != "https://override.example" {
		t.Fatalf("got %s", got)
	}
}

func TestLogoutRemovesProfile(t *testing.T) {
	home := t.TempDir()
	restore := swapCredentialHome(t, home)
	defer restore()
	credentialOpen = func(home string) (credstore.Store, error) {
		return credstore.Open(home, &recordingRunner{})
	}
	if err := saveProfile(home, "default", gatewayProfile{GatewayURL: "https://gw.example", KeyRef: "keychain:default"}); err != nil {
		t.Fatal(err)
	}
	if _, err := runTr(t, "logout"); err != nil {
		t.Fatal(err)
	}
	cfg := readClientConfig(t, home)
	if _, ok := cfg.Profiles["default"]; ok {
		t.Fatal("profile remains")
	}
}

func swapCredentialHome(t *testing.T, home string) func() {
	t.Helper()
	prevHome := credentialHome
	prevOpen := credentialOpen
	credentialHome = func() (string, error) { return home, nil }
	return func() {
		credentialHome = prevHome
		credentialOpen = prevOpen
	}
}

func runTrIn(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	root := RootCommand()
	root.SilenceErrors = true
	root.SilenceUsage = true
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetIn(bytes.NewBufferString(stdin))
	root.SetArgs(args)
	err := root.Execute()
	return buf.String(), err
}

func readClientConfig(t *testing.T, home string) clientConfig {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(home, ".yabanin", "config.json")) //nolint:gosec // G304: temp home created by the test
	if err != nil {
		t.Fatal(err)
	}
	var cfg clientConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

type recordingRunner struct {
	args  []string
	stdin string
	found string
}

func (c *recordingRunner) Run(_ context.Context, stdin []byte, name string, args ...string) (string, error) {
	c.args = append([]string{name}, args...)
	c.stdin = string(stdin)
	return "ok", nil
}

// LookPath mirrors the credential-helper discovery: an empty found field
// reports every helper as missing, a non-empty field reports that helper
// as installed so the store selection exercises the helper path.
func (c *recordingRunner) LookPath(file string) (string, error) {
	if c.found != "" && file == c.found {
		return c.found, nil
	}
	return "", os.ErrNotExist
}
