package trcli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func runSupportBundle(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	root := RootCommand()
	root.SilenceUsage = true
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs(append([]string{"support-bundle"}, args...))
	err := root.Execute()
	return stdout.String(), stderr.String(), err
}

func setSupportBundleHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}

func TestSupportBundle_PreviewContainsOnlyAllowlistedMetadata(t *testing.T) {
	home := setSupportBundleHome(t)
	config := configPath(home)
	if err := os.MkdirAll(filepath.Dir(config), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte(`not-json profile-secret profile-prompt https://private.example`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("YABANIN_GATEWAY_URL", "https://gateway-secret.example")
	t.Setenv("YABANIN_ADMIN_URL", "https://admin-secret.example")
	t.Setenv("YABANIN_API_KEY", "environment-key-secret")

	previousTransport := http.DefaultTransport
	requests := 0
	http.DefaultTransport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return nil, fmt.Errorf("unexpected request")
	})
	t.Cleanup(func() { http.DefaultTransport = previousTransport })

	stdout, stderr, err := runSupportBundle(t, "preview", "--org", "tenant-secret", "--api-key", "flag-key-secret", "--admin-url", "https://flag-admin-secret.example")
	if err != nil {
		t.Fatalf("preview failed: %v; stderr=%q", err, stderr)
	}
	if stderr != "" {
		t.Fatalf("unexpected stderr: %q", stderr)
	}
	if requests != 0 {
		t.Fatalf("preview issued %d HTTP requests", requests)
	}
	for _, secret := range []string{
		"profile-secret", "profile-prompt", "private.example", "gateway-secret", "admin-secret",
		"environment-key-secret", "tenant-secret", "flag-key-secret", "flag-admin-secret", home,
	} {
		if strings.Contains(stdout, secret) {
			t.Errorf("bundle leaked %q", secret)
		}
	}
	var got supportBundle
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("invalid bundle JSON: %v", err)
	}
	if got.SchemaVersion != 1 || got.Build.Version != safeSupportVersion(version) || got.Build.Commit != safeSupportCommit(commit) {
		t.Fatalf("unexpected schema/build metadata: %+v", got)
	}
	if got.Runtime.GoVersion != runtime.Version() || got.Runtime.OS != runtime.GOOS || got.Runtime.Arch != runtime.GOARCH {
		t.Fatalf("unexpected runtime metadata: %+v", got.Runtime)
	}
	if !got.LocalConfig.CLIProfileFilePresent || !got.LocalConfig.GatewayURLEnvSet || !got.LocalConfig.AdminURLEnvSet || !got.LocalConfig.APIKeyEnvSet {
		t.Fatalf("expected presence-only flags to be true: %+v", got.LocalConfig)
	}
}

func TestSupportBundle_CreateMatchesPreviewAndUsesPrivateMode(t *testing.T) {
	setSupportBundleHome(t)
	t.Setenv("YABANIN_GATEWAY_URL", "")
	t.Setenv("YABANIN_ADMIN_URL", "")
	t.Setenv("YABANIN_API_KEY", "")

	preview, _, err := runSupportBundle(t, "preview")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "support.json")
	created, stderr, err := runSupportBundle(t, "create", "--output", path)
	if err != nil {
		t.Fatalf("create failed: %v; stderr=%q", err, stderr)
	}
	// #nosec G304 -- path is created inside this test's private TempDir.
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != preview || created != preview {
		t.Fatalf("preview/create bytes differ:\npreview=%q\ncreated=%q\nfile=%q", preview, created, contents)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("created mode is %04o, want 0600", got)
	}
}

func TestSupportBundle_CreateRefusesExistingFileAndSymlink(t *testing.T) {
	setSupportBundleHome(t)
	for _, kind := range []string{"file", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "target")
			if err := os.WriteFile(target, []byte("keep-this-content"), 0o600); err != nil {
				t.Fatal(err)
			}
			path := target
			if kind == "symlink" {
				path = filepath.Join(dir, "link")
				if err := os.Symlink(target, path); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			}
			stdout, stderr, err := runSupportBundle(t, "create", "--output", path)
			if err == nil || err.Error() != supportBundleCreateError {
				t.Fatalf("error = %v, want safe create error", err)
			}
			if stdout != "" || !strings.Contains(stderr, supportBundleCreateError) || strings.Contains(stderr, path) {
				t.Fatalf("failure emitted output: stdout=%q stderr=%q", stdout, stderr)
			}
			// #nosec G304 -- target is a fixture created inside this test's private TempDir.
			contents, readErr := os.ReadFile(target)
			if readErr != nil || string(contents) != "keep-this-content" {
				t.Fatalf("existing target changed: bytes=%q err=%v", contents, readErr)
			}
		})
	}
}

func TestSupportBundle_CreateFailureDoesNotExposePathOrWriteJSON(t *testing.T) {
	setSupportBundleHome(t)
	path := filepath.Join(t.TempDir(), "existing-directory")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err := runSupportBundle(t, "create", "--output", path)
	if err == nil || err.Error() != supportBundleCreateError {
		t.Fatalf("error = %v, want safe create error", err)
	}
	if stdout != "" || !strings.Contains(stderr, supportBundleCreateError) || strings.Contains(stderr, path) {
		t.Fatalf("failure emitted output: stdout=%q stderr=%q", stdout, stderr)
	}
	if strings.Contains(err.Error(), path) {
		t.Fatalf("error exposed output path: %q", err)
	}
}

func TestSupportBundle_CreateUnwritableOutputFailsSafely(t *testing.T) {
	setSupportBundleHome(t)
	dir := t.TempDir()
	// #nosec G302 -- read-only fixture directory inside the test's private TempDir; restrictiveness is the scenario.
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- restores TempDir permissions so cleanup can remove the fixture.
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	probe := filepath.Join(dir, "write-probe")
	// #nosec G304 -- probe path is built inside this test's private TempDir; it only detects whether permissions are enforced.
	if file, err := os.OpenFile(probe, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600); err == nil {
		_ = file.Close()
		t.Skip("directory permissions are not enforced in this environment")
	}
	path := filepath.Join(dir, "bundle.json")
	stdout, stderr, err := runSupportBundle(t, "create", "--output", path)
	if err == nil || err.Error() != supportBundleCreateError {
		t.Fatalf("error = %v, want safe create error", err)
	}
	if stdout != "" || !strings.Contains(stderr, supportBundleCreateError) || strings.Contains(stderr, path) {
		t.Fatalf("failure emitted output: stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestSupportBundle_ProfileStatFailureIsNotFalseAbsence(t *testing.T) {
	home := t.TempDir()
	profileDir := filepath.Join(home, ".yabanin")
	if err := os.MkdirAll(profileDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(profileDir, 0o000); err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- restores TempDir permissions so cleanup can remove the fixture.
	t.Cleanup(func() { _ = os.Chmod(profileDir, 0o700) })
	if _, err := os.Stat(configPath(home)); !os.IsPermission(err) {
		t.Skipf("profile stat permission errors are not enforced in this environment: %v", err)
	}
	previousHome := credentialHome
	credentialHome = func() (string, error) { return home, nil }
	t.Cleanup(func() { credentialHome = previousHome })

	stdout, stderr, err := runSupportBundle(t, "preview")
	if err == nil || err.Error() != "support bundle metadata unavailable" {
		t.Fatalf("error = %v, want fixed metadata error instead of false absence", err)
	}
	if stdout != "" || !strings.Contains(stderr, "support bundle metadata unavailable") || strings.Contains(stderr, home) {
		t.Fatalf("failure emitted output: stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestSupportBundle_CreateRepeatFailsThenFreshPathSucceeds(t *testing.T) {
	setSupportBundleHome(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(path, []byte("keep-me"), 0o600); err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		stdout, stderr, err := runSupportBundle(t, "create", "--output", path)
		if err == nil || err.Error() != supportBundleCreateError {
			t.Fatalf("attempt %d: error = %v, want safe create error", attempt, err)
		}
		if stdout != "" || strings.Contains(stderr, path) {
			t.Fatalf("attempt %d emitted output: stdout=%q stderr=%q", attempt, stdout, stderr)
		}
	}
	// #nosec G304 -- path is a fixture created inside this test's private TempDir.
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != "keep-me" {
		t.Fatalf("existing content changed: bytes=%q err=%v", contents, err)
	}
	fresh := filepath.Join(dir, "fresh.json")
	created, stderr, err := runSupportBundle(t, "create", "--output", fresh)
	if err != nil {
		t.Fatalf("create to fresh path failed: %v; stderr=%q", err, stderr)
	}
	// #nosec G304 -- fresh is a fixture created inside this test's private TempDir.
	written, err := os.ReadFile(fresh)
	if err != nil || string(written) != created {
		t.Fatalf("fresh file differs from stdout: file=%q stdout=%q err=%v", written, created, err)
	}
}

func TestSupportBundle_CreateRequiresExplicitOutput(t *testing.T) {
	setSupportBundleHome(t)
	stdout, _, err := runSupportBundle(t, "create")
	if err == nil || err.Error() != "--output is required" {
		t.Fatalf("error = %v, want fixed missing-output error", err)
	}
	if stdout != "" {
		t.Fatalf("partial bundle printed to stdout: %q", stdout)
	}
}

type failingSupportWriter struct{}

func (failingSupportWriter) Write([]byte) (int, error) {
	return 0, errors.New("injected writer failure")
}

func TestSupportBundle_WriteFailureReturnsFixedCategory(t *testing.T) {
	setSupportBundleHome(t)

	root := RootCommand()
	root.SilenceUsage = true
	var stderr bytes.Buffer
	root.SetOut(failingSupportWriter{})
	root.SetErr(&stderr)
	root.SetArgs([]string{"support-bundle", "preview"})
	if err := root.Execute(); err == nil || err.Error() != supportBundleCreateError {
		t.Fatalf("preview write failure error = %v, want fixed create error", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.json")
	root = RootCommand()
	root.SilenceUsage = true
	stderr = bytes.Buffer{}
	root.SetOut(failingSupportWriter{})
	root.SetErr(&stderr)
	root.SetArgs([]string{"support-bundle", "create", "--output", path})
	if err := root.Execute(); err == nil || err.Error() != supportBundleCreateError {
		t.Fatalf("create stdout write failure error = %v, want fixed create error", err)
	}
	// #nosec G304 -- path is a fixture created inside this test's private TempDir.
	contents, err := os.ReadFile(path)
	if err != nil || !json.Valid(contents) {
		t.Fatalf("created file incomplete after stdout failure: bytes=%q err=%v", contents, err)
	}
}

func TestSupportBundle_UnsafeBuildMetadataIsUnknown(t *testing.T) {
	setSupportBundleHome(t)
	oldVersion, oldCommit := version, commit
	version, commit = "yb /private/build/path", "dev"
	t.Cleanup(func() { version, commit = oldVersion, oldCommit })

	stdout, _, err := runSupportBundle(t, "preview")
	if err != nil {
		t.Fatal(err)
	}
	var got supportBundle
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatal(err)
	}
	if got.Build.Version != "unknown" || got.Build.Commit != "unknown" || strings.Contains(stdout, "/private/build/path") {
		t.Fatalf("unsafe linker metadata was not normalized: %+v", got.Build)
	}
}

func TestSupportBundle_PreviewEmptyEnvironmentIsFalse(t *testing.T) {
	setSupportBundleHome(t)
	t.Setenv("YABANIN_GATEWAY_URL", "")
	t.Setenv("YABANIN_ADMIN_URL", "")
	t.Setenv("YABANIN_API_KEY", "")
	stdout, _, err := runSupportBundle(t, "preview")
	if err != nil {
		t.Fatal(err)
	}
	var got supportBundle
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatal(err)
	}
	if got.LocalConfig != (supportBundleConfig{}) {
		t.Fatalf("empty environment should report false presence: %+v", got.LocalConfig)
	}
}

func TestSupportBundle_SchemaV1FieldSetAndOrderIsFixed(t *testing.T) {
	setSupportBundleHome(t)
	t.Setenv("YABANIN_GATEWAY_URL", "")
	t.Setenv("YABANIN_ADMIN_URL", "")
	t.Setenv("YABANIN_API_KEY", "")
	stdout, _, err := runSupportBundle(t, "preview")
	if err != nil {
		t.Fatal(err)
	}
	assertSupportBundleKeys(t, []byte(stdout), "schema_version", "build", "runtime", "local_config")

	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stdout), &top); err != nil {
		t.Fatal(err)
	}
	assertSupportBundleKeys(t, top["build"], "version", "commit")
	assertSupportBundleKeys(t, top["runtime"], "go_version", "os", "arch")
	assertSupportBundleKeys(t, top["local_config"], "cli_profile_file_present", "gateway_url_env_set", "admin_url_env_set", "api_key_env_set")
}

func TestSupportBundle_PreviewIsDeterministicAndMakesNoRequests(t *testing.T) {
	setSupportBundleHome(t)
	t.Setenv("YABANIN_GATEWAY_URL", "https://gateway-secret.example")
	t.Setenv("YABANIN_ADMIN_URL", "")
	t.Setenv("YABANIN_API_KEY", "environment-key-secret")
	requests := 0
	previousTransport := http.DefaultTransport
	http.DefaultTransport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return nil, fmt.Errorf("unexpected network request from support-bundle")
	})
	t.Cleanup(func() { http.DefaultTransport = previousTransport })

	first, _, err := runSupportBundle(t, "preview")
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := runSupportBundle(t, "preview")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("preview output is not deterministic between invocations:\nfirst=%q\nsecond=%q", first, second)
	}
	created, stderr, err := runSupportBundle(t, "create", "--output", filepath.Join(t.TempDir(), "bundle.json"))
	if err != nil {
		t.Fatalf("create failed: %v; stderr=%q", err, stderr)
	}
	if created != first {
		t.Fatalf("create stdout differs from preview output:\npreview=%q\ncreated=%q", first, created)
	}
	if requests != 0 {
		t.Fatalf("support-bundle issued %d HTTP requests without operator action", requests)
	}
}

func TestSupportBundle_EnvironmentOutsideAllowlistNeverEntersBundle(t *testing.T) {
	home := setSupportBundleHome(t)
	config := configPath(home)
	if err := os.MkdirAll(filepath.Dir(config), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte(`{"prompt":"confidential prompt body","api_key":"profile-key-secret","email":"person@example.private","note":"profile-secret"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	sentinels := map[string]string{
		"YABANIN_GATEWAY_URL":    "https://gateway-secret.example",
		"YABANIN_ADMIN_URL":      "https://admin-secret.example",
		"YABANIN_API_KEY":        "environment-key-secret",
		"YABANIN_GATEWAY_URL_V2": "https://gateway-fallback-secret.example",
		"YABANIN_PROMPT":         "sentinel prompt text",
		"ANTHROPIC_API_KEY":      "other-provider-key-secret",
		"YABANIN_ORG":            "tenant-private-org",
		"YABANIN_SUPPORT_TS":     "2038-01-01T00:00:00Z",
	}
	for name, value := range sentinels {
		t.Setenv(name, value)
	}

	stdout, stderr, err := runSupportBundle(t, "preview")
	if err != nil {
		t.Fatalf("preview failed: %v; stderr=%q", err, stderr)
	}
	for name, value := range sentinels {
		if strings.Contains(stdout, value) {
			t.Errorf("bundle leaked the value of environment key %s", name)
		}
	}
	for _, material := range []string{"confidential prompt body", "profile-key-secret", "person@example.private", "profile-secret", home} {
		if strings.Contains(stdout, material) {
			t.Errorf("bundle leaked profile material %q", material)
		}
	}
	var got supportBundle
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatal(err)
	}
	if !got.LocalConfig.CLIProfileFilePresent || !got.LocalConfig.GatewayURLEnvSet || !got.LocalConfig.AdminURLEnvSet || !got.LocalConfig.APIKeyEnvSet {
		t.Fatalf("allowlisted presence flags must stay true: %+v", got.LocalConfig)
	}
	assertSupportBundleKeys(t, []byte(stdout), "schema_version", "build", "runtime", "local_config")
}

func supportBundleTopLevelKeys(t *testing.T, raw []byte) []string {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil {
		t.Fatalf("bundle is not JSON: %v", err)
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		t.Fatalf("bundle is not a JSON object: %v", token)
	}
	var keys []string
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			t.Fatal(err)
		}
		key, ok := token.(string)
		if !ok {
			t.Fatalf("unexpected non-string key token: %v", token)
		}
		keys = append(keys, key)
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := decoder.Token(); err != nil {
		t.Fatal(err)
	}
	return keys
}

func assertSupportBundleKeys(t *testing.T, raw []byte, want ...string) {
	t.Helper()
	got := supportBundleTopLevelKeys(t, raw)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("bundle field set/order = %v, want exactly %v", got, want)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
