package trcli

// download diagnostics» driven through the REAL consumer entry point — full
// `yb` root parse per invocation (cmd/yb/main.go equivalent), not a partial
// command tree and not the collect helper. The bundle is metadata-only by
// design: its "real stores" are the operator's real profile file and the real
// process environment (no Postgres/Redis on the path — pinned here). Every
// test carries an egress guard on http.DefaultTransport, so the criterion
// «Без действия оператора нет внешней отправки; redaction проверен» holds
// end-to-end: the only artifact is the local file the operator names.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runIntSupportBundle mirrors cmd/yb/main.go: one fresh full-root cobra parse
// per invocation — no SilenceUsage overrides, no helper shortcuts.
func runIntSupportBundle(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	root := RootCommand()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs(args)
	err := root.Execute()
	return stdout.String(), stderr.String(), err
}

// poisonedIntMachine builds the realistic operator machine from the negative
// scenario: keys, prompts and PII in config, environment and command line.
func poisonedIntMachine(t *testing.T) (home string, sentinels []string) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("HOME", home)
	config := configPath(home)
	if err := os.MkdirAll(filepath.Dir(config), 0o700); err != nil {
		t.Fatal(err)
	}
	profile := `{"version":1,"profiles":{"prod":{"gateway_url":"https://profile-gateway-sentinel.example",` +
		`"key_ref":"profile-keyref-sentinel","labels":{"team":"profile-label-sentinel"}}},` +
		`"prompt":"confidential-prompt-body-sentinel","email":"pii-person-sentinel@example.private"}`
	if err := os.WriteFile(config, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"YABANIN_GATEWAY_URL":    "https://env-gateway-sentinel.example",
		"YABANIN_ADMIN_URL":      "https://env-admin-sentinel.example",
		"YABANIN_API_KEY":        "env-key-sentinel",
		"YABANIN_GATEWAY_URL_V2": "https://fallback-gateway-sentinel.example",
		"YABANIN_PROMPT":         "outside-prompt-sentinel",
		"ANTHROPIC_API_KEY":      "other-provider-key-sentinel",
		"YABANIN_ORG":            "outside-org-sentinel",
		"YABANIN_SUPPORT_TS":     "2038-support-ts-sentinel",
	}
	for name, value := range env {
		t.Setenv(name, value)
	}
	sentinels = append(sentinels,
		"profile-gateway-sentinel.example", "profile-keyref-sentinel", "profile-label-sentinel",
		"confidential-prompt-body-sentinel", "pii-person-sentinel@example.private",
		"https://env-gateway-sentinel.example", "https://env-admin-sentinel.example", "env-key-sentinel",
		"https://fallback-gateway-sentinel.example", "outside-prompt-sentinel",
		"other-provider-key-sentinel", "outside-org-sentinel", "2038-support-ts-sentinel",
		home,
	)
	return home, sentinels
}

// guardIntEgress fails the test if anything travels through the default HTTP
// transport while support-bundle runs.
func guardIntEgress(t *testing.T) *int {
	t.Helper()
	requests := 0
	previousTransport := http.DefaultTransport
	http.DefaultTransport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return nil, fmt.Errorf("unexpected network request from support-bundle")
	})
	t.Cleanup(func() { http.DefaultTransport = previousTransport })
	return &requests
}

func assertIntNoSentinels(t *testing.T, sentinels []string, channels map[string]string) {
	t.Helper()
	for name, output := range channels {
		for _, sentinel := range sentinels {
			if strings.Contains(output, sentinel) {
				t.Errorf("%s leaked sentinel %q", name, sentinel)
			}
		}
	}
}

// TestIntSupportBundle_E2E_OperatorFlowLocalOnly: preview → create through
// real `yb support-bundle` invocations (global flags included, as an operator
// would type them) — three fresh parses agree byte-for-byte, the created file
// is the only artifact (0600), the schema pin holds, presence flags stay
// boolean, and no secret from config/env/flags/home reaches any output channel.
func TestIntSupportBundle_E2E_OperatorFlowLocalOnly(t *testing.T) {
	_, sentinels := poisonedIntMachine(t)
	requests := guardIntEgress(t)

	flags := []string{
		"--org", "flag-org-sentinel",
		"--api-key", "flag-key-sentinel",
		"--admin-url", "https://flag-admin-sentinel.example",
		"--base-url", "https://flag-base-sentinel.example",
	}
	sentinels = append(sentinels, "flag-org-sentinel", "flag-key-sentinel",
		"flag-admin-sentinel.example", "flag-base-sentinel.example")

	preview, stderr, err := runIntSupportBundle(t, append([]string{"support-bundle", "preview"}, flags...)...)
	if err != nil {
		t.Fatalf("preview failed: %v; stderr=%q", err, stderr)
	}
	if stderr != "" {
		t.Fatalf("unexpected stderr: %q", stderr)
	}

	path := filepath.Join(t.TempDir(), "yb-support.json")
	created, stderr, err := runIntSupportBundle(t, append([]string{"support-bundle", "create", "--output", path}, flags...)...)
	if err != nil {
		t.Fatalf("create failed: %v; stderr=%q", err, stderr)
	}
	if stderr != "" {
		t.Fatalf("unexpected create stderr: %q", stderr)
	}
	// #nosec G304 -- path is a fixture created inside this test's private TempDir.
	file, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if preview != created || preview != string(file) {
		t.Fatalf("fresh parses disagree:\npreview=%q\ncreated=%q\nfile=%q", preview, created, file)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("created mode is %04o, want 0600", got)
	}

	assertSupportBundleKeys(t, []byte(preview), "schema_version", "build", "runtime", "local_config")
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(preview), &top); err != nil {
		t.Fatal(err)
	}
	assertSupportBundleKeys(t, top["build"], "version", "commit")
	assertSupportBundleKeys(t, top["runtime"], "go_version", "os", "arch")
	assertSupportBundleKeys(t, top["local_config"], "cli_profile_file_present", "gateway_url_env_set", "admin_url_env_set", "api_key_env_set")

	var got supportBundle
	if err := json.Unmarshal([]byte(preview), &got); err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != 1 {
		t.Fatalf("schema_version = %d, want 1", got.SchemaVersion)
	}
	if !got.LocalConfig.CLIProfileFilePresent || !got.LocalConfig.GatewayURLEnvSet || !got.LocalConfig.AdminURLEnvSet || !got.LocalConfig.APIKeyEnvSet {
		t.Fatalf("presence flags must be true on the poisoned machine: %+v", got.LocalConfig)
	}

	assertIntNoSentinels(t, sentinels, map[string]string{
		"preview stdout": preview,
		"create stdout":  created,
		"created file":   string(file),
	})
	if *requests != 0 {
		t.Fatalf("support-bundle issued %d HTTP requests without operator action", *requests)
	}
}

// TestIntSupportBundle_E2E_FailureBoundaryNeverLeaksSentinels: the negative
// scenario through the error paths of the real entry point — refused create,
// missing --output, unknown subcommand. Every error surface stays categorical:
// no sentinel from config/environment/flags and no output path may appear.
func TestIntSupportBundle_E2E_FailureBoundaryNeverLeaksSentinels(t *testing.T) {
	_, sentinels := poisonedIntMachine(t)
	requests := guardIntEgress(t)

	dir := t.TempDir()
	// The operator picks an output path that already holds an old bundle; the
	// path itself carries a sentinel segment.
	path := filepath.Join(dir, "sentinel-filename.json")
	if err := os.WriteFile(path, []byte("previous-bundle-content-sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	sentinels = append(sentinels, "previous-bundle-content-sentinel")

	stdout, stderr, err := runIntSupportBundle(t, "support-bundle", "create", "--output", path)
	if err == nil || err.Error() != supportBundleCreateError {
		t.Fatalf("refused create: error = %v, want fixed category", err)
	}
	if strings.Contains(stderr, path) || strings.Contains(err.Error(), path) {
		t.Fatalf("refused create exposed the output path: stderr=%q err=%q", stderr, err)
	}
	// #nosec G304 -- path is a fixture inside this test's private TempDir.
	kept, readErr := os.ReadFile(path)
	if readErr != nil || string(kept) != "previous-bundle-content-sentinel" {
		t.Fatalf("existing target changed: bytes=%q err=%v", kept, readErr)
	}
	assertIntNoSentinels(t, sentinels, map[string]string{
		"refused stdout": stdout,
		"refused stderr": stderr,
		"refused error":  err.Error(),
	})

	stdout, stderr, err = runIntSupportBundle(t, "support-bundle", "create")
	if err == nil || err.Error() != "--output is required" {
		t.Fatalf("missing output: error = %v, want fixed flag error", err)
	}
	assertIntNoSentinels(t, sentinels, map[string]string{"missing-output stdout": stdout, "missing-output stderr": stderr})

	// cobra legacy args: an unknown verb under `support-bundle` falls through
	// to the parent's help output without an error (cobra v1.10.2: the
	// non-runnable parent accepts the verb via legacyArgs, then flag.ErrHelp
	// renders HelpFunc on stdout). Pin that exact fallback — a silent no-op
	// or an error would both be a boundary-relevant behavior change — and
	// whatever it prints must not leak.
	stdout, stderr, err = runIntSupportBundle(t, "support-bundle", "bogus-subcommand")
	if err != nil {
		t.Fatalf("unknown verb unexpectedly failed: %v", err)
	}
	if stderr != "" {
		t.Fatalf("unknown verb printed to stderr: %q", stderr)
	}
	for _, marker := range []string{
		"Usage:",
		"yb support-bundle [command]",
		"Create a local support bundle file",
		"Print the local support bundle without writing a file",
	} {
		if !strings.Contains(stdout, marker) {
			t.Fatalf("unknown verb must render the parent help on stdout; missing %q in:\n%s", marker, stdout)
		}
	}
	assertIntNoSentinels(t, sentinels, map[string]string{"unknown-verb stdout": stdout, "unknown-verb stderr": stderr})

	stdout, stderr, err = runIntSupportBundle(t, "support-bundle", "preview", "--no-such-flag")
	if err == nil {
		t.Fatal("unknown flag must fail")
	}
	assertIntNoSentinels(t, sentinels, map[string]string{"unknown-flag stdout": stdout, "unknown-flag stderr": stderr})

	if *requests != 0 {
		t.Fatalf("failure paths issued %d HTTP requests", *requests)
	}
}

// TestIntSupportBundle_E2E_ColdMachineNoEgress: a machine with no profile and
// no YABANIN environment — the public-core path runs with zero configuration,
// no entitlement surface and no network: deterministic output, all presence
// flags false, pinned schema.
func TestIntSupportBundle_E2E_ColdMachineNoEgress(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for _, name := range []string{"YABANIN_GATEWAY_URL", "YABANIN_ADMIN_URL", "YABANIN_API_KEY"} {
		t.Setenv(name, "")    // register restore of the operator's real value
		_ = os.Unsetenv(name) // the cold machine has none of them
	}
	requests := guardIntEgress(t)

	first, stderr, err := runIntSupportBundle(t, "support-bundle", "preview")
	if err != nil {
		t.Fatalf("cold preview failed: %v; stderr=%q", err, stderr)
	}
	second, _, err := runIntSupportBundle(t, "support-bundle", "preview")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("cold machine output is not deterministic:\nfirst=%q\nsecond=%q", first, second)
	}
	path := filepath.Join(t.TempDir(), "bundle.json")
	created, _, err := runIntSupportBundle(t, "support-bundle", "create", "--output", path)
	if err != nil {
		t.Fatal(err)
	}
	if created != first {
		t.Fatalf("cold create differs from preview:\npreview=%q\ncreated=%q", first, created)
	}

	assertSupportBundleKeys(t, []byte(first), "schema_version", "build", "runtime", "local_config")
	var got supportBundle
	if err := json.Unmarshal([]byte(first), &got); err != nil {
		t.Fatal(err)
	}
	if got.LocalConfig != (supportBundleConfig{}) {
		t.Fatalf("cold machine must report false presence everywhere: %+v", got.LocalConfig)
	}
	if *requests != 0 {
		t.Fatalf("cold machine issued %d HTTP requests", *requests)
	}
}
