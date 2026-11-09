package trcli

// Unit tests for the support-bundle diagnostics collection
// (N13-P05-T02 schema v2; N13-P05-T03 scrub-by-profile, schema v3).
// Everything runs in private temp dirs with injected clocks;
// redaction fixtures carry recognizable sentinels; the egress guard proves
// collection never touches the network unless the operator passes --probe.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/auditlog"
)

func runSupportDiagnostics(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	root := RootCommand()
	root.SilenceUsage = true
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs(append([]string{"support-bundle", "diagnostics"}, args...))
	err := root.Execute()
	return stdout.String(), stderr.String(), err
}

// setSupportDiagnosticsHome isolates HOME and clears every environment input
// the diagnostics collector reads, so tests are order-independent.
func setSupportDiagnosticsHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, name := range []string{"YABANIN_GATEWAY_URL", "YABANIN_ADMIN_URL", "YABANIN_API_KEY", "YABANIN_ORG"} {
		t.Setenv(name, "")    // register restore of the operator's real value
		_ = os.Unsetenv(name) // the fixture machine has none of them
	}
	return home
}

func guardDiagnosticsEgress(t *testing.T) *int {
	t.Helper()
	requests := 0
	previousTransport := http.DefaultTransport
	http.DefaultTransport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return nil, fmt.Errorf("unexpected network request from support-bundle diagnostics")
	})
	t.Cleanup(func() { http.DefaultTransport = previousTransport })
	return &requests
}

func TestSupportDiagnostics_SchemaV3FieldSetAndOrderIsFixed(t *testing.T) {
	setSupportDiagnosticsHome(t)

	stdout, stderr, err := runSupportDiagnostics(t, "preview")
	if err != nil {
		t.Fatalf("preview failed: %v; stderr=%q", err, stderr)
	}
	if stderr != "" {
		t.Fatalf("unexpected stderr: %q", stderr)
	}
	assertSupportBundleKeys(t, []byte(stdout),
		"schema_version", "build", "runtime", "local_config", "config", "health", "logs", "manifest")

	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stdout), &top); err != nil {
		t.Fatal(err)
	}
	var got supportDiagnostics
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != 3 {
		t.Fatalf("schema_version = %d, want 3", got.SchemaVersion)
	}
	if got.Build.Version != safeSupportVersion(version) || got.Build.Commit != safeSupportCommit(commit) {
		t.Fatalf("unexpected build metadata: %+v", got.Build)
	}
	// Cold machine: config and logs carry the fixed zero-value shape, probes
	// are absent because no operator asked for them.
	assertSupportBundleKeys(t, top["config"], "source", "collected", "redacted_keys")
	assertSupportBundleKeys(t, top["health"], "profile_readable", "profile_parse_ok", "credentials_file_present", "session_cache")
	assertSupportBundleKeys(t, top["logs"], "org", "scrub_profile", "files", "entries", "included_lines",
		"excluded_foreign_org", "excluded_non_json", "redaction_hits", "content_masks", "content_fields_removed")
	assertSupportBundleKeys(t, top["health"], "profile_readable", "profile_parse_ok", "credentials_file_present", "session_cache")
	if got.Health.ProfileReadable != "absent" || got.Health.ProfileParseOK {
		t.Fatalf("cold machine profile health = %+v, want absent/unparsed", got.Health)
	}
	if got.Health.Probes != nil {
		t.Fatalf("probes must be absent without --probe: %+v", got.Health.Probes)
	}
	if got.Logs.Org != "" || got.Logs.IncludedLines != 0 || got.Logs.ExcludedForeignOrg != 0 || got.Logs.ExcludedNonJSON != 0 || got.Logs.RedactionHits != 0 {
		t.Fatalf("cold machine logs must be empty: %+v", got.Logs)
	}
	if got.Logs.ScrubProfile != string(auditlog.ScrubProfileStandard) {
		t.Fatalf("cold machine scrub profile = %q, want the default standard", got.Logs.ScrubProfile)
	}
	if got.Logs.ContentMasks != 0 || got.Logs.ContentFieldsRemoved != 0 {
		t.Fatalf("cold machine content counters must be zero: %+v", got.Logs)
	}
	if got.Manifest != nil {
		t.Fatalf("cold machine manifest must be empty: %+v", got.Manifest)
	}
}

func TestSupportDiagnostics_ProfileSanitizerTable(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		check     func(t *testing.T, got supportDiagConfig)
		sentinels []string // must never appear anywhere in the sanitized config JSON
	}{
		{
			name: "full profile allowlist",
			input: `{"version":1,"profiles":{"prod":{"gateway_url":"https://user:pass@gw.example:8443/base?p=1#frag","key_ref":"keyref-sentinel","labels":{"team":"label-value-sentinel","env":"prod"}}},` +
				`"harness":{"codex":{"session":true,"ttl":"2h","future_key":"drop-me-sentinel"}},"api_key":"top-secret-sentinel","unknown_section":{"pii":"person-sentinel"}}`,
			check: func(t *testing.T, got supportDiagConfig) {
				t.Helper()
				if !got.Collected || got.ReadError != "" || got.Version == nil || *got.Version != 1 {
					t.Fatalf("unexpected header state: collected=%v error=%q version=%v", got.Collected, got.ReadError, got.Version)
				}
				if len(got.Profiles) != 1 {
					t.Fatalf("profiles = %+v, want exactly one", got.Profiles)
				}
				profile := got.Profiles[0]
				if profile.Name != "prod" {
					t.Fatalf("profile name = %q", profile.Name)
				}
				if profile.GatewayURL != "https://gw.example:8443/base" {
					t.Fatalf("gateway_url = %q, want sanitized host form", profile.GatewayURL)
				}
				if !profile.GatewayURLPresent || profile.GatewayURLRedact {
					t.Fatalf("gateway flags wrong: %+v", profile)
				}
				if !profile.KeyRefPresent || profile.LabelsPresent != 2 {
					t.Fatalf("key_ref/labels must be presence-only: %+v", profile)
				}
				if len(got.Harness) != 1 || got.Harness[0].Tool != "codex" || !got.Harness[0].Session || got.Harness[0].TTL != "2h" {
					t.Fatalf("harness = %+v", got.Harness)
				}
				// api_key, unknown_section, future_key = 3 redactions. The
				// allowlisted version is emitted (not suppressed), so it must
				// not be counted; the gateway URL is emitted sanitized
				// (userinfo/query/fragment stripped, never refused); label
				// values are counted, not emitted, so the label subtree adds
				// none.
				if got.RedactedKeys != 3 {
					t.Fatalf("redacted_keys = %d, want 3", got.RedactedKeys)
				}
			},
			sentinels: []string{"keyref-sentinel", "label-value-sentinel", "top-secret-sentinel", "drop-me-sentinel", "person-sentinel", "user:pass", "p=1", "frag"},
		},
		{
			name:  "invalid json",
			input: `{not json`,
			check: func(t *testing.T, got supportDiagConfig) {
				t.Helper()
				if !got.Collected || got.ReadError != "invalid_json" {
					t.Fatalf("expected invalid_json on collected file, got %+v", got)
				}
			},
		},
		{
			name:  "empty file",
			input: "   ",
			check: func(t *testing.T, got supportDiagConfig) {
				t.Helper()
				if got.ReadError != "empty" {
					t.Fatalf("expected empty, got %q", got.ReadError)
				}
			},
		},
		{
			name:  "json array is invalid shape",
			input: `[1,2,3]`,
			check: func(t *testing.T, got supportDiagConfig) {
				t.Helper()
				if got.ReadError != "invalid_json" {
					t.Fatalf("expected invalid_json for non-object, got %q", got.ReadError)
				}
			},
		},
		{
			name:  "version must be an integer",
			input: `{"version":"1"}`,
			check: func(t *testing.T, got supportDiagConfig) {
				t.Helper()
				if got.Version != nil || got.RedactedKeys != 1 {
					t.Fatalf("string version must be redacted: %+v", got)
				}
			},
		},
		{
			name:  "profiles must be an object",
			input: `{"profiles":[1]}`,
			check: func(t *testing.T, got supportDiagConfig) {
				t.Helper()
				if len(got.Profiles) != 0 || got.RedactedKeys != 1 {
					t.Fatalf("non-object profiles must be redacted: %+v", got)
				}
			},
		},
		{
			name:  "unsafe gateway urls are flagged not emitted",
			input: `{"profiles":{"a":{"gateway_url":"ftp://gw.example"},"b":{"gateway_url":"https://ok.example/path"}}}`,
			check: func(t *testing.T, got supportDiagConfig) {
				t.Helper()
				byName := map[string]supportDiagProfile{}
				for _, profile := range got.Profiles {
					byName[profile.Name] = profile
				}
				if !byName["a"].GatewayURLRedact || byName["a"].GatewayURL != "" {
					t.Fatalf("ftp url must be redacted: %+v", byName["a"])
				}
				if byName["b"].GatewayURL != "https://ok.example/path" {
					t.Fatalf("https url must pass: %+v", byName["b"])
				}
			},
		},
		{
			name:  "ttl shape is allowlisted",
			input: `{"harness":{"a":{"ttl":"2h30m"},"b":{"ttl":"15m"}}}`,
			check: func(t *testing.T, got supportDiagConfig) {
				t.Helper()
				byName := map[string]supportDiagHarnessTool{}
				for _, tool := range got.Harness {
					byName[tool.Tool] = tool
				}
				if byName["a"].TTL != "" || byName["a"].OtherRedacted != 0 {
					t.Fatalf("composite ttl must be redacted: %+v", byName["a"])
				}
				if byName["b"].TTL != "15m" {
					t.Fatalf("simple ttl must pass: %+v", byName["b"])
				}
				if got.RedactedKeys != 1 {
					t.Fatalf("redacted_keys = %d, want 1", got.RedactedKeys)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := sanitizeSupportProfile([]byte(test.input))
			test.check(t, got)
			encoded, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			for _, sentinel := range test.sentinels {
				if strings.Contains(string(encoded), sentinel) {
					t.Errorf("sanitized config leaked %q", sentinel)
				}
			}
		})
	}
}

func TestSupportDiagnostics_LogTailBoundsAndTruncation(t *testing.T) {
	line := fmt.Sprintf(`{"org":"a","pad":"%s"}`, strings.Repeat("x", 256))
	lineBytes := len(line) + 1
	// Build a file with 12 lines of ~270 bytes each (> 2 KiB total).
	var content strings.Builder
	for i := 0; i < 12; i++ {
		content.WriteString(line)
		content.WriteByte('\n')
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	if err := os.WriteFile(path, []byte(content.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("whole file fits", func(t *testing.T) {
		window, truncated, err := readSupportDiagLogTail(path, int64(content.Len())+1024)
		if err != nil || truncated {
			t.Fatalf("small file: truncated=%v err=%v", truncated, err)
		}
		if string(window) != content.String() {
			t.Fatal("small file window must equal the whole file")
		}
	})

	t.Run("window is a line-aligned tail", func(t *testing.T) {
		window, truncated, err := readSupportDiagLogTail(path, int64(5*lineBytes))
		if err != nil || !truncated {
			t.Fatalf("bounded read: truncated=%v err=%v", truncated, err)
		}
		sum := sha256.Sum256(window)
		if hex.EncodeToString(sum[:]) == "" {
			t.Fatal("empty window")
		}
		// The window must start exactly at a line boundary (the partial first
		// line is dropped) and hold only complete recent lines.
		windowText := string(window)
		if !strings.HasPrefix(windowText, "{") {
			t.Fatalf("window is not line-aligned: %q", windowText[:20])
		}
		if got := strings.Count(strings.TrimSuffix(windowText, "\n"), "\n") + 1; got != 4 {
			t.Fatalf("window holds %d complete lines, want 4", got)
		}
		if len(window) > 5*lineBytes {
			t.Fatalf("window exceeded the requested bound: %d", len(window))
		}
	})

	t.Run("missing file fails closed", func(t *testing.T) {
		_, _, err := readSupportDiagLogTail(filepath.Join(dir, "missing.jsonl"), 8192)
		if err == nil || err.Error() != supportBundleDiagLogReadError {
			t.Fatalf("err = %v, want fixed category", err)
		}
	})
}

func TestSupportDiagnostics_LogOrgScopingTable(t *testing.T) {
	tests := []struct {
		name             string
		selected         string
		lines            []string
		wantIncluded     []string // exact redacted messages, in order
		wantForeign      int
		wantNonJSON      int
		wantIncludedArgs []string
	}{
		{
			name:     "own org kept, foreign dropped, unattributed kept",
			selected: "org-a",
			lines: []string{
				`{"org_id":"org-a","msg":"hello"}`,
				`{"org_id":"org-b","msg":"foreign-sentinel"}`,
				`{"msg":"local event"}`,
				`plain text line`,
			},
			wantIncluded: []string{`{"org_id":"org-a","msg":"hello"}`, `{"msg":"local event"}`},
			wantForeign:  1,
			wantNonJSON:  1,
		},
		{
			name:     "no selected org drops every org-tagged line",
			selected: "",
			lines: []string{
				`{"org":"org-a","msg":"a"}`,
				`{"organization":"org-b","msg":"b"}`,
				`{"msg":"unattributed kept"}`,
			},
			wantIncluded: []string{`{"msg":"unattributed kept"}`},
			wantForeign:  2,
		},
		{
			name:     "nested org.id is attributed",
			selected: "org-a",
			lines: []string{
				`{"org":{"id":"org-a"},"msg":"nested own"}`,
				`{"org":{"id":"org-z"},"msg":"nested foreign-sentinel"}`,
			},
			// Unredacted JSON lines keep their original bytes: the
			// re-marshal to sorted keys happens only when a mask was
			// applied, so evidence fidelity is preserved.
			wantIncluded: []string{`{"org":{"id":"org-a"},"msg":"nested own"}`},
			wantForeign:  1,
		},
		{
			name:     "empty org string is not attribution",
			selected: "org-a",
			lines: []string{
				`{"org":"","msg":"kept as unattributed"}`,
			},
			wantIncluded: []string{`{"org":"","msg":"kept as unattributed"}`},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			window := []byte(strings.Join(test.lines, "\n") + "\n")
			included, foreign, nonJSON, _, _, _ := supportDiagLogLines(window, supportDiagOptions{Org: test.selected, MaxLines: supportDiagMaxLines})
			if foreign != test.wantForeign || nonJSON != test.wantNonJSON {
				t.Fatalf("counts = (foreign %d, nonjson %d), want (%d, %d)", foreign, nonJSON, test.wantForeign, test.wantNonJSON)
			}
			if len(included) != len(test.wantIncluded) {
				t.Fatalf("included %d lines, want %d: %+v", len(included), len(test.wantIncluded), included)
			}
			for i, want := range test.wantIncluded {
				if included[i].message != want {
					t.Errorf("line %d = %q, want %q", i, included[i].message, want)
				}
			}
			for _, line := range included {
				for _, forbidden := range []string{"foreign-sentinel", "org-b", "org-z"} {
					if strings.Contains(line.message, forbidden) {
						t.Errorf("included line leaked %q: %s", forbidden, line.message)
					}
				}
			}
		})
	}
}

func TestSupportDiagnostics_LogRedactionFixtures(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		want     string
		wantHits int
	}{
		{
			name:     "bearer in plain text",
			input:    `auth failure for bearer AbcDef1234567890 request`,
			want:     `auth failure for bearer [REDACTED] request`,
			wantHits: 1,
		},
		{
			name:     "json api key masked structurally",
			input:    `{"api_key":"sk-super-secret-1","msg":"ok"}`,
			want:     `{"api_key":"[REDACTED]","msg":"ok"}`,
			wantHits: 1,
		},
		{
			name:     "session key masked",
			input:    `{"key":"session-key-value-123","msg":"ok"}`,
			want:     `{"key":"[REDACTED]","msg":"ok"}`,
			wantHits: 1,
		},
		{
			name:     "kv pair inside message text masked",
			input:    `{"msg":"password=hunter22 retry"}`,
			want:     `{"msg":"password=[REDACTED] retry"}`,
			wantHits: 1,
		},
		{
			name:     "ordinary prose untouched",
			input:    `{"msg":"the token of appreciation was natural"}`,
			want:     `{"msg":"the token of appreciation was natural"}`,
			wantHits: 0,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, hits := redactSupportDiagLine(test.input)
			if got != test.want {
				t.Fatalf("redacted = %q, want %q", got, test.want)
			}
			if hits != test.wantHits {
				t.Fatalf("hits = %d, want %d", hits, test.wantHits)
			}
		})
	}
}

func TestSupportDiagnostics_HealthSnapshotCounts(t *testing.T) {
	home := setSupportDiagnosticsHome(t)
	sessions := filepath.Join(home, ".yabanin", "sessions")
	if err := os.MkdirAll(sessions, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	previousNow := supportDiagNow
	supportDiagNow = func() time.Time { return now }
	t.Cleanup(func() { supportDiagNow = previousNow })

	files := map[string]string{
		"aaa.json": `{"id":"id-sentinel","key":"key-sentinel","expires_at":"2027-01-01T00:00:00Z"}`,
		"bbb.json": `{"id":"id-sentinel","key":"key-sentinel","expires_at":"2020-01-01T00:00:00Z"}`,
		"ccc.json": `{not json`,
		"ddd.txt":  `ignored non-json extension`,
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(sessions, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// credentials file present
	if err := os.WriteFile(filepath.Join(home, ".yabanin", "credentials.json"), []byte(`{"keys":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, err := runSupportDiagnostics(t, "preview")
	if err != nil {
		t.Fatalf("preview failed: %v; stderr=%q", err, stderr)
	}
	var got supportDiagnostics
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatal(err)
	}
	want := supportDiagSessionCache{Files: 3, Valid: 1, Expired: 1, Unreadable: 1}
	if got.Health.SessionCache != want {
		t.Fatalf("session cache = %+v, want %+v", got.Health.SessionCache, want)
	}
	if !got.Health.CredentialsFilePresent {
		t.Fatal("credentials file presence must be true")
	}
	// Session identifiers and keys never surface; only counts do.
	for _, sentinel := range []string{"id-sentinel", "key-sentinel"} {
		if strings.Contains(stdout, sentinel) {
			t.Errorf("health snapshot leaked %q", sentinel)
		}
	}
	if stderr != "" {
		t.Fatalf("unexpected stderr: %q", stderr)
	}
}

func TestSupportDiagnostics_ProfileHealthStates(t *testing.T) {
	t.Run("parse failure is reported not hidden", func(t *testing.T) {
		home := setSupportDiagnosticsHome(t)
		dir := filepath.Join(home, ".yabanin")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(configPath(home), []byte(`{"version":1,"profiles":`), 0o600); err != nil {
			t.Fatal(err)
		}
		stdout, _, err := runSupportDiagnostics(t, "preview")
		if err != nil {
			t.Fatal(err)
		}
		var got supportDiagnostics
		if err := json.Unmarshal([]byte(stdout), &got); err != nil {
			t.Fatal(err)
		}
		if got.Health.ProfileReadable != "yes" || got.Health.ProfileParseOK {
			t.Fatalf("health = %+v, want readable but unparsed", got.Health)
		}
		if got.Config.ReadError != "invalid_json" {
			t.Fatalf("config read error = %q, want invalid_json", got.Config.ReadError)
		}
	})

	t.Run("permission failure is visible", func(t *testing.T) {
		home := setSupportDiagnosticsHome(t)
		dir := filepath.Join(home, ".yabanin")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(configPath(home), []byte(`{"version":1}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o000); err != nil {
			t.Fatal(err)
		}
		// #nosec G302 -- 0700 is the tightest safe DIRECTORY mode: the
		// execute bit is required for traversal, so G302's 0600 file
		// ceiling does not apply to this fixture restore.
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		if _, err := os.ReadFile(configPath(home)); !os.IsPermission(err) {
			t.Skipf("permission errors not enforced here: %v", err)
		}
		stdout, _, err := runSupportDiagnostics(t, "preview")
		if err != nil {
			t.Fatalf("unreadable profile must degrade to health state, got error %v", err)
		}
		var got supportDiagnostics
		if err := json.Unmarshal([]byte(stdout), &got); err != nil {
			t.Fatal(err)
		}
		if got.Health.ProfileReadable != "no" || got.Config.Collected {
			t.Fatalf("unreadable profile must be reported: health=%+v config=%+v", got.Health, got.Config)
		}
		if strings.Contains(stdout, home) {
			t.Fatal("bundle must not contain the home path")
		}
	})
}

func TestSupportDiagnostics_NoEgressWithoutProbeAndDeterministic(t *testing.T) {
	setSupportDiagnosticsHome(t)
	// Poisoned env URLs: collection must never dial them without --probe.
	t.Setenv("YABANIN_GATEWAY_URL", "https://egress-sentinel.example")
	t.Setenv("YABANIN_ADMIN_URL", "https://egress-sentinel.example")
	requests := guardDiagnosticsEgress(t)

	first, stderr, err := runSupportDiagnostics(t, "preview")
	if err != nil {
		t.Fatalf("preview failed: %v; stderr=%q", err, stderr)
	}
	second, _, err := runSupportDiagnostics(t, "preview")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("diagnostics preview is not deterministic:\nfirst=%q\nsecond=%q", first, second)
	}
	path := filepath.Join(t.TempDir(), "diag.json")
	created, _, err := runSupportDiagnostics(t, "create", "--output", path, "--consent")
	if err != nil {
		t.Fatal(err)
	}
	// stdout now carries the consent summary before the exact bundle JSON.
	if !strings.Contains(created, first) {
		t.Fatal("consented create stdout must contain the exact preview JSON")
	}
	// #nosec G304 -- fixture path inside the test's private TempDir.
	file, err := os.ReadFile(path)
	if err != nil || string(file) != first {
		t.Fatalf("file/preview mismatch: err=%v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("created mode %04o, want 0600", got)
	}
	if strings.Contains(first, "egress-sentinel.example") {
		t.Fatal("configured URLs must not be dialed or emitted without --probe")
	}
	if *requests != 0 {
		t.Fatalf("diagnostics issued %d HTTP requests without --probe", *requests)
	}
}

func TestSupportDiagnostics_ProbeOnlyWithOperatorFlag(t *testing.T) {
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer gateway.Close()
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer admin.Close()

	t.Run("no probe: configured env targets never dialed", func(t *testing.T) {
		setSupportDiagnosticsHome(t)
		t.Setenv("YABANIN_GATEWAY_URL", gateway.URL)
		t.Setenv("YABANIN_ADMIN_URL", admin.URL)
		requests := guardDiagnosticsEgress(t)
		stdout, _, err := runSupportDiagnostics(t, "preview")
		if err != nil {
			t.Fatal(err)
		}
		var got supportDiagnostics
		if err := json.Unmarshal([]byte(stdout), &got); err != nil {
			t.Fatal(err)
		}
		if got.Health.Probes != nil {
			t.Fatalf("probes present without --probe: %+v", got.Health.Probes)
		}
		if *requests != 0 {
			t.Fatalf("collection dialed the network %d times without --probe", *requests)
		}
	})

	t.Run("probe: only explicit targets, categorical statuses", func(t *testing.T) {
		setSupportDiagnosticsHome(t)
		stdout, _, err := runSupportDiagnostics(t, "preview", "--probe", "--base-url", gateway.URL, "--admin-url", admin.URL)
		if err != nil {
			t.Fatalf("probe preview failed: %v", err)
		}
		var got supportDiagnostics
		if err := json.Unmarshal([]byte(stdout), &got); err != nil {
			t.Fatal(err)
		}
		if len(got.Health.Probes) != 2 {
			t.Fatalf("probes = %+v, want gateway+admin", got.Health.Probes)
		}
		byTarget := map[string]string{}
		for _, probe := range got.Health.Probes {
			byTarget[probe.Target] = probe.Status
		}
		if byTarget["gateway"] != "healthy" {
			t.Fatalf("gateway probe = %q, want healthy", byTarget["gateway"])
		}
		if byTarget["admin"] != "reports unhealthy (HTTP 503)" {
			t.Fatalf("admin probe = %q", byTarget["admin"])
		}
		if strings.Contains(stdout, gateway.URL) || strings.Contains(stdout, admin.URL) {
			t.Fatal("probe targets must stay categorical: no URLs in the bundle")
		}
	})

	t.Run("probe without configured target fails fixed", func(t *testing.T) {
		setSupportDiagnosticsHome(t)
		requests := guardDiagnosticsEgress(t)
		_, _, err := runSupportDiagnostics(t, "preview", "--probe")
		if err == nil || err.Error() != supportBundleDiagProbeTargetError {
			t.Fatalf("err = %v, want fixed probe-target category", err)
		}
		if *requests != 0 {
			t.Fatalf("probe-without-target dialed %d times", *requests)
		}
	})
}

func TestSupportDiagnostics_CreateRefusesExistingAndMissingOutput(t *testing.T) {
	setSupportDiagnosticsHome(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "diag.json")
	if err := os.WriteFile(path, []byte("keep-me"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err := runSupportDiagnostics(t, "create", "--output", path, "--consent")
	if err == nil || err.Error() != supportBundleDiagnosticsError {
		t.Fatalf("err = %v, want fixed category", err)
	}
	if stdout != "" || !strings.Contains(stderr, supportBundleDiagnosticsError) || strings.Contains(stderr, path) {
		t.Fatalf("failure emitted output: stdout=%q stderr=%q", stdout, stderr)
	}
	// #nosec G304 -- fixture path inside the test's private TempDir.
	kept, readErr := os.ReadFile(path)
	if readErr != nil || string(kept) != "keep-me" {
		t.Fatalf("existing target changed: %q err=%v", kept, readErr)
	}
	if _, _, err := runSupportDiagnostics(t, "create"); err == nil || err.Error() != "--output is required" {
		t.Fatalf("missing output err = %v", err)
	}
}

func TestSupportDiagnostics_UnreadableLogFileFailsClosed(t *testing.T) {
	setSupportDiagnosticsHome(t)
	missing := filepath.Join(t.TempDir(), "missing.jsonl")
	stdout, stderr, err := runSupportDiagnostics(t, "preview", "--log-file", missing)
	if err == nil || err.Error() != supportBundleDiagLogReadError {
		t.Fatalf("err = %v, want fixed log-read category", err)
	}
	if stdout != "" || !strings.Contains(stderr, supportBundleDiagLogReadError) || strings.Contains(stderr, missing) {
		t.Fatalf("failure leaked output: stdout=%q stderr=%q", stdout, stderr)
	}
	path := filepath.Join(t.TempDir(), "diag.json")
	_, _, err = runSupportDiagnostics(t, "create", "--output", path, "--consent", "--log-file", missing)
	if err == nil || err.Error() != supportBundleDiagLogReadError {
		t.Fatalf("create err = %v, want fixed log-read category", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatal("no partial bundle file may exist after a failed collection")
	}
}

func TestSupportDiagnostics_FlagRangeValidation(t *testing.T) {
	setSupportDiagnosticsHome(t)
	for _, args := range [][]string{
		{"preview", "--log-max-lines", "0"},
		{"preview", "--log-max-lines", "10001"},
		{"preview", "--log-max-bytes", "1023"},
		{"preview", "--log-max-bytes", "16777217"},
	} {
		_, _, err := runSupportDiagnostics(t, args...)
		if err == nil {
			t.Fatalf("args %v must fail", args)
		}
		if !strings.HasPrefix(err.Error(), "--log-max-") {
			t.Fatalf("args %v err = %v, want a fixed flag error", args, err)
		}
	}
}

func TestSupportDiagnostics_PoisonedMachineNoLeaks(t *testing.T) {
	home := setSupportDiagnosticsHome(t)
	dir := filepath.Join(home, ".yabanin")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	profile := `{"version":1,` +
		`"profiles":{"prod":{"gateway_url":"https://userinfo-sentinel:pw-sentinel@profile-gw-sentinel.example/api?token=qs-sentinel","key_ref":"keyref-sentinel","labels":{"team":"label-sentinel"}}},` +
		`"prompt":"prompt-sentinel","email":"pii-sentinel@example.private","api_key":"profile-key-sentinel"}`
	if err := os.WriteFile(configPath(home), []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	logDir := t.TempDir()
	logPath := filepath.Join(logDir, "gateway.jsonl")
	logLines := strings.Join([]string{
		`{"org_id":"own-org","msg":"request ok","api_key":"log-key-sentinel"}`,
		`{"org_id":"foreign-org-sentinel","msg":"foreign payload sentinel"}`,
		`{"msg":"bearer AbcDef0123456789 expired"}`,
		`totally plain foreign-org-sentinel line`,
		`{"org_id":"own-org","msg":"password=pw-sentinel-in-log leaked"}`,
	}, "\n") + "\n"
	if err := os.WriteFile(logPath, []byte(logLines), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("YABANIN_API_KEY", "env-key-sentinel")
	t.Setenv("YABANIN_ORG", "env-org-sentinel")

	requests := guardDiagnosticsEgress(t)
	stdout, stderr, err := runSupportDiagnostics(t, "preview",
		"--org", "own-org",
		"--api-key", "flag-key-sentinel",
		"--log-file", logPath,
		"--log-max-lines", "4",
	)
	if err != nil {
		t.Fatalf("preview failed: %v; stderr=%q", err, stderr)
	}
	if *requests != 0 {
		t.Fatalf("poisoned run issued %d HTTP requests", *requests)
	}

	var got supportDiagnostics
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatal(err)
	}
	// Org scope: the selected org is the only org value in the bundle.
	if got.Logs.Org != "own-org" {
		t.Fatalf("logs.org = %q, want the selected org", got.Logs.Org)
	}
	// 5 log lines, window bounded to the last 4 → the first line is dropped
	// by the line bound; of the rest: foreign org + plain text excluded.
	if got.Logs.IncludedLines != 2 {
		t.Fatalf("included lines = %d, want 2: %+v", got.Logs.IncludedLines, got.Logs.Entries)
	}
	if got.Logs.ExcludedForeignOrg != 1 || got.Logs.ExcludedNonJSON != 1 {
		t.Fatalf("exclusion counts = (%d, %d), want (1, 1)", got.Logs.ExcludedForeignOrg, got.Logs.ExcludedNonJSON)
	}
	if got.Logs.RedactionHits < 2 {
		t.Fatalf("redaction hits = %d, want at least the two secret fixtures", got.Logs.RedactionHits)
	}
	if len(got.Manifest) != 1 {
		t.Fatalf("manifest = %+v, want exactly the log artifact", got.Manifest)
	}
	if got.Manifest[0].Artifact != "logs:"+filepath.Base(logPath) {
		t.Fatalf("manifest artifact = %q", got.Manifest[0].Artifact)
	}
	if got.Manifest[0].Sha256 == "" || got.Manifest[0].Bytes == 0 {
		t.Fatalf("manifest must fingerprint the artifact: %+v", got.Manifest[0])
	}

	// Credential-bearing URL parts are stripped; the sanitized host form
	// (scheme://host[:port][/path]) is emitted by design — it is endpoint
	// metadata, not a secret — so only userinfo, password and query
	// components are forbidden sentinels here.
	for _, sentinel := range []string{
		"userinfo-sentinel", "pw-sentinel", "qs-sentinel",
		"keyref-sentinel", "label-sentinel", "prompt-sentinel", "pii-sentinel", "profile-key-sentinel",
		"env-key-sentinel", "flag-key-sentinel", "env-org-sentinel",
		"foreign-org-sentinel", "foreign payload sentinel",
		"log-key-sentinel", "AbcDef0123456789", "pw-sentinel-in-log",
		home, logDir,
	} {
		if strings.Contains(stdout, sentinel) {
			t.Errorf("diagnostics bundle leaked %q", sentinel)
		}
	}
	// Redaction must keep the own-org entries readable for incident work.
	for _, entry := range got.Logs.Entries {
		if !strings.Contains(entry.Message, "[REDACTED]") && !strings.Contains(entry.Message, "expired") && !strings.Contains(entry.Message, "leaked") {
			t.Errorf("unexpected entry content: %+v", entry)
		}
	}
}

// compile-time guard: the collectors must stay deterministic under the
// injected clock and never need wall time elsewhere.
var _ = context.Background
