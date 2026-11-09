package trcli

// Tests for the support-bundle consent and local-export layer
// (N13-P05-T04): preview → consent → local export. The gate must refuse
// without explicit --consent (writing nothing), the summary must show counts
// and digests but never content or paths, the digest binding must refuse a
// stale consent, and the consented export stays local, 0600, deterministic.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSupportDiagnostics_ConsentGate_RefusesWithoutConsent(t *testing.T) {
	setSupportDiagnosticsHome(t)
	requests := guardDiagnosticsEgress(t)

	path := filepath.Join(t.TempDir(), "diag.json")
	stdout, stderr, err := runSupportDiagnostics(t, "create", "--output", path)
	if err == nil || err.Error() != supportDiagConsentRequiredError {
		t.Fatalf("err = %v, want fixed consent category", err)
	}
	if !strings.Contains(stderr, supportDiagConsentRequiredError) {
		t.Fatalf("stderr must carry the consent category: %q", stderr)
	}
	// The refusal IS the review surface: the summary must be on stdout.
	if !strings.HasPrefix(stdout, "support bundle diagnostics — consent summary\n") {
		t.Fatalf("refusal must render the consent summary, got: %q", stdout)
	}
	if !strings.Contains(stdout, "export: refused — nothing written") {
		t.Fatalf("refusal summary must state nothing was written: %q", stdout)
	}
	if !strings.Contains(stdout, "sha256=") || !strings.Contains(stdout, "bytes=") {
		t.Fatalf("refusal summary must carry the bundle digest and size: %q", stdout)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatal("no archive may exist without explicit consent")
	}
	if *requests != 0 {
		t.Fatalf("refused create issued %d HTTP requests", *requests)
	}
}

func TestSupportDiagnostics_ConsentGate_RefusalPrecedesFileConflict(t *testing.T) {
	setSupportDiagnosticsHome(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "diag.json")
	if err := os.WriteFile(path, []byte("keep-me"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Without consent the gate fires before any filesystem attempt: the
	// operator sees the consent category, not the file-conflict category.
	stdout, _, err := runSupportDiagnostics(t, "create", "--output", path)
	if err == nil || err.Error() != supportDiagConsentRequiredError {
		t.Fatalf("err = %v, want fixed consent category", err)
	}
	if !strings.Contains(stdout, "consent summary") {
		t.Fatalf("refusal must render the summary: %q", stdout)
	}
	kept, readErr := os.ReadFile(path) // #nosec G304 -- fixture inside the test's private TempDir
	if readErr != nil || string(kept) != "keep-me" {
		t.Fatalf("existing target changed: %q err=%v", kept, readErr)
	}
}

func TestSupportDiagnostics_ConsentGate_ConsentedLocalExport(t *testing.T) {
	setSupportDiagnosticsHome(t)
	requests := guardDiagnosticsEgress(t)

	preview, stderr, err := runSupportDiagnostics(t, "preview")
	if err != nil {
		t.Fatalf("preview failed: %v; stderr=%q", err, stderr)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "diag.json")
	created, stderr, err := runSupportDiagnostics(t, "create", "--output", path, "--consent")
	if err != nil {
		t.Fatalf("consented create failed: %v; stderr=%q", err, stderr)
	}
	// stdout = summary first, then the exact bundle JSON as the tail.
	if !strings.HasPrefix(created, "support bundle diagnostics — consent summary\n") {
		t.Fatalf("consented create must start with the summary: %q", created)
	}
	if !strings.HasSuffix(created, preview) {
		t.Fatal("consented create stdout must end with the exact preview JSON")
	}
	if !strings.Contains(created, "export: local archive written") {
		t.Fatalf("consented create must confirm the local export: %q", created)
	}
	// #nosec G304 -- fixture inside the test's private TempDir.
	file, err := os.ReadFile(path)
	if err != nil || string(file) != preview {
		t.Fatalf("archive/preview mismatch: err=%v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("archive mode %04o, want 0600", got)
	}

	// Determinism: a second consented export on the same machine state is
	// byte-identical (summary and JSON), and so is the archive.
	second, _, err := runSupportDiagnostics(t, "create", "--output", filepath.Join(dir, "diag2.json"), "--consent")
	if err != nil {
		t.Fatal(err)
	}
	if second != created {
		t.Fatal("consented create is not deterministic across invocations")
	}
	secondFile, err := os.ReadFile(filepath.Join(dir, "diag2.json")) // #nosec G304 -- fixture path
	if err != nil || !bytes.Equal(secondFile, file) {
		t.Fatalf("archives diverge: err=%v", err)
	}
	if *requests != 0 {
		t.Fatalf("consented export issued %d HTTP requests", *requests)
	}
}

func TestSupportDiagnostics_ConsentDigest_BindsExactBytes(t *testing.T) {
	setSupportDiagnosticsHome(t)
	dir := t.TempDir()

	preview, _, err := runSupportDiagnostics(t, "preview")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(preview))
	digest := hex.EncodeToString(sum[:])

	path := filepath.Join(dir, "bound.json")
	if _, _, err := runSupportDiagnostics(t, "create", "--output", path, "--consent", "--consent-digest", digest); err != nil {
		t.Fatalf("digest-bound create failed: %v", err)
	}
	file, err := os.ReadFile(path) // #nosec G304 -- fixture inside the test's private TempDir
	if err != nil || string(file) != preview {
		t.Fatalf("digest-bound archive/preview mismatch: err=%v", err)
	}

	stale := filepath.Join(dir, "stale.json")
	_, _, err = runSupportDiagnostics(t, "create", "--output", stale, "--consent", "--consent-digest", strings.Repeat("0", 64))
	if err == nil || err.Error() != supportDiagConsentDigestMismatchError {
		t.Fatalf("stale digest err = %v, want fixed mismatch category", err)
	}
	if _, statErr := os.Stat(stale); !os.IsNotExist(statErr) {
		t.Fatal("a stale consent must not write an archive")
	}

	malformed := filepath.Join(dir, "malformed.json")
	stdout, _, err := runSupportDiagnostics(t, "create", "--output", malformed, "--consent", "--consent-digest", "nothex")
	if err == nil || err.Error() != supportDiagConsentDigestFlagError {
		t.Fatalf("malformed digest err = %v, want fixed flag category", err)
	}
	if stdout != "" {
		t.Fatalf("malformed digest must fail before any output: %q", stdout)
	}
	if _, statErr := os.Stat(malformed); !os.IsNotExist(statErr) {
		t.Fatal("a malformed digest must not write an archive")
	}
}

func TestSupportDiagnostics_ConsentSummary_LeakFreeAndDeterministic(t *testing.T) {
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
		`{"org_id":"own-org","msg":"password=pw-sentinel-in-log leaked","payload":"customer-content-sentinel"}`,
	}, "\n") + "\n"
	if err := os.WriteFile(logPath, []byte(logLines), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("YABANIN_API_KEY", "env-key-sentinel")
	t.Setenv("YABANIN_ORG", "env-org-sentinel")
	requests := guardDiagnosticsEgress(t)

	path := filepath.Join(t.TempDir(), "diag.json")
	stdout, _, err := runSupportDiagnostics(t, "create", "--output", path, "--org", "own-org", "--log-file", logPath)
	if err == nil || err.Error() != supportDiagConsentRequiredError {
		t.Fatalf("err = %v, want fixed consent category", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatal("refused create must not write an archive")
	}

	// The summary shows facts and counts, never content or locations.
	for _, sentinel := range []string{
		"userinfo-sentinel", "pw-sentinel", "qs-sentinel",
		"keyref-sentinel", "label-sentinel", "prompt-sentinel", "pii-sentinel", "profile-key-sentinel",
		"env-key-sentinel", "env-org-sentinel",
		"foreign-org-sentinel", "foreign payload sentinel",
		"log-key-sentinel", "pw-sentinel-in-log", "customer-content-sentinel",
		"request ok",
		home, logDir, logPath,
	} {
		if strings.Contains(stdout, sentinel) {
			t.Errorf("consent summary leaked %q", sentinel)
		}
	}
	// Facts that MUST be visible for an informed consent: the operator's
	// selected org, the applied scrub profile, exclusion/scrub counts and the
	// log basenames (the bundle's own basename-only policy).
	for _, marker := range []string{
		"org=own-org", "scrub_profile=standard",
		"included_lines=2", "excluded_foreign_org=1", "excluded_non_json=0",
		"content_fields_removed=1", "gateway.jsonl",
	} {
		if !strings.Contains(stdout, marker) {
			t.Errorf("consent summary missing %q in:\n%s", marker, stdout)
		}
	}
	if !strings.Contains(stdout, "api_key_env_set=true") {
		t.Errorf("consent summary must report env presence booleans:\n%s", stdout)
	}

	second, _, err := runSupportDiagnostics(t, "create", "--output", path, "--org", "own-org", "--log-file", logPath)
	if err == nil || err.Error() != supportDiagConsentRequiredError {
		t.Fatalf("second refusal err = %v", err)
	}
	if second != stdout {
		t.Fatal("consent summary is not deterministic across invocations")
	}
	if *requests != 0 {
		t.Fatalf("refused create issued %d HTTP requests", *requests)
	}
}

func TestSupportDiagnostics_PreviewSummaryOnly(t *testing.T) {
	setSupportDiagnosticsHome(t)
	requests := guardDiagnosticsEgress(t)

	first, stderr, err := runSupportDiagnostics(t, "preview", "--summary")
	if err != nil {
		t.Fatalf("preview --summary failed: %v; stderr=%q", err, stderr)
	}
	if !strings.HasPrefix(first, "support bundle diagnostics — consent summary\n") {
		t.Fatalf("preview --summary must render the summary: %q", first)
	}
	if !strings.Contains(first, "export: preview only — nothing written") {
		t.Fatalf("preview summary footer wrong: %q", first)
	}
	if strings.HasPrefix(strings.TrimSpace(first), "{") {
		t.Fatal("preview --summary must not emit JSON")
	}
	second, _, err := runSupportDiagnostics(t, "preview", "--summary")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("preview --summary is not deterministic")
	}
	// The full preview stays the JSON document — unchanged contract.
	full, _, err := runSupportDiagnostics(t, "preview")
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(full, "support bundle diagnostics") {
		t.Fatal("plain preview must not render the summary")
	}
	if *requests != 0 {
		t.Fatalf("preview issued %d HTTP requests", *requests)
	}
}
