package trcli

// Unit tests for the support-bundle scrub-by-profile layer (N13-P05-T03).
// Fixtures use recognizable sentinels for customer content and PII; the
// egress guard proves scrubbing never turns collection into a network
// action; every profile boundary and counter is pinned exactly.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/auditlog"
)

// scrubFixtureLog writes a log file with the fixture lines and returns its
// path. The first line carries the customer-content sentinel, the second a
// credential sentinel, the third a foreign-org line and the fourth a
// non-JSON line — all four profiles and scoping outcomes in one file.
func scrubFixtureLog(t *testing.T) string {
	t.Helper()
	lines := []string{
		`{"org_id":"org-a","msg":"user jane@example.com from 10.1.2.3 retry","payload":"customer-content-sentinel","prompt_hash":"abc123digest"}`,
		`{"org_id":"org-a","api_key":"sk-credential-sentinel","msg":"auth ok"}`,
		`{"org_id":"org-b","msg":"foreign-org-sentinel"}`,
		`plain text line, not json`,
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSupportDiagnostics_ScrubProfileFlagValidation(t *testing.T) {
	setSupportDiagnosticsHome(t)
	path := scrubFixtureLog(t)

	t.Run("unknown value refuses the bundle with the fixed category", func(t *testing.T) {
		stdout, _, err := runSupportDiagnostics(t, "preview", "--log-file", path, "--scrub-profile", "verbose")
		if err == nil {
			t.Fatal("unknown --scrub-profile must fail")
		}
		if err.Error() != supportDiagScrubFlagError {
			t.Fatalf("err = %v, want fixed category", err)
		}
		if strings.Contains(stdout, "customer-content-sentinel") || strings.Contains(stdout, "\"logs\"") {
			t.Fatalf("a bundle must not be produced on flag error: %q", stdout)
		}
	})

	t.Run("case and whitespace normalized", func(t *testing.T) {
		stdout, _, err := runSupportDiagnostics(t, "preview", "--log-file", path, "--scrub-profile", "  STRICT ")
		if err != nil {
			t.Fatalf("normalized value must be accepted: %v", err)
		}
		var got supportDiagnostics
		if err := json.Unmarshal([]byte(stdout), &got); err != nil {
			t.Fatal(err)
		}
		if got.Logs.ScrubProfile != string(auditlog.ScrubProfileStrict) {
			t.Fatalf("scrub_profile = %q, want normalized strict", got.Logs.ScrubProfile)
		}
	})
}

func TestSupportDiagnostics_StandardProfileScrub(t *testing.T) {
	setSupportDiagnosticsHome(t)
	guard := guardDiagnosticsEgress(t)
	path := scrubFixtureLog(t)

	stdout, stderr, err := runSupportDiagnostics(t, "preview", "--log-file", path, "--org", "org-a")
	if err != nil {
		t.Fatalf("preview failed: %v; stderr=%q", err, stderr)
	}
	if *guard != 0 {
		t.Fatalf("scrubbed collection must not touch the network (%d requests)", *guard)
	}

	var got supportDiagnostics
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatal(err)
	}
	logs := got.Logs
	if logs.ScrubProfile != string(auditlog.ScrubProfileStandard) {
		t.Fatalf("scrub_profile = %q, want standard", logs.ScrubProfile)
	}
	if logs.IncludedLines != 2 || logs.ExcludedForeignOrg != 1 || logs.ExcludedNonJSON != 1 {
		t.Fatalf("scoping counts = (in %d, foreign %d, nonjson %d), want (2, 1, 1)",
			logs.IncludedLines, logs.ExcludedForeignOrg, logs.ExcludedNonJSON)
	}
	// Customer content dropped (payload), PII masked (email + IP), the
	// credential masked structurally, prompt_hash preserved.
	if logs.ContentFieldsRemoved != 1 || logs.ContentMasks != 2 || logs.RedactionHits != 1 {
		t.Fatalf("scrub counters = (dropped %d, masks %d, creds %d), want (1, 2, 1)",
			logs.ContentFieldsRemoved, logs.ContentMasks, logs.RedactionHits)
	}
	for _, forbidden := range []string{"customer-content-sentinel", "jane@example.com", "10.1.2.3", "sk-credential-sentinel", "foreign-org-sentinel"} {
		if strings.Contains(stdout, forbidden) {
			t.Fatalf("standard bundle leaked %q", forbidden)
		}
	}
	if !strings.Contains(stdout, "abc123digest") {
		t.Fatal("prompt_hash must survive standard scrubbing")
	}
	if !strings.Contains(stdout, auditlog.ScrubMaskedValue) {
		t.Fatal("masked entries must carry the shared sentinel")
	}
}

func TestSupportDiagnostics_MinimalProfileKeepsContent(t *testing.T) {
	setSupportDiagnosticsHome(t)
	path := scrubFixtureLog(t)

	stdout, stderr, err := runSupportDiagnostics(t, "preview", "--log-file", path, "--org", "org-a", "--scrub-profile", "minimal")
	if err != nil {
		t.Fatalf("preview failed: %v; stderr=%q", err, stderr)
	}

	var got supportDiagnostics
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatal(err)
	}
	logs := got.Logs
	if logs.ScrubProfile != string(auditlog.ScrubProfileMinimal) {
		t.Fatalf("scrub_profile = %q, want minimal", logs.ScrubProfile)
	}
	// T02 behavior byte-for-byte: credentials masked, content and PII kept,
	// new counters stay at zero.
	if logs.RedactionHits != 1 || logs.ContentMasks != 0 || logs.ContentFieldsRemoved != 0 {
		t.Fatalf("minimal counters = (creds %d, masks %d, dropped %d), want (1, 0, 0)",
			logs.RedactionHits, logs.ContentMasks, logs.ContentFieldsRemoved)
	}
	for _, required := range []string{"customer-content-sentinel", "jane@example.com", "abc123digest"} {
		if !strings.Contains(stdout, required) {
			t.Fatalf("minimal bundle must keep %q", required)
		}
	}
	if strings.Contains(stdout, "sk-credential-sentinel") || strings.Contains(stdout, "foreign-org-sentinel") {
		t.Fatal("minimal bundle must still mask credentials and exclude foreign orgs")
	}
}

func TestSupportDiagnostics_StrictProfileMasksAllValues(t *testing.T) {
	setSupportDiagnosticsHome(t)
	path := scrubFixtureLog(t)

	stdout, stderr, err := runSupportDiagnostics(t, "preview", "--log-file", path, "--org", "org-a", "--scrub-profile", "strict")
	if err != nil {
		t.Fatalf("preview failed: %v; stderr=%q", err, stderr)
	}

	var got supportDiagnostics
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatal(err)
	}
	logs := got.Logs
	if logs.ScrubProfile != string(auditlog.ScrubProfileStrict) {
		t.Fatalf("scrub_profile = %q, want strict", logs.ScrubProfile)
	}
	if logs.IncludedLines != 2 || logs.ContentFieldsRemoved != 1 || logs.RedactionHits != 1 {
		t.Fatalf("strict counters wrong: in=%d dropped=%d creds=%d",
			logs.IncludedLines, logs.ContentFieldsRemoved, logs.RedactionHits)
	}
	// Full-value masks across both included lines: line 1 masks org_id, msg
	// and prompt_hash (payload already dropped); line 2 masks org_id and msg
	// (api_key was already the credential sentinel when this pass ran).
	if logs.ContentMasks != 5 {
		t.Fatalf("content_masks = %d, want 5", logs.ContentMasks)
	}
	// logs.org legitimately records the operator-selected org (T02
	// behavior); only entry messages must be scrubbed of it.
	if !strings.Contains(stdout, `"org": "org-a"`) {
		t.Fatal("operator-selected org must stay recorded in logs.org")
	}
	for _, forbidden := range []string{"customer-content-sentinel", "jane@example.com", "sk-credential-sentinel", "abc123digest"} {
		if strings.Contains(stdout, forbidden) {
			t.Fatalf("strict bundle leaked %q", forbidden)
		}
	}
	for _, entry := range got.Logs.Entries {
		if strings.Contains(entry.Message, "org-a") {
			t.Fatalf("strict entry leaked the org value: %s", entry.Message)
		}
	}
	// Key names survive; only values are masked. (Entry messages are
	// JSON-escaped inside the bundle, so match the bare key names.)
	if !strings.Contains(stdout, `prompt_hash`) || !strings.Contains(stdout, `api_key`) {
		t.Fatal("strict must preserve key names")
	}
}

func TestSupportDiagnostics_ScrubLineUnitBoundaries(t *testing.T) {
	t.Run("content-only drop must re-marshal (leak regression)", func(t *testing.T) {
		line := `{"org_id":"org-a","msg":"hello","payload":"customer-content-sentinel"}`
		out, credHits, masks, dropped := scrubSupportDiagLineByProfile(line, auditlog.ScrubProfileStandard)
		if credHits != 0 || masks != 0 || dropped != 1 {
			t.Fatalf("counts = (creds %d, masks %d, dropped %d), want (0, 0, 1)", credHits, masks, dropped)
		}
		if strings.Contains(out, "customer-content-sentinel") {
			t.Fatalf("content-only drop leaked the payload: %s", out)
		}
		if out == line {
			t.Fatal("a changed tree must never return the original bytes")
		}
	})

	t.Run("untouched line keeps original bytes", func(t *testing.T) {
		line := `{"org":{"id":"org-a"},"msg":"plain event"}`
		out, credHits, masks, dropped := scrubSupportDiagLineByProfile(line, auditlog.ScrubProfileStandard)
		if out != line || credHits != 0 || masks != 0 || dropped != 0 {
			t.Fatalf("plain line changed: %q (creds %d, masks %d, dropped %d)", out, credHits, masks, dropped)
		}
	})

	t.Run("minimal dispatch is the T02 redactor", func(t *testing.T) {
		line := `{"api_key":"sk-sentinel","msg":"ok"}`
		want, wantHits := redactSupportDiagLine(line)
		out, credHits, masks, dropped := scrubSupportDiagLineByProfile(line, auditlog.ScrubProfileMinimal)
		if out != want || credHits != wantHits || masks != 0 || dropped != 0 {
			t.Fatalf("minimal diverged from redactSupportDiagLine: %q", out)
		}
	})

	t.Run("strict drops content then masks the rest", func(t *testing.T) {
		line := `{"org_id":"org-a","payload":"customer-content-sentinel","n":7,"flag":true,"empty":""}`
		out, credHits, masks, dropped := scrubSupportDiagLineByProfile(line, auditlog.ScrubProfileStrict)
		if credHits != 0 || dropped != 1 {
			t.Fatalf("counts = (creds %d, dropped %d), want (0, 1)", credHits, dropped)
		}
		// org_id masked; empty string untouched; number and bool preserved.
		if masks != 1 {
			t.Fatalf("masks = %d, want 1", masks)
		}
		for _, required := range []string{`"n":7`, `"flag":true`, `"empty":""`, `"org_id":"[REDACTED]"`} {
			if !strings.Contains(out, required) {
				t.Fatalf("strict output lost %q: %s", required, out)
			}
		}
		if strings.Contains(out, "customer-content-sentinel") {
			t.Fatalf("strict leaked the payload: %s", out)
		}
	})

	t.Run("non-json falls back to credentials-only", func(t *testing.T) {
		line := `bearer BbCcDdEeFf00112233 crash`
		for _, profile := range []auditlog.ScrubProfile{auditlog.ScrubProfileMinimal, auditlog.ScrubProfileStandard, auditlog.ScrubProfileStrict} {
			out, _, _, _ := scrubSupportDiagLineByProfile(line, profile)
			if strings.Contains(out, "BbCcDdEeFf00112233") {
				t.Fatalf("profile %s leaked the credential from non-JSON input: %s", profile, out)
			}
		}
	})
}

func TestSupportDiagnostics_ScrubDeterminism(t *testing.T) {
	setSupportDiagnosticsHome(t)
	path := scrubFixtureLog(t)

	first, _, err := runSupportDiagnostics(t, "preview", "--log-file", path, "--org", "org-a")
	if err != nil {
		t.Fatalf("first preview failed: %v", err)
	}
	second, _, err := runSupportDiagnostics(t, "preview", "--log-file", path, "--org", "org-a")
	if err != nil {
		t.Fatalf("second preview failed: %v", err)
	}
	if first != second {
		t.Fatal("identical machine state must produce byte-identical bundles")
	}
}

func TestSupportDiagnostics_ScrubFlagDefaultIsStandard(t *testing.T) {
	setSupportDiagnosticsHome(t)
	path := scrubFixtureLog(t)

	stdout, _, err := runSupportDiagnostics(t, "preview", "--log-file", path, "--org", "org-a")
	if err != nil {
		t.Fatalf("preview failed: %v", err)
	}
	var got supportDiagnostics
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatal(err)
	}
	if got.Logs.ScrubProfile != string(auditlog.ScrubProfileStandard) || got.Logs.ContentFieldsRemoved != 1 {
		t.Fatalf("default must behave as standard: profile=%q dropped=%d",
			got.Logs.ScrubProfile, got.Logs.ContentFieldsRemoved)
	}
}
