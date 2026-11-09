package clientconfig

// Reviewed apply tests (N16-P02-T04): gate refusals, insert/update
// idempotency, vendor-field preservation, byte-identical rollback, IO
// failure recovery through the rename seam, and the secret-never-leak
// guarantee across every rendered surface. Determinism is asserted by
// byte-comparing repeated runs.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/upstream"
)

// litellmApplyForbiddenSecrets mirrors the T03 redaction test: values that
// exist in the fixtures and must never surface in any apply artifact.
var litellmApplyForbiddenSecrets = map[string][]string{
	"full.yaml": {
		"sk-1234abcdef123456", "hunter2", "os.environ/OPENAI_API_KEY",
		"T000/B000", "cache.internal", "OPENAI_API_KEY",
	},
	"conflicts.yaml": {
		"sk-aaaabbbbccccdddd", "sk-eeeeffffgggghhhh",
	},
	"secrets.yaml": {
		"sk-supersecret123456789", "p4ssw0rd", "topsecret-redis-pass",
		"sk-internalkey123456", "supersecret-azure-key",
	},
}

// copyReport deep-copies a report so tests can mutate one variant without
// touching the cached fixture output.
func copyReport(t *testing.T, rep *LiteLLMMigrationReport) *LiteLLMMigrationReport {
	t.Helper()
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	var out LiteLLMMigrationReport
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	return &out
}

func applyTargetsIn(t *testing.T, dir string) LiteLLMApplyTargets {
	t.Helper()
	return LiteLLMApplyTargets{
		CatalogPath: filepath.Join(dir, "catalog.json"),
		LedgerPath:  filepath.Join(dir, "apply-ledger.json"),
	}
}

// requireRefusal asserts the error is a LiteLLMApplyRefusal and returns its
// aggregated problems.
func requireRefusal(t *testing.T, err error) []string {
	t.Helper()
	if err == nil {
		t.Fatalf("expected refusal, got success")
	}
	var refusal *LiteLLMApplyRefusal
	if !errors.As(err, &refusal) {
		t.Fatalf("expected LiteLLMApplyRefusal, got %T: %v", err, err)
	}
	return refusal.Problems
}

func assertProblemsMention(t *testing.T, problems []string, want ...string) {
	t.Helper()
	joined := strings.Join(problems, "\n")
	for _, w := range want {
		if !strings.Contains(joined, w) {
			t.Fatalf("problems do not mention %q; got:\n%s", w, joined)
		}
	}
}

func mustApply(t *testing.T, rep *LiteLLMMigrationReport, targets LiteLLMApplyTargets) *LiteLLMApplyResult {
	t.Helper()
	res, err := LiteLLMApply(rep, targets)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	return res
}

func mustParseCatalogFile(t *testing.T, path string) upstream.CatalogDocument {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: test-controlled path
	if err != nil {
		t.Fatalf("read catalog: %v", err)
	}
	doc, _, err := upstream.ParseCatalogDocument(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("applied catalog does not parse: %v", err)
	}
	if err := upstream.ValidateCatalogDocument(doc); err != nil {
		t.Fatalf("applied catalog does not validate: %v", err)
	}
	return doc
}

func fileBytes(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: test-controlled path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func assertFileAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected %s to be absent (stat err: %v)", path, err)
	}
}

// TestLiteLLMApply_GateRefusals walks the refusal vocabulary: every mutated
// report must be refused with the matching problem, and nothing may be
// written to the target directory.
func TestLiteLLMApply_GateRefusals(t *testing.T) {
	base := mustDryRun(t, "full.yaml")

	cases := []struct {
		name    string
		fix     func(rep *LiteLLMMigrationReport)
		mention []string
	}{
		{
			name:    "wrong schema",
			fix:     func(rep *LiteLLMMigrationReport) { rep.Schema = 99 },
			mention: []string{"unsupported report schema"},
		},
		{
			name:    "unknown source format",
			fix:     func(rep *LiteLLMMigrationReport) { rep.Source.Format = "other" },
			mention: []string{`is not "litellm_proxy_config"`},
		},
		{
			name:    "summary counts disagree",
			fix:     func(rep *LiteLLMMigrationReport) { rep.Summary.Transferable = 99 },
			mention: []string{"does not match its finding lists"},
		},
		{
			name:    "unexpected action",
			fix:     func(rep *LiteLLMMigrationReport) { rep.Plan[0].Action = "catalog.delete" },
			mention: []string{"unknown action"},
		},
		{
			name:    "provider outside targets",
			fix:     func(rep *LiteLLMMigrationReport) { rep.Plan[0].Provider = "custom-llm" },
			mention: []string{"is not a pinned provider target"},
		},
		{
			name:    "model wildcard",
			fix:     func(rep *LiteLLMMigrationReport) { rep.Plan[0].Model = "gpt-*" },
			mention: []string{"wildcard model"},
		},
		{
			name: "alias shadows model",
			fix: func(rep *LiteLLMMigrationReport) {
				rep.Plan[0].Aliases = append(rep.Plan[0].Aliases, rep.Plan[0].Model)
			},
			mention: []string{"shadows"},
		},
		{
			name: "duplicate alias across entries",
			fix: func(rep *LiteLLMMigrationReport) {
				rep.Plan[0].Aliases = []string{"fast-openai"} // Plan[1] carries it too
			},
			mention: []string{"claimed by more than one plan entry"},
		},
		{
			name: "unknown capability",
			fix: func(rep *LiteLLMMigrationReport) {
				rep.Plan[0].Capabilities["telepathy"] = true
			},
			mention: []string{"unknown capability"},
		},
		{
			name: "capability false value",
			fix: func(rep *LiteLLMMigrationReport) {
				rep.Plan[0].Capabilities["chat"] = false
			},
			mention: []string{"presence-only"},
		},
		{
			name:    "negative limit",
			fix:     func(rep *LiteLLMMigrationReport) { rep.Plan[0].Limits.MaxTPM = -1 },
			mention: []string{"negative"},
		},
		{
			name:    "all limits zero",
			fix:     func(rep *LiteLLMMigrationReport) { rep.Plan[0].Limits = &LiteLLMPlanLimits{} },
			mention: []string{"limits carry no positive bound"},
		},
		{
			name: "source path is not a transfer",
			fix: func(rep *LiteLLMMigrationReport) {
				rep.Plan[0].SourcePaths = []string{"model_list[9]"}
			},
			mention: []string{"does not link to a transfer finding"},
		},
		{
			name: "secret path as source",
			fix: func(rep *LiteLLMMigrationReport) {
				rep.Plan[0].SourcePaths = []string{"model_list[0].litellm_params.api_key"}
			},
			mention: []string{"is unsupported in this report"},
		},
		{
			name:    "no source paths",
			fix:     func(rep *LiteLLMMigrationReport) { rep.Plan[0].SourcePaths = nil },
			mention: []string{"no source paths"},
		},
		{
			name: "duplicate catalog row across entries",
			fix: func(rep *LiteLLMMigrationReport) {
				rep.Plan[1].Provider = rep.Plan[0].Provider
				rep.Plan[1].Model = rep.Plan[0].Model
			},
			mention: []string{"duplicate (provider, model) identity"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := copyReport(t, base)
			tc.fix(rep)
			dir := t.TempDir()
			targets := applyTargetsIn(t, dir)
			_, err := LiteLLMApply(rep, targets)
			problems := requireRefusal(t, err)
			assertProblemsMention(t, problems, tc.mention...)
			// Nothing may be written by a refused apply.
			assertFileAbsent(t, targets.CatalogPath)
			assertFileAbsent(t, targets.LedgerPath)
			assertFileAbsent(t, LiteLLMApplyBackupPath(targets.CatalogPath))
		})
	}
}

// TestLiteLLMApply_EmptyPlanRefused pins the wildcard-fixture behavior: a
// report with zero plan entries is a refusal, never a silent success.
func TestLiteLLMApply_EmptyPlanRefused(t *testing.T) {
	rep := mustDryRun(t, "wildcard.yaml")
	dir := t.TempDir()
	_, err := LiteLLMApply(rep, applyTargetsIn(t, dir))
	problems := requireRefusal(t, err)
	assertProblemsMention(t, problems, "no plan entries")
	_, err = BuildLiteLLMApplyPreview(rep, applyTargetsIn(t, dir), nil)
	requireRefusal(t, err)
}

// TestLiteLLMApply_ConflictedAndUnsupportedSourcesRefused verifies the
// linkage rule against real finding paths: a plan entry may only cite
// transfer findings, never conflicted or unsupported ones.
func TestLiteLLMApply_ConflictedAndUnsupportedSourcesRefused(t *testing.T) {
	base := mustDryRun(t, "conflicts.yaml")
	if len(base.Conflicts) == 0 || len(base.Unsupported) == 0 {
		t.Fatalf("fixture must contain conflicts and unsupported findings")
	}
	for _, tc := range []struct {
		name    string
		path    string
		mention []string
	}{
		{
			name:    "conflicted",
			path:    base.Conflicts[0].Path,
			mention: []string{"is conflicted in this report"},
		},
		{
			name:    "unsupported",
			path:    base.Unsupported[0].Path,
			mention: []string{"is unsupported in this report"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := copyReport(t, base)
			rep.Plan[0].SourcePaths = []string{tc.path}
			_, err := LiteLLMApply(rep, applyTargetsIn(t, t.TempDir()))
			assertProblemsMention(t, requireRefusal(t, err), tc.mention...)
		})
	}
}

// TestLiteLLMApply_InsertIdempotentRollback is the lifecycle test: fresh
// insert → byte-stable re-apply → rollback removes created files → re-apply
// reproduces identical bytes → double rollback fails loudly.
func TestLiteLLMApply_InsertIdempotentRollback(t *testing.T) {
	rep := mustDryRun(t, "full.yaml")
	dir := t.TempDir()
	targets := applyTargetsIn(t, dir)

	first := mustApply(t, rep, targets)
	if !first.Changed || first.CatalogExisted {
		t.Fatalf("first apply must change an absent catalog: %+v", first)
	}
	if got, want := len(first.Applied), 3; got != want {
		t.Fatalf("applied rows: got %d, want %d", got, want)
	}
	for i, want := range []string{LiteLLMApplyInserted, LiteLLMApplyInserted, LiteLLMApplyInserted} {
		if first.Applied[i].Result != want {
			t.Fatalf("applied[%d].Result = %q, want %q", i, first.Applied[i].Result, want)
		}
	}
	doc := mustParseCatalogFile(t, targets.CatalogPath)
	if len(doc.Models) != 3 {
		t.Fatalf("catalog rows: got %d, want 3", len(doc.Models))
	}
	byKey := map[string]*upstream.CatalogModelEntry{}
	for i := range doc.Models {
		row := &doc.Models[i]
		byKey[row.Provider+":"+row.Model] = row
	}
	gpt4o := byKey["openai:gpt-4o"]
	if gpt4o == nil {
		t.Fatalf("openai:gpt-4o missing from applied catalog")
	}
	if !gpt4o.Capabilities["chat"] {
		t.Fatalf("openai:gpt-4o capabilities = %v, want chat", gpt4o.Capabilities)
	}
	if gpt4o.Limits == nil || gpt4o.Limits.MaxTPM != 20000 || gpt4o.Limits.MaxRPM != 200 ||
		gpt4o.Limits.MaxOutputTokens != 16384 {
		t.Fatalf("openai:gpt-4o limits = %+v", gpt4o.Limits)
	}
	if len(gpt4o.Aliases) != 0 {
		t.Fatalf("openai:gpt-4o aliases = %v, want none", gpt4o.Aliases)
	}
	mini := byKey["openai:gpt-4o-mini"]
	if mini == nil || len(mini.Aliases) != 1 || mini.Aliases[0] != "fast-openai" {
		t.Fatalf("openai:gpt-4o-mini row = %+v", mini)
	}
	claude := byKey["anthropic:claude-sonnet-4-5"]
	if claude == nil || strings.Join(claude.Aliases, ",") != "claude,claude-fast,sonnet" {
		t.Fatalf("anthropic:claude-sonnet-4-5 aliases = %v", claude.Aliases)
	}

	// Ledger contents: schema, digest, counts, per-entry rows with seq.
	ledgerData := fileBytes(t, targets.LedgerPath)
	var ledger LiteLLMApplyLedger
	if err := json.Unmarshal(ledgerData, &ledger); err != nil {
		t.Fatalf("ledger does not parse: %v", err)
	}
	if ledger.Schema != LiteLLMApplyLedgerSchema || ledger.LastReportSHA256 != first.ReportSHA256 ||
		ledger.SecretsRedacted != 5 || len(ledger.Entries) != 3 {
		t.Fatalf("ledger header/entries wrong: %+v", ledger)
	}
	for i, entry := range ledger.Entries {
		if entry.Seq != int64(i+1) {
			t.Fatalf("ledger entry %d seq = %d", i, entry.Seq)
		}
		if entry.Result != LiteLLMApplyInserted {
			t.Fatalf("ledger entry %d result = %q", i, entry.Result)
		}
		digest, digestErr := planEntryDigest(rep.Plan[i])
		if digestErr != nil {
			t.Fatalf("ledger entry %d digest: %v", i, digestErr)
		}
		if entry.ContentSHA256 != digest {
			t.Fatalf("ledger entry %d digest mismatch", i)
		}
	}

	// Backups are kept after a successful apply so the operator can always
	// roll back; a fresh-doc apply yields two zero-length backups.
	catalogBackup := LiteLLMApplyBackupPath(targets.CatalogPath)
	ledgerBackup := LiteLLMApplyBackupPath(targets.LedgerPath)
	if len(fileBytes(t, catalogBackup)) != 0 || len(fileBytes(t, ledgerBackup)) != 0 {
		t.Fatalf("fresh-doc apply backups must be zero-length (absent pre-state)")
	}

	// Idempotent re-apply: no-op, byte-stable, no new ledger rows.
	catalogBefore := fileBytes(t, targets.CatalogPath)
	ledgerBefore := fileBytes(t, targets.LedgerPath)
	second := mustApply(t, rep, targets)
	if second.Changed {
		t.Fatalf("re-apply must be a no-op: %+v", second)
	}
	if second.CatalogSHA256 != first.CatalogSHA256 {
		t.Fatalf("re-apply changed the catalog digest: %s != %s", second.CatalogSHA256, first.CatalogSHA256)
	}
	if !bytes.Equal(fileBytes(t, targets.CatalogPath), catalogBefore) ||
		!bytes.Equal(fileBytes(t, targets.LedgerPath), ledgerBefore) {
		t.Fatalf("re-apply rewrote files (must stay byte-stable)")
	}

	// Rollback: byte-identical removal of the created files and backups.
	rb, err := LiteLLMRollback(targets)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if !rb.CatalogRemoved || !rb.LedgerRemoved {
		t.Fatalf("rollback of fresh-doc apply must remove both files: %+v", rb)
	}
	assertFileAbsent(t, targets.CatalogPath)
	assertFileAbsent(t, targets.LedgerPath)
	assertFileAbsent(t, catalogBackup)
	assertFileAbsent(t, ledgerBackup)

	// Rolling back with no backups present is a loud refusal.
	if _, err := LiteLLMRollback(targets); err == nil ||
		!strings.Contains(err.Error(), "no apply backup found") {
		t.Fatalf("re-rollback must refuse with 'no apply backup found', got: %v", err)
	}

	// Re-apply after rollback reproduces the exact same bytes.
	third := mustApply(t, rep, targets)
	if !third.Changed || third.CatalogSHA256 != first.CatalogSHA256 {
		t.Fatalf("re-apply after rollback diverged: %+v", third)
	}
	if !bytes.Equal(fileBytes(t, targets.CatalogPath), catalogBefore) ||
		!bytes.Equal(fileBytes(t, targets.LedgerPath), ledgerBefore) {
		t.Fatalf("re-apply after rollback produced different bytes (must be deterministic)")
	}

	// A rollback after a fresh re-apply removes the created files again:
	// zero-length backups record the absent pre-state.
	rb2, err := LiteLLMRollback(targets)
	if err != nil {
		t.Fatalf("second lifecycle rollback: %v", err)
	}
	if !rb2.CatalogRemoved || !rb2.LedgerRemoved {
		t.Fatalf("second lifecycle rollback must remove both files: %+v", rb2)
	}
	assertFileAbsent(t, targets.CatalogPath)
	assertFileAbsent(t, targets.LedgerPath)
}

// TestLiteLLMApply_UpdatePreservesVendorFields seeds a catalog with vendor
// data (price, context window, deprecation, extra capability, alias) and
// verifies the apply updates exactly the carried fields.
func TestLiteLLMApply_UpdatePreservesVendorFields(t *testing.T) {
	dir := t.TempDir()
	targets := applyTargetsIn(t, dir)
	seed := map[string]any{
		"schema_version": upstream.CatalogSchemaCurrent,
		"version":        "seed",
		"source":         "test-seed",
		"models": []map[string]any{{
			"provider":       "openai",
			"model":          "gpt-4o",
			"aliases":        []string{"legacy"},
			"capabilities":   map[string]bool{"tools": true},
			"limits":         map[string]any{"context_window_tokens": 128000},
			"price":          map[string]float64{"input": 2.5, "output": 10},
			"effective_from": "2024-01-01",
			"deprecated_at":  "2026-12-31T00:00:00Z",
		}},
	}
	seedBytes, err := json.Marshal(seed)
	if err != nil {
		t.Fatalf("marshal seed: %v", err)
	}
	if err := os.WriteFile(targets.CatalogPath, seedBytes, 0o600); err != nil {
		t.Fatalf("write seed catalog: %v", err)
	}

	rep := mustDryRun(t, "full.yaml")
	res := mustApply(t, rep, targets)
	if got, want := res.Applied[0].Result, LiteLLMApplyUpdated; got != want {
		t.Fatalf("gpt-4o outcome = %q, want %q", got, want)
	}
	row := mustParseCatalogFile(t, targets.CatalogPath).Models[0]
	if row.Price == nil || row.Price.Input != 2.5 || row.Price.Output != 10 {
		t.Fatalf("price not preserved: %+v", row.Price)
	}
	if row.Limits == nil || row.Limits.ContextWindowTokens != 128000 {
		t.Fatalf("context window not preserved: %+v", row.Limits)
	}
	if row.EffectiveFrom != "2024-01-01" || row.DeprecatedAt != "2026-12-31T00:00:00Z" {
		t.Fatalf("effective/deprecated not preserved: %q / %q", row.EffectiveFrom, row.DeprecatedAt)
	}
	if !row.Capabilities["tools"] || !row.Capabilities["chat"] {
		t.Fatalf("capabilities must union (tools preserved, chat added): %v", row.Capabilities)
	}
	aliasSet := map[string]bool{}
	for _, alias := range row.Aliases {
		aliasSet[alias] = true
	}
	if !aliasSet["legacy"] {
		t.Fatalf("existing alias dropped: %v", row.Aliases)
	}

	// The claude row was inserted alongside the update.
	if len(mustParseCatalogFile(t, targets.CatalogPath).Models) != 3 {
		t.Fatalf("apply must add the other plan rows")
	}
}

// TestLiteLLMRollback_ByteIdentity applies onto irregularly formatted
// pre-existing files and verifies rollback restores the exact bytes.
func TestLiteLLMRollback_ByteIdentity(t *testing.T) {
	dir := t.TempDir()
	targets := applyTargetsIn(t, dir)
	// Deliberately irregular JSON (tabs, key order, trailing newline) so a
	// canonicalizing rollback would be caught by the byte comparison.
	catalogPre := []byte("{\n\t\"models\": [],\n\t\"source\": \"operator\",\n\t\"version\": \"hand\",\n\t\"schema_version\": 1\n}\n")
	ledgerPre := []byte("{\n\t\"schema\": 1,\n\t\"last_report_sha256\": \"\",\n\t\"secrets_redacted\": 0,\n\t\"entries\": []\n}\n")
	if err := os.WriteFile(targets.CatalogPath, catalogPre, 0o600); err != nil {
		t.Fatalf("write catalog: %v", err)
	}
	if err := os.WriteFile(targets.LedgerPath, ledgerPre, 0o600); err != nil {
		t.Fatalf("write ledger: %v", err)
	}

	rep := mustDryRun(t, "minimal.yaml")
	if _, err := LiteLLMApply(rep, targets); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if bytes.Equal(fileBytes(t, targets.CatalogPath), catalogPre) {
		t.Fatalf("apply must have changed the catalog")
	}
	rb, err := LiteLLMRollback(targets)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if !rb.CatalogRestored || !rb.LedgerRestored {
		t.Fatalf("rollback must restore both files: %+v", rb)
	}
	if !bytes.Equal(fileBytes(t, targets.CatalogPath), catalogPre) ||
		!bytes.Equal(fileBytes(t, targets.LedgerPath), ledgerPre) {
		t.Fatalf("rollback did not restore byte-identical pre-state")
	}
	assertFileAbsent(t, LiteLLMApplyBackupPath(targets.CatalogPath))
	assertFileAbsent(t, LiteLLMApplyBackupPath(targets.LedgerPath))
}

// TestLiteLLMRollback_InconsistentBackupSetRefused pins the exactly-one-
// backup refusal.
func TestLiteLLMRollback_InconsistentBackupSetRefused(t *testing.T) {
	for _, tc := range []struct {
		name   string
		create string
	}{
		{"only catalog backup", "catalog"},
		{"only ledger backup", "ledger"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			targets := applyTargetsIn(t, dir)
			if err := os.WriteFile(targets.CatalogPath, []byte("{}"), 0o600); err != nil {
				t.Fatalf("seed catalog: %v", err)
			}
			path := targets.LedgerPath
			if tc.create == "catalog" {
				path = targets.CatalogPath
			}
			backup := LiteLLMApplyBackupPath(path)
			if err := os.WriteFile(backup, []byte("x"), 0o600); err != nil {
				t.Fatalf("seed backup: %v", err)
			}
			_, err := LiteLLMRollback(targets)
			if err == nil || !strings.Contains(err.Error(), "inconsistent backup set") {
				t.Fatalf("rollback must refuse inconsistent set, got: %v", err)
			}
		})
	}
}

// TestLiteLLMApply_IOFailureRestoresPreState forces the ledger rename to
// fail through the seam and verifies: loud error, byte-identical pre-state,
// backups kept, next apply refuses until rollback clears the set, and the
// retry then succeeds.
func TestLiteLLMApply_IOFailureRestoresPreState(t *testing.T) {
	dir := t.TempDir()
	targets := applyTargetsIn(t, dir)

	catalogPre := []byte("{\"schema_version\":1,\"version\":\"pre\",\"source\":\"operator\",\"models\":[]}")
	ledgerPre := []byte("{\"schema\":1,\"entries\":[]}")
	if err := os.WriteFile(targets.CatalogPath, catalogPre, 0o600); err != nil {
		t.Fatalf("write catalog: %v", err)
	}
	if err := os.WriteFile(targets.LedgerPath, ledgerPre, 0o600); err != nil {
		t.Fatalf("write ledger: %v", err)
	}

	origRename := litellmRename
	litellmRename = func(src, dst string) error {
		if dst == targets.LedgerPath {
			return fmt.Errorf("simulated ledger rename failure")
		}
		return origRename(src, dst)
	}
	defer func() { litellmRename = origRename }()

	rep := mustDryRun(t, "minimal.yaml")
	_, applyErr := LiteLLMApply(rep, targets)
	if applyErr == nil || !strings.Contains(applyErr.Error(), "ledger write failed") ||
		!strings.Contains(applyErr.Error(), "restored") {
		t.Fatalf("IO failure must fail loudly with restore notice, got: %v", applyErr)
	}
	// Pre-state restored byte-identically on both targets.
	if !bytes.Equal(fileBytes(t, targets.CatalogPath), catalogPre) ||
		!bytes.Equal(fileBytes(t, targets.LedgerPath), ledgerPre) {
		t.Fatalf("pre-state was not restored byte-identically after IO failure")
	}
	// Backups with the pre bytes remain.
	catalogBackup := LiteLLMApplyBackupPath(targets.CatalogPath)
	ledgerBackup := LiteLLMApplyBackupPath(targets.LedgerPath)
	if !bytes.Equal(fileBytes(t, catalogBackup), catalogPre) ||
		!bytes.Equal(fileBytes(t, ledgerBackup), ledgerPre) {
		t.Fatalf("backups must carry the pre-apply bytes")
	}

	// With backups present, the next apply refuses loudly (fail-closed).
	litellmRename = origRename
	_, err := LiteLLMApply(rep, targets)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("apply with existing backups must refuse, got: %v", err)
	}

	// Rollback clears the set byte-identically; the retry then succeeds.
	if _, err := LiteLLMRollback(targets); err != nil {
		t.Fatalf("rollback after failed apply: %v", err)
	}
	if !bytes.Equal(fileBytes(t, targets.CatalogPath), catalogPre) ||
		!bytes.Equal(fileBytes(t, targets.LedgerPath), ledgerPre) {
		t.Fatalf("rollback after failed apply diverged from pre-state")
	}
	res := mustApply(t, rep, targets)
	if !res.Changed {
		t.Fatalf("retry apply must succeed and change the catalog")
	}
}

// TestLiteLLMApply_IOFailureFreshDocRemovesCreatedFiles covers the absent
// pre-state: after the failed ledger commit both created files are gone and
// the zero-length backups mark them as "was absent" for rollback.
func TestLiteLLMApply_IOFailureFreshDocRemovesCreatedFiles(t *testing.T) {
	dir := t.TempDir()
	targets := applyTargetsIn(t, dir)
	origRename := litellmRename
	litellmRename = func(src, dst string) error {
		if dst == targets.LedgerPath {
			return fmt.Errorf("simulated ledger rename failure")
		}
		return origRename(src, dst)
	}
	defer func() { litellmRename = origRename }()

	rep := mustDryRun(t, "minimal.yaml")
	_, err := LiteLLMApply(rep, targets)
	if err == nil {
		t.Fatalf("apply must fail")
	}
	assertFileAbsent(t, targets.CatalogPath)
	assertFileAbsent(t, targets.LedgerPath)
	catalogBackup := LiteLLMApplyBackupPath(targets.CatalogPath)
	ledgerBackup := LiteLLMApplyBackupPath(targets.LedgerPath)
	if len(fileBytes(t, catalogBackup)) != 0 || len(fileBytes(t, ledgerBackup)) != 0 {
		t.Fatalf("absent pre-state must be backed up as zero-length files")
	}
	litellmRename = origRename
	rb, err := LiteLLMRollback(targets)
	if err != nil {
		t.Fatalf("rollback after failed fresh apply: %v", err)
	}
	if !rb.CatalogRemoved || !rb.LedgerRemoved {
		t.Fatalf("rollback must treat zero-length backups as absent pre-state: %+v", rb)
	}
}

// TestLiteLLMApply_LedgerCorruptionRefused: a ledger that does not parse is
// a loud refusal, never a silent rebuild.
func TestLiteLLMApply_LedgerCorruptionRefused(t *testing.T) {
	base := mustDryRun(t, "minimal.yaml")
	cases := []struct {
		name    string
		ledger  string
		mention []string
	}{
		{"bad json", "{not json", []string{"parse apply ledger"}},
		{"wrong schema", `{"schema":2,"entries":[]}`, []string{"unsupported apply ledger schema"}},
		{"seq disorder", `{"schema":1,"entries":[{"seq":2,"provider":"openai","model":"m","result":"inserted","content_sha256":"a"},{"seq":1,"provider":"openai","model":"m2","result":"inserted","content_sha256":"b"}]}`, []string{"out of order"}},
		{"missing digest", `{"schema":1,"entries":[{"seq":1,"provider":"openai","model":"m","result":"inserted"}]}`, []string{"missing content digest"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			targets := applyTargetsIn(t, dir)
			if err := os.WriteFile(targets.LedgerPath, []byte(tc.ledger), 0o600); err != nil {
				t.Fatalf("write ledger: %v", err)
			}
			_, err := LiteLLMApply(base, targets)
			if err == nil || !strings.Contains(err.Error(), "current apply ledger is invalid") {
				t.Fatalf("corrupt ledger must refuse loudly, got: %v", err)
			}
			assertProblemsMention(t, []string{err.Error()}, tc.mention...)
		})
	}
}

// TestLiteLLMApply_InvalidCurrentCatalogRefused: a catalog that does not
// parse blocks the apply entirely.
func TestLiteLLMApply_InvalidCurrentCatalogRefused(t *testing.T) {
	dir := t.TempDir()
	targets := applyTargetsIn(t, dir)
	if err := os.WriteFile(targets.CatalogPath, []byte("{\"schema_version\":9}"), 0o600); err != nil {
		t.Fatalf("write catalog: %v", err)
	}
	rep := mustDryRun(t, "minimal.yaml")
	_, err := LiteLLMApply(rep, targets)
	if err == nil || !strings.Contains(err.Error(), "current catalog is invalid") {
		t.Fatalf("invalid catalog must refuse loudly, got: %v", err)
	}
	assertFileAbsent(t, targets.LedgerPath)
}

// TestLiteLLMApply_SecretsNeverLeak mirrors the T03 guarantee across every
// rendered apply surface: preview text, preview JSON, result text, result
// JSON, rollback text.
func TestLiteLLMApply_SecretsNeverLeak(t *testing.T) {
	fixtures := []string{"full.yaml", "conflicts.yaml", "secrets.yaml"}
	for _, fixture := range fixtures {
		t.Run(fixture, func(t *testing.T) {
			rep := mustDryRun(t, fixture)
			dir := t.TempDir()
			targets := applyTargetsIn(t, dir)
			preview, err := BuildLiteLLMApplyPreview(rep, targets, nil)
			if err != nil {
				t.Fatalf("preview: %v", err)
			}
			previewJSON, err := LiteLLMApplyPreviewJSON(preview)
			if err != nil {
				t.Fatalf("preview json: %v", err)
			}
			res, err := LiteLLMApply(rep, targets)
			if err != nil {
				t.Fatalf("apply: %v", err)
			}
			resultText := RenderLiteLLMApplyResult(res)
			resultJSON, err := LiteLLMApplyResultJSON(res)
			if err != nil {
				t.Fatalf("result json: %v", err)
			}
			rbText := RenderLiteLLMRollbackResult(&LiteLLMRollbackResult{Targets: targets})
			surfaces := map[string]string{
				"preview_text": RenderLiteLLMApplyPreview(preview),
				"preview_json": previewJSON,
				"result_text":  resultText,
				"result_json":  resultJSON,
				"rollback":     rbText,
			}
			for surface, body := range surfaces {
				for _, secret := range litellmApplyForbiddenSecrets[fixture] {
					if strings.Contains(body, secret) {
						t.Fatalf("%s: leaked secret %q:\n%s", surface, secret, body)
					}
				}
			}
		})
	}
}

// TestLiteLLMApply_DeterministicOutputs: two independent runs over equal
// starting states must produce byte-identical catalogs, ledgers and previews.
func TestLiteLLMApply_DeterministicOutputs(t *testing.T) {
	render := func(dir string) ([]byte, []byte, string) {
		rep := mustDryRun(t, "full.yaml")
		targets := applyTargetsIn(t, dir)
		preview, err := BuildLiteLLMApplyPreview(rep, targets, nil)
		if err != nil {
			t.Fatalf("preview: %v", err)
		}
		if _, err := LiteLLMApply(rep, targets); err != nil {
			t.Fatalf("apply: %v", err)
		}
		return fileBytes(t, targets.CatalogPath), fileBytes(t, targets.LedgerPath),
			RenderLiteLLMApplyPreview(preview)
	}
	dirA, dirB := t.TempDir(), t.TempDir()
	catA, ledA, prevA := render(dirA)
	catB, ledB, prevB := render(dirB)
	// Preview text embeds the target paths; normalize them before comparing.
	prevA = strings.ReplaceAll(prevA, dirA, "TARGET-DIR")
	prevB = strings.ReplaceAll(prevB, dirB, "TARGET-DIR")
	if !bytes.Equal(catA, catB) {
		t.Fatalf("catalog bytes are not deterministic:\nA: %s\nB: %s", catA, catB)
	}
	if !bytes.Equal(ledA, ledB) {
		t.Fatalf("ledger bytes are not deterministic:\nA: %s\nB: %s", ledA, ledB)
	}
	if prevA != prevB {
		t.Fatalf("preview text is not deterministic:\nA: %s\nB: %s", prevA, prevB)
	}
}

// TestLiteLLMApplyPreview_MatchesApplyOutcome: the preview predicts each
// row's outcome against the current catalog, and the apply realizes it.
func TestLiteLLMApplyPreview_MatchesApplyOutcome(t *testing.T) {
	dir := t.TempDir()
	targets := applyTargetsIn(t, dir)
	rep := mustDryRun(t, "full.yaml")

	preview, err := BuildLiteLLMApplyPreview(rep, targets, nil)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if len(preview.Entries) != len(rep.Plan) {
		t.Fatalf("preview entries = %d, plan = %d", len(preview.Entries), len(rep.Plan))
	}
	for i, entry := range preview.Entries {
		if entry.Outcome != LiteLLMApplyInserted || entry.Action != rep.Plan[i].Action ||
			entry.Provider != rep.Plan[i].Provider || entry.Model != rep.Plan[i].Model {
			t.Fatalf("preview entry %d mismatch: %+v", i, entry)
		}
	}
	if preview.SecretsRedacted != 5 {
		t.Fatalf("preview secrets redacted = %d, want 5", preview.SecretsRedacted)
	}

	// Apply, then preview again: every entry is now predicted unchanged, and
	// the apply agrees.
	if _, err := LiteLLMApply(rep, targets); err != nil {
		t.Fatalf("apply: %v", err)
	}
	current := fileBytes(t, targets.CatalogPath)
	preview2, err := BuildLiteLLMApplyPreview(rep, targets, current)
	if err != nil {
		t.Fatalf("preview 2: %v", err)
	}
	for i, entry := range preview2.Entries {
		if entry.Outcome != LiteLLMApplyUnchanged {
			t.Fatalf("preview2 entry %d outcome = %q, want unchanged", i, entry.Outcome)
		}
		if len(entry.AliasesAdded) != 0 || len(entry.LimitsChanged) != 0 {
			t.Fatalf("preview2 entry %d claims changes: %+v", i, entry)
		}
	}
}

// TestLiteLLMApply_DefaultLedgerPath pins the derivation.
func TestLiteLLMApply_DefaultLedgerPath(t *testing.T) {
	if got, want := LiteLLMApplyDefaultLedgerPath("/etc/yabanin/catalog.json"),
		"/etc/yabanin/catalog.litellm-apply-ledger.json"; got != want {
		t.Fatalf("default ledger path = %q, want %q", got, want)
	}
	// Explicit targets must never be overridden.
	targets := LiteLLMApplyTargets{CatalogPath: "catalog.json", LedgerPath: "custom.json"}
	rep := mustDryRun(t, "wildcard.yaml")
	_, err := LiteLLMApply(rep, targets) // refuses on empty plan, after path resolution
	problems := requireRefusal(t, err)
	assertProblemsMention(t, problems, "no plan entries")
}
