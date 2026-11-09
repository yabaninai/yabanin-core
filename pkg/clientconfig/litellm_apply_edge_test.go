package clientconfig

// Edge-branch tests for the reviewed apply (N16-P02-T04): top-level guards,
// gate name/path problems, stat/read/commit failure branches (ENOTDIR tricks
// and the rename seam), rollback under read-only directories, renderer
// branches and the direct merge of presence-only capabilities.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/upstream"
)

// readOnlyDir makes dir read-only for failure fixtures and restores 0700
// on cleanup (LIFO: before t.TempDir removes the tree).
func readOnlyDir(t *testing.T, dir string) {
	t.Helper()
	//nolint:gosec // G302: directory (not file) permission — 0500 is the intended read-only fixture state
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod %s read-only: %v", dir, err)
	}
	t.Cleanup(func() {
		//nolint:gosec // G302: directory (not file) permission — restore for TempDir removal
		_ = os.Chmod(dir, 0o700)
	})
}

// edgeReport builds a minimal report that passes the apply gate: one
// transferable finding linked by one plan entry.
func edgeReport(t *testing.T) *LiteLLMMigrationReport {
	t.Helper()
	pin := LiteLLMConfigPin()
	if len(pin.ProviderTargets) == 0 {
		t.Fatalf("no pinned provider targets")
	}
	providers := append([]string(nil), pin.ProviderTargets...)
	sort.Strings(providers)
	rep := &LiteLLMMigrationReport{
		Schema: LiteLLMDryRunSchema,
		Source: LiteLLMReportSource{Format: pin.Format},
		Scope: LiteLLMScope{
			Migrated: []string{"model_list"},
			NotMigrated: []LiteLLMScopeItem{{
				Item:   "user_accounts",
				Reason: "never migrated",
			}},
		},
		Transferable: []LiteLLMFinding{{
			Path:        "model_list[0].model_name",
			Kind:        "model_name",
			Disposition: "accepted",
			Detail:      "edge fixture",
		}},
		Plan: []LiteLLMPlanEntry{{
			Action:      LiteLLMPlanActionUpsert,
			Provider:    providers[0],
			Model:       "edge-model",
			SourcePaths: []string{"model_list[0].model_name"},
		}},
	}
	rep.Summary = LiteLLMSummary{Transferable: 1, PlanEntries: 1}
	return rep
}

// firstCapabilityKey returns a deterministic key from the pinned capability
// vocabulary.
func firstCapabilityKey(t *testing.T) string {
	t.Helper()
	vocabulary := make([]string, 0)
	for key := range upstream.CatalogCapabilityFields() {
		vocabulary = append(vocabulary, key)
	}
	if len(vocabulary) == 0 {
		t.Fatalf("capability vocabulary is empty")
	}
	sort.Strings(vocabulary)
	return vocabulary[0]
}

func TestApplyTopLevelGuardsAndRefusalError(t *testing.T) {
	dir := t.TempDir()
	targets := applyTargetsIn(t, dir)

	// Nil report refusal + its aggregated Error rendering.
	_, err := LiteLLMApply(nil, targets)
	problems := requireRefusal(t, err)
	if len(problems) != 1 || problems[0] != "nil report" {
		t.Fatalf("unexpected nil-report problems: %v", problems)
	}
	var refusal *LiteLLMApplyRefusal
	if !errors.As(err, &refusal) {
		t.Fatalf("expected refusal type, got %T", err)
	}
	want := "litellm apply refused (1 problem(s)); nothing was written: nil report"
	if refusal.Error() != want {
		t.Fatalf("refusal Error mismatch:\n got: %s\nwant: %s", refusal.Error(), want)
	}

	// Empty catalog paths.
	if _, err := LiteLLMApply(edgeReport(t), LiteLLMApplyTargets{}); err == nil ||
		!strings.Contains(err.Error(), "catalog path is empty") {
		t.Fatalf("empty catalog path guard: err=%v", err)
	}
	if _, err := BuildLiteLLMApplyPreview(edgeReport(t), LiteLLMApplyTargets{}, nil); err == nil ||
		!strings.Contains(err.Error(), "catalog path is empty") {
		t.Fatalf("preview empty catalog path guard: err=%v", err)
	}
	if _, err := LiteLLMRollback(LiteLLMApplyTargets{}); err == nil ||
		!strings.Contains(err.Error(), "catalog path is empty") {
		t.Fatalf("rollback empty catalog path guard: err=%v", err)
	}

	// Default ledger derivation without a .json extension.
	if got := LiteLLMApplyDefaultLedgerPath(filepath.Join(dir, "catalog.yml")); got != filepath.Join(dir, "catalog.litellm-apply-ledger.json") {
		t.Fatalf("default ledger for non-json name: %s", got)
	}
	if got := LiteLLMApplyDefaultLedgerPath(filepath.Join(dir, "catalog")); got != filepath.Join(dir, "catalog.litellm-apply-ledger.json") {
		t.Fatalf("default ledger for extension-less name: %s", got)
	}
	// Dotfiles: filepath.Ext(".gitignore") returns the whole base name, so
	// the stem would be empty — the derivation must fall back to the base.
	if got := LiteLLMApplyDefaultLedgerPath(filepath.Join(dir, ".gitignore")); got != filepath.Join(dir, ".gitignore.litellm-apply-ledger.json") {
		t.Fatalf("default ledger for dotfile name: %s", got)
	}

	// The digest shortener is a pure helper: >12 chars truncate, shorter
	// and empty digests pass through untouched.
	if got := litellmShortDigest("0123456789abcdef"); got != "0123456789ab" {
		t.Fatalf("short digest truncation: %s", got)
	}
	for _, keep := range []string{"0123456789ab", "short", ""} {
		if got := litellmShortDigest(keep); got != keep {
			t.Fatalf("short digest passthrough %q: got %q", keep, got)
		}
	}
}

func TestApplyGateNameAndPathProblems(t *testing.T) {
	dir := t.TempDir()
	targets := applyTargetsIn(t, dir)

	rep := edgeReport(t)
	rep.Plan[0].Model = ""
	rep.Plan[0].Aliases = []string{" pad ", "wild*card"}
	rep.Plan[0].SourcePaths = []string{"", rep.Transferable[0].Path}

	_, err := LiteLLMApply(rep, targets)
	problems := requireRefusal(t, err)
	joined := strings.Join(problems, "\n")
	for _, want := range []string{
		"empty model",
		`whitespace-padded alias " pad "`,
		`wildcard alias "wild*card" can never be applied`,
		"empty source path",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing problem %q in:\n%s", want, joined)
		}
	}
}

func TestApplyReadAndStatErrorBranches(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	notDir := filepath.Join(blocker, "nested.json") // ENOTDIR on every access

	// Direct helpers.
	if _, _, err := readLiteLLMTargetFile(notDir); err == nil {
		t.Fatalf("readLiteLLMTargetFile: expected ENOTDIR error")
	} else if os.IsNotExist(err) {
		t.Fatalf("readLiteLLMTargetFile: ENOTDIR misreported as not-exist")
	}
	if _, err := litellmFileExists(notDir); err == nil {
		t.Fatalf("litellmFileExists: expected stat error")
	}
	if err := writeLiteLLMFileAtomic(filepath.Join(dir, "missing-subdir", "x"), []byte("y")); err == nil ||
		!strings.Contains(err.Error(), "create temp next to") {
		t.Fatalf("writeLiteLLMFileAtomic missing dir: err=%v", err)
	}

	// Apply: unreadable catalog target.
	if _, err := LiteLLMApply(edgeReport(t), LiteLLMApplyTargets{CatalogPath: notDir}); err == nil ||
		!strings.Contains(err.Error(), "read catalog") {
		t.Fatalf("apply unreadable catalog: err=%v", err)
	}

	// Apply: unreadable ledger target (catalog path is fine).
	if _, err := LiteLLMApply(edgeReport(t), LiteLLMApplyTargets{
		CatalogPath: filepath.Join(dir, "catalog.json"),
		LedgerPath:  notDir,
	}); err == nil || !strings.Contains(err.Error(), "read ledger") {
		t.Fatalf("apply unreadable ledger: err=%v", err)
	}

	// Rollback: unreadable catalog backup.
	if _, err := LiteLLMRollback(LiteLLMApplyTargets{CatalogPath: notDir}); err == nil ||
		!strings.Contains(err.Error(), "read catalog backup") {
		t.Fatalf("rollback unreadable catalog backup: err=%v", err)
	}

	// Rollback: catalog backup readable, ledger backup ENOTDIR.
	catalogPath := filepath.Join(dir, "catalog2.json")
	if err := os.WriteFile(catalogPath+".litellm-backup", []byte("{}"), 0o600); err != nil {
		t.Fatalf("write catalog backup stub: %v", err)
	}
	if _, err := LiteLLMRollback(LiteLLMApplyTargets{
		CatalogPath: catalogPath,
		LedgerPath:  notDir,
	}); err == nil || !strings.Contains(err.Error(), "read ledger backup") {
		t.Fatalf("rollback unreadable ledger backup: err=%v", err)
	}
}

func TestApplyCommitSeamMatrix(t *testing.T) {
	report := edgeReport(t)
	seed := []byte(`{"schema_version":2,"version":"import-test","source":"edge-test"}`)

	cases := []struct {
		name    string
		failOn  func(dst string) bool
		wantErr []string
	}{
		{
			name: "catalog commit fails",
			failOn: func(dst string) bool {
				return strings.HasSuffix(dst, "catalog.json")
			},
			wantErr: []string{"targets untouched, backups at"},
		},
		{
			name: "ledger commit fails, catalog restores",
			failOn: func(dst string) bool {
				return strings.HasSuffix(dst, "apply-ledger.json")
			},
			wantErr: []string{"ledger write failed", "catalog was restored to its pre-apply state", "ledger was never written"},
		},
		{
			name:    "ledger commit fails, restore fails too",
			failOn:  nil, // sequenced below: fail from the second commit rename on
			wantErr: []string{"ledger write failed", "catalog restore also failed", "inspect"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			targets := applyTargetsIn(t, dir)
			// Seed a catalog so the restore path has content to put back.
			if err := os.WriteFile(targets.CatalogPath, seed, 0o600); err != nil {
				t.Fatalf("seed catalog: %v", err)
			}

			origRename := litellmRename
			commitCalls := 0
			litellmRename = func(src, dst string) error {
				if strings.HasSuffix(dst, ".litellm-backup") {
					return os.Rename(src, dst)
				}
				if tc.failOn != nil {
					if tc.failOn(dst) {
						return fmt.Errorf("simulated rename failure")
					}
					return os.Rename(src, dst)
				}
				// Sequenced mode: the catalog commit succeeds, every later
				// non-backup rename (ledger commit, restore) fails.
				commitCalls++
				if commitCalls >= 2 {
					return fmt.Errorf("simulated rename failure")
				}
				return os.Rename(src, dst)
			}
			_, err := LiteLLMApply(report, targets)
			litellmRename = origRename
			if err == nil {
				t.Fatalf("expected seam failure")
			}
			for _, want := range tc.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error missing %q:\n%s", want, err.Error())
				}
			}
			// When the catalog restore succeeded, the catalog keeps its
			// seeded bytes. When the restore itself failed (loudly), the
			// merged content stays in place for manual inspection. The
			// backup set exists in both cases.
			if !strings.Contains(err.Error(), "catalog restore also failed") {
				current, readErr := os.ReadFile(targets.CatalogPath)
				if readErr != nil || !bytes.Equal(current, seed) {
					t.Fatalf("catalog not restored to seed (read err %v)", readErr)
				}
			}
			for _, backup := range []string{targets.CatalogPath + ".litellm-backup", targets.LedgerPath + ".litellm-backup"} {
				if _, statErr := os.Stat(backup); statErr != nil {
					t.Fatalf("backup %s missing after seam failure: %v", backup, statErr)
				}
			}
		})
	}

	// Direct writeLiteLLMFileAtomic commit failure discards the temp file.
	dir := t.TempDir()
	origRename := litellmRename
	litellmRename = func(src, dst string) error { return fmt.Errorf("simulated rename failure") }
	err := writeLiteLLMFileAtomic(filepath.Join(dir, "x.json"), []byte("{}"))
	litellmRename = origRename
	if err == nil {
		t.Fatalf("expected commit failure")
	}
	entries, readDirErr := os.ReadDir(dir)
	if readDirErr != nil || len(entries) != 0 {
		t.Fatalf("temp files left behind after commit failure (entries %v, err %v)", entries, readDirErr)
	}
}

func TestRollbackReadOnlyDirectory(t *testing.T) {
	report := edgeReport(t)

	t.Run("remove created catalog fails", func(t *testing.T) {
		dir := t.TempDir()
		targets := applyTargetsIn(t, dir)
		mustApply(t, report, targets)
		readOnlyDir(t, dir)

		_, err := LiteLLMRollback(targets)
		if err == nil || !strings.Contains(err.Error(), "remove created catalog") {
			t.Fatalf("rollback readonly: err=%v", err)
		}
		// The catalog survives; both backups are kept.
		if _, statErr := os.Stat(targets.CatalogPath); statErr != nil {
			t.Fatalf("catalog removed by failed rollback: %v", statErr)
		}
	})

	t.Run("restore catalog fails", func(t *testing.T) {
		dir := t.TempDir()
		targets := applyTargetsIn(t, dir)
		seed := []byte(`{"schema_version":2,"version":"import-test","source":"edge-test"}`)
		if err := os.WriteFile(targets.CatalogPath, seed, 0o600); err != nil {
			t.Fatalf("seed catalog: %v", err)
		}
		mustApply(t, report, targets)
		readOnlyDir(t, dir)

		_, err := LiteLLMRollback(targets)
		if err == nil || !strings.Contains(err.Error(), "restore catalog") || !strings.Contains(err.Error(), "backups kept") {
			t.Fatalf("rollback readonly restore: err=%v", err)
		}
		if _, statErr := os.Stat(targets.CatalogPath + ".litellm-backup"); statErr != nil {
			t.Fatalf("backups not kept after failed restore: %v", statErr)
		}
	})
}

func TestPreviewRefusesInvalidCurrentCatalog(t *testing.T) {
	dir := t.TempDir()
	targets := applyTargetsIn(t, dir)
	_, err := BuildLiteLLMApplyPreview(edgeReport(t), targets, []byte("{not json"))
	if err == nil || !strings.Contains(err.Error(), "current catalog is invalid") {
		t.Fatalf("preview invalid catalog: err=%v", err)
	}
}

func TestRollbackRenderersAndJSON(t *testing.T) {
	report := edgeReport(t)

	// Removed case (fresh catalog).
	dir := t.TempDir()
	targets := applyTargetsIn(t, dir)
	mustApply(t, report, targets)
	rb, err := LiteLLMRollback(targets)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	text := RenderLiteLLMRollbackResult(rb)
	for _, want := range []string{
		"catalog: " + targets.CatalogPath + " removed (pre-apply state: absent)",
		"ledger: " + targets.LedgerPath + " removed (pre-apply state: absent)",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("rollback text missing %q:\n%s", want, text)
		}
	}
	jsonText, err := LiteLLMRollbackResultJSON(rb)
	if err != nil {
		t.Fatalf("rollback json: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(jsonText), &parsed); err != nil {
		t.Fatalf("rollback json parse: %v", err)
	}

	// Untouched case: zero-value flags render "untouched" twice and the
	// short digest of an empty string.
	untouched := RenderLiteLLMRollbackResult(&LiteLLMRollbackResult{Targets: targets})
	if strings.Count(untouched, "untouched") != 2 {
		t.Fatalf("untouched render wrong:\n%s", untouched)
	}
}

func TestApplyRenderersUpdateBranches(t *testing.T) {
	dir := t.TempDir()
	targets := applyTargetsIn(t, dir)
	capKey := firstCapabilityKey(t)

	pin := LiteLLMConfigPin()
	hasOpenAI := false
	for _, provider := range pin.ProviderTargets {
		if provider == "openai" {
			hasOpenAI = true
			break
		}
	}
	if !hasOpenAI {
		t.Fatalf("openai is not a pinned provider target")
	}

	rep := edgeReport(t)
	rep.Plan[0].Provider = "openai"
	rep.Plan[0].Aliases = []string{"edge-alias"}
	rep.Plan[0].Capabilities = map[string]bool{capKey: true}
	rep.Plan[0].Limits = &LiteLLMPlanLimits{MaxTPM: 4800}

	// Preview against an existing catalog and against an absent one. The
	// seed carries the same (provider, model) identity as the plan, so the
	// preview outcome is an update, not an insert.
	seed := `{"schema_version":2,"version":"import-test","source":"edge-test","models":[{"provider":"openai","model":"edge-model","price":{"input":1.5}}]}`
	previewExisting, err := BuildLiteLLMApplyPreview(rep, targets, []byte(seed))
	if err != nil {
		t.Fatalf("preview existing: %v", err)
	}
	existingText := RenderLiteLLMApplyPreview(previewExisting)
	for _, want := range []string{
		"exists — merged by the apply",
		"aliases added: edge-alias",
		"capabilities: " + capKey,
		"limits: max_tpm=4800",
		"limits changed: max_tpm",
		"NOT migrated:",
	} {
		if !strings.Contains(existingText, want) {
			t.Fatalf("existing preview missing %q:\n%s", want, existingText)
		}
	}
	previewFresh, err := BuildLiteLLMApplyPreview(rep, targets, nil)
	if err != nil {
		t.Fatalf("preview fresh: %v", err)
	}
	if freshText := RenderLiteLLMApplyPreview(previewFresh); !strings.Contains(freshText, "absent — created by the apply") {
		t.Fatalf("fresh preview wrong:\n%s", freshText)
	}
	if _, err := LiteLLMApplyPreviewJSON(previewExisting); err != nil {
		t.Fatalf("preview json: %v", err)
	}

	// Apply against the seeded catalog: the row is updated, aliases and
	// capability are added, limits are applied.
	if err := os.WriteFile(targets.CatalogPath, []byte(seed), 0o600); err != nil {
		t.Fatalf("seed write: %v", err)
	}
	result := mustApply(t, rep, targets)
	resultText := RenderLiteLLMApplyResult(result)
	for _, want := range []string{
		"aliases added: edge-alias",
		"capabilities applied: " + capKey,
		"limits applied: max_tpm",
	} {
		if !strings.Contains(resultText, want) {
			t.Fatalf("result text missing %q:\n%s", want, resultText)
		}
	}
	if _, err := LiteLLMApplyResultJSON(result); err != nil {
		t.Fatalf("result json: %v", err)
	}

	// Re-apply is a no-op; its renderer states that explicitly.
	noOp := mustApply(t, rep, targets)
	if noOpText := RenderLiteLLMApplyResult(noOp); !strings.Contains(noOpText, "no-op (already applied)") {
		t.Fatalf("no-op render wrong:\n%s", noOpText)
	}
}

// adversarialFixtureYAML stacks every guard shape the walker must classify
// loudly: scalar deployments, missing identities, unknown providers and
// modes, wildcards, non-integer/zero/negative limits, duplicate keys,
// load-balanced groups, dangling aliases/fallbacks, unknown sections and
// environment secrets. It lives inline (not as a .yaml testdata file) so
// the fixture travels with the test.
const adversarialFixtureYAML = `# Adversarial input for the LiteLLM dry-run walker (N16-P02-T04 coverage
# supplement). Output counts are pinned in TestDryRunAdversarialFixture.
model_list:
  - "scalar-entry"
  - model_name: ""
    litellm_params: "not-a-mapping"
  - litellm_params:
      model: "openai/"
  - model_name: "noprov"
    litellm_params:
      model: "bare-model"
  - model_name: "unknownprov"
    litellm_params:
      model: "bare-model"
      custom_llm_provider: "unknownvendor"
  - model_name: "wild*"
    litellm_params:
      model: "openai/gpt-*"
      tpm: "not-a-number"
  - model_name: "negzero"
    litellm_params:
      model: "openai/m1"
      tpm: -5
      rpm: 0
  - model_name: "shapes"
    unknown_field: "x"
    model_info: "not-a-mapping"
    litellm_params:
      model: "openai/m1"
  - model_name: "info"
    model_info:
      mode: "weird-mode"
      max_output_tokens: 0
      max_input_tokens: 5000
    litellm_params:
      model: "openai/m2"
  - model_name: "g1"
    litellm_params:
      model: "openai/gpt-4o"
      tpm: 1000
      rpm: 100
  - model_name: "dupkey"
    model_name: "dupkey"
    litellm_params:
      model: "openai/m3"
  - model_name: "g2"
    litellm_params:
      model: "openai/model-a"
  - model_name: "g2"
    litellm_params:
      model: "openai/model-b"
router_settings:
  model_group_alias:
    ok-alias: g1
    "": g1
    to-unknown: "nosuch-group"
    gpt-4o: g1
    g1: g1
    dup-alias: g1
    "dup-alias ": g2
  fallbacks:
    - g1: [g2, "nosuch-group"]
    - "*": [g1]
    - g2: "not-a-sequence"
    - "nosuch-group": [g1]
    - "scalar-item"
litellm_settings:
  drop_params: true
general_settings: "not-a-mapping"
environment_variables:
  API_KEY: "sk-adversarial-secret"
  API_KEY: "sk-duplicate-secret"
weird_section: {}
`

func TestDryRunAdversarialFixture(t *testing.T) {
	// One fixture stacking every guard shape the walker must classify
	// loudly. Pins the summary and a sample of details so the guard
	// vocabulary stays stable for the reviewed apply.
	rep, err := LiteLLMDryRun([]byte(adversarialFixtureYAML))
	if err != nil {
		t.Fatalf("LiteLLMDryRun(adversarial): unexpected error: %v", err)
	}
	assertCounts(t, rep, LiteLLMSummary{
		Transferable: 10, Differences: 5, Conflicts: 22,
		Unsupported: 6, Secrets: 2, PlanEntries: 3,
	})
	text := RenderLiteLLMReport(rep)
	for _, want := range []string{
		"deployment entry must be a mapping",
		"model_name is required and must be a non-empty scalar",
		"litellm_params must be a mapping",
		"provider cannot be determined",
		`provider "unknownvendor" has no Yabanin adapter`,
		`wildcard model group "wild*"`,
		"tpm must be a plain decimal integer",
		"negative tpm limit cannot transfer",
		`rpm=0 means "block all traffic"`,
		"model_info must be a mapping",
		"max_output_tokens=0 cannot transfer",
		`duplicate key "model_name"`,
		`duplicate key "API_KEY"`,
		"has 2 deployments across different targets",
		"need a non-empty alias and target group",
		`points at unknown model group "nosuch-group"`,
		`shadows the canonical model name of openai/gpt-4o`,
		`collides with an existing model group name`,
		"must be a sequence of model group names",
		"single-key {group: [chain]} mapping",
		"dangling route and is never transferred",
		"general_settings must be a mapping",
		`top-level section "weird_section"`,
		`mode "weird-mode" has no mapping`,
		"transferring an input cap as a full-window bound",
		"the enforcement posture differs",
		"catch-all can map to the single global fallback",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("adversarial report missing %q", want)
		}
	}
	if len(rep.Secrets) != 2 {
		t.Fatalf("expected the two environment keys as redacted secrets, got %+v", rep.Secrets)
	}
	for _, s := range rep.Secrets {
		if strings.Contains(s.Field, "sk-") {
			t.Fatalf("secret value leaked into the field name: %+v", s)
		}
	}
}

func TestApplyLedgerBackupWriteFailure(t *testing.T) {
	// The ledger lives in an unwritable directory: the ledger backup write
	// fails after the catalog backup succeeded, and the apply removes the
	// catalog backup again (all-or-nothing attempt).
	dirA, dirB := t.TempDir(), t.TempDir()
	catalogPath := filepath.Join(dirA, "catalog.json")
	ledgerPath := filepath.Join(dirB, "ledger.json")
	readOnlyDir(t, dirB)

	_, err := LiteLLMApply(edgeReport(t), LiteLLMApplyTargets{CatalogPath: catalogPath, LedgerPath: ledgerPath})
	if err == nil || !strings.Contains(err.Error(), "write ledger backup") || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("ledger backup failure: err=%v", err)
	}
	if _, statErr := os.Stat(catalogPath + ".litellm-backup"); !os.IsNotExist(statErr) {
		t.Fatalf("catalog backup must be removed after failed ledger backup: %v", statErr)
	}
}

func TestRollbackLedgerDirectoryFailures(t *testing.T) {
	report := edgeReport(t)

	t.Run("remove created ledger fails", func(t *testing.T) {
		dirA, dirB := t.TempDir(), t.TempDir()
		targets := LiteLLMApplyTargets{
			CatalogPath: filepath.Join(dirA, "catalog.json"),
			LedgerPath:  filepath.Join(dirB, "ledger.json"),
		}
		mustApply(t, report, targets) // ledger was created (absent pre-state)
		readOnlyDir(t, dirB)

		_, err := LiteLLMRollback(targets)
		if err == nil || !strings.Contains(err.Error(), "remove created ledger") || !strings.Contains(err.Error(), "catalog already restored") {
			t.Fatalf("rollback ledger remove failure: err=%v", err)
		}
		if _, statErr := os.Stat(targets.LedgerPath); statErr != nil {
			t.Fatalf("ledger must survive the failed removal: %v", statErr)
		}
	})

	t.Run("restore ledger fails", func(t *testing.T) {
		dirA, dirB := t.TempDir(), t.TempDir()
		targets := LiteLLMApplyTargets{
			CatalogPath: filepath.Join(dirA, "catalog.json"),
			LedgerPath:  filepath.Join(dirB, "ledger.json"),
		}
		if err := os.WriteFile(targets.LedgerPath, []byte("{\"schema\":1}\n"), 0o600); err != nil {
			t.Fatalf("seed ledger: %v", err)
		}
		mustApply(t, report, targets) // ledger existed (non-empty backup)
		readOnlyDir(t, dirB)

		_, err := LiteLLMRollback(targets)
		if err == nil || !strings.Contains(err.Error(), "restore ledger") || !strings.Contains(err.Error(), "catalog restored; backups kept") {
			t.Fatalf("rollback ledger restore failure: err=%v", err)
		}
	})
}

func TestRollbackRenderRestoredBranches(t *testing.T) {
	dir := t.TempDir()
	targets := applyTargetsIn(t, dir)
	if err := os.WriteFile(targets.CatalogPath, []byte(`{"schema_version":2,"version":"import-test","source":"edge-test"}`), 0o600); err != nil {
		t.Fatalf("seed catalog: %v", err)
	}
	mustApply(t, edgeReport(t), targets)
	rb, err := LiteLLMRollback(targets)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	text := RenderLiteLLMRollbackResult(rb)
	for _, want := range []string{
		"catalog: " + targets.CatalogPath + " restored (sha256 ",
		"ledger: " + targets.LedgerPath + " removed (pre-apply state: absent)",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("restored rollback text missing %q:\n%s", want, text)
		}
	}
}

func TestMergeSkipsFalseCapabilities(t *testing.T) {
	// The apply gate refuses false capabilities (presence-only vocabulary);
	// the merge itself is a pure function, so the skip branch is exercised
	// directly here.
	doc := freshLiteLLMCatalogDoc()
	capKey := firstCapabilityKey(t)
	plan := []LiteLLMPlanEntry{{
		Action:       LiteLLMPlanActionUpsert,
		Provider:     "openai",
		Model:        "cap-model",
		Capabilities: map[string]bool{capKey: false},
		SourcePaths:  []string{"model_list[0].model_name"},
	}}
	_, applied, err := mergeLiteLLMPlan(&doc, plan)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if len(applied) != 1 || len(applied[0].CapabilitiesApplied) != 0 {
		t.Fatalf("false capability must not be applied: %+v", applied)
	}

	// UPDATE branch: a row that already exists carries over the seeded
	// capabilities; a false capability is skipped while a true one is
	// applied on top.
	capTrue := firstCapabilityKey(t)
	var capFalse string
	for k := range upstream.CatalogCapabilityFields() {
		if k != capTrue {
			capFalse = k
			break
		}
	}
	if capFalse == "" {
		t.Fatalf("need a second capability key")
	}
	doc2 := freshLiteLLMCatalogDoc()
	doc2.Models = append(doc2.Models, upstream.CatalogModelEntry{
		Provider: "openai", Model: "existing",
		Capabilities: map[string]bool{capFalse: true},
	})
	plan2 := []LiteLLMPlanEntry{{
		Action:       LiteLLMPlanActionUpsert,
		Provider:     "openai",
		Model:        "existing",
		Capabilities: map[string]bool{capTrue: true, capFalse: false},
		SourcePaths:  []string{"model_list[9].model_name"},
	}}
	_, applied2, err2 := mergeLiteLLMPlan(&doc2, plan2)
	if err2 != nil {
		t.Fatalf("merge update: %v", err2)
	}
	var row *upstream.CatalogModelEntry
	for i := range doc2.Models {
		if doc2.Models[i].Provider == "openai" && doc2.Models[i].Model == "existing" {
			row = &doc2.Models[i]
			break
		}
	}
	if row == nil {
		t.Fatalf("updated row missing from document")
	}
	if len(applied2) != 1 || len(applied2[0].CapabilitiesApplied) != 1 || applied2[0].CapabilitiesApplied[0] != capTrue {
		t.Fatalf("update must apply only the true capability: %+v", applied2)
	}
	if !row.Capabilities[capTrue] || !row.Capabilities[capFalse] {
		t.Fatalf("update must keep seeded capabilities and add the applied one: %+v", row.Capabilities)
	}
}

func TestLedgerParseAndMembershipEdges(t *testing.T) {
	// Empty identity in a ledger row is a parse error.
	raw := []byte(`{"schema":1,"entries":[{"seq":1,"provider":"","model":"m","content_sha256":"abc"}]}`)
	if _, err := parseLiteLLMApplyLedger(raw); err == nil || !strings.Contains(err.Error(), "empty provider or model") {
		t.Fatalf("empty identity parse: err=%v", err)
	}

	// Membership: the provider/model/digest triple must match exactly.
	ledger := &LiteLLMApplyLedger{Entries: []LiteLLMApplyLedgerEntry{{
		Seq: 1, Provider: "openai", Model: "m", ContentSHA256: "digest-1",
	}}}
	if !ledgerHasEntry(ledger, LiteLLMAppliedEntry{Provider: "openai", Model: "m", ContentSHA256: "digest-1"}) {
		t.Fatalf("identical entry must be found")
	}
	if ledgerHasEntry(ledger, LiteLLMAppliedEntry{Provider: "openai", Model: "m", ContentSHA256: "digest-2"}) {
		t.Fatalf("different digest must not match")
	}
	if ledgerHasEntry(ledger, LiteLLMAppliedEntry{Provider: "anthropic", Model: "m", ContentSHA256: "digest-1"}) {
		t.Fatalf("different provider must not match")
	}
}
