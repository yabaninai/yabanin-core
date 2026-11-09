// Reviewed apply step for the LiteLLM proxy-config migration (N16-P02-T04,
// owner decisions I65/I12, PRODUCT-CONTRACT.md §14). This file owns the only
// path from a dry-run report to configuration state: the apply consumes a
// *LiteLLMMigrationReport produced by LiteLLMDryRun — never the raw proxy
// config — and the dry-run engine (litellm_migrate*.go) never mutates
// configuration. Only the functions in this file write, under the invariants
// pinned here:
//   - verified semantics are the only entry: every plan entry is re-verified
//     against the report itself (schema, summary consistency, source-path
//     linkage to transfer findings, catalog vocabulary) before anything is
//     written; a path that the same report marks conflicted or unsupported
//     can never be applied;
//   - idempotency: applying the same reviewed report twice is a no-op — the
//     second run writes no bytes and adds no duplicate ledger entries;
//   - rollback: both touched files (catalog document and apply ledger) are
//     backed up byte-exactly before the first write, and rollback restores
//     the byte-identical pre-state, including the "did not exist" state;
//   - secrets-in-preview: previews and results render report content only,
//     which carries secret paths and field names but never values;
//   - fail-closed: every anomaly (unknown schema, tampered summary, missing
//     or inconsistent backup, partial I/O failure) aborts the whole apply,
//     restores the pre-state and returns a loud error; a partial apply is
//     impossible.
package clientconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/reireirei/yabanin/pkg/upstream"
)

// LiteLLMApplyLedgerSchema is the apply-ledger document schema version.
// Consumers must refuse ledgers they do not know.
const LiteLLMApplyLedgerSchema = 1

// LiteLLMPlanActionUpsert is the only plan action the apply gate accepts.
// The dry-run plan builder emits exactly this value; anything else in a
// consumed report is a refusal.
const LiteLLMPlanActionUpsert = "catalog.upsert"

// Row-level outcomes of a reviewed apply (and of a preview outcome).
const (
	LiteLLMApplyInserted  = "inserted"
	LiteLLMApplyUpdated   = "updated"
	LiteLLMApplyUnchanged = "unchanged"
)

// litellmRename is the rename seam used by the atomic write path. Tests
// replace it to exercise the fail-closed restore path deterministically.
var litellmRename = os.Rename

// LiteLLMApplyTargets names the files a reviewed apply touches: the target
// catalog document and the apply ledger that journals what was applied.
type LiteLLMApplyTargets struct {
	// CatalogPath is the target catalog document (JSON). It may not exist
	// yet; the apply then creates it and the rollback removes it again.
	CatalogPath string `json:"catalog_path"`
	// LedgerPath is the apply ledger. Empty means the derived default
	// (LiteLLMApplyDefaultLedgerPath of CatalogPath).
	LedgerPath string `json:"ledger_path,omitempty"`
}

// LiteLLMApplyDefaultLedgerPath derives the ledger path from the catalog
// path: "catalog.json" → "catalog.litellm-apply-ledger.json".
func LiteLLMApplyDefaultLedgerPath(catalogPath string) string {
	dir, base := filepath.Split(catalogPath)
	stem := strings.TrimSuffix(base, filepath.Ext(base))
	if stem == "" {
		stem = base
	}
	return filepath.Join(dir, stem+".litellm-apply-ledger.json")
}

// LiteLLMApplyBackupPath is the sibling backup file of one touched target.
// A zero-length backup records "the target did not exist before the apply".
func LiteLLMApplyBackupPath(path string) string {
	return path + ".litellm-backup"
}

// LiteLLMApplyRefusal aggregates every gate problem of one apply attempt.
// The apply is all-or-nothing: a refusal means nothing was written.
type LiteLLMApplyRefusal struct {
	Problems []string
}

func (e *LiteLLMApplyRefusal) Error() string {
	return fmt.Sprintf("litellm apply refused (%d problem(s)); nothing was written: %s",
		len(e.Problems), strings.Join(e.Problems, "; "))
}

// LiteLLMAppliedEntry is the per-row outcome of one apply.
type LiteLLMAppliedEntry struct {
	Action       string   `json:"action"`
	Provider     string   `json:"provider"`
	Model        string   `json:"model"`
	Result       string   `json:"result"`
	AliasesAdded []string `json:"aliases_added,omitempty"`
	// CapabilitiesApplied/LimitsApplied list the field names this apply
	// actually changed on an existing row (inserted rows list nothing —
	// the whole row is new).
	CapabilitiesApplied []string `json:"capabilities_applied,omitempty"`
	LimitsApplied       []string `json:"limits_applied,omitempty"`
	// ContentSHA256 is the digest of the canonical plan entry JSON; the
	// ledger uses it to detect duplicate entries.
	ContentSHA256 string   `json:"content_sha256"`
	SourcePaths   []string `json:"source_paths"`
}

// LiteLLMApplyLedgerEntry is one journal row of the apply ledger.
type LiteLLMApplyLedgerEntry struct {
	Seq           int64    `json:"seq"`
	Provider      string   `json:"provider"`
	Model         string   `json:"model"`
	Result        string   `json:"result"`
	ContentSHA256 string   `json:"content_sha256"`
	SourcePaths   []string `json:"source_paths"`
}

// LiteLLMApplyLedger is the apply journal stored next to the catalog
// document. It records plan-content digests, never configuration values, and
// carries the T03 secret hand-off as a count (values are never included).
type LiteLLMApplyLedger struct {
	Schema int `json:"schema"`
	// LastReportSHA256 binds the ledger to the digest of the last report
	// that changed migration state (document content or ledger rows).
	LastReportSHA256 string                    `json:"last_report_sha256"`
	SecretsRedacted  int                       `json:"secrets_redacted"`
	Entries          []LiteLLMApplyLedgerEntry `json:"entries"`
}

// LiteLLMApplyResult is what an apply (or idempotent re-apply) reports.
type LiteLLMApplyResult struct {
	Targets        LiteLLMApplyTargets `json:"targets"`
	ReportSHA256   string              `json:"report_sha256"`
	CatalogExisted bool                `json:"catalog_existed"`
	// Changed is false exactly when the apply was an idempotent no-op and
	// no file was touched.
	Changed         bool                  `json:"changed"`
	Applied         []LiteLLMAppliedEntry `json:"applied"`
	LedgerUpdated   bool                  `json:"ledger_updated"`
	CatalogSHA256   string                `json:"catalog_sha256"`
	LedgerSHA256    string                `json:"ledger_sha256,omitempty"`
	SecretsRedacted int                   `json:"secrets_redacted"`
}

// LiteLLMApplyPreviewEntry is one plan row as the preview renders it against
// the current catalog state.
type LiteLLMApplyPreviewEntry struct {
	Action        string             `json:"action"`
	Provider      string             `json:"provider"`
	Model         string             `json:"model"`
	Outcome       string             `json:"outcome"`
	Aliases       []string           `json:"aliases,omitempty"`
	AliasesAdded  []string           `json:"aliases_added,omitempty"`
	Capabilities  map[string]bool    `json:"capabilities,omitempty"`
	Limits        *LiteLLMPlanLimits `json:"limits,omitempty"`
	LimitsChanged []string           `json:"limits_changed,omitempty"`
	SourcePaths   []string           `json:"source_paths"`
}

// LiteLLMApplyPreview is the operator-facing review artifact: exactly what
// the apply would do, computed without writing anything. Building it runs
// the same gate as the apply, so a preview that renders is an apply that is
// eligible; secret paths appear as path + field name only.
type LiteLLMApplyPreview struct {
	Schema          int                        `json:"schema"`
	ReportSHA256    string                     `json:"report_sha256"`
	Targets         LiteLLMApplyTargets        `json:"targets"`
	CatalogExists   bool                       `json:"catalog_exists"`
	Entries         []LiteLLMApplyPreviewEntry `json:"entries"`
	Scope           LiteLLMScope               `json:"scope"`
	SecretsRedacted int                        `json:"secrets_redacted"`
	// SecretPaths repeats the report's redacted secret locations (path and
	// field name only — values are never included).
	SecretPaths []LiteLLMSecret `json:"secret_paths,omitempty"`
}

// LiteLLMRollbackResult is what a rollback reports.
type LiteLLMRollbackResult struct {
	Targets         LiteLLMApplyTargets `json:"targets"`
	CatalogRestored bool                `json:"catalog_restored"`
	CatalogRemoved  bool                `json:"catalog_removed"`
	CatalogSHA256   string              `json:"catalog_sha256,omitempty"`
	LedgerRestored  bool                `json:"ledger_restored"`
	LedgerRemoved   bool                `json:"ledger_removed"`
	LedgerSHA256    string              `json:"ledger_sha256,omitempty"`
}

// freshLiteLLMCatalogDoc is the document an apply starts from when the
// target catalog does not exist yet. The defaults are deterministic (no
// wall-clock data) so identical applies produce byte-identical documents.
func freshLiteLLMCatalogDoc() upstream.CatalogDocument {
	return upstream.CatalogDocument{
		SchemaVersion: upstream.CatalogSchemaCurrent,
		Version:       "litellm-import",
		Source:        "litellm proxy-config migration (reviewed apply)",
	}
}

// sha256HexLiteLLM is the digest used for report/catalog/ledger binding.
func sha256HexLiteLLM(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// marshalLiteLLMJSON is the canonical serialization used for every file the
// apply writes (deterministic: MarshalIndent plus a trailing newline).
func marshalLiteLLMJSON(v any) ([]byte, error) {
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

// litellmApplyReportDigest binds an apply to the exact reviewed report: the
// SHA256 over the deterministic JSON re-render of the report struct. It is
// stable across processes and independent of the operator file's formatting.
func litellmApplyReportDigest(rep *LiteLLMMigrationReport) (string, error) {
	body, err := LiteLLMReportJSON(rep)
	if err != nil {
		return "", fmt.Errorf("litellm apply: render report for digest: %w", err)
	}
	return sha256HexLiteLLM([]byte(body)), nil
}

// planEntryDigest digests one plan entry canonically; the ledger deduplicates
// on it.
func planEntryDigest(entry LiteLLMPlanEntry) (string, error) {
	body, err := marshalLiteLLMJSON(entry)
	if err != nil {
		return "", fmt.Errorf("litellm apply: render plan entry: %w", err)
	}
	return sha256HexLiteLLM(body), nil
}

// litellmTargetProviderSet lists the provider ids a plan entry may use (the
// values of the pinned source→target mapping, never its keys).
func litellmTargetProviderSet() map[string]bool {
	set := make(map[string]bool, len(litellmProviderTargets))
	for _, target := range litellmProviderTargets {
		set[target] = true
	}
	return set
}

// applyNameProblem reports an empty or whitespace-padded namespace name, or
// "" when the name is acceptable shape-wise (wildcards are checked apart).
func applyNameProblem(where, kind, value string) string {
	if value == "" {
		return fmt.Sprintf("%s: empty %s", where, kind)
	}
	if strings.TrimSpace(value) != value {
		return fmt.Sprintf("%s: whitespace-padded %s %q", where, kind, value)
	}
	return ""
}

// verifyLiteLLMApplyPlan re-verifies a dry-run report against the pinned
// vocabulary and returns the plan entries eligible for apply. Refusal
// depends on the report alone; configuration state plays no part. Every
// problem is collected — the refusal lists all of them at once.
func verifyLiteLLMApplyPlan(rep *LiteLLMMigrationReport) ([]LiteLLMPlanEntry, error) {
	if rep == nil {
		return nil, &LiteLLMApplyRefusal{Problems: []string{"nil report"}}
	}
	problems := make([]string, 0, 4)
	if rep.Schema != LiteLLMDryRunSchema {
		problems = append(problems, fmt.Sprintf(
			"unsupported report schema %d (this apply consumes schema %d)", rep.Schema, LiteLLMDryRunSchema))
	}
	if pin := LiteLLMConfigPin(); rep.Source.Format != pin.Format {
		problems = append(problems, fmt.Sprintf("report source format %q is not %q", rep.Source.Format, pin.Format))
	}
	if s := rep.Summary; s.Transferable != len(rep.Transferable) || s.Differences != len(rep.Differences) ||
		s.Conflicts != len(rep.Conflicts) || s.Unsupported != len(rep.Unsupported) ||
		s.Secrets != len(rep.Secrets) || s.PlanEntries != len(rep.Plan) {
		problems = append(problems, "report summary does not match its finding lists (report is truncated or tampered)")
	}
	if len(rep.Plan) == 0 {
		problems = append(problems, "report carries no plan entries; there is nothing verified to apply")
	}

	transferPaths := make(map[string]bool, len(rep.Transferable))
	for _, f := range rep.Transferable {
		transferPaths[f.Path] = true
	}
	conflictPaths := make(map[string]bool, len(rep.Conflicts))
	for _, f := range rep.Conflicts {
		conflictPaths[f.Path] = true
	}
	unsupportedPaths := make(map[string]bool, len(rep.Unsupported))
	for _, f := range rep.Unsupported {
		unsupportedPaths[f.Path] = true
	}

	seenPairs := make(map[string]bool, len(rep.Plan))
	seenAliases := make(map[string]bool, len(rep.Plan))
	targets := litellmTargetProviderSet()
	vocabulary := upstream.CatalogCapabilityFields()
	for i := range rep.Plan {
		entry := &rep.Plan[i]
		where := fmt.Sprintf("plan[%d] (%s/%s)", i, entry.Provider, entry.Model)
		problems = verifyLiteLLMApplyPlanEntry(entry, where, problems, targets, vocabulary)

		pair := entry.Provider + ":" + entry.Model
		if seenPairs[pair] {
			problems = append(problems, fmt.Sprintf("%s: duplicate (provider, model) identity %s", where, pair))
		}
		seenPairs[pair] = true
		for _, alias := range entry.Aliases {
			key := entry.Provider + ":" + alias
			if seenAliases[key] {
				problems = append(problems, fmt.Sprintf("%s: alias %q is claimed by more than one plan entry in provider %s",
					where, alias, entry.Provider))
			}
			seenAliases[key] = true
		}
		for _, source := range entry.SourcePaths {
			switch {
			case source == "":
				problems = append(problems, fmt.Sprintf("%s: empty source path", where))
			case conflictPaths[source]:
				problems = append(problems, fmt.Sprintf("%s: source path %q is conflicted in this report and can never be applied",
					where, source))
			case unsupportedPaths[source]:
				problems = append(problems, fmt.Sprintf("%s: source path %q is unsupported in this report and can never be applied",
					where, source))
			case !transferPaths[source]:
				problems = append(problems, fmt.Sprintf("%s: source path %q does not link to a transfer finding in this report",
					where, source))
			}
		}
	}
	if len(problems) > 0 {
		return nil, &LiteLLMApplyRefusal{Problems: problems}
	}
	return append([]LiteLLMPlanEntry(nil), rep.Plan...), nil
}

// verifyLiteLLMApplyPlanEntry appends one entry's vocabulary and shape
// problems (action, identity, aliases, capabilities, limits, source paths)
// to problems and returns the extended slice.
func verifyLiteLLMApplyPlanEntry(entry *LiteLLMPlanEntry, where string, problems []string,
	targets map[string]bool, vocabulary map[string]string) []string {
	if entry.Action != LiteLLMPlanActionUpsert {
		problems = append(problems, fmt.Sprintf("%s: unknown action %q; only %q can be applied",
			where, entry.Action, LiteLLMPlanActionUpsert))
	}
	if !targets[entry.Provider] {
		problems = append(problems, fmt.Sprintf("%s: provider %q is not a pinned provider target", where, entry.Provider))
	}
	if p := applyNameProblem(where, "model", entry.Model); p != "" {
		problems = append(problems, p)
	} else if strings.Contains(entry.Model, "*") {
		problems = append(problems, fmt.Sprintf("%s: wildcard model %q can never be applied", where, entry.Model))
	}
	for _, alias := range entry.Aliases {
		if p := applyNameProblem(where, "alias", alias); p != "" {
			problems = append(problems, p)
			continue
		}
		if strings.Contains(alias, "*") {
			problems = append(problems, fmt.Sprintf("%s: wildcard alias %q can never be applied", where, alias))
			continue
		}
		if alias == entry.Model {
			problems = append(problems, fmt.Sprintf("%s: alias %q shadows the model name", where, alias))
		}
	}
	for key, value := range entry.Capabilities {
		if _, ok := vocabulary[key]; !ok {
			problems = append(problems, fmt.Sprintf("%s: unknown capability key %q", where, key))
		}
		if !value {
			problems = append(problems, fmt.Sprintf("%s: capability %q carries false; the plan vocabulary is presence-only", where, key))
		}
	}
	if entry.Limits != nil {
		fields := []struct {
			name  string
			value int64
		}{
			{"max_tpm", entry.Limits.MaxTPM},
			{"max_rpm", entry.Limits.MaxRPM},
			{"max_output_tokens", entry.Limits.MaxOutputTokens},
		}
		anyPositive := false
		for _, f := range fields {
			switch {
			case f.value < 0:
				problems = append(problems, fmt.Sprintf("%s: limits.%s is negative (%d)", where, f.name, f.value))
			case f.value > 0:
				anyPositive = true
			}
		}
		if !anyPositive {
			problems = append(problems, fmt.Sprintf("%s: limits carry no positive bound", where))
		}
	}
	if len(entry.SourcePaths) == 0 {
		problems = append(problems, fmt.Sprintf("%s: no source paths; a plan entry must link to its verified sources", where))
	}
	return problems
}

// catalogRowFromPlan maps one verified plan entry onto a fresh catalog row.
// The plan deliberately carries no context-window bound: max_input_tokens is
// a decision finding at the source and is never transferred silently.
func catalogRowFromPlan(entry LiteLLMPlanEntry) upstream.CatalogModelEntry {
	row := upstream.CatalogModelEntry{
		Provider: entry.Provider,
		Model:    entry.Model,
	}
	if len(entry.Aliases) > 0 {
		row.Aliases = append([]string(nil), entry.Aliases...)
	}
	if len(entry.Capabilities) > 0 {
		row.Capabilities = make(map[string]bool, len(entry.Capabilities))
		for key, value := range entry.Capabilities {
			row.Capabilities[key] = value
		}
	}
	if entry.Limits != nil {
		row.Limits = &upstream.CatalogLimits{
			MaxTPM:          entry.Limits.MaxTPM,
			MaxRPM:          entry.Limits.MaxRPM,
			MaxOutputTokens: entry.Limits.MaxOutputTokens,
		}
	}
	return row
}

// mergeLiteLLMPlan returns the merged catalog document and per-row outcomes.
// The merge is additive beyond the plan-owned fields: price, sell windows,
// deprecation instants, the context-window bound and every other operator or
// vendor attribute of an existing row are preserved. The plan sets exactly
// the capabilities and limit fields it carries and unions aliases — it never
// unsets or deletes anything. The caller validates the merged document.
func mergeLiteLLMPlan(doc *upstream.CatalogDocument, plan []LiteLLMPlanEntry) (upstream.CatalogDocument, []LiteLLMAppliedEntry, error) {
	merged := *doc
	merged.Models = append([]upstream.CatalogModelEntry(nil), doc.Models...)
	index := make(map[string]int, len(merged.Models))
	for i := range merged.Models {
		key := merged.Models[i].Provider + ":" + merged.Models[i].Model
		index[key] = i
	}
	applied := make([]LiteLLMAppliedEntry, 0, len(plan))
	for _, entry := range plan {
		digest, err := planEntryDigest(entry)
		if err != nil {
			return upstream.CatalogDocument{}, nil, err
		}
		result := LiteLLMAppliedEntry{
			Action:        entry.Action,
			Provider:      entry.Provider,
			Model:         entry.Model,
			SourcePaths:   append([]string(nil), entry.SourcePaths...),
			ContentSHA256: digest,
		}
		key := entry.Provider + ":" + entry.Model
		if existing, ok := index[key]; ok {
			row := &merged.Models[existing]
			result.Result = LiteLLMApplyUnchanged
			have := make(map[string]bool, len(row.Aliases))
			for _, alias := range row.Aliases {
				have[alias] = true
			}
			for _, alias := range entry.Aliases {
				if !have[alias] {
					have[alias] = true
					row.Aliases = append(row.Aliases, alias)
					result.AliasesAdded = append(result.AliasesAdded, alias)
				}
			}
			for _, key := range sortedCapabilityKeys(entry.Capabilities) {
				if !entry.Capabilities[key] {
					continue
				}
				if row.Capabilities == nil {
					row.Capabilities = make(map[string]bool, 1)
				}
				if !row.Capabilities[key] {
					row.Capabilities[key] = true
					result.CapabilitiesApplied = append(result.CapabilitiesApplied, key)
				}
			}
			if entry.Limits != nil {
				if row.Limits == nil {
					row.Limits = &upstream.CatalogLimits{}
				}
				for _, f := range []struct {
					name  string
					value int64
				}{
					{"max_tpm", entry.Limits.MaxTPM},
					{"max_rpm", entry.Limits.MaxRPM},
					{"max_output_tokens", entry.Limits.MaxOutputTokens},
				} {
					if f.value > 0 && catalogLimitFieldOf(row.Limits, f.name) != f.value {
						catalogLimitSetField(row.Limits, f.name, f.value)
						result.LimitsApplied = append(result.LimitsApplied,
							fmt.Sprintf("%s=%d", f.name, f.value))
					}
				}
			}
			if len(result.AliasesAdded)+len(result.CapabilitiesApplied)+len(result.LimitsApplied) > 0 {
				result.Result = LiteLLMApplyUpdated
			}
		} else {
			merged.Models = append(merged.Models, catalogRowFromPlan(entry))
			index[key] = len(merged.Models) - 1
			result.Result = LiteLLMApplyInserted
		}
		applied = append(applied, result)
	}
	return merged, applied, nil
}

// sortedCapabilityKeys returns the map's keys in sorted order so merges and
// renders stay deterministic.
func sortedCapabilityKeys(caps map[string]bool) []string {
	keys := make([]string, 0, len(caps))
	for key := range caps {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// catalogLimitFieldOf / catalogLimitSetField access the catalog limit fields
// the plan vocabulary touches by pinned name.
func catalogLimitFieldOf(l *upstream.CatalogLimits, name string) int64 {
	switch name {
	case "max_tpm":
		return l.MaxTPM
	case "max_rpm":
		return l.MaxRPM
	default:
		return l.MaxOutputTokens
	}
}

func catalogLimitSetField(l *upstream.CatalogLimits, name string, value int64) {
	switch name {
	case "max_tpm":
		l.MaxTPM = value
	case "max_rpm":
		l.MaxRPM = value
	default:
		l.MaxOutputTokens = value
	}
}

// litellmPreState is the byte-exact pre-apply state of both touched files.
// A zero-length byte slice with existed=true means the pre-state was an
// empty file; existed=false means the file did not exist.
type litellmPreState struct {
	catalog        []byte
	catalogExisted bool
	ledger         []byte
	ledgerExisted  bool
}

// restoreLiteLLMTarget restores one target: removes the file when the
// pre-state was absent, writes the exact bytes back otherwise.
func restoreLiteLLMTarget(path string, data []byte, existed bool) error {
	if !existed {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return writeLiteLLMFileAtomic(path, data)
}

// readLiteLLMTargetFile reads a target file; absence is not an error and
// yields (nil, false, nil).
func readLiteLLMTargetFile(path string) ([]byte, bool, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is the operator's catalog/ledger target, not a secret or remote path
	if err == nil {
		return data, true, nil
	}
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	return nil, false, err
}

// litellmFileExists reports existence, turning stat failures into errors
// instead of silently treating them as absence (fail-closed).
func litellmFileExists(path string) (bool, error) {
	if _, err := os.Stat(path); err == nil {
		return true, nil
	} else if os.IsNotExist(err) {
		return false, nil
	} else {
		return false, fmt.Errorf("stat %s: %w", path, err)
	}
}

// writeLiteLLMFileAtomic writes data to path through a temp file in the same
// directory, fsynced before rename. Created files carry 0600 permissions.
func writeLiteLLMFileAtomic(path string, data []byte) error {
	pending, err := prepareLiteLLMWrite(path, data)
	if err != nil {
		return err
	}
	if err := pending.commit(); err != nil {
		pending.discard()
		return err
	}
	return nil
}

// litellmPendingWrite is one prepared-but-not-committed file write: the temp
// file exists and is fsynced, the target is untouched until commit.
type litellmPendingWrite struct {
	tmpName string
	target  string
}

// prepareLiteLLMWrite writes data into a fsynced temp file next to target.
func prepareLiteLLMWrite(target string, data []byte) (*litellmPendingWrite, error) {
	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, filepath.Base(target)+".tmp-*")
	if err != nil {
		return nil, fmt.Errorf("create temp next to %s: %w", target, err)
	}
	pending := &litellmPendingWrite{tmpName: tmp.Name(), target: target}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		pending.discard()
		return nil, fmt.Errorf("write temp for %s: %w", target, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		pending.discard()
		return nil, fmt.Errorf("sync temp for %s: %w", target, err)
	}
	if err := tmp.Close(); err != nil {
		pending.discard()
		return nil, fmt.Errorf("close temp for %s: %w", target, err)
	}
	return pending, nil
}

// commit renames the temp file onto the target.
func (p *litellmPendingWrite) commit() error {
	if err := litellmRename(p.tmpName, p.target); err != nil {
		return fmt.Errorf("move write into place for %s: %w", p.target, err)
	}
	return nil
}

// discard removes the temp file (best-effort).
func (p *litellmPendingWrite) discard() {
	_ = os.Remove(p.tmpName)
}

// parseLiteLLMApplyLedger parses and sanity-checks a ledger document: schema
// pin, non-empty identities, digests present, sequence numbers monotonic.
func parseLiteLLMApplyLedger(data []byte) (*LiteLLMApplyLedger, error) {
	var ledger LiteLLMApplyLedger
	if err := json.Unmarshal(data, &ledger); err != nil {
		return nil, fmt.Errorf("parse apply ledger: %w", err)
	}
	if ledger.Schema != LiteLLMApplyLedgerSchema {
		return nil, fmt.Errorf("unsupported apply ledger schema %d (this apply consumes schema %d)",
			ledger.Schema, LiteLLMApplyLedgerSchema)
	}
	prevSeq := int64(0)
	for i := range ledger.Entries {
		entry := &ledger.Entries[i]
		if entry.Provider == "" || entry.Model == "" {
			return nil, fmt.Errorf("apply ledger entry %d: empty provider or model", i)
		}
		if entry.ContentSHA256 == "" {
			return nil, fmt.Errorf("apply ledger entry %d (%s/%s): missing content digest",
				i, entry.Provider, entry.Model)
		}
		if entry.Seq <= prevSeq {
			return nil, fmt.Errorf("apply ledger entry %d: sequence %d is out of order (previous %d)",
				i, entry.Seq, prevSeq)
		}
		prevSeq = entry.Seq
	}
	return &ledger, nil
}

// ledgerHasEntry reports whether the ledger already records this exact
// (provider, model, content digest) triple — the duplicate-entry guard that
// keeps a re-apply from appending identical rows.
func ledgerHasEntry(ledger *LiteLLMApplyLedger, applied LiteLLMAppliedEntry) bool {
	for i := range ledger.Entries {
		entry := &ledger.Entries[i]
		if entry.Provider == applied.Provider && entry.Model == applied.Model &&
			entry.ContentSHA256 == applied.ContentSHA256 {
			return true
		}
	}
	return false
}

// LiteLLMApply executes a reviewed dry-run report against the target
// catalog: verify gate → merge → backup → atomic write → ledger journal.
// It refuses before touching anything when the gate, the current catalog or
// the current ledger is unacceptable, refuses to clobber an existing backup
// set, and restores the pre-state loudly when any write fails midway.
func LiteLLMApply(rep *LiteLLMMigrationReport, targets LiteLLMApplyTargets) (*LiteLLMApplyResult, error) {
	if targets.CatalogPath == "" {
		return nil, fmt.Errorf("litellm apply: catalog path is empty")
	}
	if targets.LedgerPath == "" {
		targets.LedgerPath = LiteLLMApplyDefaultLedgerPath(targets.CatalogPath)
	}
	plan, err := verifyLiteLLMApplyPlan(rep)
	if err != nil {
		return nil, err
	}
	digest, err := litellmApplyReportDigest(rep)
	if err != nil {
		return nil, err
	}

	// Current state: catalog document and apply ledger. Both are untrusted
	// input — a file that does not parse is a loud refusal, never a repair.
	catalogBytes, catalogExisted, err := readLiteLLMTargetFile(targets.CatalogPath)
	if err != nil {
		return nil, fmt.Errorf("litellm apply: read catalog: %w", err)
	}
	var doc upstream.CatalogDocument
	if catalogExisted {
		doc, _, err = upstream.ParseCatalogDocument(bytes.NewReader(catalogBytes))
		if err != nil {
			return nil, fmt.Errorf("litellm apply: current catalog is invalid; nothing will be applied until it parses: %w", err)
		}
	} else {
		doc = freshLiteLLMCatalogDoc()
	}
	merged, applied, err := mergeLiteLLMPlan(&doc, plan)
	if err != nil {
		return nil, err
	}
	if err := upstream.ValidateCatalogDocument(merged); err != nil {
		return nil, fmt.Errorf("litellm apply: merged catalog document is invalid; nothing was written: %w", err)
	}
	mergedBytes, err := marshalLiteLLMJSON(merged)
	if err != nil {
		return nil, fmt.Errorf("litellm apply: render merged catalog: %w", err)
	}
	currentCanonical, err := marshalLiteLLMJSON(doc)
	if err != nil {
		return nil, fmt.Errorf("litellm apply: render current catalog: %w", err)
	}
	docChanged := !catalogExisted || !bytes.Equal(mergedBytes, currentCanonical)

	ledgerBytes, ledgerExisted, err := readLiteLLMTargetFile(targets.LedgerPath)
	if err != nil {
		return nil, fmt.Errorf("litellm apply: read ledger: %w", err)
	}
	var ledger LiteLLMApplyLedger
	if ledgerExisted {
		parsed, parseErr := parseLiteLLMApplyLedger(ledgerBytes)
		if parseErr != nil {
			return nil, fmt.Errorf("litellm apply: current apply ledger is invalid: %w", parseErr)
		}
		ledger = *parsed
	} else {
		ledger = LiteLLMApplyLedger{Schema: LiteLLMApplyLedgerSchema}
	}

	// New journal rows: every entry when the document changes, otherwise
	// exactly the entries the ledger has not recorded yet. The guard keeps
	// an identical re-apply from appending duplicate rows.
	nextSeq := int64(0)
	for i := range ledger.Entries {
		if ledger.Entries[i].Seq > nextSeq {
			nextSeq = ledger.Entries[i].Seq
		}
	}
	var newEntries []LiteLLMApplyLedgerEntry
	for i := range applied {
		res := applied[i]
		if docChanged || !ledgerHasEntry(&ledger, res) {
			nextSeq++
			newEntries = append(newEntries, LiteLLMApplyLedgerEntry{
				Seq:           nextSeq,
				Provider:      res.Provider,
				Model:         res.Model,
				Result:        res.Result,
				ContentSHA256: res.ContentSHA256,
				SourcePaths:   append([]string(nil), res.SourcePaths...),
			})
		}
	}
	ledgerChanged := len(newEntries) > 0 || (ledgerExisted && ledger.LastReportSHA256 != digest)

	if !docChanged && !ledgerChanged {
		// Idempotent no-op: byte-stable outputs, no writes at all.
		return &LiteLLMApplyResult{
			Targets:         targets,
			ReportSHA256:    digest,
			CatalogExisted:  catalogExisted,
			Changed:         false,
			Applied:         applied,
			CatalogSHA256:   sha256HexLiteLLM(catalogBytes),
			SecretsRedacted: len(rep.Secrets),
		}, nil
	}

	// Write path. A previous, unrolled-back backup set is a loud refusal:
	// the operator restores or removes it explicitly first.
	catalogBackup := LiteLLMApplyBackupPath(targets.CatalogPath)
	ledgerBackup := LiteLLMApplyBackupPath(targets.LedgerPath)
	for _, backup := range []string{catalogBackup, ledgerBackup} {
		exists, statErr := litellmFileExists(backup)
		if statErr != nil {
			return nil, fmt.Errorf("litellm apply: %w", statErr)
		}
		if exists {
			return nil, fmt.Errorf("litellm apply: backup %s already exists; a previous apply was not rolled back — restore or remove it explicitly before applying again", backup)
		}
	}

	pre := litellmPreState{
		catalog:        catalogBytes,
		catalogExisted: catalogExisted,
		ledger:         ledgerBytes,
		ledgerExisted:  ledgerExisted,
	}
	catalogBackupData := pre.catalog
	if !catalogExisted {
		catalogBackupData = []byte{}
	}
	ledgerBackupData := pre.ledger
	if !ledgerExisted {
		ledgerBackupData = []byte{}
	}
	if err := writeLiteLLMFileAtomic(catalogBackup, catalogBackupData); err != nil {
		return nil, fmt.Errorf("litellm apply: write catalog backup: %w (nothing was changed)", err)
	}
	if err := writeLiteLLMFileAtomic(ledgerBackup, ledgerBackupData); err != nil {
		_ = os.Remove(catalogBackup) // keep the attempt all-or-nothing
		return nil, fmt.Errorf("litellm apply: write ledger backup: %w (nothing was changed)", err)
	}

	// Commit phase: prepare both payloads completely, then rename. If the
	// second rename fails, the pre-state is restored from memory and the
	// error names exactly what happened — a partial apply is impossible.
	newLedger := ledger
	newLedger.Schema = LiteLLMApplyLedgerSchema
	newLedger.LastReportSHA256 = digest
	newLedger.SecretsRedacted = len(rep.Secrets)
	newLedger.Entries = append(append([]LiteLLMApplyLedgerEntry(nil), ledger.Entries...), newEntries...)
	ledgerOut, err := marshalLiteLLMJSON(newLedger)
	if err != nil {
		return nil, fmt.Errorf("litellm apply: render ledger: %w", err)
	}

	catalogPending, err := prepareLiteLLMWrite(targets.CatalogPath, mergedBytes)
	if err != nil {
		return nil, fmt.Errorf("litellm apply: %w (targets untouched, backups at %s and %s)", err, catalogBackup, ledgerBackup)
	}
	ledgerPending, err := prepareLiteLLMWrite(targets.LedgerPath, ledgerOut)
	if err != nil {
		catalogPending.discard()
		return nil, fmt.Errorf("litellm apply: %w (targets untouched, backups at %s and %s)", err, catalogBackup, ledgerBackup)
	}
	if err := catalogPending.commit(); err != nil {
		ledgerPending.discard()
		return nil, fmt.Errorf("litellm apply: %w (targets untouched, backups at %s and %s)", err, catalogBackup, ledgerBackup)
	}
	if err := ledgerPending.commit(); err != nil {
		// The catalog was already renamed into place; the ledger rename
		// failed, so the ledger target was never touched. Restore exactly
		// what was committed — nothing else — and report loudly.
		if restoreErr := restoreLiteLLMTarget(targets.CatalogPath, pre.catalog, pre.catalogExisted); restoreErr != nil {
			return nil, fmt.Errorf("litellm apply: ledger write failed (%v); catalog restore also failed (%v) — inspect %s, %s and backups %s, %s",
				err, restoreErr, targets.CatalogPath, targets.LedgerPath, catalogBackup, ledgerBackup)
		}
		return nil, fmt.Errorf("litellm apply: ledger write failed (%v); catalog was restored to its pre-apply state and the ledger was never written — remove %s and %s to clean up",
			err, catalogBackup, ledgerBackup)
	}

	return &LiteLLMApplyResult{
		Targets:         targets,
		ReportSHA256:    digest,
		CatalogExisted:  catalogExisted,
		Changed:         true,
		Applied:         applied,
		LedgerUpdated:   true,
		CatalogSHA256:   sha256HexLiteLLM(mergedBytes),
		LedgerSHA256:    sha256HexLiteLLM(ledgerOut),
		SecretsRedacted: len(rep.Secrets),
	}, nil
}

// LiteLLMRollback restores the byte-identical pre-apply state from the
// backup set: a zero-length backup means the target did not exist and is
// removed again, a non-empty backup is written back and verified by re-read.
// Backups are removed only after both targets are restored; any failure
// keeps them so the rollback can be retried.
func LiteLLMRollback(targets LiteLLMApplyTargets) (*LiteLLMRollbackResult, error) {
	if targets.CatalogPath == "" {
		return nil, fmt.Errorf("litellm rollback: catalog path is empty")
	}
	if targets.LedgerPath == "" {
		targets.LedgerPath = LiteLLMApplyDefaultLedgerPath(targets.CatalogPath)
	}
	catalogBackup := LiteLLMApplyBackupPath(targets.CatalogPath)
	ledgerBackup := LiteLLMApplyBackupPath(targets.LedgerPath)

	catalogBackupData, catalogBackupExists, err := readLiteLLMTargetFile(catalogBackup)
	if err != nil {
		return nil, fmt.Errorf("litellm rollback: read catalog backup: %w", err)
	}
	ledgerBackupData, ledgerBackupExists, err := readLiteLLMTargetFile(ledgerBackup)
	if err != nil {
		return nil, fmt.Errorf("litellm rollback: read ledger backup: %w", err)
	}
	if !catalogBackupExists && !ledgerBackupExists {
		return nil, fmt.Errorf("litellm rollback: no apply backup found (looked at %s and %s); nothing to roll back",
			catalogBackup, ledgerBackup)
	}
	if catalogBackupExists != ledgerBackupExists {
		return nil, fmt.Errorf("litellm rollback: inconsistent backup set (catalog backup present: %v, ledger backup present: %v); refusing to touch either file — inspect both manually",
			catalogBackupExists, ledgerBackupExists)
	}

	result := &LiteLLMRollbackResult{Targets: targets}

	// Catalog restore.
	if len(catalogBackupData) == 0 {
		if err := restoreLiteLLMTarget(targets.CatalogPath, nil, false); err != nil {
			return nil, fmt.Errorf("litellm rollback: remove created catalog: %w", err)
		}
		result.CatalogRemoved = true
	} else {
		if err := writeLiteLLMFileAtomic(targets.CatalogPath, catalogBackupData); err != nil {
			return nil, fmt.Errorf("litellm rollback: restore catalog: %w (backups kept)", err)
		}
		restored, _, readErr := readLiteLLMTargetFile(targets.CatalogPath)
		if readErr != nil || !bytes.Equal(restored, catalogBackupData) {
			return nil, fmt.Errorf("litellm rollback: catalog restore verification failed (read error: %v); backups kept at %s",
				readErr, catalogBackup)
		}
		result.CatalogRestored = true
		result.CatalogSHA256 = sha256HexLiteLLM(catalogBackupData)
	}

	// Ledger restore.
	if len(ledgerBackupData) == 0 {
		if err := restoreLiteLLMTarget(targets.LedgerPath, nil, false); err != nil {
			return nil, fmt.Errorf("litellm rollback: remove created ledger: %w (catalog already restored)", err)
		}
		result.LedgerRemoved = true
	} else {
		if err := writeLiteLLMFileAtomic(targets.LedgerPath, ledgerBackupData); err != nil {
			return nil, fmt.Errorf("litellm rollback: restore ledger: %w (catalog restored; backups kept)", err)
		}
		restored, _, readErr := readLiteLLMTargetFile(targets.LedgerPath)
		if readErr != nil || !bytes.Equal(restored, ledgerBackupData) {
			return nil, fmt.Errorf("litellm rollback: ledger restore verification failed (read error: %v); backups kept at %s",
				readErr, ledgerBackup)
		}
		result.LedgerRestored = true
		result.LedgerSHA256 = sha256HexLiteLLM(ledgerBackupData)
	}

	for _, backup := range []string{catalogBackup, ledgerBackup} {
		if err := os.Remove(backup); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("litellm rollback: state restored, but backup cleanup failed for %s: %w", backup, err)
		}
	}
	return result, nil
}

// BuildLiteLLMApplyPreview verifies the report through the apply gate and
// renders what the apply would do against the current catalog bytes
// (nil = catalog absent). It writes nothing, and it refuses exactly the
// reports LiteLLMApply refuses.
func BuildLiteLLMApplyPreview(rep *LiteLLMMigrationReport, targets LiteLLMApplyTargets, currentCatalog []byte) (*LiteLLMApplyPreview, error) {
	if targets.CatalogPath == "" {
		return nil, fmt.Errorf("litellm apply: catalog path is empty")
	}
	if targets.LedgerPath == "" {
		targets.LedgerPath = LiteLLMApplyDefaultLedgerPath(targets.CatalogPath)
	}
	plan, err := verifyLiteLLMApplyPlan(rep)
	if err != nil {
		return nil, err
	}
	digest, err := litellmApplyReportDigest(rep)
	if err != nil {
		return nil, err
	}
	var doc upstream.CatalogDocument
	exists := currentCatalog != nil
	if exists {
		var parseErr error
		doc, _, parseErr = upstream.ParseCatalogDocument(bytes.NewReader(currentCatalog))
		if parseErr != nil {
			return nil, fmt.Errorf("litellm apply: current catalog is invalid; nothing can be applied until it parses: %w", parseErr)
		}
	} else {
		doc = freshLiteLLMCatalogDoc()
	}
	_, applied, err := mergeLiteLLMPlan(&doc, plan)
	if err != nil {
		return nil, err
	}
	entries := make([]LiteLLMApplyPreviewEntry, 0, len(applied))
	for i := range applied {
		res := applied[i]
		entry := plan[i]
		entries = append(entries, LiteLLMApplyPreviewEntry{
			Action:        entry.Action,
			Provider:      entry.Provider,
			Model:         entry.Model,
			Outcome:       res.Result,
			Aliases:       entry.Aliases,
			AliasesAdded:  res.AliasesAdded,
			Capabilities:  entry.Capabilities,
			Limits:        entry.Limits,
			LimitsChanged: res.LimitsApplied,
			SourcePaths:   entry.SourcePaths,
		})
	}
	preview := &LiteLLMApplyPreview{
		Schema:          rep.Schema,
		ReportSHA256:    digest,
		Targets:         targets,
		CatalogExists:   exists,
		Entries:         entries,
		Scope:           rep.Scope,
		SecretsRedacted: rep.Summary.Secrets,
	}
	if len(rep.Secrets) > 0 {
		preview.SecretPaths = append([]LiteLLMSecret(nil), rep.Secrets...)
	}
	return preview, nil
}

// litellmShortDigest abbreviates a digest for text renderers.
func litellmShortDigest(digest string) string {
	if len(digest) > 12 {
		return digest[:12]
	}
	return digest
}

// RenderLiteLLMApplyPreview renders the operator-facing preview text. It is
// deterministic and renders report content only — secret locations appear as
// path and field name, never as values.
func RenderLiteLLMApplyPreview(p *LiteLLMApplyPreview) string {
	var b strings.Builder
	fmt.Fprintf(&b, "LiteLLM reviewed apply preview (report schema %d, report digest %s)\n",
		p.Schema, litellmShortDigest(p.ReportSHA256))
	state := "absent — created by the apply"
	if p.CatalogExists {
		state = "exists — merged by the apply"
	}
	fmt.Fprintf(&b, "target catalog: %s (%s)\n", p.Targets.CatalogPath, state)
	fmt.Fprintf(&b, "apply ledger: %s\n", p.Targets.LedgerPath)
	inserted, updated, unchanged := 0, 0, 0
	for _, entry := range p.Entries {
		switch entry.Outcome {
		case LiteLLMApplyInserted:
			inserted++
		case LiteLLMApplyUpdated:
			updated++
		case LiteLLMApplyUnchanged:
			unchanged++
		}
	}
	fmt.Fprintf(&b, "plan entries: %d → inserted: %d, updated: %d, unchanged: %d\n",
		len(p.Entries), inserted, updated, unchanged)
	fmt.Fprintf(&b, "transfers: %s\n", strings.Join(p.Scope.Migrated, "; "))
	for _, item := range p.Scope.NotMigrated {
		fmt.Fprintf(&b, "NOT migrated: %s — %s\n", item.Item, item.Reason)
	}
	if p.SecretsRedacted > 0 {
		fmt.Fprintf(&b, "secrets redacted in source: %d (paths and field names only — values are never included)\n", p.SecretsRedacted)
		for _, s := range p.SecretPaths {
			fmt.Fprintf(&b, "  - %s (%s)\n", s.Path, s.Field)
		}
	}
	if len(p.Entries) > 0 {
		b.WriteString("plan:\n")
		for i, entry := range p.Entries {
			fmt.Fprintf(&b, "  [%d] %s %s %s/%s (sources: %s)\n",
				i+1, entry.Outcome, entry.Action, entry.Provider, entry.Model, strings.Join(entry.SourcePaths, ", "))
			if len(entry.Aliases) > 0 {
				fmt.Fprintf(&b, "      aliases: %s\n", strings.Join(entry.Aliases, ", "))
			}
			if len(entry.AliasesAdded) > 0 {
				fmt.Fprintf(&b, "      aliases added: %s\n", strings.Join(entry.AliasesAdded, ", "))
			}
			if len(entry.Capabilities) > 0 {
				fmt.Fprintf(&b, "      capabilities: %s\n", strings.Join(sortedCapabilityKeys(entry.Capabilities), ", "))
			}
			if entry.Limits != nil {
				var lims []string
				if entry.Limits.MaxTPM > 0 {
					lims = append(lims, fmt.Sprintf("max_tpm=%d", entry.Limits.MaxTPM))
				}
				if entry.Limits.MaxRPM > 0 {
					lims = append(lims, fmt.Sprintf("max_rpm=%d", entry.Limits.MaxRPM))
				}
				if entry.Limits.MaxOutputTokens > 0 {
					lims = append(lims, fmt.Sprintf("max_output_tokens=%d", entry.Limits.MaxOutputTokens))
				}
				fmt.Fprintf(&b, "      limits: %s\n", strings.Join(lims, ", "))
			}
			if len(entry.LimitsChanged) > 0 {
				fmt.Fprintf(&b, "      limits changed: %s\n", strings.Join(entry.LimitsChanged, ", "))
			}
		}
	}
	b.WriteString("preview only — nothing was written; the reviewed apply step executes this plan\n")
	return b.String()
}

// LiteLLMApplyPreviewJSON renders the deterministic JSON form of a preview.
func LiteLLMApplyPreviewJSON(p *LiteLLMApplyPreview) (string, error) {
	body, err := marshalLiteLLMJSON(p)
	if err != nil {
		return "", fmt.Errorf("render litellm apply preview: %w", err)
	}
	return string(body), nil
}

// RenderLiteLLMApplyResult renders the post-apply operator summary. It
// carries digests, identities and counts only — no configuration values and
// no secret material.
func RenderLiteLLMApplyResult(r *LiteLLMApplyResult) string {
	var b strings.Builder
	state := "changed"
	if !r.Changed {
		state = "no-op (already applied)"
	}
	fmt.Fprintf(&b, "LiteLLM reviewed apply: %s (report digest %s)\n", state, litellmShortDigest(r.ReportSHA256))
	fmt.Fprintf(&b, "catalog: %s (sha256 %s)\n", r.Targets.CatalogPath, litellmShortDigest(r.CatalogSHA256))
	if r.Changed {
		fmt.Fprintf(&b, "ledger: %s (sha256 %s)\n", r.Targets.LedgerPath, litellmShortDigest(r.LedgerSHA256))
	}
	inserted, updated, unchanged := 0, 0, 0
	for _, entry := range r.Applied {
		switch entry.Result {
		case LiteLLMApplyInserted:
			inserted++
		case LiteLLMApplyUpdated:
			updated++
		case LiteLLMApplyUnchanged:
			unchanged++
		}
	}
	fmt.Fprintf(&b, "rows: %d → inserted: %d, updated: %d, unchanged: %d\n",
		len(r.Applied), inserted, updated, unchanged)
	for i, entry := range r.Applied {
		fmt.Fprintf(&b, "  [%d] %s %s/%s (sources: %s)\n",
			i+1, entry.Result, entry.Provider, entry.Model, strings.Join(entry.SourcePaths, ", "))
		if len(entry.AliasesAdded) > 0 {
			fmt.Fprintf(&b, "      aliases added: %s\n", strings.Join(entry.AliasesAdded, ", "))
		}
		if len(entry.CapabilitiesApplied) > 0 {
			fmt.Fprintf(&b, "      capabilities applied: %s\n", strings.Join(entry.CapabilitiesApplied, ", "))
		}
		if len(entry.LimitsApplied) > 0 {
			fmt.Fprintf(&b, "      limits applied: %s\n", strings.Join(entry.LimitsApplied, ", "))
		}
	}
	if r.SecretsRedacted > 0 {
		fmt.Fprintf(&b, "secrets redacted in source: %d (values never included anywhere in this flow)\n", r.SecretsRedacted)
	}
	return b.String()
}

// LiteLLMApplyResultJSON renders the deterministic JSON form of an apply
// result.
func LiteLLMApplyResultJSON(r *LiteLLMApplyResult) (string, error) {
	body, err := marshalLiteLLMJSON(r)
	if err != nil {
		return "", fmt.Errorf("render litellm apply result: %w", err)
	}
	return string(body), nil
}

// RenderLiteLLMRollbackResult renders the post-rollback operator summary.
func RenderLiteLLMRollbackResult(r *LiteLLMRollbackResult) string {
	var b strings.Builder
	b.WriteString("LiteLLM apply rollback complete\n")
	switch {
	case r.CatalogRestored:
		fmt.Fprintf(&b, "catalog: %s restored (sha256 %s)\n", r.Targets.CatalogPath, litellmShortDigest(r.CatalogSHA256))
	case r.CatalogRemoved:
		fmt.Fprintf(&b, "catalog: %s removed (pre-apply state: absent)\n", r.Targets.CatalogPath)
	default:
		fmt.Fprintf(&b, "catalog: %s untouched\n", r.Targets.CatalogPath)
	}
	switch {
	case r.LedgerRestored:
		fmt.Fprintf(&b, "ledger: %s restored (sha256 %s)\n", r.Targets.LedgerPath, litellmShortDigest(r.LedgerSHA256))
	case r.LedgerRemoved:
		fmt.Fprintf(&b, "ledger: %s removed (pre-apply state: absent)\n", r.Targets.LedgerPath)
	default:
		fmt.Fprintf(&b, "ledger: %s untouched\n", r.Targets.LedgerPath)
	}
	return b.String()
}

// LiteLLMRollbackResultJSON renders the deterministic JSON form of a
// rollback result.
func LiteLLMRollbackResultJSON(r *LiteLLMRollbackResult) (string, error) {
	body, err := marshalLiteLLMJSON(r)
	if err != nil {
		return "", fmt.Errorf("render litellm rollback result: %w", err)
	}
	return string(body), nil
}
