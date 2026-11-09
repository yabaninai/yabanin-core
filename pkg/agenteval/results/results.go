// Package results adapts versioned external agent-eval run results (the
// pkg/agenteval/contracts journal: manifest.json + episodes.jsonl) into
// router.QualitySnapshot
//
// D1: the quality source IS the versioned eval run — the snapshot identity is
// the manifest RunID; git commit and dataset digest ride along as provenance.
// D2: ONLY owner-approved runs surface. The approvals registry is a JSON file
// maintained by the owner flow (a accepted Recommendation becomes the
// approved snapshot); this adapter is READ-ONLY and never writes run data or
// approvals at runtime. No auto-apply exists anywhere in this package.
//
// N09-P03-T03: an approval may (and for every new routing change should)
// carry the owner decision provenance — the imported-eval basis, the evidence
// summary and the limitations the owner accepted it under, and optionally the
// pinned dataset digest. The imported results are third-party input and are
// never presented as an independent Yabanin verification; authorizing a
// routing CHANGE with that evidence is the owner gate in
// router.AuthorizeQualityRoutingChange. Here, a damaged or foreign-basis
// decision fails closed: no snapshot, no routing change.
//
// Test-set leak invariant: the produced QualitySnapshot is built exclusively
// from arm model slugs and aggregate outcome counts. Episode and case
// identifiers, prompts and verdict content have no representation in
// router.QualitySnapshot, so eval test-set rows cannot enter routing inputs.
package results

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/reireirei/yabanin/pkg/agenteval/contracts"
	"github.com/reireirei/yabanin/pkg/router"
)

// Approval pins an org's owner-approved eval run (D2). Recording an approval
// is an owner action taken out-of-band (Recommendation accepted → snapshot);
// the runtime only ever reads it. ApprovedBy and ApprovedAt are the manual
// approval's provenance: an approval that cannot show who approved it and
// when is damaged provenance and never surfaces a snapshot.
//
// Decision provenance (N09-P03-T03): Basis/EvidenceSummary/Limitations record
// the owner decision over the IMPORTED evaluation — what evidence it rests on
// and what limitations it carries; DatasetDigest optionally pins the imported
// dataset content hash. The fields are all-or-nothing: a half-recorded
// decision is damaged provenance. The only accepted basis is
// router.QualityBasisImportedEval — user feedback and any other signal never
// qualify and fail closed. Approvals recorded before this field existed
// (legacy, empty decision) keep serving the revision they already applied;
// they authorize no NEW change (that requires the router decision gate).
type Approval struct {
	RunID      string `json:"run_id"`
	ApprovedBy string `json:"approved_by"`
	ApprovedAt string `json:"approved_at"`
	Basis      string `json:"basis,omitempty"`
	// EvidenceSummary is the owner's explanation of the evidence the decision
	// rests on; Limitations states what that evidence does not cover.
	EvidenceSummary string `json:"evidence_summary,omitempty"`
	Limitations     string `json:"limitations,omitempty"`
	// DatasetDigest, when set, must equal the run's dataset content hash; a
	// mismatch is corrupted provenance and never surfaces a snapshot.
	DatasetDigest string `json:"dataset_digest,omitempty"`
}

// approvalsRegistry is the on-disk registry file layout. schema_version
// gates future evolution; unknown fields are rejected.
type approvalsRegistry struct {
	SchemaVersion int                 `json:"schema_version"`
	Approvals     map[string]Approval `json:"approvals"`
}

// Source is a read-only router.QualitySource over a directory of versioned
// agenteval run results plus the owner-approval registry file.
type Source struct {
	runsRoot      string
	approvalsPath string
}

// NewSource builds a Source. runsRoot holds one sub-directory per run id
// (manifest.json + episodes.jsonl, the journal layout of pkg/agenteval/
// contracts); approvalsPath points at the owner-managed approval registry.
func NewSource(runsRoot, approvalsPath string) *Source {
	return &Source{runsRoot: runsRoot, approvalsPath: approvalsPath}
}

// QualitySnapshot implements router.QualitySource for one org. Every
// unavailable input — no approval for the org, missing run directory,
// malformed manifest or episodes, run-id mismatch — returns an error wrapping
// router.ErrQualityUnavailable; callers fall back to the classifier path.
//
// Scores: per arm (model slug), the fraction of COMPLETED episodes with a
// success task outcome over all completed episodes with a verdict outcome.
// arms without completed episodes stay absent (insufficient data upstream).
// agenteval datasets carry no classifier-class split, so the snapshot fills
// only the Overall table; PerClass stays nil (router.QualitySnapshot falls
// back to Overall per class).
func (s *Source) QualitySnapshot(_ context.Context, orgID string) (*router.QualitySnapshot, error) {
	if orgID == "" {
		return nil, unavailable("empty org id")
	}
	ap, err := s.approvedRun(orgID)
	if err != nil {
		return nil, err
	}
	runDir := filepath.Join(s.runsRoot, ap.RunID)
	manifest, err := loadManifest(runDir)
	if err != nil {
		return nil, err
	}
	if manifest.RunID != ap.RunID {
		return nil, unavailable(fmt.Sprintf("manifest run id %q does not match approved run %q", manifest.RunID, ap.RunID))
	}
	if ap.DatasetDigest != "" {
		if d := datasetDigest(manifest); d != ap.DatasetDigest {
			return nil, unavailable(fmt.Sprintf("run dataset digest %q does not match approval-pinned digest %q — corrupted provenance", d, ap.DatasetDigest))
		}
	}
	createdAt, err := time.Parse(time.RFC3339, manifest.CreatedAt)
	if err != nil {
		return nil, unavailable(fmt.Sprintf("manifest created_at %q is not RFC3339", manifest.CreatedAt))
	}
	episodes, err := loadEpisodes(runDir)
	if err != nil {
		return nil, err
	}
	return &router.QualitySnapshot{
		Version:       manifest.RunID,
		Source:        "agenteval",
		CreatedAt:     createdAt,
		GitCommit:     manifest.GitCommit,
		DatasetDigest: datasetDigest(manifest),
		PolicyProfile: manifest.Profile,
		Overall:       buildOverall(manifest.Arms, episodes),
	}, nil
}

// approvedRun loads the registry and returns the org's approval. An org
// without a fully provenanced approval never sees quality routing (D2):
// unknown registry schema versions, approvals without a recorded approver or
// well-formed approval time, and damaged or foreign-basis decision records
// are damaged provenance and fail closed.
func (s *Source) approvedRun(orgID string) (Approval, error) {
	raw, err := os.ReadFile(s.approvalsPath)
	if err != nil {
		return Approval{}, unavailable(fmt.Sprintf("approvals registry %q unreadable: %v", s.approvalsPath, err))
	}
	var reg approvalsRegistry
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&reg); err != nil {
		return Approval{}, unavailable(fmt.Sprintf("approvals registry %q malformed: %v", s.approvalsPath, err))
	}
	if reg.SchemaVersion != contracts.SchemaVersion {
		return Approval{}, unavailable(fmt.Sprintf("approvals registry schema_version = %d, want %d", reg.SchemaVersion, contracts.SchemaVersion))
	}
	ap, ok := reg.Approvals[orgID]
	if !ok || ap.RunID == "" {
		return Approval{}, unavailable("no owner-approved quality snapshot for org " + orgID)
	}
	if ap.ApprovedBy == "" {
		return Approval{}, unavailable(fmt.Sprintf("approval for org %s pins run %q without a recorded approver", orgID, ap.RunID))
	}
	if _, err := time.Parse(time.RFC3339, ap.ApprovedAt); err != nil {
		return Approval{}, unavailable(fmt.Sprintf("approval for org %s has approved_at %q that is not RFC3339: %v", orgID, ap.ApprovedAt, err))
	}
	if err := validateDecisionProvenance(orgID, ap); err != nil {
		return Approval{}, err
	}
	return ap, nil
}

// validateDecisionProvenance enforces the imported-scores decision record on
// an approval (N09-P03-T03):
//   - legacy approvals (no decision fields) pass: absence is not damage, and
//     the runtime never changes a route by itself;
//   - a recorded decision must be COMPLETE (all-or-nothing): a basis with a
//     missing evidence summary or limitations is damaged provenance;
//   - the only accepted basis is the imported external evaluation
//     (router.QualityBasisImportedEval) — user feedback and any other signal
//     never steer routing and fail closed.
func validateDecisionProvenance(orgID string, ap Approval) error {
	if ap.Basis == "" && ap.EvidenceSummary == "" && ap.Limitations == "" {
		return nil
	}
	if ap.Basis != router.QualityBasisImportedEval {
		return unavailable(fmt.Sprintf("approval for org %s records decision basis %q, want %q — user feedback and other non-imported signals never steer routing", orgID, ap.Basis, router.QualityBasisImportedEval))
	}
	if ap.EvidenceSummary == "" || ap.Limitations == "" {
		return unavailable(fmt.Sprintf("approval for org %s records an incomplete decision: evidence summary and limitations are both required", orgID))
	}
	return nil
}

// loadManifest strictly decodes <dir>/manifest.json and checks the journal
func loadManifest(dir string) (contracts.Manifest, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json")) //nolint:gosec // G304: dir is the operator-configured run root joined with the registry-pinned run id, not request input
	if err != nil {
		return contracts.Manifest{}, unavailable(fmt.Sprintf("run manifest unreadable: %v", err))
	}
	var m contracts.Manifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return contracts.Manifest{}, unavailable(fmt.Sprintf("run manifest malformed: %v", err))
	}
	if m.SchemaVersion != contracts.SchemaVersion {
		return contracts.Manifest{}, unavailable(fmt.Sprintf("run manifest schema_version = %d, want %d", m.SchemaVersion, contracts.SchemaVersion))
	}
	if m.RunID == "" {
		return contracts.Manifest{}, unavailable("run manifest has empty run_id")
	}
	if m.Profile == "" {
		// T02 review addendum, finding 2 (N09-P03-T03 follow-up): the schema
		// requires a non-empty profile; a hand-crafted empty profile would
		// bypass the cross-profile hold (absence semantics) — damaged
		// provenance, fail closed.
		return contracts.Manifest{}, unavailable("run manifest has empty profile — evaluation policy provenance incomplete")
	}
	return m, nil
}

// loadEpisodes strictly decodes <dir>/episodes.jsonl. Only aggregate outcome
// fields are consumed downstream; case/episode identifiers are dropped here
// (test-set leak invariant).
func loadEpisodes(dir string) ([]contracts.EpisodeRecord, error) {
	f, err := os.Open(filepath.Join(dir, "episodes.jsonl")) //nolint:gosec // G304: operator-configured run root, not request input
	if err != nil {
		return nil, unavailable(fmt.Sprintf("episodes journal unreadable: %v", err))
	}
	defer f.Close()
	var out []contracts.EpisodeRecord
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec contracts.EpisodeRecord
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rec); err != nil {
			return nil, unavailable(fmt.Sprintf("episodes journal malformed: %v", err))
		}
		out = append(out, rec)
	}
	if err := sc.Err(); err != nil {
		return nil, unavailable(fmt.Sprintf("episodes journal unreadable: %v", err))
	}
	return out, nil
}

// buildOverall aggregates completed episodes per arm into per-model quality
// scores. Only arm → model slug and the outcome fraction survive; nothing
// episode- or case-specific is retained.
func buildOverall(arms []contracts.Arm, episodes []contracts.EpisodeRecord) map[string]router.QualityScore {
	slugs := make(map[string]string, len(arms))
	for _, a := range arms {
		if a.ID != "" && a.ModelSlug != "" {
			slugs[a.ID] = a.ModelSlug
		}
	}
	type agg struct {
		samples   int
		successes int
	}
	byArm := make(map[string]*agg)
	for _, ep := range episodes {
		if ep.ExecutionStatus != contracts.StatusCompleted || ep.TaskOutcome == nil {
			continue
		}
		a := byArm[ep.Arm]
		if a == nil {
			a = &agg{}
			byArm[ep.Arm] = a
		}
		a.samples++
		if *ep.TaskOutcome == "success" {
			a.successes++
		}
	}
	overall := make(map[string]router.QualityScore, len(byArm))
	for armID, a := range byArm {
		slug, ok := slugs[armID]
		if !ok || a.samples == 0 {
			continue
		}
		overall[slug] = router.QualityScore{
			Score:   float64(a.successes) / float64(a.samples),
			Samples: a.samples,
		}
	}
	return overall
}

// datasetDigest returns the first dataset SHA-256 as the provenance digest.
func datasetDigest(m contracts.Manifest) string {
	if len(m.Dataset.SHA256) == 0 {
		return ""
	}
	return m.Dataset.SHA256[0]
}

// unavailable wraps a cause into the router's ErrQualityUnavailable contract.
func unavailable(reason string) error {
	return fmt.Errorf("%w: %s", router.ErrQualityUnavailable, reason)
}
