package results

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/agenteval/contracts"
	"github.com/reireirei/yabanin/pkg/router"
)

const (
	// leakCanary marks every piece of episode/case-specific data in the
	// fixture; the produced snapshot must never contain any of it.
	leakCanary = "LEAK_CANARY"
	testRunID  = "9b6f1c2e-3a44-4f55-8a21-7c9d0e1b2a33"
)

// writeRunDir materializes a versioned run directory (manifest.json +
// episodes.jsonl). Arms map arm id → model slug; outcomes is a list of
// (arm, status, outcome) tuples materialized as episodes.
func writeRunDir(t *testing.T, root, runID, createdAt string, arms map[string]string, outcomes [][3]string) string {
	t.Helper()
	dir := filepath.Join(root, runID)
	require.NoError(t, os.MkdirAll(dir, 0o750))

	armJSON := make([]string, 0, len(arms))
	for id, slug := range arms {
		armJSON = append(armJSON, fmt.Sprintf(`{"id":%q,"model_slug":%q,"endpoint_url":"https://up.example/v1","provider_pinning":"pinned","headers_allowed":["authorization"]}`, id, slug))
	}
	manifest := fmt.Sprintf(`{"schema_version":1,"run_id":%q,"created_at":%q,"profile":"QUALITY_40","git_commit":"abc123def456","dataset":{"catalog_id":"%s-catalog","selection_file":"sel.json","sha256":["digest-%s"],"split":"eval"},"arms":[%s],"caps":{"max_llm_attempts":6,"max_tool_calls":12,"max_wall_seconds":300,"episode_cap_usd":0.25,"max_child_agents":0,"max_concurrent_llm":2},"price_snapshot":{"source":"console","as_of":"2026-10-01","currency":"USD","entries":[]},"spend":{"authorized":true,"limit_usd":10,"approved_by":"owner","approved_at":"2026-10-15T00:00:00Z"},"integrity":{}}`,
		runID, createdAt, leakCanary, runID[:8], strings.Join(armJSON, ","))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o600))

	var sb strings.Builder
	for i, o := range outcomes {
		arm, status, outcome := o[0], o[1], o[2]
		outcomeJSON := "null"
		if outcome != "" {
			outcomeJSON = fmt.Sprintf("%q", outcome)
		}
		fmt.Fprintf(&sb, `{"episode_id":%q,"root_id":%q,"case_id":%q,"arm":%q,"repetition":1,"execution_status":%q,"stop_reason":"natural","task_outcome":%s,"safety_outcome":"clean","protocol_outcome":"ok","usage":{"llm_calls":2,"tool_calls":1,"tokens_in":100,"tokens_out":30,"reasoning_tokens":null,"cache_read":0},"cost":{"estimated_usd":0.01,"observed_usd":null,"uncertain_usd":null,"coverage":0.5},"verdict_ref":%q,"artifacts":[]}`,
			fmt.Sprintf("ep-%s-%d", leakCanary, i), runID, fmt.Sprintf("case-%s-%d", leakCanary, i), arm, status, outcomeJSON, fmt.Sprintf("v-%s-%d", leakCanary, i))
		fmt.Fprintln(&sb)
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "episodes.jsonl"), []byte(sb.String()), 0o600))
	return dir
}

func writeApprovals(t *testing.T, path string, approvals map[string]Approval) {
	t.Helper()
	reg := map[string]any{"schema_version": 1}
	if approvals != nil {
		entries := map[string]any{}
		for org, ap := range approvals {
			entries[org] = ap
		}
		reg["approvals"] = entries
	}
	raw, err := json.Marshal(reg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0o600))
}

// fixtureSource builds runs root + approvals with org-1 approved for testRunID.
func fixtureSource(t *testing.T, outcomes [][3]string) *Source {
	t.Helper()
	root := t.TempDir()
	writeRunDir(t, root, testRunID, time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		map[string]string{"arm-a": "model-a", "arm-b": "model-b"}, outcomes)
	writeApprovals(t, filepath.Join(root, "approvals.json"), map[string]Approval{
		"org-1": {RunID: testRunID, ApprovedBy: "owner", ApprovedAt: "2026-10-16T00:00:00Z"},
	})
	return NewSource(root, filepath.Join(root, "approvals.json"))
}

func TestSource_QualitySnapshot_BuildsVersionedAggregate(t *testing.T) {
	src := fixtureSource(t, [][3]string{
		{"arm-a", "completed", "success"},
		{"arm-a", "completed", "success"},
		{"arm-a", "completed", "fail"},
		{"arm-b", "completed", "success"},
		{"arm-b", "failed", "success"}, // not completed → excluded
		{"arm-a", "completed", ""},     // no outcome → excluded
	})

	snap, err := src.QualitySnapshot(context.Background(), "org-1")
	require.NoError(t, err)
	require.NotNil(t, snap)

	assert.Equal(t, testRunID, snap.Version, "D1: snapshot identity is the versioned run id")
	assert.Equal(t, "agenteval", snap.Source)
	assert.Equal(t, "abc123def456", snap.GitCommit)
	assert.Equal(t, "digest-"+testRunID[:8], snap.DatasetDigest)
	assert.Equal(t, "QUALITY_40", snap.PolicyProfile, "the eval policy profile rides along as provenance")
	assert.WithinDuration(t, time.Now().Add(-time.Hour), snap.CreatedAt, time.Minute)
	assert.True(t, snap.Fresh(24*time.Hour, time.Now()))

	require.Contains(t, snap.Overall, "model-a")
	require.Contains(t, snap.Overall, "model-b")
	assert.InDelta(t, 2.0/3.0, snap.Overall["model-a"].Score, 1e-9)
	assert.Equal(t, 3, snap.Overall["model-a"].Samples)
	assert.InDelta(t, 1.0, snap.Overall["model-b"].Score, 1e-9)
	assert.Equal(t, 1, snap.Overall["model-b"].Samples)
	assert.Nil(t, snap.PerClass, "agenteval has no classifier-class split")
}

func TestSource_UnapprovedOrg_Unavailable(t *testing.T) {
	src := fixtureSource(t, [][3]string{{"arm-a", "completed", "success"}})

	snap, err := src.QualitySnapshot(context.Background(), "org-2")
	require.Error(t, err)
	assert.Nil(t, snap)
	require.ErrorIs(t, err, router.ErrQualityUnavailable, "org without owner approval never gets quality data (D2)")

	_, err = src.QualitySnapshot(context.Background(), "")
	require.Error(t, err)
	assert.ErrorIs(t, err, router.ErrQualityUnavailable)
}

func TestSource_MissingOrMalformedInputs_Unavailable(t *testing.T) {
	root := t.TempDir()
	writeRunDir(t, root, testRunID, time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		map[string]string{"arm-a": "model-a"}, [][3]string{{"arm-a", "completed", "success"}})

	t.Run("missing approvals file", func(t *testing.T) {
		src := NewSource(root, filepath.Join(root, "nope.json"))
		_, err := src.QualitySnapshot(context.Background(), "org-1")
		require.Error(t, err)
		assert.ErrorIs(t, err, router.ErrQualityUnavailable)
	})
	t.Run("approved run dir missing", func(t *testing.T) {
		ap := filepath.Join(root, "ap.json")
		writeApprovals(t, ap, map[string]Approval{"org-1": {RunID: "00000000-0000-0000-0000-000000000000", ApprovedBy: "owner", ApprovedAt: "2026-10-16T00:00:00Z"}})
		src := NewSource(root, ap)
		_, err := src.QualitySnapshot(context.Background(), "org-1")
		require.Error(t, err)
		assert.ErrorIs(t, err, router.ErrQualityUnavailable)
	})
	t.Run("manifest run id mismatch", func(t *testing.T) {
		const dirID = "11111111-2222-3333-4444-555555555555"
		const otherID = "99999999-8888-7777-6666-555555555555"
		runDir := writeRunDir(t, root, dirID, time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
			map[string]string{"arm-a": "model-a"}, [][3]string{{"arm-a", "completed", "success"}})
		// Forge a manifest whose run_id disagrees with the directory the
		// approval pins: the adapter must refuse the snapshot.
		mpath := filepath.Join(runDir, "manifest.json")
		raw, err := os.ReadFile(mpath) //nolint:gosec // G304: test fixture path under t.TempDir
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(mpath, bytes.Replace(raw, []byte(dirID), []byte(otherID), 1), 0o600)) //nolint:gosec // G703: mpath is a test fixture path under t.TempDir, not request input

		ap := filepath.Join(root, "ap.json")
		writeApprovals(t, ap, map[string]Approval{"org-1": {RunID: dirID, ApprovedBy: "owner", ApprovedAt: "2026-10-16T00:00:00Z"}})
		src := NewSource(root, ap)
		_, err = src.QualitySnapshot(context.Background(), "org-1")
		require.Error(t, err)
		assert.ErrorIs(t, err, router.ErrQualityUnavailable, "approval must pin the run identity")
	})
	t.Run("bad created_at", func(t *testing.T) {
		bad := writeRunDir(t, root, "11111111-2222-3333-4444-555555555555", "not-a-date",
			map[string]string{"arm-a": "model-a"}, [][3]string{{"arm-a", "completed", "success"}})
		ap := filepath.Join(bad, "ap.json")
		writeApprovals(t, ap, map[string]Approval{"org-1": {RunID: "11111111-2222-3333-4444-555555555555", ApprovedBy: "owner", ApprovedAt: "2026-10-16T00:00:00Z"}})
		src := NewSource(bad, ap)
		_, err := src.QualitySnapshot(context.Background(), "org-1")
		require.Error(t, err)
		assert.ErrorIs(t, err, router.ErrQualityUnavailable)
	})
}

// rewriteJSON unmarshals raw into a generic map, mutates it and returns the
// re-marshaled form (keeps every other field byte-compatible with the fixture).
func rewriteJSON(t *testing.T, raw []byte, mutate func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	mutate(m)
	out, err := json.Marshal(m)
	require.NoError(t, err)
	return out
}

// forged input to the versioned quality source must fail CLOSED — a strict
// decode refusal wrapped in router.ErrQualityUnavailable, never a partial or
// guessed snapshot. partial/unknown states are not success.
func TestSource_CorruptRunInputs_Unavailable(t *testing.T) {
	root := t.TempDir()
	runID := "22222222-3333-4444-5555-666666666666"
	runDir := writeRunDir(t, root, runID, time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		map[string]string{"arm-a": "model-a"}, [][3]string{{"arm-a", "completed", "success"}})
	ap := filepath.Join(root, "approvals.json")
	writeApprovals(t, ap, map[string]Approval{"org-1": {RunID: runID, ApprovedBy: "owner", ApprovedAt: "2026-10-16T00:00:00Z"}})
	manifestPath := filepath.Join(runDir, "manifest.json")
	episodesPath := filepath.Join(runDir, "episodes.jsonl")
	goodManifest := readFile(t, manifestPath)
	goodEpisodes := readFile(t, episodesPath)

	restore := func(t *testing.T) {
		t.Helper()
		require.NoError(t, os.WriteFile(manifestPath, goodManifest, 0o600))
		require.NoError(t, os.WriteFile(episodesPath, goodEpisodes, 0o600))
	}

	assertUnavailable := func(t *testing.T) {
		t.Helper()
		src := NewSource(root, ap)
		snap, err := src.QualitySnapshot(context.Background(), "org-1")
		require.Error(t, err)
		assert.Nil(t, snap, "a corrupt input must never yield a snapshot")
		assert.ErrorIs(t, err, router.ErrQualityUnavailable, "strict decode refusals must surface as quality-unavailable, not as a different error class")
	}

	t.Run("manifest truncated json", func(t *testing.T) {
		defer restore(t)
		require.NoError(t, os.WriteFile(manifestPath, []byte(`{"schema_version":1,"run_id":`), 0o600))
		assertUnavailable(t)
	})
	t.Run("manifest unknown field refused", func(t *testing.T) {
		defer restore(t)
		raw := rewriteJSON(t, goodManifest, func(m map[string]any) { m["unexpected_field"] = 1 })
		require.NoError(t, os.WriteFile(manifestPath, raw, 0o600))
		assertUnavailable(t)
	})
	t.Run("manifest schema_version stale", func(t *testing.T) {
		defer restore(t)
		raw := bytes.Replace(goodManifest, []byte(`"schema_version":1`), []byte(`"schema_version":2`), 1)
		require.NotEqual(t, goodManifest, raw, "fixture must actually carry schema_version 1")
		require.NoError(t, os.WriteFile(manifestPath, raw, 0o600))
		assertUnavailable(t)
	})
	t.Run("episodes malformed line", func(t *testing.T) {
		defer restore(t)
		require.NoError(t, os.WriteFile(episodesPath, append(goodEpisodes, []byte("{\"broken\":\n")...), 0o600))
		assertUnavailable(t)
	})
	t.Run("episodes unknown field refused", func(t *testing.T) {
		defer restore(t)
		var rec map[string]any
		require.NoError(t, json.Unmarshal(bytes.TrimSpace(goodEpisodes), &rec))
		rec["leak_field"] = "x"
		raw, err := json.Marshal(rec)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(episodesPath, append(raw, '\n'), 0o600))
		assertUnavailable(t)
	})
	t.Run("approvals registry malformed json", func(t *testing.T) {
		badAP := filepath.Join(root, "bad-approvals.json")
		require.NoError(t, os.WriteFile(badAP, []byte("not-json"), 0o600))
		src := NewSource(root, badAP)
		_, err := src.QualitySnapshot(context.Background(), "org-1")
		require.Error(t, err)
		assert.ErrorIs(t, err, router.ErrQualityUnavailable)
	})
	t.Run("approvals registry unknown field refused", func(t *testing.T) {
		badAP := filepath.Join(root, "unknown-approvals.json")
		require.NoError(t, os.WriteFile(badAP, []byte(`{"schema_version":1,"extra":true}`), 0o600))
		src := NewSource(root, badAP)
		_, err := src.QualitySnapshot(context.Background(), "org-1")
		require.Error(t, err)
		assert.ErrorIs(t, err, router.ErrQualityUnavailable)
	})
	t.Run("approval entry with empty run id", func(t *testing.T) {
		emptyAP := filepath.Join(root, "empty-approvals.json")
		writeApprovals(t, emptyAP, map[string]Approval{"org-1": {RunID: "", ApprovedBy: "owner", ApprovedAt: "2026-10-16T00:00:00Z"}})
		src := NewSource(root, emptyAP)
		_, err := src.QualitySnapshot(context.Background(), "org-1")
		require.Error(t, err)
		assert.ErrorIs(t, err, router.ErrQualityUnavailable, "an approval without a pinned run id approves nothing")
	})
	t.Run("approvals registry unknown schema_version", func(t *testing.T) {
		badAP := filepath.Join(root, "future-approvals.json")
		require.NoError(t, os.WriteFile(badAP, []byte(`{"schema_version":99,"approvals":{"org-1":{"run_id":`+fmt.Sprintf("%q", runID)+`,"approved_by":"owner","approved_at":"2026-10-16T00:00:00Z"}}}`), 0o600))
		src := NewSource(root, badAP)
		_, err := src.QualitySnapshot(context.Background(), "org-1")
		require.Error(t, err)
		assert.ErrorIs(t, err, router.ErrQualityUnavailable, "an unknown registry schema version is damaged provenance, never routing input")
	})
	t.Run("approval without recorded approver", func(t *testing.T) {
		noApproverAP := filepath.Join(root, "no-approver-approvals.json")
		writeApprovals(t, noApproverAP, map[string]Approval{"org-1": {RunID: runID, ApprovedAt: "2026-10-16T00:00:00Z"}})
		src := NewSource(root, noApproverAP)
		_, err := src.QualitySnapshot(context.Background(), "org-1")
		require.Error(t, err)
		assert.ErrorIs(t, err, router.ErrQualityUnavailable, "a run pin without a recorded approver is not a manual approval")
	})
	t.Run("approval with malformed approved_at", func(t *testing.T) {
		badTimeAP := filepath.Join(root, "bad-time-approvals.json")
		writeApprovals(t, badTimeAP, map[string]Approval{"org-1": {RunID: runID, ApprovedBy: "owner", ApprovedAt: "yesterday-ish"}})
		src := NewSource(root, badTimeAP)
		_, err := src.QualitySnapshot(context.Background(), "org-1")
		require.Error(t, err)
		assert.ErrorIs(t, err, router.ErrQualityUnavailable, "an approval time that cannot be parsed is damaged provenance")
	})
}

// readFile is a test-local file read (paths are fixtures under t.TempDir).
func readFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // G304: fixture path under t.TempDir
	require.NoError(t, err)
	return raw
}

// operation against an unusable source, sequentially and concurrently, keeps
// returning the same diagnosable quality-unavailable failure — no state is
// built up, no partial snapshot ever escapes, no panic under load.
func TestSource_RepeatAndParallel_FailureStable(t *testing.T) {
	root := t.TempDir()
	ap := filepath.Join(root, "approvals.json")
	writeApprovals(t, ap, map[string]Approval{"org-1": {RunID: "33333333-4444-5555-6666-777777777777", ApprovedBy: "owner", ApprovedAt: "2026-10-16T00:00:00Z"}})
	src := NewSource(root, ap) // approved run dir does not exist

	for i := 0; i < 10; i++ {
		snap, err := src.QualitySnapshot(context.Background(), "org-1")
		require.Error(t, err, "iteration %d", i)
		assert.Nil(t, snap)
		require.ErrorIs(t, err, router.ErrQualityUnavailable)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := src.QualitySnapshot(context.Background(), "org-1")
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.Error(t, err)
		require.ErrorIs(t, err, router.ErrQualityUnavailable)
	}
}

// per-arm (completed, successes) outcome counts (same wire form as the owner
// flow journal).
func writeVersionedRun(t *testing.T, root, runID string, arms map[string]string, outcomes map[string][2]int) string {
	t.Helper()
	dir := filepath.Join(root, runID)
	require.NoError(t, os.MkdirAll(dir, 0o750))
	armList := make([]contracts.Arm, 0, len(arms))
	for id, slug := range arms {
		armList = append(armList, contracts.Arm{ID: id, ModelSlug: slug, EndpointURL: "https://up.example/v1", ProviderPinning: "pinned", HeadersAllowed: []string{"authorization"}})
	}
	capUSD := 0.25
	m := contracts.Manifest{
		SchemaVersion: contracts.SchemaVersion,
		RunID:         runID,
		CreatedAt:     time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		Profile:       "QUALITY_40",
		GitCommit:     "fb9889df0000",
		Dataset:       contracts.DatasetRef{CatalogID: "catalog", SelectionFile: "sel.json", SHA256: []string{"sha256-" + runID}, Split: "eval"},
		Arms:          armList,
		Caps:          contracts.Caps{MaxLLMAttempts: 6, EpisodeCapUSD: &capUSD},
		Integrity:     map[string]string{},
	}
	raw, err := json.Marshal(m)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o600))

	var sb strings.Builder
	enc := json.NewEncoder(&sb)
	for _, arm := range armList {
		completed, successes := outcomes[arm.ID][0], outcomes[arm.ID][1]
		for i := 0; i < completed; i++ {
			outcome := "fail"
			if i < successes {
				outcome = "success"
			}
			stop := "natural"
			require.NoError(t, enc.Encode(contracts.EpisodeRecord{
				EpisodeID: fmt.Sprintf("%s-%s-%03d", runID[:8], arm.ID, i),
				RootID:    runID, CaseID: fmt.Sprintf("case-%s-%03d", runID[:8], i),
				Arm: arm.ID, Repetition: 1, ExecutionStatus: contracts.StatusCompleted,
				StopReason: &stop, TaskOutcome: &outcome, SafetyOutcome: "clean", ProtocolOutcome: "ok",
			}))
		}
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "episodes.jsonl"), []byte(sb.String()), 0o600))
	return dir
}

// evidence computed over snapshots the REAL adapter built from two versioned
// run directories — vN (run-1) and vN+1 (run-2, favorite regressed; run-3,
// favorite improved). The evidence function output shape is pinned and the
// JSON is logged for the integration record.
func TestOverlapEvidence_FromRealRunDirs(t *testing.T) {
	const (
		runV1 = "aaaaaaaa-0000-4000-8000-000000000001"
		runV2 = "aaaaaaaa-0000-4000-8000-000000000002"
		runV3 = "aaaaaaaa-0000-4000-8000-000000000003"
	)
	root := t.TempDir()
	arms := map[string]string{"arm-a": "qual-a", "arm-b": "qual-b"}
	writeVersionedRun(t, root, runV1, arms, map[string][2]int{"arm-a": {30, 18}, "arm-b": {30, 27}}) // qual-a .60, qual-b .90
	writeVersionedRun(t, root, runV2, arms, map[string][2]int{"arm-a": {30, 21}, "arm-b": {30, 24}}) // qual-a .70, qual-b .80→ favorite regressed .90→.80
	writeVersionedRun(t, root, runV3, arms, map[string][2]int{"arm-a": {30, 21}, "arm-b": {30, 28}}) // qual-b .93 → improved

	snapshotFor := func(runID string) *router.QualitySnapshot {
		ap := filepath.Join(root, "ap-"+runID+".json")
		writeApprovals(t, ap, map[string]Approval{"org-1": {RunID: runID, ApprovedBy: "owner", ApprovedAt: "2026-10-16T00:00:00Z"}})
		snap, err := NewSource(root, ap).QualitySnapshot(context.Background(), "org-1")
		require.NoError(t, err)
		return snap
	}
	prev := snapshotFor(runV1)
	next := snapshotFor(runV2)
	improved := snapshotFor(runV3)

	hold := router.CompareQualitySnapshots(prev, next, 0)
	assert.False(t, hold.ShiftAllowed, "regressed favorite (0.90 → 0.80) must hold traffic")
	assert.True(t, hold.Regression)
	assert.Equal(t, "favorite_regressed", hold.Reason)
	assert.Equal(t, runV1, hold.PreviousVersion)
	assert.Equal(t, runV2, hold.NextVersion)
	assert.Equal(t, "qual-b", hold.BestNextModel)
	require.Len(t, hold.Compared, 2, "both models appear in the overlap evidence")
	assert.InDelta(t, -0.1, hold.Compared[1].Delta, 1e-9)

	allow := router.CompareQualitySnapshots(prev, improved, 0)
	assert.True(t, allow.ShiftAllowed, "improved favorite with baseline overlap may shift")
	assert.False(t, allow.Regression)
	assert.Equal(t, "overlap_ok", allow.Reason)

	holdJSON, err := json.Marshal(hold)
	require.NoError(t, err)
	allowJSON, err := json.Marshal(allow)
	require.NoError(t, err)
	t.Logf("overlap evidence (hold): %s", holdJSON)
	t.Logf("overlap evidence (allow): %s", allowJSON)
}

func TestSource_NoTestsetLeak_ByConstruction(t *testing.T) {
	src := fixtureSource(t, [][3]string{
		{"arm-a", "completed", "success"},
		{"arm-b", "completed", "fail"},
	})

	snap, err := src.QualitySnapshot(context.Background(), "org-1")
	require.NoError(t, err)

	raw, err := json.Marshal(snap)
	require.NoError(t, err)

	// Nothing episode/case-specific may survive into the routing input.
	assert.NotContains(t, string(raw), leakCanary, "eval test-set rows leaked into the quality snapshot")
	assert.NotContains(t, string(raw), leakCanary+"-catalog", "dataset catalog identity is not routing input")

	// Whitelist pin: the snapshot wire form can ONLY carry aggregate,
	// versioned fields — there is no field able to hold an eval row.
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	allowed := map[string]bool{
		"version": true, "source": true, "created_at": true,
		"git_commit": true, "dataset_digest": true, "policy_profile": true,
		"overall": true, "per_class": true,
	}
	for k := range m {
		assert.True(t, allowed[k], "unexpected quality-snapshot field %q", k)
	}
	overall, ok := m["overall"].(map[string]any)
	require.True(t, ok)
	for model, v := range overall {
		assert.NotContains(t, model, leakCanary)
		score, ok := v.(map[string]any)
		require.True(t, ok)
		for sk := range score {
			assert.Contains(t, []string{"score", "samples"}, sk)
		}
	}
}

func TestSource_ReadOnly_NeverWrites(t *testing.T) {
	root := t.TempDir()
	writeRunDir(t, root, testRunID, time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		map[string]string{"arm-a": "model-a"}, [][3]string{{"arm-a", "completed", "success"}})
	ap := filepath.Join(root, "approvals.json")
	writeApprovals(t, ap, map[string]Approval{"org-1": {RunID: testRunID, ApprovedBy: "owner", ApprovedAt: "2026-10-16T00:00:00Z"}})

	before := dirSnapshot(t, root)
	src := NewSource(root, ap)
	for _, org := range []string{"org-1", "org-2", "org-1"} {
		_, _ = src.QualitySnapshot(context.Background(), org)
	}
	assert.Equal(t, before, dirSnapshot(t, root), "the read adapter must never mutate run data or approvals (no runtime writes)")
}

// dirSnapshot hashes every file path+content under root for a write check.
func dirSnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	require.NoError(t, filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path) //nolint:gosec // G304: test fixture path under t.TempDir
		if err != nil {
			return err
		}
		out[path] = string(raw)
		return nil
	}))
	return out
}

// decisionApproval returns org-1's approval carrying a COMPLETE imported-eval
// decision record (N09-P03-T03): basis, evidence summary, limitations and the
// pinned dataset digest (writeRunDir stamps sha256 "digest-<run-id prefix>").
func decisionApproval(runID string) Approval {
	return Approval{
		RunID:      runID,
		ApprovedBy: "owner",
		ApprovedAt: "2026-10-16T00:00:00Z",
		Basis:      router.QualityBasisImportedEval,
		EvidenceSummary: "imported run: the favorite improved on the previous revision's model overlap " +
			"(owner-reviewed aggregate outcomes)",
		Limitations: "external import — not an independent Yabanin verification; 30 completed episodes " +
			"per arm; eval set and policy profile fixed at import time",
		DatasetDigest: "digest-" + runID[:8],
	}
}

// A complete decision record surfaces the snapshot exactly like a legacy pin:
// the route stays bound to the imported revision (run id) — the decision adds
// the evidence/limitations explanation, it does not change the binding.
func TestSource_DecisionApproval_SurfacesImportedRevision(t *testing.T) {
	root := t.TempDir()
	writeRunDir(t, root, testRunID, time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		map[string]string{"arm-a": "model-a"}, [][3]string{{"arm-a", "completed", "success"}})
	ap := filepath.Join(root, "approvals.json")
	writeApprovals(t, ap, map[string]Approval{"org-1": decisionApproval(testRunID)})

	snap, err := NewSource(root, ap).QualitySnapshot(context.Background(), "org-1")
	require.NoError(t, err)
	require.NotNil(t, snap)
	assert.Equal(t, testRunID, snap.Version, "the route is bound to the imported revision")
	assert.Equal(t, "digest-"+testRunID[:8], snap.DatasetDigest, "pinned digest matches the imported dataset")
}

// Damaged or foreign-basis decision provenance never surfaces a snapshot:
// production routing cannot change on corrupted provenance, an incomplete
// decision record or user feedback (card negative criteria) — the org fails
// closed to the unchanged classifier path with a diagnosable reason.
func TestSource_DecisionApproval_Damaged_Unavailable(t *testing.T) {
	assertUnavailable := func(t *testing.T, ap Approval) {
		t.Helper()
		root := t.TempDir()
		writeRunDir(t, root, testRunID, time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
			map[string]string{"arm-a": "model-a"}, [][3]string{{"arm-a", "completed", "success"}})
		apPath := filepath.Join(root, "approvals.json")
		writeApprovals(t, apPath, map[string]Approval{"org-1": ap})

		snap, err := NewSource(root, apPath).QualitySnapshot(context.Background(), "org-1")
		require.Error(t, err)
		assert.Nil(t, snap, "damaged decision provenance must never yield a snapshot")
		require.ErrorIs(t, err, router.ErrQualityUnavailable)
	}

	complete := decisionApproval(testRunID)

	t.Run("user feedback basis never steers routing", func(t *testing.T) {
		ap := complete
		ap.Basis = "user_feedback"
		assertUnavailable(t, ap)
	})
	t.Run("unknown basis never steers routing", func(t *testing.T) {
		ap := complete
		ap.Basis = "internal_dashboard_v2"
		assertUnavailable(t, ap)
	})
	t.Run("basis recorded without an evidence summary", func(t *testing.T) {
		ap := complete
		ap.EvidenceSummary = ""
		assertUnavailable(t, ap)
	})
	t.Run("basis recorded without limitations", func(t *testing.T) {
		ap := complete
		ap.Limitations = ""
		assertUnavailable(t, ap)
	})
	t.Run("evidence summary without a basis is a half-record", func(t *testing.T) {
		ap := complete
		ap.Basis = ""
		assertUnavailable(t, ap)
	})
	t.Run("pinned dataset digest does not match the run", func(t *testing.T) {
		ap := complete
		ap.DatasetDigest = "digest-tampered"
		assertUnavailable(t, ap)
	})
}

// T02 review addendum, finding 2: a hand-crafted manifest with an empty
// profile would bypass the cross-profile hold via absence semantics — the
// adapter fails closed on the incomplete provenance instead.
func TestSource_EmptyProfileManifest_Unavailable(t *testing.T) {
	root := t.TempDir()
	runDir := writeRunDir(t, root, testRunID, time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		map[string]string{"arm-a": "model-a"}, [][3]string{{"arm-a", "completed", "success"}})
	mpath := filepath.Join(runDir, "manifest.json")
	raw := rewriteJSON(t, readFile(t, mpath), func(m map[string]any) { m["profile"] = "" })
	require.NoError(t, os.WriteFile(mpath, raw, 0o600))

	ap := filepath.Join(root, "approvals.json")
	writeApprovals(t, ap, map[string]Approval{"org-1": decisionApproval(testRunID)})

	snap, err := NewSource(root, ap).QualitySnapshot(context.Background(), "org-1")
	require.Error(t, err)
	assert.Nil(t, snap)
	require.ErrorIs(t, err, router.ErrQualityUnavailable)
	assert.Contains(t, err.Error(), "empty profile", "the refusal names the missing provenance facet")
}

//
// N09-P03-T04: rollback and missing slices over imported results — without a
// built-in runner, an LLM judge or built-in model comparisons (I64). A
// rollback is an OWNER action on the approval registry (the runtime adapter
// stays read-only); the restored revision carries its full provenance chain,
// so corrupted provenance on a rolled-back-to run fails closed exactly like
// on a forward change.
//

const (
	rollbackOldRunID = "11111111-1111-1111-1111-111111111111" // previously applied
	rollbackNewRunID = "22222222-2222-2222-2222-222222222222" // currently applied
)

// The route is re-bound to a previously applied imported revision by the
// owner re-pointing the approval registry out-of-band; the runtime never
// writes, and the restored revision's provenance (digest pin, run-id match)
// is enforced exactly as on the forward path. If the restored run's data is
// later damaged, the source refuses it and the org fails closed to the
// classifier path — a rollback never resurrects corrupted provenance.
func TestSource_RollbackByApprovalRepoint(t *testing.T) {
	root := t.TempDir()
	oldCreated := time.Now().Add(-72 * time.Hour).UTC().Format(time.RFC3339)
	newCreated := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	writeRunDir(t, root, rollbackOldRunID, oldCreated,
		map[string]string{"arm-a": "model-a"}, [][3]string{{"arm-a", "completed", "success"}})
	writeRunDir(t, root, rollbackNewRunID, newCreated,
		map[string]string{"arm-a": "model-a"}, [][3]string{{"arm-a", "completed", "success"}})
	ap := filepath.Join(root, "approvals.json")

	t.Run("forward: org applied the newer revision", func(t *testing.T) {
		writeApprovals(t, ap, map[string]Approval{"org-1": decisionApproval(rollbackNewRunID)})
		snap, err := NewSource(root, ap).QualitySnapshot(context.Background(), "org-1")
		require.NoError(t, err)
		require.NotNil(t, snap)
		assert.Equal(t, rollbackNewRunID, snap.Version, "the route is bound to the imported revision")
		assert.True(t, snap.Fresh(48*time.Hour, time.Now()))
	})

	t.Run("rollback: owner re-points the approval to the previously applied revision", func(t *testing.T) {
		writeApprovals(t, ap, map[string]Approval{"org-1": decisionApproval(rollbackOldRunID)})
		snap, err := NewSource(root, ap).QualitySnapshot(context.Background(), "org-1")
		require.NoError(t, err)
		require.NotNil(t, snap)
		assert.Equal(t, rollbackOldRunID, snap.Version, "the restored revision is the rollback target")
		assert.Equal(t, "digest-"+rollbackOldRunID[:8], snap.DatasetDigest)
		// Stale-scores contract at the source boundary: the restored
		// snapshot carries its honest created_at, so a rollback to a
		// revision older than the operator's freshness window degrades to
		// the classifier path at serve time — it cannot steer stale scores.
		assert.False(t, snap.Fresh(48*time.Hour, time.Now()),
			"the 72h-old restored revision is stale for a 48h window: the serve gate must degrade it")
		assert.True(t, snap.Fresh(7*24*time.Hour, time.Now()),
			"the same revision is fresh for a wider window: the owner chooses the window")
	})

	t.Run("corrupted provenance on the restored run fails closed", func(t *testing.T) {
		m := rewriteJSON(t, readFile(t, filepath.Join(root, rollbackOldRunID, "manifest.json")),
			func(m map[string]any) {
				ds := m["dataset"].(map[string]any)
				ds["sha256"] = []any{"digest-damaged-after-rollback"}
			})
		require.NoError(t, os.WriteFile(filepath.Join(root, rollbackOldRunID, "manifest.json"), m, 0o600))

		snap, err := NewSource(root, ap).QualitySnapshot(context.Background(), "org-1")
		require.Error(t, err)
		assert.Nil(t, snap, "a rolled-back-to run with damaged provenance must never surface")
		require.ErrorIs(t, err, router.ErrQualityUnavailable)
		assert.Contains(t, err.Error(), "corrupted provenance")
	})
}

// Missing slices: an arm without completed episodes has no measured quality
// and stays ABSENT from the overall table (insufficient data upstream, not a
// zero score), and agenteval data carries no classifier-class split, so the
// snapshot ships no per-class slices at all — the router's overall fallback
// per class is the only slice consumers can rely on.
func TestSource_MissingSlices_ArmWithoutCompletedEpisodes(t *testing.T) {
	src := fixtureSource(t, [][3]string{
		{"arm-a", "completed", "success"},
		{"arm-b", "failed", "success"},  // not completed → excluded
		{"arm-b", "running", "success"}, // not completed → excluded
		{"arm-b", "completed", ""},      // completed without an outcome → excluded
	})

	snap, err := src.QualitySnapshot(context.Background(), "org-1")
	require.NoError(t, err)
	require.NotNil(t, snap)

	require.Contains(t, snap.Overall, "model-a")
	assert.NotContains(t, snap.Overall, "model-b",
		"an arm without completed episodes must be absent — absence, not a fabricated 0.0 score")
	assert.Nil(t, snap.PerClass, "imported agenteval runs ship no class slices")
}
