package router

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/classifier"
	"github.com/reireirei/yabanin/pkg/sovereign"
)

// qualityTestSnapshot builds a snapshot with an Overall table.
func qualityTestSnapshot(version string, age time.Duration, scores map[string]QualityScore) *QualitySnapshot {
	return &QualitySnapshot{
		Version:   version,
		Source:    "test",
		CreatedAt: time.Now().Add(-age),
		Overall:   scores,
	}
}

func TestSelectModelWithQuality_PicksBestWithinPoolOnly(t *testing.T) {
	loader := &mockModelLoader{models: []ModelInfo{
		{Name: "model-a", Tier: "cheap", TierPool: []string{"easy"}, Weight: 1, Enabled: true},
		{Name: "model-b", Tier: "cheap", TierPool: []string{"easy"}, Weight: 1, Enabled: true},
	}}
	tr := NewTierRouter(loader, nil)

	// model-c scores highest but is NOT in the (policy-filtered) pool — a
	// quality ranking may never widen the candidate set.
	snap := qualityTestSnapshot("v12", time.Hour, map[string]QualityScore{
		"model-a": {Score: 0.5, Samples: 100},
		"model-b": {Score: 0.9, Samples: 100},
		"model-c": {Score: 0.99, Samples: 100},
	})

	m, outcome, err := tr.SelectModelWithQuality(context.Background(), classifier.ClassEasy, "org-1", "", snap)
	require.NoError(t, err)
	assert.Equal(t, "model-b", m.Name)
	assert.True(t, outcome.Used)
	assert.Equal(t, "v12", outcome.Version, "the decision must carry the snapshot version")
}

func TestSelectModelWithQuality_SovereigntyPreFilterNeverBypassed(t *testing.T) {
	// CN-flagged eval favorite is excluded by the DEFAULT policy pre-filter
	// (a wired policy store applies sovereign.DefaultPolicy in ensureLoaded),
	// so even a 0.99 score cannot route traffic to it.
	loader := &mockModelLoader{models: []ModelInfo{
		{Name: "model-a", Tier: "cheap", TierPool: []string{"easy"}, Weight: 1, Enabled: true},
		{Name: "model-cn", Tier: "cheap", TierPool: []string{"easy"}, Weight: 1, Enabled: true, CNFlagged: true},
	}}
	tr := NewTierRouter(loader, nil).WithPolicyStore(sovereign.NewPolicyStore(nil, nil))

	snap := qualityTestSnapshot("v12", time.Hour, map[string]QualityScore{
		"model-a":  {Score: 0.4, Samples: 100},
		"model-cn": {Score: 0.99, Samples: 100},
	})

	m, outcome, err := tr.SelectModelWithQuality(context.Background(), classifier.ClassEasy, "org-1", "", snap)
	require.NoError(t, err)
	assert.Equal(t, "model-a", m.Name, "policy-excluded favorite must never win")
	assert.True(t, outcome.Used)
}

func TestSelectModelWithQuality_NilSnapshotFallsBack(t *testing.T) {
	loader := &mockModelLoader{models: []ModelInfo{
		{Name: "model-a", Tier: "cheap", TierPool: []string{"easy"}, Weight: 1, Enabled: true},
	}}
	tr := NewTierRouter(loader, nil)

	m, outcome, err := tr.SelectModelWithQuality(context.Background(), classifier.ClassEasy, "org-1", "", nil)
	require.NoError(t, err)
	assert.Equal(t, "model-a", m.Name, "nil snapshot must degrade to the plain selection")
	assert.False(t, outcome.Used)
	assert.Equal(t, QualityFallbackNoSnapshot, outcome.FallbackReason)
}

func TestSelectModelWithQuality_InsufficientSamplesFallsBack(t *testing.T) {
	loader := &mockModelLoader{models: []ModelInfo{
		{Name: "model-a", Tier: "cheap", TierPool: []string{"easy"}, Weight: 1, Enabled: true},
	}}
	tr := NewTierRouter(loader, nil)

	snap := qualityTestSnapshot("v12", time.Hour, map[string]QualityScore{
		"model-a": {Score: 0.99, Samples: QualityMinSamples - 1},
	})

	m, outcome, err := tr.SelectModelWithQuality(context.Background(), classifier.ClassEasy, "org-1", "", snap)
	require.NoError(t, err)
	assert.Equal(t, "model-a", m.Name, "insufficient data must degrade to the plain selection")
	assert.False(t, outcome.Used)
	assert.Equal(t, QualityFallbackInsufficientData, outcome.FallbackReason)
	assert.Equal(t, "v12", outcome.Version)
}

func TestSelectModelWithQuality_AffinityOnlyBreaksTies(t *testing.T) {
	loader := &mockModelLoader{models: []ModelInfo{
		{Name: "model-a", Tier: "cheap", TierPool: []string{"easy"}, Weight: 1, Enabled: true},
		{Name: "model-b", Tier: "cheap", TierPool: []string{"easy"}, Weight: 1, Enabled: true},
	}}
	tied := qualityTestSnapshot("v12", time.Hour, map[string]QualityScore{
		"model-a": {Score: 0.8, Samples: 50},
		"model-b": {Score: 0.8, Samples: 50},
	})
	better := qualityTestSnapshot("v12", time.Hour, map[string]QualityScore{
		"model-a": {Score: 0.9, Samples: 50},
		"model-b": {Score: 0.7, Samples: 50},
	})

	// Tie → the session's warm model claims it.
	tr := NewTierRouter(loader, nil)
	m, outcome, err := tr.SelectModelWithQuality(context.Background(), classifier.ClassEasy, "org-1", "model-b", tied)
	require.NoError(t, err)
	assert.Equal(t, "model-b", m.Name)
	assert.True(t, outcome.Used)

	// Strictly lower score → affinity never overrides the ranking.
	m, _, err = tr.SelectModelWithQuality(context.Background(), classifier.ClassEasy, "org-1", "model-b", better)
	require.NoError(t, err)
	assert.Equal(t, "model-a", m.Name)
}

func TestSelectModelWithQuality_PerClassOverridesOverall(t *testing.T) {
	loader := &mockModelLoader{models: []ModelInfo{
		{Name: "model-a", Tier: "cheap", TierPool: []string{"easy"}, Weight: 1, Enabled: true},
		{Name: "model-b", Tier: "turbo", TierPool: []string{"hard"}, Weight: 1, Enabled: true},
	}}
	tr := NewTierRouter(loader, nil)
	snap := qualityTestSnapshot("v12", time.Hour, map[string]QualityScore{
		"model-a": {Score: 0.9, Samples: 50},
		"model-b": {Score: 0.2, Samples: 50},
	})
	snap.PerClass = map[classifier.Class]map[string]QualityScore{
		classifier.ClassHard: {
			"model-a": {Score: 0.1, Samples: 50},
			"model-b": {Score: 0.95, Samples: 50},
		},
	}

	m, outcome, err := tr.SelectModelWithQuality(context.Background(), classifier.ClassHard, "org-1", "", snap)
	require.NoError(t, err)
	assert.Equal(t, "model-b", m.Name, "hard class must use the class-specific table")
	assert.True(t, outcome.Used)

	m, _, err = tr.SelectModelWithQuality(context.Background(), classifier.ClassEasy, "org-1", "", snap)
	require.NoError(t, err)
	assert.Equal(t, "model-a", m.Name, "classes without a split fall back to the overall table")
}

// a FIXED quality table gives a deterministic route — 50 consecutive
// selections all land on the same model. No RNG participates in the quality
// pick (seed: none needed; determinism is by construction: score ranking over
// a fixed pool order), which is exactly what makes the route regression-testable.
func TestSelectModelWithQuality_FixedTable_DeterministicRoute(t *testing.T) {
	loader := &mockModelLoader{models: []ModelInfo{
		{Name: "model-a", Tier: "cheap", TierPool: []string{"easy"}, Weight: 3, Enabled: true},
		{Name: "model-b", Tier: "cheap", TierPool: []string{"easy"}, Weight: 1, Enabled: true},
	}}
	tr := NewTierRouter(loader, nil)
	fixed := qualityTestSnapshot("v12", time.Hour, map[string]QualityScore{
		"model-a": {Score: 0.55, Samples: 40},
		"model-b": {Score: 0.90, Samples: 40},
	})

	picks := map[string]int{}
	for i := 0; i < 50; i++ {
		m, outcome, err := tr.SelectModelWithQuality(context.Background(), classifier.ClassEasy, "org-1", "", fixed)
		require.NoError(t, err, "iteration %d", i)
		assert.True(t, outcome.Used)
		assert.Equal(t, "v12", outcome.Version)
		picks[m.Name]++
	}
	assert.Equal(t, map[string]int{"model-b": 50}, picks,
		"the fixed table must route every request to the same model regardless of weights")
}

// changing the measured quality (the routing weight between the two models)
// changes the decision — the table, not habit, steers traffic.
func TestSelectModelWithQuality_ScoreChangeFlipsDecision(t *testing.T) {
	loader := &mockModelLoader{models: []ModelInfo{
		{Name: "model-a", Tier: "cheap", TierPool: []string{"easy"}, Weight: 1, Enabled: true},
		{Name: "model-b", Tier: "cheap", TierPool: []string{"easy"}, Weight: 1, Enabled: true},
	}}
	tr := NewTierRouter(loader, nil)

	first := qualityTestSnapshot("v12", time.Hour, map[string]QualityScore{
		"model-a": {Score: 0.50, Samples: 40},
		"model-b": {Score: 0.80, Samples: 40},
	})
	m, outcome, err := tr.SelectModelWithQuality(context.Background(), classifier.ClassEasy, "org-1", "", first)
	require.NoError(t, err)
	assert.Equal(t, "model-b", m.Name, "v12: the higher score wins")
	assert.Equal(t, "v12", outcome.Version)

	second := qualityTestSnapshot("v13", time.Hour, map[string]QualityScore{
		"model-a": {Score: 0.70, Samples: 40},
		"model-b": {Score: 0.60, Samples: 40},
	})
	m, outcome, err = tr.SelectModelWithQuality(context.Background(), classifier.ClassEasy, "org-1", "", second)
	require.NoError(t, err)
	assert.Equal(t, "model-a", m.Name, "v13: the flipped table flips the route")
	assert.Equal(t, "v13", outcome.Version, "the decision carries the new table's version")
}

func TestQualitySnapshot_Fresh(t *testing.T) {
	now := time.Now()
	assert.True(t, qualityTestSnapshot("v", time.Hour, nil).Fresh(24*time.Hour, now))
	assert.False(t, qualityTestSnapshot("v", 48*time.Hour, nil).Fresh(24*time.Hour, now), "older than maxAge is stale")
	assert.False(t, qualityTestSnapshot("v", -time.Hour, nil).Fresh(24*time.Hour, now), "future-dated snapshot is not fresh")
	var zero *QualitySnapshot
	assert.False(t, zero.Fresh(24*time.Hour, now))
	bad := &QualitySnapshot{Version: "v"}
	assert.False(t, bad.Fresh(24*time.Hour, now), "zero CreatedAt is not fresh")
}

func TestCompareQualitySnapshots_AllowOnOverlap(t *testing.T) {
	prev := qualityTestSnapshot("v12", 48*time.Hour, map[string]QualityScore{
		"model-a": {Score: 0.6, Samples: 60},
		"model-b": {Score: 0.8, Samples: 60},
	})
	next := qualityTestSnapshot("v13", time.Hour, map[string]QualityScore{
		"model-a": {Score: 0.7, Samples: 60},
		"model-b": {Score: 0.85, Samples: 60},
	})

	ev := CompareQualitySnapshots(prev, next, 0)
	assert.True(t, ev.ShiftAllowed)
	assert.False(t, ev.Regression)
	assert.Equal(t, "overlap_ok", ev.Reason)
	assert.Equal(t, "v12", ev.PreviousVersion)
	assert.Equal(t, "v13", ev.NextVersion)
	assert.Equal(t, "model-b", ev.BestNextModel)
	require.Len(t, ev.Compared, 2)
	assert.InDelta(t, 0.05, ev.Compared[1].Delta, 1e-9)
}

func TestCompareQualitySnapshots_HoldOnFavoriteRegression(t *testing.T) {
	prev := qualityTestSnapshot("v12", 48*time.Hour, map[string]QualityScore{
		"model-a": {Score: 0.6, Samples: 60},
		"model-b": {Score: 0.9, Samples: 60},
	})
	next := qualityTestSnapshot("v13", time.Hour, map[string]QualityScore{
		"model-a": {Score: 0.7, Samples: 60},
		"model-b": {Score: 0.82, Samples: 60}, // favorite drops 0.9 → 0.82
	})

	ev := CompareQualitySnapshots(prev, next, 0)
	assert.False(t, ev.ShiftAllowed, "a regressed favorite must hold traffic")
	assert.True(t, ev.Regression)
	assert.Equal(t, "favorite_regressed", ev.Reason)
}

func TestCompareQualitySnapshots_HoldOnInsufficientData(t *testing.T) {
	prev := qualityTestSnapshot("v12", 48*time.Hour, map[string]QualityScore{
		"model-a": {Score: 0.6, Samples: 60},
	})
	next := qualityTestSnapshot("v13", time.Hour, map[string]QualityScore{
		"model-a": {Score: 0.9, Samples: QualityMinSamples - 1},
	})

	ev := CompareQualitySnapshots(prev, next, 0)
	assert.False(t, ev.ShiftAllowed)
	assert.Equal(t, "insufficient_data", ev.Reason)
}

func TestCompareQualitySnapshots_HoldOnNoBaselineOverlap(t *testing.T) {
	prev := qualityTestSnapshot("v12", 48*time.Hour, map[string]QualityScore{
		"model-a": {Score: 0.6, Samples: 60},
	})
	next := qualityTestSnapshot("v13", time.Hour, map[string]QualityScore{
		"model-x": {Score: 0.95, Samples: 60}, // favorite was never measured in vN
	})

	ev := CompareQualitySnapshots(prev, next, 0)
	assert.False(t, ev.ShiftAllowed, "no baseline proof ⇒ hold (fail-closed)")
	assert.Equal(t, "no_baseline_overlap", ev.Reason)

	var nilPrev *QualitySnapshot
	ev = CompareQualitySnapshots(nilPrev, next, 0)
	assert.False(t, ev.ShiftAllowed)
	assert.Equal(t, "no_baseline_overlap", ev.Reason)
}

// TestCompareQualitySnapshots_HoldOnProfileMismatch pins the provenance
// guard: snapshots recorded under different evaluation policy profiles are
// not comparable evidence — the overlap must hold, never dress a shift in
// cross-population "overlap_ok". Absence of a profile on either side (legacy
// snapshots) is not a conflict and still compares on the model overlap.
func TestCompareQualitySnapshots_HoldOnProfileMismatch(t *testing.T) {
	withProfile := func(version, profile string) *QualitySnapshot {
		s := qualityTestSnapshot(version, time.Hour, map[string]QualityScore{
			"model-a": {Score: 0.6, Samples: 60},
			"model-b": {Score: 0.9, Samples: 60},
		})
		s.PolicyProfile = profile
		return s
	}

	ev := CompareQualitySnapshots(withProfile("v12", "QUALITY_40"), withProfile("v13", "OTHER_PROFILE_10"), 0)
	assert.False(t, ev.ShiftAllowed, "cross-profile overlap must never allow a shift")
	assert.Empty(t, ev.BestNextModel, "no favorite is computed from incomparable populations")
	assert.Equal(t, "profile_mismatch", ev.Reason)
	assert.Equal(t, "v12", ev.PreviousVersion)
	assert.Equal(t, "v13", ev.NextVersion)

	// Same recorded profile is comparable evidence as usual.
	ev = CompareQualitySnapshots(withProfile("v12", "QUALITY_40"), withProfile("v13", "QUALITY_40"), 0)
	assert.True(t, ev.ShiftAllowed)
	assert.Equal(t, "overlap_ok", ev.Reason)

	// A profile recorded on one side only is absence, not conflict.
	ev = CompareQualitySnapshots(withProfile("v12", "QUALITY_40"), qualityTestSnapshot("v13", time.Hour, map[string]QualityScore{
		"model-b": {Score: 0.9, Samples: 60},
	}), 0)
	assert.True(t, ev.ShiftAllowed, "legacy snapshots without a profile still compare on model overlap")
	assert.Equal(t, "overlap_ok", ev.Reason)
}

func TestCompareQualitySnapshots_DeterministicFavoriteOnTie(t *testing.T) {
	scores := map[string]QualityScore{
		"model-b": {Score: 0.9, Samples: 60},
		"model-a": {Score: 0.9, Samples: 60},
	}
	next := qualityTestSnapshot("v13", time.Hour, scores)
	prev := qualityTestSnapshot("v12", 48*time.Hour, scores)

	for i := 0; i < 10; i++ {
		ev := CompareQualitySnapshots(prev, next, 0)
		assert.Equal(t, "model-a", ev.BestNextModel, "ties must resolve deterministically (alphabetical)")
	}
}
