package router

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/classifier"
)

//
// N09-P03-T04 serve-path verification: stale scores and missing slices never
// steer production routing. No built-in runner, no LLM judge, no built-in
// model comparison (I64) — these tests use fixed imported-style tables only.
//
// Layering (documented for the reviewer):
//   - staleness beyond an operator maxAge is a CALLER policy: the caller
//     checks QualitySnapshot.Fresh (the gateway does, before selecting) and
//     degrades with reason "stale_snapshot";
//   - provenance absence (no version identity / no creation time) is NOT a
//     policy question — the router refuses such snapshots itself, so the
//     invariant holds regardless of caller;
//   - a missing per-class slice falls back to the overall table; a model
//     missing from the effective table (or below the sample floor) can never
//     win and the selection falls back to the unchanged classifier path.
//

func TestSelectModelWithQuality_UnprovenancedSnapshotNeverSteers(t *testing.T) {
	loader := &mockModelLoader{models: []ModelInfo{
		// model-b is parked at weight 0 (never selected by the weighted
		// fallback) so the degraded pick below is deterministic model-a.
		{Name: "model-a", Tier: "cheap", TierPool: []string{"easy"}, Weight: 3, Enabled: true},
		{Name: "model-b", Tier: "cheap", TierPool: []string{"easy"}, Weight: 0, Enabled: true},
	}}
	tr := NewTierRouter(loader, nil)
	scores := map[string]QualityScore{
		"model-a": {Score: 0.1, Samples: 100},
		"model-b": {Score: 0.99, Samples: 100},
	}

	t.Run("zero creation time", func(t *testing.T) {
		snap := &QualitySnapshot{Version: "v13", Source: "test", Overall: scores} // no CreatedAt
		m, outcome, err := tr.SelectModelWithQuality(context.Background(), classifier.ClassEasy, "org-1", "", snap)
		require.NoError(t, err)
		assert.False(t, outcome.Used, "a snapshot without provenance must never steer")
		assert.Equal(t, QualityFallbackUnprovenanced, outcome.FallbackReason)
		assert.Equal(t, "model-a", m.Name, "the unchanged weighted selection decides (heavier weight wins)")
	})
	t.Run("no version identity", func(t *testing.T) {
		snap := &QualitySnapshot{Source: "test", CreatedAt: time.Now().Add(-time.Hour), Overall: scores} // no Version
		m, outcome, err := tr.SelectModelWithQuality(context.Background(), classifier.ClassEasy, "org-1", "", snap)
		require.NoError(t, err)
		assert.False(t, outcome.Used, "an unversioned snapshot has no D1 identity and must never steer")
		assert.Equal(t, QualityFallbackUnprovenanced, outcome.FallbackReason)
		assert.Equal(t, "model-a", m.Name)
	})
	t.Run("usable-for-routing cross-check against Fresh", func(t *testing.T) {
		good := qualityTestSnapshot("v13", time.Hour, scores)
		assert.True(t, good.UsableForRouting())
		assert.True(t, good.Fresh(24*time.Hour, time.Now()))
		stale := qualityTestSnapshot("v13", 48*time.Hour, scores)
		assert.True(t, stale.UsableForRouting(), "staleness is caller policy, not damaged provenance")
		assert.False(t, stale.Fresh(24*time.Hour, time.Now()), "the caller's freshness gate refuses it")
		var nilSnap *QualitySnapshot
		assert.False(t, nilSnap.UsableForRouting())
	})
}

func TestSelectModelWithQuality_MissingSlicesFallBack(t *testing.T) {
	loader := &mockModelLoader{models: []ModelInfo{
		{Name: "model-a", Tier: "cheap", TierPool: []string{"easy"}, Weight: 1, Enabled: true},
		{Name: "model-b", Tier: "cheap", TierPool: []string{"easy"}, Weight: 1, Enabled: true},
	}}
	tr := NewTierRouter(loader, nil)

	t.Run("class slice missing for the routed class falls back to overall", func(t *testing.T) {
		// The snapshot carries a hard-class split only (mirrors an imported
		// run evaluated on one class); easy routing must still work off the
		// overall table, not error and not silently no-op.
		snap := qualityTestSnapshot("v13", time.Hour, map[string]QualityScore{
			"model-a": {Score: 0.9, Samples: 60},
			"model-b": {Score: 0.4, Samples: 60},
		})
		snap.PerClass = map[classifier.Class]map[string]QualityScore{
			classifier.ClassHard: {"model-a": {Score: 0.2, Samples: 40}},
		}

		m, outcome, err := tr.SelectModelWithQuality(context.Background(), classifier.ClassEasy, "org-1", "", snap)
		require.NoError(t, err)
		assert.True(t, outcome.Used, "the overall table is a valid slice for the class")
		assert.Equal(t, "model-a", m.Name, "easy routes by the overall table (0.9 > 0.4)")
		assert.Equal(t, "v13", outcome.Version)

		// The class WITH the split uses the split table: models outside the
		// split have no measured quality for that class and cannot win it.
		m, _, err = tr.SelectModelWithQuality(context.Background(), classifier.ClassHard, "org-1", "", snap)
		require.NoError(t, err)
		assert.Equal(t, "model-a", m.Name, "hard routes by the split table (model-a 0.2/40; model-b unmeasured there)")
	})
	t.Run("class slice present but empty falls back to overall", func(t *testing.T) {
		snap := qualityTestSnapshot("v13", time.Hour, map[string]QualityScore{
			"model-a": {Score: 0.9, Samples: 60},
			"model-b": {Score: 0.4, Samples: 60},
		})
		snap.PerClass = map[classifier.Class]map[string]QualityScore{
			classifier.ClassHard: {},
		}
		m, outcome, err := tr.SelectModelWithQuality(context.Background(), classifier.ClassHard, "org-1", "", snap)
		require.NoError(t, err)
		assert.True(t, outcome.Used)
		assert.Equal(t, "model-a", m.Name, "an empty split is absence, not evidence — the overall table decides")
	})
	t.Run("class slice without the pool models degrades to the classifier path", func(t *testing.T) {
		// The routed class's split exists but covers none of the pool —
		// measured quality cannot steer this class, and the weighted
		// selection runs unchanged (insufficient_data, never an error).
		snap := qualityTestSnapshot("v13", time.Hour, map[string]QualityScore{
			"model-a": {Score: 0.9, Samples: 60},
			"model-b": {Score: 0.4, Samples: 60},
		})
		snap.PerClass = map[classifier.Class]map[string]QualityScore{
			classifier.ClassEasy: {
				"model-x": {Score: 0.99, Samples: 100}, // scored model is not in the pool
			},
		}
		m, outcome, err := tr.SelectModelWithQuality(context.Background(), classifier.ClassEasy, "org-1", "", snap)
		require.NoError(t, err)
		assert.False(t, outcome.Used)
		assert.Equal(t, QualityFallbackInsufficientData, outcome.FallbackReason)
		assert.Equal(t, "v13", outcome.Version, "the outcome names the version whose slice was unusable")
		assert.NotNil(t, m, "the classifier path still returns a usable model")
	})
	t.Run("under-sampled entries in the class slice cannot steer", func(t *testing.T) {
		snap := qualityTestSnapshot("v13", time.Hour, map[string]QualityScore{
			"model-a": {Score: 0.1, Samples: 60},
			"model-b": {Score: 0.99, Samples: 60},
		})
		snap.PerClass = map[classifier.Class]map[string]QualityScore{
			classifier.ClassEasy: {
				"model-a": {Score: 0.01, Samples: QualityMinSamples - 1},
				"model-b": {Score: 0.99, Samples: QualityMinSamples - 1},
			},
		}
		m, outcome, err := tr.SelectModelWithQuality(context.Background(), classifier.ClassEasy, "org-1", "", snap)
		require.NoError(t, err)
		assert.False(t, outcome.Used)
		assert.Equal(t, QualityFallbackInsufficientData, outcome.FallbackReason)
		assert.Contains(t, []string{"model-a", "model-b"}, m.Name, "the unchanged weighted selection decides; quality never does")
	})
	t.Run("snapshot without any score table degrades without error", func(t *testing.T) {
		snap := qualityTestSnapshot("v13", time.Hour, nil)
		m, outcome, err := tr.SelectModelWithQuality(context.Background(), classifier.ClassEasy, "org-1", "", snap)
		require.NoError(t, err)
		assert.False(t, outcome.Used)
		assert.Equal(t, QualityFallbackInsufficientData, outcome.FallbackReason)
		assert.NotNil(t, m, "the classifier path still returns a usable model")
	})
}
