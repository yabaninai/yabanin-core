package cache

import (
	"math"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Regression: the semantic lookup used to compute similarity := 1 - (1 - cosine
// distance), inverting the value a second time. Perfect matches scored 0 and
// were rejected by the 0.95 threshold while dissimilar prompts scored > 1 and
// were served as cache hits (X-Cache-Similarity was observed at 1.3686).

func TestCosineDistanceToSimilarity(t *testing.T) {
	tests := []struct {
		name     string
		distance float64
		want     float32
	}{
		{"identical vectors", 0.0, 1.0},
		{"threshold boundary (default 0.95)", 0.05, 0.95},
		{"orthogonal vectors", 1.0, 0.0},
		{"opposite vectors", 2.0, -1.0},
		{"near match", 0.02, 0.98},
		{"far but not opposite", 1.5, -0.5},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := cosineDistanceToSimilarity(tc.distance)
			assert.InDelta(t, tc.want, got, 1e-6)
		})
	}
}

func TestCosineDistanceToSimilarity_DefaultThresholdAcceptsNearExact(t *testing.T) {
	threshold := float32(DefaultSimilarityThreshold)
	// A near-exact prompt must pass the default threshold.
	assert.GreaterOrEqual(t, cosineDistanceToSimilarity(0.04), threshold,
		"distance 0.04 (similarity 0.96) must be accepted")

	// A dissimilar prompt must be rejected — this used to pass at 1.3+.
	assert.Less(t, cosineDistanceToSimilarity(1.4), threshold,
		"distance 1.4 (similarity -0.4) must be rejected")
}

// TestSquaredL2Distance_MatchesCosineConversion is the property test tying the
// shared SquaredL2Distance metric (used by pkg/costsim's simulator) to the
// production semantic-path conversion in semantic.go: for random unit vectors
// (what pgvector-indexed embeddings are), sim = 1 - L2²/2 must equal
// cosineDistanceToSimilarity applied to the pgvector cosine distance
// (1 - dot), because L2² = 2 - 2·dot for unit vectors.
func TestSquaredL2Distance_MatchesCosineConversion(t *testing.T) {
	rng := rand.New(rand.NewSource(7)) //nolint:gosec // G404: deterministic property test, not security-sensitive
	const (
		rounds = 2000
		dim    = 16
		eps    = 1e-5
	)

	unit := func() []float32 {
		v := make([]float32, dim)
		var norm float64
		for i := range v {
			v[i] = float32(rng.NormFloat64())
			norm += float64(v[i]) * float64(v[i])
		}
		n := math.Sqrt(norm)
		for i := range v {
			v[i] = float32(float64(v[i]) / n)
		}
		return v
	}

	for i := 0; i < rounds; i++ {
		a, b := unit(), unit()
		var dot float64
		for j := range a {
			dot += float64(a[j]) * float64(b[j])
		}

		dCosine := 1 - dot // pgvector <=> between unit vectors
		want := float64(cosineDistanceToSimilarity(dCosine))
		got := 1 - SquaredL2Distance(a, b)/2

		assert.InDeltaf(t, want, got, eps,
			"round %d: 1 - L2²/2 = %v, production conversion = %v (dot = %v)", i, got, want, dot)
	}
}
