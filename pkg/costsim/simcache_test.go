package audit

import (
	"fmt"
	"math"
	"math/rand"
	"testing"
	"time"
)

func TestSimCache_Exact_FirstNeverHitsSecondDoes(t *testing.T) {
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	recs := []Record{
		{Model: "gpt-4o", Provider: "openai", Prompt: "the prompt", PromptTokens: 100, CompletionTokens: 10, Timestamp: base},
		{Model: "gpt-4o", Provider: "openai", Prompt: "different", PromptTokens: 50, CompletionTokens: 5, Timestamp: base.Add(time.Second)},
		{Model: "gpt-4o", Provider: "openai", Prompt: "the prompt", PromptTokens: 100, CompletionTokens: 10, Timestamp: base.Add(2 * time.Second)}, // hit
	}
	res, err := SimulateCache(recs, SimCacheOptions{Mode: ModeExact})
	if err != nil {
		t.Fatalf("SimulateCache: %v", err)
	}
	if res.Hits != 1 {
		t.Errorf("Hits = %d, want 1 (only the third record is a repeat)", res.Hits)
	}
	if res.Requests != 3 {
		t.Errorf("Requests = %d, want 3", res.Requests)
	}
	// Hit rate = 1/3.
	if math.Abs(res.HitRate-1.0/3.0) > 1e-9 {
		t.Errorf("HitRate = %v, want 1/3", res.HitRate)
	}
	// Avoided tokens = the repeat's tokens.
	if res.TokensAvoided != 110 {
		t.Errorf("TokensAvoided = %d, want 110", res.TokensAvoided)
	}
}

func TestSimCache_Exact_TTLExpiry(t *testing.T) {
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	recs := []Record{
		{Model: "gpt-4o", Provider: "openai", Prompt: "p", PromptTokens: 10, CompletionTokens: 1, Timestamp: base},
		// 25h later — past the 24h TTL, so the first entry has expired -> miss.
		{Model: "gpt-4o", Provider: "openai", Prompt: "p", PromptTokens: 10, CompletionTokens: 1, Timestamp: base.Add(25 * time.Hour)},
	}
	res, err := SimulateCache(recs, SimCacheOptions{Mode: ModeExact, TTL: 24 * time.Hour})
	if err != nil {
		t.Fatalf("SimulateCache: %v", err)
	}
	if res.Hits != 0 {
		t.Errorf("Hits = %d, want 0 (entry expired past TTL)", res.Hits)
	}
}

func TestSimCache_Exact_NoTimestampsUsesInputOrder(t *testing.T) {
	recs := []Record{
		{Model: "gpt-4o", Provider: "openai", Prompt: "p", PromptTokens: 10, CompletionTokens: 1},
		{Model: "gpt-4o", Provider: "openai", Prompt: "p", PromptTokens: 10, CompletionTokens: 1}, // hit (input order)
	}
	res, err := SimulateCache(recs, SimCacheOptions{Mode: ModeExact})
	if err != nil {
		t.Fatalf("SimulateCache: %v", err)
	}
	if res.Hits != 1 {
		t.Errorf("Hits = %d, want 1 (input-order repeat)", res.Hits)
	}
}

func TestSimCache_TemperatureGate(t *testing.T) {
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	recs := []Record{
		// temperature > 0 -> excluded from counted hits by default.
		{Model: "gpt-4o", Provider: "openai", Prompt: "p", PromptTokens: 10, CompletionTokens: 1, Temperature: 0.7, TemperatureSet: true, Timestamp: base},
		{Model: "gpt-4o", Provider: "openai", Prompt: "p", PromptTokens: 10, CompletionTokens: 1, Temperature: 0.7, TemperatureSet: true, Timestamp: base.Add(time.Second)},
	}
	// Default: nondeterministic excluded -> 0 considered, 0 hits, 2 excluded.
	res, err := SimulateCache(recs, SimCacheOptions{Mode: ModeExact})
	if err != nil {
		t.Fatalf("SimulateCache: %v", err)
	}
	if res.ExcludedNondeterministic != 2 || res.Requests != 0 || res.Hits != 0 {
		t.Errorf("default: excluded=%d reqs=%d hits=%d, want 2/0/0", res.ExcludedNondeterministic, res.Requests, res.Hits)
	}
	// Opted in: both considered, the second is a hit.
	res2, _ := SimulateCache(recs, SimCacheOptions{Mode: ModeExact, CacheNondeterministic: true})
	if res2.ExcludedNondeterministic != 0 || res2.Hits != 1 {
		t.Errorf("opted-in: excluded=%d hits=%d, want 0/1", res2.ExcludedNondeterministic, res2.Hits)
	}
}

func TestSimCache_Semantic_FixedVectors(t *testing.T) {
	// Fixed-vector embedder: map prompt -> a known unit vector. Under the
	// honest conversion (sim = 1 - L2²/2) similarity is exactly the dot
	// product of unit vectors.
	vectors := map[string][]float32{
		"a": {1, 0},
		// 0.92 dot with "a" -> similarity 0.92 >= 0.9 threshold -> HIT.
		// (Deliberately above the boundary: a float32-rounded exact-boundary
		// case is not a stable assertion.)
		"b": {0.92, float32(math.Sqrt(1 - 0.92*0.92))},
		// 0.5 dot with "a" -> similarity 0.5 < 0.9 -> MISS.
		"c": {0.5, float32(math.Sqrt(1 - 0.25))},
	}
	embed := func(text string) ([]float32, error) {
		v, ok := vectors[text]
		if !ok {
			return nil, fmt.Errorf("no vector for %q", text)
		}
		return v, nil
	}
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	recs := []Record{
		{Model: "gpt-4o", Provider: "openai", Prompt: "a", PromptTokens: 10, CompletionTokens: 1, Timestamp: base},
		{Model: "gpt-4o", Provider: "openai", Prompt: "b", PromptTokens: 10, CompletionTokens: 1, Timestamp: base.Add(time.Second)},     // sim 0.92 -> hit
		{Model: "gpt-4o", Provider: "openai", Prompt: "c", PromptTokens: 10, CompletionTokens: 1, Timestamp: base.Add(2 * time.Second)}, // sim 0.5 -> miss
	}
	res, err := SimulateCache(recs, SimCacheOptions{Mode: ModeSemantic, Embed: embed, Threshold: 0.9})
	if err != nil {
		t.Fatalf("SimulateCache: %v", err)
	}
	// "a" is a miss (first), "b" hits (sim 0.92 >= 0.9), "c" misses (0.5 < 0.9).
	// "b" is also inserted on its own after hitting? No: on a hit we do NOT insert
	// a new entry (the existing live entry covers it). "c" misses and is inserted.
	if res.Hits != 1 {
		t.Errorf("Hits = %d, want 1 (only 'b' is within threshold)", res.Hits)
	}
	if len(res.SimilarityHistogram) == 0 {
		t.Error("semantic mode should produce a similarity histogram")
	}
}

func TestSimCache_Semantic_RequiresEmbedder(t *testing.T) {
	_, err := SimulateCache([]Record{{Model: "gpt-4o", Prompt: "x"}}, SimCacheOptions{Mode: ModeSemantic})
	if err == nil {
		t.Fatal("expected error when semantic mode has no embedder")
	}
}

func TestSimCache_OffAndEmpty(t *testing.T) {
	res, err := SimulateCache(nil, SimCacheOptions{Mode: ModeOff})
	if err != nil {
		t.Fatalf("SimulateCache: %v", err)
	}
	if res.Hits != 0 || res.Requests != 0 {
		t.Errorf("off/empty should yield zeros, got %+v", res)
	}
	res2, _ := SimulateCache([]Record{{Model: "gpt-4o", Prompt: "x"}}, SimCacheOptions{Mode: ModeOff})
	if res2.Hits != 0 || res2.Requests != 0 {
		t.Errorf("off mode should consider nothing, got %+v", res2)
	}
}

func TestSimCache_MaxEntriesEviction(t *testing.T) {
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	// MaxEntries=2; insert 3 distinct prompts (each a miss + insert), then repeat
	// the first. With eviction the first may have been evicted, but the test only
	// asserts the cap is respected (no panic, hits consistent with <=2 live).
	recs := []Record{
		{Model: "gpt-4o", Provider: "openai", Prompt: "p1", PromptTokens: 10, CompletionTokens: 1, Timestamp: base},
		{Model: "gpt-4o", Provider: "openai", Prompt: "p2", PromptTokens: 10, CompletionTokens: 1, Timestamp: base.Add(time.Second)},
		{Model: "gpt-4o", Provider: "openai", Prompt: "p3", PromptTokens: 10, CompletionTokens: 1, Timestamp: base.Add(2 * time.Second)},
		{Model: "gpt-4o", Provider: "openai", Prompt: "p2", PromptTokens: 10, CompletionTokens: 1, Timestamp: base.Add(3 * time.Second)}, // p2 still live (inserted 2nd of 3)
	}
	res, err := SimulateCache(recs, SimCacheOptions{Mode: ModeExact, MaxEntries: 2})
	if err != nil {
		t.Fatalf("SimulateCache: %v", err)
	}
	// p2 is the most recently inserted before the repeat, so it should still be
	// live with a 2-entry cap (p1 evicted). This asserts eviction happens without
	// breaking a still-live entry.
	if res.Hits != 1 {
		t.Errorf("Hits = %d, want 1 (p2 still live, p1 evicted)", res.Hits)
	}
}

func TestCosineSimilarityFromL2(t *testing.T) {
	// Identical unit vectors -> similarity 1.
	a := []float32{1, 0}
	if got := cosineSimilarityFromL2(a, a); math.Abs(got-1.0) > 1e-9 {
		t.Errorf("identical similarity = %v, want 1", got)
	}
	// Orthogonal unit vectors -> similarity 0.
	b := []float32{0, 1}
	if got := cosineSimilarityFromL2(a, b); math.Abs(got-0.0) > 1e-9 {
		t.Errorf("orthogonal similarity = %v, want 0", got)
	}
	// Opposite unit vectors -> similarity 0 (clamped from -1: below-threshold
	// pairs never hit the cache either way).
	c := []float32{-1, 0}
	if got := cosineSimilarityFromL2(a, c); math.Abs(got-0.0) > 1e-9 {
		t.Errorf("opposite similarity = %v, want 0", got)
	}
}

// TestCosineSimilarityFromL2_PropertyMatchesProductionConversion is the
// property test for the L2→similarity conversion: for random unit vectors the
// simulator's similarity must equal the cosine similarity the production
// semantic path produces from a pgvector cosine distance. For unit vectors
// L2² = 2 - 2·dot, so sim = 1 - L2²/2 = dot = 1 - (1 - dot) — i.e. identical
// to cache's cosineDistanceToSimilarity applied to the pgvector distance
// (1 - dot). The conversion used to square the already-squared distance and
// overstate similarity for dissimilar prompts.
func TestCosineSimilarityFromL2_PropertyMatchesProductionConversion(t *testing.T) {
	rng := rand.New(rand.NewSource(42)) //nolint:gosec // G404: deterministic property test, not security-sensitive
	const (
		rounds = 2000
		eps    = 1e-5
	)

	unit := func() []float32 {
		v := make([]float32, 8)
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
		// pgvector cosine distance between unit vectors.
		dCosine := 1 - dot
		// Production semantic-path conversion (pkg/cache semantic.go).
		prodSim := 1 - dCosine

		got := cosineSimilarityFromL2(a, b)
		// The simulator clamps to [0,1] by design: below-threshold pairs are
		// misses and the histogram bins over 0..1. The production conversion
		// may go negative for opposite vectors — the property is equality
		// under that documented clamp.
		want := math.Max(0, math.Min(1, prodSim))
		if math.Abs(float64(got)-want) > eps {
			t.Fatalf("round %d: simFromL2 = %v, production conversion = %v (dot = %v)", i, got, prodSim, dot)
		}
		// Monotonic honesty: the conversion must never overstate similarity
		// past the clamp bounds.
		if got < 0 || got > 1 {
			t.Fatalf("round %d: similarity %v outside [0,1]", i, got)
		}
	}
}
