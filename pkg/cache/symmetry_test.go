package cache

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// W-CACHE: the lookup and write paths must canonicalize prompts identically —
// the exact hash and the semantic embedding are computed over the same
// normalized bytes on both paths, so the same logical prompt with different
// JSON key order (or volatile fields) produces a cache hit.

// promptHashEmbedder derives the embedding from the prompt text, so two calls
// return identical vectors if and only if they received identical bytes. A
// fixed-vector stub would mask asymmetric embed inputs.
type promptHashEmbedder struct {
	mu     sync.Mutex
	inputs []string
}

func (e *promptHashEmbedder) Embed(_ context.Context, text string) ([]float32, error) {
	e.mu.Lock()
	e.inputs = append(e.inputs, text)
	e.mu.Unlock()

	sum := sha256.Sum256([]byte(text))
	vec := make([]float32, 384)
	for i := range vec {
		vec[i] = float32(sum[i%len(sum)]) / 255.0
	}
	return vec, nil
}

func (e *promptHashEmbedder) recorded() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.inputs...)
}

func TestNormalizeForCache_KeyOrderIndependence(t *testing.T) {
	rawA := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}],"stream":false}`)
	rawB := []byte(`{"stream":false,"messages":[{"content":"hello","role":"user"}],"model":"gpt-4o"}`)

	normA := normalizeForCache(rawA)
	normB := normalizeForCache(rawB)

	assert.JSONEq(t, string(normA), string(normB), "same logical prompt must canonicalize to the same JSON")
	assert.Equal(t, string(normA), string(normB), "bytes must be identical, not just JSON-equal")
	assert.Equal(t, ComputePromptHash(normA), ComputePromptHash(normB),
		"the exact hash must be key-order independent")
}

func TestNormalizeForCache_VolatileFieldsStripped(t *testing.T) {
	rawA := []byte(`{"request_id":"req-1","messages":[{"role":"user","content":"hello"}]}`)
	rawB := []byte(`{"request_id":"req-2","messages":[{"role":"user","content":"hello"}]}`)

	assert.Equal(t,
		ComputePromptHash(normalizeForCache(rawA)),
		ComputePromptHash(normalizeForCache(rawB)),
		"request_id is volatile and must not change the cache identity")
}

// TestService_SemanticHit_DifferentKeyOrder is the acceptance test: a prompt
// written through the gateway Write path must produce a semantic hit when the
// same logical prompt arrives with reordered keys (and a different
// request_id) through the gateway Lookup path.
func TestService_SemanticHit_DifferentKeyOrder(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testcontainers (Postgres+Redis) test in -short mode")
	}
	ctx := context.Background()
	pool := newSemanticPGPool(t, nil)
	rdb := redisContainer(t)

	emb := &promptHashEmbedder{}
	pc := NewPolicyCache(60 * time.Second)
	pc.loader = func(context.Context, string) (*OrgPolicy, error) {
		return &OrgPolicy{Mode: PrivacyEnabled, Semantic: true}, nil
	}
	w := NewWriter(ctx, pool, emb, slog.New(slog.DiscardHandler))
	t.Cleanup(func() { w.StopWithTimeout(5 * time.Second) })

	cs := &CacheService{
		exact:      NewRedisStore(rdb, 24*time.Hour),
		semantic:   NewSemanticCache(pool, 0, 0),
		store:      NewStore(pool),
		writer:     w,
		policy:     pc,
		embedder:   emb,
		embedCache: NewEmbedCache(64),
		log:        slog.New(slog.DiscardHandler),
	}

	// Same logical prompt, different key order, different volatile fields.
	writeBody := []byte(`{"model":"gpt-4o","request_id":"req-1","messages":[{"role":"user","content":"what is the capital of France?"}],"stream":false}`)
	lookupBody := []byte(`{"stream":false,"request_id":"req-2","messages":[{"content":"what is the capital of France?","role":"user"}],"model":"gpt-4o"}`)
	require.NotEqual(t, string(writeBody), string(lookupBody), "sanity: raw bodies differ before normalization")

	ri := RouteIdentity{OrgID: "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11", Model: "smart"}
	resp := json.RawMessage(`{"id":"c1","choices":[{"message":{"content":"Paris"}}]}`)
	require.NoError(t, cs.Write(ctx, ri, writeBody, resp, 5, 3))

	// Wait for the async pgvector write (the exact layer was already filled).
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, _, written := cs.WriterStats()
		if written >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("writer never persisted the job")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Bypass the exact layer so the lookup must reach the semantic path.
	require.NoError(t, cs.exact.Delete(ctx, ri.OrgID, ri.Model,
		ComputePromptHash(normalizeForCache(writeBody))))

	hit, err := cs.LookupWithResult(ctx, ri, lookupBody)
	require.NoError(t, err)
	require.NotNil(t, hit, "same prompt with a different key order must be a semantic hit")
	assert.Equal(t, "semantic", hit.SourceType)
	assert.GreaterOrEqual(t, hit.Similarity, float32(DefaultSimilarityThreshold))
	assert.JSONEq(t, string(resp), string(hit.Data))

	// Both paths embedded the same canonical bytes.
	inputs := emb.recorded()
	require.Len(t, inputs, 2, "write and lookup must each embed exactly once")
	assert.Equal(t, inputs[0], inputs[1], "write and lookup must embed identical normalized bytes")
}
