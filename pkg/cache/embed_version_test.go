package cache

// N03-P04-T02: versioned embeddings and thresholds.
//
// The semantic cache must never serve an entry whose stored vector comes
// from a different embedding space (embedder model or query prefix changed)
// or a different similarity-admission epoch (threshold rule changed): cosine
// similarity between vectors from different spaces is meaningless and turned
// "a similar question" into "someone else's answer". The mechanism: the
// writer stamps (embed_ver, threshold_ver) into the provenance envelope; the
// semantic lookup serves an entry only when both match its current versions
// (strict equality — unknown/legacy stamps are misses that refill).
//
// Structure mirrors the packet acceptance: negative cases prove a mismatched
// space or epoch degrades to a miss (never an error, never a foreign
// answer); positive controls prove matching versions still hit, so the check
// does not over-invalidate.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/embeddings"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// spaceEmbedder is a version-aware test embedder: fixed vector, explicit
// space identity. The production analogue is *embeddings.HTTPClient, whose
// SpaceVersion derives from model+queryPrefix.
type spaceEmbedder struct {
	embeddings.StaticClient
	ver string
}

func (s *spaceEmbedder) SpaceVersion() string { return s.ver }

// embedVerVec returns the shared fixed vector: every embedder in these tests
// produces the SAME embedding, so only the version stamps can decide hits.
func embedVerVec() []float32 { return makeTestEmbedding(384, 0.1) }

const embedVerTestThresholdVer = "sem1:0.9500:cosine:100"

func TestSemanticAdmissionVersion_StableAndNamed(t *testing.T) {
	v1 := SemanticAdmissionVersion()
	v2 := SemanticAdmissionVersion()
	assert.Equal(t, v1, v2, "admission version must be stable within a build")
	assert.Contains(t, v1, "0.9500", "default threshold must be part of the identity")
	assert.Contains(t, v1, "100", "default ef must be part of the identity")
}

func TestProvenance_SpaceMatch(t *testing.T) {
	testCases := []struct {
		name         string
		storedEmbed  string
		storedThresh string
		curEmbed     string
		curThresh    string
		want         bool
	}{
		{"same versions match", "emb1:a", "sem1:x", "emb1:a", "sem1:x", true},
		{"version-blind both sides match (legacy stubs)", "", "", "", "", true},
		{"different embed space", "emb1:a", "sem1:x", "emb1:b", "sem1:x", false},
		{"different threshold epoch", "emb1:a", "sem1:x", "emb1:a", "sem1:y", false},
		{"legacy entry vs versioning lookup", "", "sem1:x", "emb1:a", "sem1:x", false},
		{"versioned entry vs blind lookup", "emb1:a", "sem1:x", "", "sem1:x", false},
		{"legacy threshold only", "emb1:a", "", "emb1:a", "sem1:x", false},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p := Provenance{EmbedVer: tc.storedEmbed, ThresholdVer: tc.storedThresh}
			assert.Equal(t, tc.want, p.SpaceMatch(tc.curEmbed, tc.curThresh))
		})
	}
}

func TestSealEntryVersioned_RoundTripAndLegacyCompat(t *testing.T) {
	ri := RouteIdentity{OrgID: "org-1", Model: "gpt-4o"}
	data := json.RawMessage(`{"id":"cmpl-1"}`)

	sealed, err := SealEntryVersioned(data, ri, "emb1:a", embedVerTestThresholdVer)
	require.NoError(t, err)

	prov, unsealed, ok := OpenEntry(sealed)
	require.True(t, ok)
	assert.JSONEq(t, string(data), string(unsealed))
	assert.Equal(t, "emb1:a", prov.EmbedVer)
	assert.Equal(t, embedVerTestThresholdVer, prov.ThresholdVer)
	assert.Equal(t, "org-1", prov.OrgID)
	assert.Equal(t, "gpt-4o", prov.ModelUsed)

	// The legacy seal produces entries with empty version stamps — they
	// unseal fine (old readers keep working after rollback) and only the
	// strict SpaceMatch degrades them to misses on the semantic path.
	legacy, err := SealEntry(data, ri)
	require.NoError(t, err)
	provL, _, okL := OpenEntry(legacy)
	require.True(t, okL)
	assert.Empty(t, provL.EmbedVer)
	assert.Empty(t, provL.ThresholdVer)
}

func TestEmbedderSpaceVersion_InterfaceDispatch(t *testing.T) {
	assert.Equal(t, "emb-space-a", embedderSpaceVersion(&spaceEmbedder{StaticClient: embeddings.StaticClient{Embedding: embedVerVec()}, ver: "emb-space-a"}))
	// Version-blind embedders (production: none today; tests: Static/Noop).
	assert.Empty(t, embedderSpaceVersion(&embeddings.StaticClient{Embedding: []float32{1}}))
	assert.Empty(t, embedderSpaceVersion(nil))
}

// --- Docker-backed negatives (testdb/redisContainer skip in -short) ---------

const (
	embedVerModel     = "gpt-4o"
	embedVerPromptFmt = `{"messages":[{"role":"user","content":"Отчёт за 2025-03-31, доступ %s"}]}`
	embedVerResponseA = `{"id":"cmpl-embver-a","choices":[{"message":{"content":"answer-a"}}]}`
)

// embedVerSemanticPolicy opens every cache layer for the test org.
func embedVerSemanticPolicy(context.Context, string) (*OrgPolicy, error) {
	return &OrgPolicy{Mode: PrivacyEnabled, Semantic: true, TTL: time.Hour}, nil
}

// plantSemanticEntry writes a pgvector row directly: response sealed with the
// given version stamps, vector from the given embedder. Same org/model as the
// lookups below, so ONLY the version stamps can differ. When any version
// stamp is set the helper stamps the decisive content too — mirroring the
// real writer (writer.go), so a versioning lookup consults a faithful
// envelope; a fully-legacy planting (both versions empty) keeps the true
// pre-T02/T05 envelope with all stamps empty.
func plantSemanticEntry(t *testing.T, ctx context.Context, store *Store, orgID, prompt, embVer, threshVer string) {
	t.Helper()
	vec := embedVerVec()
	ri := RouteIdentity{OrgID: orgID, Model: embedVerModel}
	normalized := normalizeForCache([]byte(prompt))
	decVer, decFP := "", ""
	if embVer != "" || threshVer != "" {
		decVer, decFP = DecisiveContentStamp(normalized)
	}
	sealed, err := SealEntryVersionedContent(json.RawMessage(embedVerResponseA), ri, embVer, threshVer, decVer, decFP)
	require.NoError(t, err)
	_, err = store.Put(ctx, &Entry{
		OrgID:      orgID,
		ModelTier:  embedVerModel,
		PromptHash: ComputePromptHash(normalized),
		Embedding:  vec,
		Response:   sealed,
		TokensIn:   10,
		TokensOut:  5,
		ModelVer:   ri.Resolved().Version,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(time.Hour),
	})
	require.NoError(t, err)
}

// TestEmbedVersion_DifferentSpaceIsMiss proves the card negative on real
// backends: the SAME question, under the SAME org and model, must NOT be
// answered from an entry stored in a different embedding space.
func TestEmbedVersion_DifferentSpaceIsMiss(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Postgres(t)
	rdb := redisContainer(t)

	orgID := seedCacheOrg(t, pool, t.Name(), true, "semantic")
	prompt := fmt.Sprintf(embedVerPromptFmt, orgID)
	plantSemanticEntry(t, ctx, NewStore(pool), orgID, prompt, "emb-space-a", embedVerTestThresholdVer)

	// Lookup from space B: the ANN search finds the entry (identical vector),
	// but the space mismatch must degrade it to a miss — not serve answer-a.
	svcB := NewCacheService(ctx, pool, rdb, &spaceEmbedder{StaticClient: embeddings.StaticClient{Embedding: embedVerVec()}, ver: "emb-space-b"}, slog.New(slog.DiscardHandler), false)
	svcB.SetOrgPolicyLoader(embedVerSemanticPolicy)
	hit, err := svcB.LookupWithResult(ctx, RouteIdentity{OrgID: orgID, Model: embedVerModel}, []byte(prompt))
	require.NoError(t, err, "a version mismatch is a miss, never an error")
	assert.Nil(t, hit, "a foreign embedding space must not answer the question")

	// Positive control: the same space still hits, so the check does not
	// over-invalidate matching entries.
	svcA := NewCacheService(ctx, pool, rdb, &spaceEmbedder{StaticClient: embeddings.StaticClient{Embedding: embedVerVec()}, ver: "emb-space-a"}, slog.New(slog.DiscardHandler), false)
	svcA.SetOrgPolicyLoader(embedVerSemanticPolicy)
	hitA, err := svcA.LookupWithResult(ctx, RouteIdentity{OrgID: orgID, Model: embedVerModel}, []byte(prompt))
	require.NoError(t, err)
	require.NotNil(t, hitA, "same-space lookup must still hit")
	assert.Equal(t, "semantic", hitA.SourceType)
	assert.JSONEq(t, embedVerResponseA, string(hitA.Data))
}

// TestEmbedVersion_LegacyEntryIsMissUnderVersioning proves the upgrade path:
// entries written before versioning (empty stamps) are not compared across
// the unknown boundary — they miss and refill under the current versions.
func TestEmbedVersion_LegacyEntryIsMissUnderVersioning(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Postgres(t)
	rdb := redisContainer(t)

	orgID := seedCacheOrg(t, pool, t.Name(), true, "semantic")
	prompt := fmt.Sprintf(embedVerPromptFmt, orgID)
	plantSemanticEntry(t, ctx, NewStore(pool), orgID, prompt, "", embedVerTestThresholdVer)

	svc := NewCacheService(ctx, pool, rdb, &spaceEmbedder{StaticClient: embeddings.StaticClient{Embedding: embedVerVec()}, ver: "emb-space-a"}, slog.New(slog.DiscardHandler), false)
	svc.SetOrgPolicyLoader(embedVerSemanticPolicy)
	hit, err := svc.LookupWithResult(ctx, RouteIdentity{OrgID: orgID, Model: embedVerModel}, []byte(prompt))
	require.NoError(t, err)
	assert.Nil(t, hit, "an entry with unknown space must not be served by a versioning lookup")
}

// TestEmbedVersion_ThresholdEpochChangeIsMiss proves threshold versioning:
// an entry admitted under a different admission rule is not served under the
// current rule, keeping hit/confusion attribution per-epoch.
func TestEmbedVersion_ThresholdEpochChangeIsMiss(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Postgres(t)
	rdb := redisContainer(t)

	orgID := seedCacheOrg(t, pool, t.Name(), true, "semantic")
	prompt := fmt.Sprintf(embedVerPromptFmt, orgID)
	plantSemanticEntry(t, ctx, NewStore(pool), orgID, prompt, "emb-space-a", "sem1:0.9000:cosine:100")

	svc := NewCacheService(ctx, pool, rdb, &spaceEmbedder{StaticClient: embeddings.StaticClient{Embedding: embedVerVec()}, ver: "emb-space-a"}, slog.New(slog.DiscardHandler), false)
	svc.SetOrgPolicyLoader(embedVerSemanticPolicy)
	hit, err := svc.LookupWithResult(ctx, RouteIdentity{OrgID: orgID, Model: embedVerModel}, []byte(prompt))
	require.NoError(t, err)
	assert.Nil(t, hit, "an entry from another threshold epoch must not be served under the current rule")
}

// TestEmbedVersion_WriterStampsCurrentVersions proves the write path stamps
// the writer's resolved space version (from its embedder) and the package
// admission version into the stored envelope — the lookup-side strict match
// is only safe if writes actually record them.
func TestEmbedVersion_WriterStampsCurrentVersions(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Postgres(t)

	orgID := seedCacheOrg(t, pool, t.Name(), true, "semantic")
	prompt := fmt.Sprintf(embedVerPromptFmt, orgID)

	w := NewWriter(ctx, pool, &spaceEmbedder{StaticClient: embeddings.StaticClient{Embedding: embedVerVec()}, ver: "emb-space-w"}, slog.New(slog.DiscardHandler))
	ok := w.Submit(writerJob{
		orgID:      orgID,
		modelTier:  embedVerModel,
		modelVer:   RouteVersion,
		promptJSON: json.RawMessage(prompt),
		response:   json.RawMessage(embedVerResponseA),
		tokensIn:   10, tokensOut: 5,
	})
	require.True(t, ok)
	require.True(t, w.Stop())
	queued, dropped, written := w.Stats()
	failed, _ := w.OutcomeStats()
	t.Logf("writer counters: queued=%d dropped=%d written=%d failed=%d", queued, dropped, written, failed)
	require.Equal(t, int64(1), written, "the job must be persisted")

	var nRows int
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT count(*) FROM cache_entries WHERE org_id=$1::uuid AND model_tier=$2",
		orgID, embedVerModel).Scan(&nRows))
	require.Equal(t, 1, nRows, "exactly the writer's row must exist")

	// Read the raw row back through the store surface the lookup uses.
	// Threshold 1.0 is the legacy L2² pre-filter of this direct read (the
	// round-tripped vector text keeps ~6 significant digits, so identical
	// vectors compare with a tiny non-zero distance); it is not the
	// similarity threshold, which lives in SemanticCache.Lookup.
	entry, err := NewStore(pool).GetSemantic(ctx, orgID, embedVerModel, embedVerVec(), 1.0)
	require.NoError(t, err)
	require.NotNil(t, entry, "the writer must have persisted a semantic-searchable row")
	assert.Equal(t, ComputePromptHash(normalizeForCache([]byte(prompt))), entry.PromptHash)

	prov, _, okOpen := OpenEntry(entry.Response)
	require.True(t, okOpen)
	assert.Equal(t, "emb-space-w", prov.EmbedVer, "writer must stamp its embedder's space version")
	assert.Equal(t, SemanticAdmissionVersion(), prov.ThresholdVer, "writer must stamp the admission rule version")
	assert.Equal(t, DecisiveContentVer, prov.DecisiveVer, "writer must stamp the decisive-content detector version (N03-P04-T05)")
	_, wantFP := DecisiveContentStamp(normalizeForCache([]byte(prompt)))
	assert.Equal(t, wantFP, prov.DecisiveFP, "writer must stamp the decisive fingerprint of the normalized prompt (N03-P04-T05)")
}
