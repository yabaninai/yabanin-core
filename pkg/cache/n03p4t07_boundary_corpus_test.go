package cache

// N03-P04-T07: boundary corpus for semantic-cache quality — three aspects.
//
// The card freezes a REUSABLE boundary corpus for the three quality axes of
// the semantic cache and pins every case with exact numbers and an
// OBSERVABLE outcome (a real hit/miss through the decision path), never a
// vacuous assertion:
//
//	(A) thresholds/versions — exact similarity edges at the admission
//	    boundary (cos = 0.95 ± 1e-4, crafted vectors), embedding-space
//	    identity edges and threshold-epoch edges at ADMITTED geometry
//	    (sim ≈ 1.0), so exactly one identity guard decides each case;
//	(B) multilingual/qualifiers — translation pairs (same meaning,
//	    different script) recorded FACTUALLY with numbers (qualifier tags,
//	    qualified and blind-embedder geometry), and the qualifier on/off
//	    boundary: the same base space with and without a qualifier tag must
//	    never share rows in either direction;
//	(C) near-miss false hits — the T06 confusion corpus's 23 near-* pairs
//	    (9 date, 6 number, 3 access, 5 entity; 7 of them the documented
//	    dc2-residual subset) replayed PER-PAIR, each pinned with its exact
//	    stub similarity vs the 0.95 threshold and its observable outcome:
//	    structural pairs MISS with the decisive guard owning the decision
//	    (geometry alone would admit), residual pairs HIT as documented
//	    erroneous reuses (dc2 class named, served answer proven to be the
//	    pair's own).
//
// DISTINCTNESS vs T06 (n03p4t06_joint_scenario_test.go): T06 owns the JOINT
// scenario — all 30 pairs share ONE org so every lookup sees a 30-row ANN
// candidate set (cross-pair leakage, guard order under realistic density).
// This corpus owns the BOUNDARY edges T06 cannot express: pairs at the
// exact threshold boundary, version-identity edges, the qualifier on/off
// edge, and per-pair one-row-org replay where attribution is unambiguous
// by construction. The pair definitions and the whole harness are REUSED
// from T04/T05/T06 (n03p4t06Corpus, holdoutEmbedder, holdoutAttribute); no
// T06 test is duplicated or weakened.
//
// REAL/MOCK split (honest): REAL = Postgres/pgvector + Redis through
// testdb containers and the real CacheService decision path (exact →
// pg_exact → semantic ANN → Provenance.SpaceMatch → DecisiveMatch). MOCK =
// the embedding function — the deterministic holdout n-gram stub
// (documented geometry model) and crafted vectors for the exact-boundary
// cases. No live embedding service is needed BY DESIGN: the corpus must
// stay runnable and byte-reproducible.
//
// The semantic search seam lives entirely in pkg/cache (SemanticCache.Lookup
// plus the CacheService lookup branch); pkg/gateway only surfaces
// hit.Similarity (X-Cache-Similarity header, events) and has no
// search-decision logic, so the corpus pins the seam at its home.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/embeddings"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Corpus: the near-miss subset (aspect C) and the qualifier boundary pair
// ---------------------------------------------------------------------------

// n03p4t07NearMiss returns the 23 near-* pairs of the frozen T06 corpus:
// 9 near-date, 6 near-number, 3 near-access, 5 near-entity — 16 structural
// (dc1 separates them) and 7 residual (documented dc2 blindness). The
// definitions stay owned by T06; this corpus REUSES them so a dc1/dc2 or
// wording change updates exactly one place.
func n03p4t07NearMiss() []n03p4t06Pair {
	var out []n03p4t06Pair
	for _, p := range n03p4t06Corpus() {
		if strings.HasPrefix(p.Class, "near-") {
			out = append(out, p)
		}
	}
	return out
}

// n03p4t07Translations returns the cross-language pairs (aspect B): same
// meaning, different script. Reused from the same frozen corpus.
func n03p4t07Translations() []n03p4t06Pair {
	var out []n03p4t06Pair
	for _, p := range n03p4t06Corpus() {
		if p.Class == holdoutClassCrossLang {
			out = append(out, p)
		}
	}
	return out
}

// The context-qualifier boundary pair (aspect B): same language, same
// question shape, ONE non-decisive word apart, no digits, no quoted or
// mid-sentence capitalized names, no access-marker stems — the decisive
// stamps are empty on BOTH sides, so exactly the qualifier identity can
// decide. Sentence-initial words are excluded from the entity class by the
// extractor (decisive_content.go), which is why the swapped word sits first.
const (
	n03p4t07QuCachedText = "Review the deployment checklist for the upcoming platform rollout: confirm every environment variable is documented, the migration plan is attached, and each rollback step has an owner assigned before the change freeze begins."
	n03p4t07QuLookupText = "Inspect the deployment checklist for the upcoming platform rollout: confirm every environment variable is documented, the migration plan is attached, and each rollback step has an owner assigned before the change freeze begins."
)

var (
	n03p4t07QuCached = holdoutPrompt(n03p4t07QuCachedText)
	n03p4t07QuLookup = holdoutPrompt(n03p4t07QuLookupText)
)

// n03p4t07Answer is a distinct response body per case: any hit must serve
// EXACTLY this body, proving which question's answer was reused.
func n03p4t07Answer(id string) string {
	return fmt.Sprintf(`{"id":"cmpl-n03p4t07-%s","choices":[{"message":{"content":"answer for %s"}}]}`, id, id)
}

// ---------------------------------------------------------------------------
// Crafted vectors for the exact threshold boundary (aspect A)
// ---------------------------------------------------------------------------

// n03p4t07Dir returns a deterministic pseudo-random unit vector (float64).
// holdoutHash keeps it platform- and run-stable, like the embedding stub;
// the hash maps into [-1, 1] through the holdout stub's bounded-modulo
// idiom (no narrowing integer conversion).
func n03p4t07Dir(dim int, salt uint64) []float64 {
	v := make([]float64, dim)
	var norm float64
	for i := range v {
		h := holdoutHash(fmt.Sprintf("n03p4t07-dir:%d:%d", salt, i))
		v[i] = float64(h%2001)/1000.0 - 1.0
		norm += v[i] * v[i]
	}
	norm = math.Sqrt(norm)
	for i := range v {
		v[i] /= norm
	}
	return v
}

// n03p4t07EdgeVecs returns (base, query) float32 unit vectors whose float64
// cosine is `want` by construction: query = want·base + √(1-want²)·ortho,
// with ortho a unit vector orthogonal to base (Gram–Schmidt). float32
// storage and pgvector arithmetic move the measured similarity by ~1e-6, so
// edges at 0.9501 / 0.9499 (margin 1e-4 around the 0.95 threshold) sit
// safely on their respective sides.
func n03p4t07EdgeVecs(dim int, want float64) (base, query []float32) {
	b := n03p4t07Dir(dim, 1)
	h := n03p4t07Dir(dim, 2)
	dot := 0.0
	for i := range b {
		dot += b[i] * h[i]
	}
	o := make([]float64, dim)
	var onorm float64
	for i := range b {
		o[i] = h[i] - dot*b[i]
		onorm += o[i] * o[i]
	}
	onorm = math.Sqrt(onorm)
	s := math.Sqrt(1 - want*want)
	base = make([]float32, dim)
	query = make([]float32, dim)
	for i := range b {
		base[i] = float32(b[i])
		query[i] = float32(want*b[i] + s*(o[i]/onorm))
	}
	return base, query
}

// n03p4t07PlantVec plants a pgvector row with an EXACT vector and version
// stamps (the plantSemanticEntry pattern with the vector as a parameter):
// response sealed with the given stamps, decisive content stamped like the
// real writer when any version stamp is set. Same org/model as the lookups,
// so only the stamped identities or the vector geometry can decide.
func n03p4t07PlantVec(t *testing.T, ctx context.Context, store *Store, orgID, model, prompt string, vec []float32, embVer, threshVer string) {
	t.Helper()
	ri := RouteIdentity{OrgID: orgID, Model: model}
	normalized := normalizeForCache([]byte(prompt))
	decVer, decFP := "", ""
	if embVer != "" || threshVer != "" {
		decVer, decFP = DecisiveContentStamp(normalized)
	}
	sealed, err := SealEntryVersionedContent(json.RawMessage(embedVerResponseA), ri, embVer, threshVer, decVer, decFP)
	require.NoError(t, err)
	_, err = store.Put(ctx, &Entry{
		OrgID:      orgID,
		ModelTier:  model,
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

// n03p4t07SeedOrg seeds one cache-enabled semantic-mode org for this corpus
// and returns its id (same row shape as seedCacheOrg, which this corpus
// does not reuse for one reason: the INSERT threads the caller's context so
// the corpus is contextcheck-clean by construction). The cleanup re-runs on
// context.Background() on purpose — t.Cleanup fires after the test's ctx
// may already be canceled; fixtures own their context lifetime (documented
// seedCacheOrg idiom).
func n03p4t07SeedOrg(ctx context.Context, t *testing.T, pool *pgxpool.Pool, name string) string {
	t.Helper()
	var orgID string
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug, cache_enabled, cache_mode) VALUES ($1, $2, true, 'semantic') RETURNING id::text`,
		name, name).Scan(&orgID))
	t.Cleanup(func() { //nolint:contextcheck // fixture owns its context lifetime: cleanup fires after the test ctx may be canceled (seedCacheOrg idiom)
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id::text = $1", orgID)
	})
	return orgID
}

// ---------------------------------------------------------------------------
// Always-on unit tests (run in -short): corpus integrity + identity edges
// ---------------------------------------------------------------------------

// TestN03P04T07_CorpusIntegrity pins the boundary corpus's structure: the
// card's count contract (23 near-* = 9 date + 6 number + 3 access + 5
// entity, 7 residual), unique answers/prompts (attribution), and — per
// pair — the exact pinned stub similarity vs the 0.95 threshold together
// with the guard that must own the decision. The printed cos values ARE
// the pins: the stub is deterministic, so they reproduce byte-for-byte.
func TestN03P04T07_CorpusIntegrity(t *testing.T) {
	stub := holdoutEmbedder{}
	near := n03p4t07NearMiss()
	attrs := n03p4t06Attrs(stub, near)
	threshold := float64(DefaultSimilarityThreshold)

	// Count contract (card): 23 near-* pairs, per class and residual split.
	require.Len(t, near, 23)
	perClass := map[string]int{}
	residual, structural := 0, 0
	for _, p := range near {
		perClass[p.Class]++
		if p.Residual {
			residual++
			assert.Contains(t, n03p4t06DC2, p.DC2Class, "%s: residual pair must name a documented dc2 class", p.ID)
			assert.False(t, p.ExpectHit, "%s: residual pairs are should-miss by definition", p.ID)
		} else {
			structural++
		}
	}
	assert.Equal(t, map[string]int{
		holdoutClassNearDate:   9,
		holdoutClassNearNumber: 6,
		holdoutClassNearAccess: 3,
		holdoutClassNearEntity: 5,
	}, perClass)
	assert.Equal(t, 16, structural, "structural near-* pairs")
	assert.Equal(t, 7, residual, "residual (dc2-blind) near-* pairs")

	// Attribution uniqueness + the per-pair boundary pin.
	seenAnswers := map[string]string{}
	seenPrompts := map[string]string{}
	for _, p := range near {
		t.Run(p.ID, func(t *testing.T) {
			if owner, seen := seenAnswers[p.Answer]; seen {
				t.Fatalf("answers must be unique: %s reuses %s", p.ID, owner)
			}
			seenAnswers[p.Answer] = p.ID
			for _, prompt := range []string{p.Cached, p.Lookup} {
				if owner, seen := seenPrompts[prompt]; seen {
					t.Fatalf("prompts must be unique in the boundary corpus: %s reuses %s", p.ID, owner)
				}
				seenPrompts[prompt] = p.ID
			}

			attr := attrs[p.ID]
			cos := holdoutCosine(attr.cachedVec, attr.lookupVec)
			assert.NotEqual(t, attr.cachedHash, attr.lookupHash, "%s: pair members must hit different exact keys", p.ID)
			assert.GreaterOrEqual(t, cos, threshold,
				"%s: near-miss pairs must sit at/above the admission threshold — else the threshold, not the guard, decides and the boundary case is void", p.ID)
			if p.Residual {
				assert.True(t, attr.sameDecisive(), "%s: residual pair must collide at stamp level (dc1 blindness)", p.ID)
				t.Logf("PIN %-17s [%s|dc2 %s] cos=%.4f ≥ %.2f, stamps EQUAL → documented erroneous reuse (observable HIT)",
					p.ID, p.Class, p.DC2Class, cos, threshold)
			} else {
				assert.False(t, attr.sameDecisive(), "%s: structural pair must separate by decisive stamp", p.ID)
				t.Logf("PIN %-17s [%s] cos=%.4f ≥ %.2f, stamps differ → decisive guard rejects (observable MISS)",
					p.ID, p.Class, cos, threshold)
			}
		})
	}

	// Aspect B corpus members: translations + the qualifier boundary pair.
	for _, p := range n03p4t07Translations() {
		attr := n03p4t06Attrs(stub, []n03p4t06Pair{p})[p.ID]
		assert.NotEqual(t, attr.cachedTag, attr.lookupTag, "%s: translation pair must separate by qualifier tag", p.ID)
		cosQ := holdoutCosine(attr.cachedVec, attr.lookupVec)
		normC := normalizeForCache([]byte(p.Cached))
		normL := normalizeForCache([]byte(p.Lookup))
		cosBlind := holdoutCosine(
			holdoutEmbedText(qualifiedEmbedInput(string(normC), "")),
			holdoutEmbedText(qualifiedEmbedInput(string(normL), "")))
		t.Logf("PIN %s tags %s→%s cos(qualified)=%.4f cos(blind-embedder)=%.4f — translation numbers recorded factually",
			p.ID, attr.cachedTag, attr.lookupTag, cosQ, cosBlind)
	}

	attrQU := holdoutAttribute(stub, n03p4t07QuCached, n03p4t07QuLookup)
	assert.NotEqual(t, attrQU.cachedHash, attrQU.lookupHash, "qualifier pair must hit different exact keys")
	assert.True(t, attrQU.sameDecisive(), "qualifier pair must be stamp-identical (no decisive tokens on either side) so the qualifier identity is the only decider")
	assert.Equal(t, "latn", attrQU.cachedTag, "qualifier pair members must qualify identically")
	assert.Equal(t, attrQU.cachedTag, attrQU.lookupTag)
	cosQU := holdoutCosine(attrQU.cachedVec, attrQU.lookupVec)
	assert.GreaterOrEqual(t, cosQU, threshold, "qualifier pair must be geometrically admitted — the space identity must be what rejects it")
	t.Logf("PIN qualifier-edge pair cos=%.4f ≥ %.2f, tag %q both sides, stamps equal → space identity decides",
		cosQU, threshold, attrQU.cachedTag)
}

// TestN03P04T07_AdmissionStampBoundaries pins the threshold/epoch identity
// at its exact edges (aspect A, unit half): the stamp format, the ±ε edge
// stamps, and the strict-equality SpaceMatch behavior across an epoch
// boundary — a threshold change on either side invalidates the entry, byte
// for byte, before any vector is compared.
func TestN03P04T07_AdmissionStampBoundaries(t *testing.T) {
	// Package-default pin (byte-exact; embedVerTestThresholdVer is T02's
	// independent copy of the same stamp).
	require.Equal(t, "sem1:0.9500:cosine:100", SemanticAdmissionVersion())
	require.Equal(t, embedVerTestThresholdVer, SemanticAdmissionVersion())

	// Per-instance resolution: zero values resolve to the default rule
	// byte-identically; explicit values stamp their own rule.
	assert.Equal(t, SemanticAdmissionVersion(), NewSemanticCache(nil, 0, 0).AdmissionVersion())
	assert.Equal(t, "sem1:0.9700:cosine:100", NewSemanticCache(nil, 0.97, 0).AdmissionVersion())
	assert.Equal(t, "sem1:0.9500:cosine:200", NewSemanticCache(nil, 0.95, 200).AdmissionVersion())

	// The ±1e-4 edges are distinct epochs — the identity moves at the exact
	// boundary of the admission parameter.
	above := NewSemanticCache(nil, 0.9501, 100).AdmissionVersion()
	below := NewSemanticCache(nil, 0.9499, 100).AdmissionVersion()
	assert.Equal(t, "sem1:0.9501:cosine:100", above)
	assert.Equal(t, "sem1:0.9499:cosine:100", below)
	assert.NotEqual(t, SemanticAdmissionVersion(), above)
	assert.NotEqual(t, SemanticAdmissionVersion(), below)
	assert.NotEqual(t, above, below)

	// SpaceMatch at the edges: strict equality — an entry is servable only
	// inside its own epoch, in both directions.
	entry := Provenance{EmbedVer: "emb-space-a", ThresholdVer: SemanticAdmissionVersion()}
	assert.False(t, entry.SpaceMatch("emb-space-a", above), "default-epoch entry must not serve a ±ε-shifted epoch")
	assert.False(t, entry.SpaceMatch("emb-space-a", below))
	entryAbove := Provenance{EmbedVer: "emb-space-a", ThresholdVer: above}
	assert.True(t, entryAbove.SpaceMatch("emb-space-a", above), "same-epoch entries must still match (no over-invalidation)")

	// Edge-vector construction sanity (pure Go): the crafted pairs hit the
	// requested cosines to within float32 conversion noise.
	for _, want := range []float64{0.9501, 0.9499} {
		base, query := n03p4t07EdgeVecs(holdoutDim, want)
		assert.InDelta(t, want, holdoutCosine(base, query), 1e-5, "crafted vectors must realize the target cosine")
		assert.InDelta(t, 1.0, holdoutCosine(base, base), 1e-6)
	}
}

// TestN03P04T07_QualifierIdentityBoundaries pins the qualifier identity at
// its edges (aspect B, unit half): script-classifier boundary inputs, the
// qualified-space composition (both halves move the version), and the
// blind-vs-qualified embedder dispatch the Docker on/off test walks.
func TestN03P04T07_QualifierIdentityBoundaries(t *testing.T) {
	// Script classifier edges: dominant script, exact tie, no letters.
	assert.Equal(t, "latn", embeddings.ScriptQualifier("Deployment checklist for the rollout"))
	assert.Equal(t, "cyrl", embeddings.ScriptQualifier("Вопрос про развёртывание"))
	assert.Equal(t, "none", embeddings.ScriptQualifier("1234 5678 — : ;"))
	assert.Equal(t, "mix", embeddings.ScriptQualifier("abcabc гдежзи"), "an exact 6/6 letter tie must classify as mix")

	// Qualified space version: empty tag keeps the pre-T03 identity; every
	// non-empty tag — including "none" for digits-only prompts — is a
	// distinct space.
	base := holdoutSpaceVer
	assert.Equal(t, base, embeddings.QualifiedSpaceVersion(base, ""))
	assert.Equal(t, base+"|q:latn", embeddings.QualifiedSpaceVersion(base, "latn"))
	assert.Equal(t, "|q:cyrl", embeddings.QualifiedSpaceVersion("", "cyrl"))
	vLatn := embeddings.QualifiedSpaceVersion(base, "latn")
	assert.NotEqual(t, vLatn, base)
	assert.NotEqual(t, vLatn, embeddings.QualifiedSpaceVersion(base, "cyrl"), "the qualifier half must move the version")
	assert.NotEqual(t, vLatn, embeddings.QualifiedSpaceVersion("other-space", "latn"), "the space half must move the version")
	assert.NotEqual(t, base, embeddings.QualifiedSpaceVersion(base, "none"), "even a stamp-less numeric prompt gets its own qualified space")

	// The embedding-input prefix: the bytes the vector actually conditions on.
	assert.Empty(t, embeddings.QualifierInputPrefix(""))
	assert.Equal(t, "[q:latn] ", embeddings.QualifierInputPrefix("latn"))

	// Dispatch: the holdout stub always qualifies (production qualifier-ON
	// analog); a SpaceVersioner-only embedder is qualifier-blind — the exact
	// configuration boundary the Docker on/off test walks.
	stub := holdoutEmbedder{}
	blinded := &spaceEmbedder{StaticClient: embeddings.StaticClient{Embedding: embedVerVec()}, ver: holdoutSpaceVer}
	for _, text := range []string{n03p4t07QuCachedText, n03p4t07QuLookupText} {
		assert.Equal(t, "latn", embedderInputTag(stub, text))
		assert.Empty(t, embedderInputTag(blinded, text))
	}
}

// ---------------------------------------------------------------------------
// Docker-backed boundary edges (testdb/redisContainer skip in -short)
// ---------------------------------------------------------------------------

// TestN03P04T07_ThresholdAndVersionEdges walks aspect A on real pgvector:
// exact similarity edges at the admission boundary (±1e-4 around 0.95) and
// the version-identity edges at ADMITTED geometry, where exactly one guard
// (space or epoch) is responsible for the miss. Every case records its
// measured numbers.
func TestN03P04T07_ThresholdAndVersionEdges(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Postgres(t)
	rdb := redisContainer(t)
	store := NewStore(pool)
	threshold := float64(DefaultSimilarityThreshold)
	verPrompt := fmt.Sprintf(embedVerPromptFmt, "n03p4t07-identities")

	t.Run("similarity just above threshold hits at the default epoch", func(t *testing.T) {
		org := n03p4t07SeedOrg(ctx, t, pool, "n03p4t07-edge-above")
		base, query := n03p4t07EdgeVecs(holdoutDim, 0.9501)
		n03p4t07PlantVec(t, ctx, store, org, embedVerModel, verPrompt, base, "emb-space-edge", SemanticAdmissionVersion())

		res, err := NewSemanticCache(pool, 0, 0).Lookup(ctx, org, embedVerModel, "", query)
		require.NoError(t, err)
		require.NotNil(t, res, "cos=0.9501 (≥ 0.95) must admit")
		assert.GreaterOrEqual(t, float64(res.Similarity), threshold)
		assert.InDelta(t, 0.9501, float64(res.Similarity), 2e-4, "measured pgvector similarity must pin the crafted edge")
		t.Logf("EDGE above: crafted cos=0.9501, pgvector sim=%.6f ≥ %.2f → HIT", res.Similarity, threshold)
	})

	t.Run("similarity just below threshold misses with ANN top-1 rejected", func(t *testing.T) {
		org := n03p4t07SeedOrg(ctx, t, pool, "n03p4t07-edge-below")
		base, query := n03p4t07EdgeVecs(holdoutDim, 0.9499)
		n03p4t07PlantVec(t, ctx, store, org, embedVerModel, verPrompt, base, "emb-space-edge", SemanticAdmissionVersion())

		res, err := NewSemanticCache(pool, 0, 0).Lookup(ctx, org, embedVerModel, "", query)
		require.ErrorIs(t, err, ErrMiss, "cos=0.9499 (< 0.95) must reject — even as the ANN's nearest and only row")
		assert.Nil(t, res)
		t.Logf("EDGE below: crafted cos=0.9499 rejected at threshold %.2f (top-1 ANN row, ErrMiss)", threshold)

		// The same row under a looser per-instance epoch: observable, and
		// its measured pgvector similarity is the exact number the default
		// epoch rejected.
		sc94 := NewSemanticCache(pool, 0.94, 0)
		assert.Equal(t, "sem1:0.9400:cosine:100", sc94.AdmissionVersion())
		res94, err := sc94.Lookup(ctx, org, embedVerModel, "", query)
		require.NoError(t, err)
		require.NotNil(t, res94, "the below-edge row must be observable under a 0.94 instance")
		assert.Less(t, float64(res94.Similarity), threshold)
		assert.InDelta(t, 0.9499, float64(res94.Similarity), 2e-4)
		t.Logf("EDGE below: pgvector sim=%.6f < %.2f — the exact number the default epoch rejected (0.94 instance admits)",
			res94.Similarity, threshold)
	})

	t.Run("real service path: threshold boundary with every identity aligned", func(t *testing.T) {
		// Same prompt, same stamps (space/epoch/decisive), only the vector
		// geometry differs: the threshold alone decides, end to end. The
		// planted rows are PG-only, so the exact and pg_exact layers miss
		// and the semantic branch decides.
		prompt := holdoutPrompt(n03p4t07QuCachedText)
		newSvc := func(q []float32) *CacheService {
			svc := NewCacheService(ctx, pool, rdb,
				&spaceEmbedder{StaticClient: embeddings.StaticClient{Embedding: q}, ver: "emb-space-edge"},
				slog.New(slog.DiscardHandler), false)
			svc.SetOrgPolicyLoader(embedVerSemanticPolicy)
			return svc
		}

		orgAbove := n03p4t07SeedOrg(ctx, t, pool, "n03p4t07-svc-edge-above")
		baseAbove, qAbove := n03p4t07EdgeVecs(holdoutDim, 0.9501)
		n03p4t07PlantVec(t, ctx, store, orgAbove, embedVerModel, prompt, baseAbove, "emb-space-edge", SemanticAdmissionVersion())
		hit, err := newSvc(qAbove).LookupWithResult(ctx, RouteIdentity{OrgID: orgAbove, Model: embedVerModel}, []byte(prompt))
		require.NoError(t, err)
		require.NotNil(t, hit, "cos=0.9501 must survive the whole real decision path")
		assert.Equal(t, "semantic", hit.SourceType)
		assert.JSONEq(t, embedVerResponseA, string(hit.Data))
		assert.GreaterOrEqual(t, float64(hit.Similarity), threshold)
		t.Logf("EDGE svc above: sim=%.6f ≥ %.2f → semantic HIT end-to-end", hit.Similarity, threshold)

		orgBelow := n03p4t07SeedOrg(ctx, t, pool, "n03p4t07-svc-edge-below")
		baseBelow, qBelow := n03p4t07EdgeVecs(holdoutDim, 0.9499)
		n03p4t07PlantVec(t, ctx, store, orgBelow, embedVerModel, prompt, baseBelow, "emb-space-edge", SemanticAdmissionVersion())
		miss, err := newSvc(qBelow).LookupWithResult(ctx, RouteIdentity{OrgID: orgBelow, Model: embedVerModel}, []byte(prompt))
		require.NoError(t, err)
		assert.Nil(t, miss, "cos=0.9499 must miss through the whole real decision path")
		t.Logf("EDGE svc below: ANN top-1 at crafted cos=0.9499 rejected by threshold %.2f end-to-end", threshold)
	})

	t.Run("cross-space identity at admitted geometry misses", func(t *testing.T) {
		// Re-pin of T02's space negative as a corpus member: identical
		// vectors (sim ≈ 1.0 — the threshold cannot reject) and only the
		// space stamp differs.
		org := n03p4t07SeedOrg(ctx, t, pool, "n03p4t07-cross-space")
		n03p4t07PlantVec(t, ctx, store, org, embedVerModel, verPrompt, embedVerVec(), "emb-space-a", SemanticAdmissionVersion())

		svcB := NewCacheService(ctx, pool, rdb,
			&spaceEmbedder{StaticClient: embeddings.StaticClient{Embedding: embedVerVec()}, ver: "emb-space-b"},
			slog.New(slog.DiscardHandler), false)
		svcB.SetOrgPolicyLoader(embedVerSemanticPolicy)
		hit, err := svcB.LookupWithResult(ctx, RouteIdentity{OrgID: org, Model: embedVerModel}, []byte(verPrompt))
		require.NoError(t, err)
		assert.Nil(t, hit, "a foreign embedding space must not answer at admitted geometry — the space identity owns this miss")

		svcA := NewCacheService(ctx, pool, rdb,
			&spaceEmbedder{StaticClient: embeddings.StaticClient{Embedding: embedVerVec()}, ver: "emb-space-a"},
			slog.New(slog.DiscardHandler), false)
		svcA.SetOrgPolicyLoader(embedVerSemanticPolicy)
		hitA, err := svcA.LookupWithResult(ctx, RouteIdentity{OrgID: org, Model: embedVerModel}, []byte(verPrompt))
		require.NoError(t, err)
		require.NotNil(t, hitA, "same-space lookup must still hit (no over-invalidation)")
		assert.Equal(t, "semantic", hitA.SourceType)
		assert.JSONEq(t, embedVerResponseA, string(hitA.Data))
		t.Logf("EDGE cross-space: lookup sim≈%.4f (admitted) rejected by SpaceMatch emb-space-a ≠ emb-space-b", float64(hitA.Similarity))
	})

	t.Run("cross-epoch identity (mid-rollout threshold deployment) misses", func(t *testing.T) {
		// The card's threshold-change edge at admitted geometry: an entry
		// admitted under the CURRENT default epoch must not answer once a
		// deployment resolves a different admission rule — no retroactive
		// bypass in either direction. (White-box override of the service's
		// resolved epoch: exactly what a mid-rollout replica carries.)
		org := n03p4t07SeedOrg(ctx, t, pool, "n03p4t07-cross-epoch")
		base, q := n03p4t07EdgeVecs(holdoutDim, 0.9501)
		n03p4t07PlantVec(t, ctx, store, org, embedVerModel, verPrompt, base, "emb-space-edge", SemanticAdmissionVersion())
		newSvc := func(thresholdVer string) *CacheService {
			svc := NewCacheService(ctx, pool, rdb,
				&spaceEmbedder{StaticClient: embeddings.StaticClient{Embedding: q}, ver: "emb-space-edge"},
				slog.New(slog.DiscardHandler), false)
			svc.SetOrgPolicyLoader(embedVerSemanticPolicy)
			svc.thresholdVer = thresholdVer
			return svc
		}

		rolledOut := newSvc("sem1:0.9700:cosine:100")
		hit, err := rolledOut.LookupWithResult(ctx, RouteIdentity{OrgID: org, Model: embedVerModel}, []byte(verPrompt))
		require.NoError(t, err)
		assert.Nil(t, hit, "a mid-rollout replica with a new admission rule must not serve old-epoch entries")

		current := newSvc(SemanticAdmissionVersion())
		hitCur, err := current.LookupWithResult(ctx, RouteIdentity{OrgID: org, Model: embedVerModel}, []byte(verPrompt))
		require.NoError(t, err)
		require.NotNil(t, hitCur, "the current epoch must still serve its own entries")
		assert.Equal(t, "semantic", hitCur.SourceType)
		t.Logf("EDGE cross-epoch: sim=%.6f (admitted) rejected by ThresholdVer sem1:0.9700:cosine:100 ≠ %s",
			hitCur.Similarity, SemanticAdmissionVersion())
	})

	t.Run("entry from a looser past epoch is never served under the current rule", func(t *testing.T) {
		// Re-pin of T02's epoch negative as a corpus member: the pre-change
		// rule (0.90) admitted more; the current rule must not serve it.
		org := n03p4t07SeedOrg(ctx, t, pool, "n03p4t07-past-epoch")
		base, q := n03p4t07EdgeVecs(holdoutDim, 0.9501)
		n03p4t07PlantVec(t, ctx, store, org, embedVerModel, verPrompt, base, "emb-space-edge", "sem1:0.9000:cosine:100")

		svc := NewCacheService(ctx, pool, rdb,
			&spaceEmbedder{StaticClient: embeddings.StaticClient{Embedding: q}, ver: "emb-space-edge"},
			slog.New(slog.DiscardHandler), false)
		svc.SetOrgPolicyLoader(embedVerSemanticPolicy)
		hit, err := svc.LookupWithResult(ctx, RouteIdentity{OrgID: org, Model: embedVerModel}, []byte(verPrompt))
		require.NoError(t, err)
		assert.Nil(t, hit, "a looser past epoch must not leak into the current rule")
		t.Logf("EDGE past-epoch: row admitted under sem1:0.9000:cosine:100 not served under %s", SemanticAdmissionVersion())
	})
}

// TestN03P04T07_QualifierAndTranslationBoundary walks aspect B on the real
// decision path: translation pairs (same meaning, different script) whose
// rows live in different qualified spaces, and the qualifier on/off
// boundary — the same base space with and without a tag never shares rows,
// in either direction, at admitted geometry.
func TestN03P04T07_QualifierAndTranslationBoundary(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Postgres(t)
	rdb := redisContainer(t)
	store := NewStore(pool)
	stub := holdoutEmbedder{}
	threshold := float64(DefaultSimilarityThreshold)
	attrsAll := n03p4t06Attrs(stub, n03p4t06Corpus())
	translations := n03p4t07Translations()

	t.Run("translation pairs separate by space identity — numbers recorded", func(t *testing.T) {
		svc := NewCacheService(ctx, pool, rdb, stub, slog.New(slog.DiscardHandler), false)
		svc.SetOrgPolicyLoader(embedVerSemanticPolicy)

		// Write phase: each pair in its own org through the REAL write path.
		orgs := map[string]string{}
		for _, p := range translations {
			org := n03p4t07SeedOrg(ctx, t, pool, "n03p4t07-tr-"+p.ID)
			orgs[p.ID] = org
			require.NoError(t, svc.Write(ctx, RouteIdentity{OrgID: org, Model: holdoutModel},
				[]byte(p.Cached), json.RawMessage(p.Answer), 10, 5), "%s: write must succeed", p.ID)
		}
		require.True(t, svc.writer.Stop(), "the writer must drain before any lookup")

		// Provenance receipt: rows are stamped with the QUALIFIED space of
		// the cached prompt's script — the identity the lookups compare
		// against.
		for _, p := range translations {
			attr := attrsAll[p.ID]
			ri := RouteIdentity{OrgID: orgs[p.ID], Model: holdoutModel}.Resolved()
			entry, err := store.GetExact(ctx, ri.OrgID, ri.Model, attr.cachedHash, ri.Version)
			require.NoError(t, err, p.ID)
			require.NotNil(t, entry, "%s: the writer must have persisted a row", p.ID)
			prov, _, ok := OpenEntry(entry.Response)
			require.True(t, ok, p.ID)
			assert.Equal(t, embeddings.QualifiedSpaceVersion(holdoutSpaceVer, attr.cachedTag), prov.EmbedVer,
				"%s: row must be stamped with the qualifier-extended space version", p.ID)
			assert.Equal(t, SemanticAdmissionVersion(), prov.ThresholdVer, "%s: current epoch stamp", p.ID)
		}

		// Lookup phase: the translation must MISS through the space identity
		// (same meaning, different script → different qualified space). The
		// geometry numbers are recorded factually — the blind-embedder cos
		// is what a pre-T03 embedder would face.
		for _, p := range translations {
			t.Run(p.ID, func(t *testing.T) {
				attr := attrsAll[p.ID]
				hit, err := svc.LookupWithResult(ctx, RouteIdentity{OrgID: orgs[p.ID], Model: holdoutModel}, []byte(p.Lookup))
				require.NoError(t, err, "%s: a translation lookup must never error", p.ID)
				assert.Nil(t, hit, "%s: a different-script question must not be answered from the other script's row", p.ID)

				cosQ := holdoutCosine(attr.cachedVec, attr.lookupVec)
				normC := normalizeForCache([]byte(p.Cached))
				normL := normalizeForCache([]byte(p.Lookup))
				cosBlind := holdoutCosine(
					holdoutEmbedText(qualifiedEmbedInput(string(normC), "")),
					holdoutEmbedText(qualifiedEmbedInput(string(normL), "")))
				assert.NotEqual(t, attr.cachedTag, attr.lookupTag)
				t.Logf("PIN %s MISS via SpaceMatch %q ≠ %q; cos(qualified)=%.4f cos(blind)=%.4f — factual, no behavior claim",
					p.ID, attr.cachedTag, attr.lookupTag, cosQ, cosBlind)
			})
		}
	})

	t.Run("qualifier on/off boundary: one base space never shares rows", func(t *testing.T) {
		// The row: written through the QUALIFIED path (holdout stub →
		// |q:latn space, vector = V1, the qualified embedding of the cached
		// prompt). The blind reader is a SpaceVersioner-only embedder that
		// statically returns V1: its geometry admits at sim = 1.0 BY
		// CONSTRUCTION, so only the space identity can own the miss.
		orgQU := n03p4t07SeedOrg(ctx, t, pool, "n03p4t07-qualifier-onoff")
		svcQ := NewCacheService(ctx, pool, rdb, stub, slog.New(slog.DiscardHandler), false)
		svcQ.SetOrgPolicyLoader(embedVerSemanticPolicy)
		require.NoError(t, svcQ.Write(ctx, RouteIdentity{OrgID: orgQU, Model: holdoutModel},
			[]byte(n03p4t07QuCached), json.RawMessage(n03p4t07Answer("qu-edge")), 10, 5))
		require.True(t, svcQ.writer.Stop())

		normC := normalizeForCache([]byte(n03p4t07QuCached))
		normL := normalizeForCache([]byte(n03p4t07QuLookup))
		v1 := holdoutEmbedText(qualifiedEmbedInput(string(normC), "latn"))
		v2 := holdoutEmbedText(qualifiedEmbedInput(string(normL), "latn"))

		// Receipt: the row is stamped into the qualified space |q:latn.
		riQ := RouteIdentity{OrgID: orgQU, Model: holdoutModel}.Resolved()
		entry, err := store.GetExact(ctx, riQ.OrgID, riQ.Model, ComputePromptHash(normC), riQ.Version)
		require.NoError(t, err)
		require.NotNil(t, entry)
		prov, _, ok := OpenEntry(entry.Response)
		require.True(t, ok)
		assert.Equal(t, embeddings.QualifiedSpaceVersion(holdoutSpaceVer, "latn"), prov.EmbedVer,
			"the qualified write must stamp the |q:latn space")

		// Blind lookup of the OTHER member (one non-decisive word apart):
		// base space "holdout-ngram-emb1" vs the row's "…|q:latn", admitted
		// geometry → the space identity must reject.
		blinded := &spaceEmbedder{StaticClient: embeddings.StaticClient{Embedding: v1}, ver: holdoutSpaceVer}
		svcB := NewCacheService(ctx, pool, rdb, blinded, slog.New(slog.DiscardHandler), false)
		svcB.SetOrgPolicyLoader(embedVerSemanticPolicy)
		hit, err := svcB.LookupWithResult(ctx, RouteIdentity{OrgID: orgQU, Model: holdoutModel}, []byte(n03p4t07QuLookup))
		require.NoError(t, err)
		assert.Nil(t, hit, "a qualifier-blind lookup in the base space must not serve a |q:latn row at sim=1.0 geometry")

		// Byte-identical control through the same blind service: the exact
		// layer still serves its own question (no over-invalidation).
		hitOwn, err := svcB.LookupWithResult(ctx, RouteIdentity{OrgID: orgQU, Model: holdoutModel}, []byte(n03p4t07QuCached))
		require.NoError(t, err)
		require.NotNil(t, hitOwn, "the byte-identical question must hit the exact layer")
		assert.Equal(t, "exact", hitOwn.SourceType)
		assert.JSONEq(t, n03p4t07Answer("qu-edge"), string(hitOwn.Data))

		// Reverse direction: a BLIND writer stamps its row into the base
		// space (vector V1 statically); the qualified reader looking up the
		// other member embeds V2 — admitted geometry pinned ≥ threshold —
		// and must still miss through the space identity.
		orgRev := n03p4t07SeedOrg(ctx, t, pool, "n03p4t07-qualifier-reverse")
		blindWriter := &spaceEmbedder{StaticClient: embeddings.StaticClient{Embedding: v1}, ver: holdoutSpaceVer}
		svcRev := NewCacheService(ctx, pool, rdb, blindWriter, slog.New(slog.DiscardHandler), false)
		svcRev.SetOrgPolicyLoader(embedVerSemanticPolicy)
		require.NoError(t, svcRev.Write(ctx, RouteIdentity{OrgID: orgRev, Model: holdoutModel},
			[]byte(n03p4t07QuCached), json.RawMessage(n03p4t07Answer("qu-edge-rev")), 10, 5))
		require.True(t, svcRev.writer.Stop())

		riRev := RouteIdentity{OrgID: orgRev, Model: holdoutModel}.Resolved()
		entryRev, err := store.GetExact(ctx, riRev.OrgID, riRev.Model, ComputePromptHash(normC), riRev.Version)
		require.NoError(t, err)
		require.NotNil(t, entryRev)
		provRev, _, okRev := OpenEntry(entryRev.Response)
		require.True(t, okRev)
		assert.Equal(t, holdoutSpaceVer, provRev.EmbedVer, "the blind write must stamp the base space (no tag)")

		svcQ2 := NewCacheService(ctx, pool, rdb, stub, slog.New(slog.DiscardHandler), false)
		svcQ2.SetOrgPolicyLoader(embedVerSemanticPolicy)
		hitRev, err := svcQ2.LookupWithResult(ctx, RouteIdentity{OrgID: orgRev, Model: holdoutModel}, []byte(n03p4t07QuLookup))
		require.NoError(t, err)
		assert.Nil(t, hitRev, "a qualified lookup (|q:latn) must not serve a base-space row")

		cosAdmitted := holdoutCosine(v1, v2)
		assert.GreaterOrEqual(t, cosAdmitted, threshold,
			"the reverse lookup's geometry (cos of the row vector vs the qualified lookup vector) must admit — the space identity owns both misses")
		t.Logf("PIN qualifier on/off BOTH directions miss via SpaceMatch; reverse lookup geometry cos(V1,V2)=%.4f ≥ %.2f",
			cosAdmitted, threshold)
	})
}

// TestN03P04T07_NearMissBoundaryReplay replays the 23 near-* boundary pairs
// PER-PAIR (aspect C): every pair gets its own org, so the ANN candidate
// set is one row and the outcome is attributable to exactly one neighbor by
// construction. Structural pairs must MISS with the decisive guard owning
// the decision (their own-twin similarity is pinned ≥ threshold, so the
// threshold cannot be what rejected them); residual pairs must HIT as
// documented erroneous reuses (dc2 class named, own answer served) — a
// deliberate corpus pin that must be updated if dc2 ever lands. This is the
// per-pair complement to T06's joint scenario, not a duplicate.
func TestN03P04T07_NearMissBoundaryReplay(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Postgres(t)
	rdb := redisContainer(t)
	store := NewStore(pool)
	stub := holdoutEmbedder{}
	svc := NewCacheService(ctx, pool, rdb, stub, slog.New(slog.DiscardHandler), false)
	svc.SetOrgPolicyLoader(embedVerSemanticPolicy)
	threshold := float64(DefaultSimilarityThreshold)

	near := n03p4t07NearMiss()
	attrs := n03p4t06Attrs(stub, near)

	// Write phase: one org per pair through the REAL write path.
	orgs := map[string]string{}
	for _, p := range near {
		org := n03p4t07SeedOrg(ctx, t, pool, "n03p4t07-nm-"+p.ID)
		orgs[p.ID] = org
		require.NoError(t, svc.Write(ctx, RouteIdentity{OrgID: org, Model: holdoutModel},
			[]byte(p.Cached), json.RawMessage(p.Answer), 10, 5), "%s: write must succeed", p.ID)
	}
	require.True(t, svc.writer.Stop(), "the writer must drain before the replay")

	// Provenance receipt: every row carries the identities the lookups
	// below compare against.
	for _, p := range near {
		attr := attrs[p.ID]
		ri := RouteIdentity{OrgID: orgs[p.ID], Model: holdoutModel}.Resolved()
		entry, err := store.GetExact(ctx, ri.OrgID, ri.Model, attr.cachedHash, ri.Version)
		require.NoError(t, err, p.ID)
		require.NotNil(t, entry, "%s: the writer must have persisted a row", p.ID)
		prov, _, ok := OpenEntry(entry.Response)
		require.True(t, ok, p.ID)
		assert.Equal(t, embeddings.QualifiedSpaceVersion(holdoutSpaceVer, attr.cachedTag), prov.EmbedVer,
			"%s: qualifier-extended space stamp", p.ID)
		assert.Equal(t, SemanticAdmissionVersion(), prov.ThresholdVer, "%s: epoch stamp", p.ID)
		assert.Equal(t, attr.cachedDec, prov.DecisiveFP, "%s: decisive fingerprint stamp", p.ID)
	}

	// Lookup phase: observable outcomes with the owning guard named.
	type outcome struct {
		hit   bool
		sim   float64
		cos   float64
		class string // TN | FP | FN-RESIDUAL | DEFECT
	}
	outcomes := map[string]outcome{}

	for _, p := range near {
		attr := attrs[p.ID]
		t.Run(p.ID, func(t *testing.T) {
			hit, err := svc.LookupWithResult(ctx, RouteIdentity{OrgID: orgs[p.ID], Model: holdoutModel}, []byte(p.Lookup))
			require.NoError(t, err, "%s: a replay lookup must never error", p.ID)

			out := outcome{cos: holdoutCosine(attr.cachedVec, attr.lookupVec)}
			if hit != nil {
				out.hit, out.sim = true, float64(hit.Similarity)
				// A hit must serve THIS pair's cached answer — anything else
				// would be cross-pair leakage (a defect, not a count).
				require.JSONEq(t, p.Answer, string(hit.Data),
					"%s: the served body must be the pair's own cached answer", p.ID)
				assert.GreaterOrEqual(t, float64(hit.Similarity), threshold,
					"%s: a hit below threshold is impossible — decision-path defect", p.ID)
			}

			switch {
			case hit == nil && !p.Residual:
				out.class = "TN"
				require.False(t, attr.sameDecisive(), "%s: structural miss must be decidable — stamps differ", p.ID)
				assert.GreaterOrEqual(t, out.cos, threshold,
					"%s: the threshold cannot have decided this miss (own-twin geometry admits) — the decisive guard owns it", p.ID)
				t.Logf("PIN %s [%s] own-twin cos=%.4f ≥ %.2f, stamps differ → decisive guard; observable MISS",
					p.ID, p.Class, out.cos, threshold)
			case hit == nil && p.Residual:
				out.class = "FN-RESIDUAL"
				t.Errorf("%s: residual dc2 pair (%s) unexpectedly missed — the documented residue did not manifest; update this corpus pin deliberately",
					p.ID, p.DC2Class)
			case p.Residual:
				out.class = "FP"
				require.Contains(t, n03p4t06DC2, p.DC2Class)
				t.Logf("PIN %s [%s|dc2 %s] sim=%.4f ≥ %.2f, stamps equal → documented ERRONEOUS REUSE (dc2 decision input); served own answer",
					p.ID, p.Class, p.DC2Class, out.sim, threshold)
			default:
				out.class = "DEFECT"
				t.Errorf("%s: structural pair HIT (sim=%.4f) though decisive stamps differ — decision-path defect",
					p.ID, out.sim)
			}
			outcomes[p.ID] = out
		})
	}

	// Confusion table: per class and totals — the boundary corpus's numbers.
	order := []string{holdoutClassNearDate, holdoutClassNearNumber, holdoutClassNearAccess, holdoutClassNearEntity}
	totals := map[string]int{}
	t.Logf("N03-P04-T07 per-pair boundary confusion (own org per pair, threshold %.2f):", threshold)
	for _, class := range order {
		tn, fp, other := 0, 0, 0
		for _, p := range near {
			if p.Class != class {
				continue
			}
			switch outcomes[p.ID].class {
			case "TN":
				tn++
			case "FP":
				fp++
			default:
				other++
			}
		}
		totals[class+":TN"] = tn
		totals[class+":FP"] = fp
		t.Logf("  %-12s TN=%d FP=%d other=%d", class, tn, fp, other)
		assert.Zero(t, other, "%s: every pair must resolve to TN or FP (or fail loudly above)", class)
		assert.Equal(t, map[string]int{holdoutClassNearDate: 9, holdoutClassNearNumber: 6, holdoutClassNearAccess: 3, holdoutClassNearEntity: 5}[class],
			tn+fp+other, "%s: replay must cover every pair of the class", class)
	}
	for _, class := range order {
		totals["TN"] += totals[class+":TN"]
		totals["FP"] += totals[class+":FP"]
	}
	assert.Equal(t, 16, totals["TN"], "structural pairs: observable MISS each")
	assert.Equal(t, 7, totals["FP"], "residual pairs: documented erroneous reuse each")
	t.Logf("TOTALS TN=%d FP=%d defects=0 (structural misses are guard-decided, residual hits are the documented dc2 residue)",
		totals["TN"], totals["FP"])
}
