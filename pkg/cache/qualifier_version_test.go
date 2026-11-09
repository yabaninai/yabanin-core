package cache

// N03-P04-T03: separate multilingual domain and context qualifiers in the
// semantic cache.
//
// T02 made entries attributable to an embedding space (embed_ver) and an
// admission epoch (threshold_ver) with strict-equality matching. T03 binds
// the PER-INPUT multilingual/domain qualifier into that same space identity:
// the qualifier tag is derived deterministically from the prompt content
// (dominant script), it conditions the embedded text (prefix, like
// QueryPrefix) and it extends the stamped space version on both the write
// and the lookup path. Consequences proven below:
//   - a ru↔en near-duplicate pair can NEVER serve each other (different
//     qualifier → different space → miss), even when the embedder returns
//     the identical vector for both — separation does not depend on
//     embedder quality;
//   - same-language lookups still hit (the check does not over-invalidate);
//   - a qualifier-configuration change is a new epoch: entries stamped
//     under another qualifier configuration miss, and the writer under the
//     new configuration re-stamps so refills land in their own epoch (T02
//     semantics extended);
//   - the exact layers are hash-keyed and stay untouched (RT-05): an exact
//     hit is served exactly as before with qualifiers active.
//
// Docker-backed cases (testdb/redisContainer) skip in -short, mirroring
// embed_version_test.go. Each org holds at most one pgvector row with the
// shared fixed vector, so ANN row selection is deterministic and only the
// qualifier stamps can decide the outcome.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync/atomic"
	"testing"

	"github.com/reireirei/yabanin/pkg/embeddings"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// qualifierEmbedder is a qualifier-aware test embedder: fixed vector,
// explicit space identity, script qualification mirroring the production
// HTTPClient semantics (InputQualifierTag gates on the scripts flag and
// appends the domain). It records the inputs it was asked to embed so tests
// can prove the prefix reaches the embedder symmetrically on write and
// lookup.
type qualifierEmbedder struct {
	embeddings.StaticClient
	ver     string
	scripts bool
	domain  string

	lastInput atomic.Value // string: last text passed to Embed
}

func (s *qualifierEmbedder) SpaceVersion() string { return s.ver }

func (s *qualifierEmbedder) InputQualifierTag(text string) string {
	if !s.scripts {
		return ""
	}
	tag := embeddings.ScriptQualifier(text)
	if s.domain != "" {
		tag += ";d:" + s.domain
	}
	return tag
}

func (s *qualifierEmbedder) Embed(ctx context.Context, text string) ([]float32, error) {
	s.lastInput.Store(text)
	return s.StaticClient.Embed(ctx, text)
}

func (s *qualifierEmbedder) recordedInput() string {
	v, _ := s.lastInput.Load().(string)
	return v
}

// qualifierVec is the single shared vector: every embedder in these tests
// produces the SAME embedding, so only qualifier stamps can decide hits.
func qualifierVec() []float32 { return embedVerVec() }

// --- Unit: the shared derivation helpers (single point of truth) ------------

func TestQualifierSourceText_ExtractsMessageContent(t *testing.T) {
	// Content only — structural keys and model/org noise outside the
	// messages must not dilute the user's script in short prompts.
	body := `{"messages":[{"role":"system","content":"You are a helpful assistant"},{"role":"user","content":"Какой срок подачи квартального отчёта?"}],"model":"gpt-4o"}`
	got := qualifierSourceText([]byte(body))
	assert.Contains(t, got, "Какой срок подачи квартального отчёта?")
	assert.Contains(t, got, "You are a helpful assistant")
	assert.NotContains(t, got, `"messages"`)
	assert.NotContains(t, got, "gpt-4o")
	assert.Equal(t, "cyrl", embeddings.ScriptQualifier(got))

	// Determinism: same bytes in, same bytes out.
	assert.Equal(t, got, qualifierSourceText([]byte(body)))

	// Unparsable body falls back to the raw bytes (still deterministic).
	raw := `not json at all`
	assert.Equal(t, raw, qualifierSourceText([]byte(raw)))

	// JSON without a messages array falls back to the raw bytes.
	assert.Equal(t, `{"foo":1}`, qualifierSourceText([]byte(`{"foo":1}`)))

	// Non-string content entries are skipped; an all-empty result falls back
	// to the raw bytes.
	parts := `{"messages":[{"role":"user","content":[{"type":"text"}]}]}`
	assert.Equal(t, parts, qualifierSourceText([]byte(parts)))
}

func TestEmbedderInputTag_Dispatch(t *testing.T) {
	ru := "Какой срок подачи квартального отчёта?"
	ruPrompt := `{"messages":[{"role":"user","content":"` + ru + `"}]}`

	// Qualifier-aware embedder derives a script tag from the content.
	on := &qualifierEmbedder{StaticClient: embeddings.StaticClient{Embedding: qualifierVec()}, ver: "emb-space-a", scripts: true}
	assert.Equal(t, "cyrl", embedderInputTag(on, qualifierSourceText([]byte(ruPrompt))))

	// The same embedder with qualification off is tag-blind.
	off := &qualifierEmbedder{StaticClient: embeddings.StaticClient{Embedding: qualifierVec()}, ver: "emb-space-a", scripts: false}
	assert.Empty(t, embedderInputTag(off, qualifierSourceText([]byte(ruPrompt))))

	// Version-blind stubs (T02's spaceEmbedder) are qualifier-blind too.
	assert.Empty(t, embedderInputTag(&spaceEmbedder{StaticClient: embeddings.StaticClient{Embedding: qualifierVec()}, ver: "emb-space-a"}, ru))
	assert.Empty(t, embedderInputTag(nil, ru))
}

func TestQualifiedEmbedInput_IdentityOnEmptyTag(t *testing.T) {
	prompt := `{"messages":[{"role":"user","content":"hello"}]}`
	assert.Equal(t, prompt, qualifiedEmbedInput(prompt, ""), "an empty tag must keep the input byte-identical (pre-T03 behavior)")
	assert.Equal(t, "[q:cyrl] "+prompt, qualifiedEmbedInput(prompt, "cyrl"))
}

// --- Docker-backed negatives and controls -----------------------------------

const (
	qualifierPromptEN = `{"messages":[{"role":"user","content":"What is the deadline for filing the quarterly report submitted on 2025-03-31 for org %s?"}]}`
	// qualifierPromptRU is the translation near-duplicate of the EN prompt:
	// same question, same date, different language. A geometric similarity
	// check (or the fixed test vector below) would happily alias them; the
	// qualifier separation must not.
	qualifierPromptRU = `{"messages":[{"role":"user","content":"Какой срок подачи квартального отчёта, отправленного 31.03.2025 для org %s?"}]}`
	qualifierResponse = `{"id":"cmpl-qualifier","choices":[{"message":{"content":"answer-quarterly"}}]}`
)

// TestQualifier_CrossLanguageNearDuplicateIsMiss is the card negative: an
// entry written for an ENGLISH prompt must never answer the RUSSIAN
// near-duplicate. The embedder returns the identical vector for both, so the
// MISS can only come from the qualifier-separated space identity — exactly
// the guarantee the card asks for.
func TestQualifier_CrossLanguageNearDuplicateIsMiss(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Postgres(t)
	rdb := redisContainer(t)

	orgID := seedCacheOrg(t, pool, t.Name(), true, "semantic")
	promptEN := fmt.Sprintf(qualifierPromptEN, orgID)
	promptRU := fmt.Sprintf(qualifierPromptRU, orgID)

	// Entry stamped in the EN qualifier space of emb-space-a.
	plantSemanticEntry(t, ctx, NewStore(pool), orgID, promptEN, "emb-space-a|q:latn", embedVerTestThresholdVer)

	emb := &qualifierEmbedder{StaticClient: embeddings.StaticClient{Embedding: qualifierVec()}, ver: "emb-space-a", scripts: true}
	svc := NewCacheService(ctx, pool, rdb, emb, slog.New(slog.DiscardHandler), false)
	svc.SetOrgPolicyLoader(embedVerSemanticPolicy)

	// The lookup embeds the RU near-duplicate (same stored vector!), derives
	// tag "cyrl" and must refuse the "latn" entry.
	hit, err := svc.LookupWithResult(ctx, RouteIdentity{OrgID: orgID, Model: embedVerModel}, []byte(promptRU))
	require.NoError(t, err, "a qualifier mismatch is a miss, never an error")
	assert.Nil(t, hit, "a cross-language near-duplicate must not receive the other language's answer")
}

// TestQualifier_SameLanguageNearDuplicateHits is the positive control: the
// qualifier separation must not over-invalidate. The EN lookup against the
// EN entry derives the same "latn" tag and still hits semantically.
func TestQualifier_SameLanguageNearDuplicateHits(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Postgres(t)
	rdb := redisContainer(t)

	orgID := seedCacheOrg(t, pool, t.Name(), true, "semantic")
	promptEN := fmt.Sprintf(qualifierPromptEN, orgID)
	promptEN2 := `{"messages":[{"role":"user","content":"When is the deadline for filing the quarterly report submitted on 2025-03-31 for org ` + orgID + `?"}]}`

	plantSemanticEntry(t, ctx, NewStore(pool), orgID, promptEN, "emb-space-a|q:latn", embedVerTestThresholdVer)

	emb := &qualifierEmbedder{StaticClient: embeddings.StaticClient{Embedding: qualifierVec()}, ver: "emb-space-a", scripts: true}
	svc := NewCacheService(ctx, pool, rdb, emb, slog.New(slog.DiscardHandler), false)
	svc.SetOrgPolicyLoader(embedVerSemanticPolicy)

	// A same-language phrasing variant: exact miss (different hash), semantic hit.
	hit, err := svc.LookupWithResult(ctx, RouteIdentity{OrgID: orgID, Model: embedVerModel}, []byte(promptEN2))
	require.NoError(t, err)
	require.NotNil(t, hit, "same-language lookup must still hit its qualifier space")
	assert.Equal(t, "semantic", hit.SourceType)
	assert.JSONEq(t, embedVerResponseA, string(hit.Data), "the planted EN entry's answer must be served")
}

// TestQualifier_UnqualifiedEntryMissesQualifierLookup extends the T02
// upgrade path in the other direction: a qualifier-AWARE lookup treats a
// pre-T03 entry (stamped without a qualifier) as a foreign space — strict
// equality, self-healing miss.
func TestQualifier_UnqualifiedEntryMissesQualifierLookup(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Postgres(t)
	rdb := redisContainer(t)

	orgID := seedCacheOrg(t, pool, t.Name(), true, "semantic")
	promptEN := fmt.Sprintf(qualifierPromptEN, orgID)

	// Pre-T03 stamp: base version, no qualifier suffix.
	plantSemanticEntry(t, ctx, NewStore(pool), orgID, promptEN, "emb-space-a", embedVerTestThresholdVer)

	emb := &qualifierEmbedder{StaticClient: embeddings.StaticClient{Embedding: qualifierVec()}, ver: "emb-space-a", scripts: true}
	svc := NewCacheService(ctx, pool, rdb, emb, slog.New(slog.DiscardHandler), false)
	svc.SetOrgPolicyLoader(embedVerSemanticPolicy)

	hit, err := svc.LookupWithResult(ctx, RouteIdentity{OrgID: orgID, Model: embedVerModel}, []byte(promptEN))
	require.NoError(t, err)
	assert.Nil(t, hit, "an entry without a qualifier stamp must not be served by a qualifier-aware lookup")
}

// TestQualifier_QualifierConfigChangeIsMissAndRefill proves the T02
// semantics extend to the qualifier configuration. Two orgs keep the ANN
// selection deterministic (one row each, identical vectors):
//   - org ON: written with qualification on → stamped "emb-space-w|q:latn",
//     embedded input prefixed; a qualifier-OFF lookup of the same prompt is
//     a different epoch → miss;
//   - org OFF: written with qualification off → bare "emb-space-w" stamp,
//     unchanged input; the matching OFF epoch serves it, while a
//     qualifier-ON lookup of the same row misses.
func TestQualifier_QualifierConfigChangeIsMissAndRefill(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Postgres(t)
	rdb := redisContainer(t)

	orgOn := seedCacheOrg(t, pool, t.Name()+"-on", true, "semantic")
	orgOff := seedCacheOrg(t, pool, t.Name()+"-off", true, "semantic")
	promptOn := fmt.Sprintf(qualifierPromptEN, orgOn)
	promptOff := fmt.Sprintf(qualifierPromptEN, orgOff)

	// 1. The qualifier-ON writer stamps the qualified space AND prefixes the
	// embedded input.
	embOn := &qualifierEmbedder{StaticClient: embeddings.StaticClient{Embedding: qualifierVec()}, ver: "emb-space-w", scripts: true}
	w := NewWriter(ctx, pool, embOn, slog.New(slog.DiscardHandler))
	require.True(t, w.Submit(writerJob{orgID: orgOn, modelTier: embedVerModel, modelVer: RouteVersion, promptJSON: json.RawMessage(promptOn), response: json.RawMessage(qualifierResponse), tokensIn: 10, tokensOut: 5}))
	require.True(t, w.Stop())
	_, _, written := w.Stats()
	require.Equal(t, int64(1), written, "the qualified write must be persisted")
	assert.Equal(t, "[q:latn] "+string(normalizeForCache([]byte(promptOn))), embOn.recordedInput(),
		"the writer must condition the embedding input on the qualifier prefix")

	entry, err := NewStore(pool).GetSemantic(ctx, orgOn, embedVerModel, qualifierVec(), 1.0)
	require.NoError(t, err)
	require.NotNil(t, entry)
	prov, _, ok := OpenEntry(entry.Response)
	require.True(t, ok)
	assert.Equal(t, "emb-space-w|q:latn", prov.EmbedVer, "the writer must stamp the qualifier-extended space version")
	assert.Equal(t, SemanticAdmissionVersion(), prov.ThresholdVer)

	// 2. The same prompt under a qualifier-OFF service is a different epoch:
	// strict-equality miss, never the foreign-epoch entry.
	embOff := &qualifierEmbedder{StaticClient: embeddings.StaticClient{Embedding: qualifierVec()}, ver: "emb-space-w", scripts: false}
	svcOff := NewCacheService(ctx, pool, rdb, embOff, slog.New(slog.DiscardHandler), false)
	svcOff.SetOrgPolicyLoader(embedVerSemanticPolicy)
	hit, err := svcOff.LookupWithResult(ctx, RouteIdentity{OrgID: orgOn, Model: embedVerModel}, []byte(promptOn))
	require.NoError(t, err)
	assert.Nil(t, hit, "a qualifier-configuration change must start a new epoch (miss + refill)")

	// 3. The qualifier-OFF writer stamps the bare T02 version and embeds the
	// unchanged input — the refill lands in its own epoch.
	w2 := NewWriter(ctx, pool, embOff, slog.New(slog.DiscardHandler))
	require.True(t, w2.Submit(writerJob{orgID: orgOff, modelTier: embedVerModel, modelVer: RouteVersion, promptJSON: json.RawMessage(promptOff), response: json.RawMessage(qualifierResponse), tokensIn: 10, tokensOut: 5}))
	require.True(t, w2.Stop())
	entry2, err := NewStore(pool).GetSemantic(ctx, orgOff, embedVerModel, qualifierVec(), 1.0)
	require.NoError(t, err)
	require.NotNil(t, entry2)
	prov2, _, ok2 := OpenEntry(entry2.Response)
	require.True(t, ok2)
	assert.Equal(t, "emb-space-w", prov2.EmbedVer, "the qualifier-off writer must stamp the bare space version")
	assert.Equal(t, string(normalizeForCache([]byte(promptOff))), embOff.recordedInput(),
		"the qualifier-off writer must not change the embedding input")

	// 4. The refilled epoch serves its own configuration...
	hit2, err := svcOff.LookupWithResult(ctx, RouteIdentity{OrgID: orgOff, Model: embedVerModel}, []byte(promptOff))
	require.NoError(t, err)
	require.NotNil(t, hit2, "the refilled entry must serve its own epoch")
	assert.Equal(t, "semantic", hit2.SourceType)
	// Note: this semantic hit is promoted into the org's Redis exact layer
	// (read-through), so a hash-identical re-lookup would now be served by
	// the exact path. That is accepted behavior (RT-05): the exact layers
	// stay hash-keyed and qualifier-blind BY DESIGN — the qualifier tag is a
	// deterministic function of the same normalized bytes as the hash, so an
	// exact hit always implies the same qualifier; no cross-language
	// confusion is possible there.

	// 5. ...and a qualifier-ON lookup of the OFF-epoch row misses on the
	// semantic path (symmetry): a reworded EN variant has a different hash
	// (exact layers can't answer it) but the identical vector, so only the
	// strict space equality decides — "emb-space-w|q:latn" vs "emb-space-w".
	promptOffVariant := `{"messages":[{"role":"user","content":"Please tell me the filing deadline for the quarterly report submitted on 2025-03-31 for org ` + orgOff + `?"}]}`
	svcOn := NewCacheService(ctx, pool, rdb, embOn, slog.New(slog.DiscardHandler), false)
	svcOn.SetOrgPolicyLoader(embedVerSemanticPolicy)
	hit3, err := svcOn.LookupWithResult(ctx, RouteIdentity{OrgID: orgOff, Model: embedVerModel}, []byte(promptOffVariant))
	require.NoError(t, err)
	assert.Nil(t, hit3, "a qualifier-ON lookup must not semantically serve an unqualified epoch's entry")
}

// TestQualifier_ExactPathUnaffected_RT05 proves the qualifier treatment is
// semantic-path only: the exact layers are hash-keyed, and an exact hit is
// served exactly as before with qualifiers active — including the RT-05
// org boundary.
func TestQualifier_ExactPathUnaffected_RT05(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Postgres(t)
	rdb := redisContainer(t)

	orgID := seedCacheOrg(t, pool, t.Name(), true, "semantic")
	otherOrg := seedCacheOrg(t, pool, t.Name()+"-other", true, "semantic")
	promptEN := fmt.Sprintf(qualifierPromptEN, orgID)

	emb := &qualifierEmbedder{StaticClient: embeddings.StaticClient{Embedding: qualifierVec()}, ver: "emb-space-a", scripts: true}
	svc := NewCacheService(ctx, pool, rdb, emb, slog.New(slog.DiscardHandler), false)
	svc.SetOrgPolicyLoader(embedVerSemanticPolicy)

	require.NoError(t, svc.Write(ctx, RouteIdentity{OrgID: orgID, Model: embedVerModel}, []byte(promptEN), json.RawMessage(qualifierResponse), 10, 5))
	require.True(t, svc.writer.Stop(), "the writer must drain before lookups")

	// Same prompt, same org → exact hit, untouched by qualifier logic.
	hit, err := svc.LookupWithResult(ctx, RouteIdentity{OrgID: orgID, Model: embedVerModel}, []byte(promptEN))
	require.NoError(t, err)
	require.NotNil(t, hit)
	assert.Equal(t, "exact", hit.SourceType, "qualifiers must not degrade the exact path (RT-05)")

	// Same prompt bytes, DIFFERENT org → still a miss on every layer (RT-05
	// org boundary holds with qualifiers active).
	hitOther, err := svc.LookupWithResult(ctx, RouteIdentity{OrgID: otherOrg, Model: embedVerModel}, []byte(promptEN))
	require.NoError(t, err)
	assert.Nil(t, hitOther, "cross-org reuse must stay impossible with qualifiers active")
}

// TestQualifier_T02BlindBehaviorUnchanged is the regression contract for the
// existing fleet: with a qualifier-BLIND embedder (T02's spaceEmbedder), the
// full lookup flow must behave exactly as accepted in T02 — including the
// planted-stamp positive control.
func TestQualifier_T02BlindBehaviorUnchanged(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Postgres(t)
	rdb := redisContainer(t)

	orgID := seedCacheOrg(t, pool, t.Name(), true, "semantic")
	promptEN := fmt.Sprintf(qualifierPromptEN, orgID)

	plantSemanticEntry(t, ctx, NewStore(pool), orgID, promptEN, "emb-space-a", embedVerTestThresholdVer)

	emb := &spaceEmbedder{StaticClient: embeddings.StaticClient{Embedding: qualifierVec()}, ver: "emb-space-a"}
	svc := NewCacheService(ctx, pool, rdb, emb, slog.New(slog.DiscardHandler), false)
	svc.SetOrgPolicyLoader(embedVerSemanticPolicy)

	hit, err := svc.LookupWithResult(ctx, RouteIdentity{OrgID: orgID, Model: embedVerModel}, []byte(promptEN))
	require.NoError(t, err)
	require.NotNil(t, hit, "qualifier-blind embedders must keep the exact T02 behavior (same-space hit)")
	assert.Equal(t, "semantic", hit.SourceType)
}
