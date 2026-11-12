package cache

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/embeddings"
)

// This suite pins the public lookup contract of CacheService.LookupWithResult
// (and the Lookup compatibility wrapper) as documented on the methods: a
// policy-disabled org, an enforcement-off regime and every degraded backend
// are misses (nil, nil) — never errors; only a failing backend store
// surfaces an error; an entry is served only under a provenance that matches
// the caller's route identity. Constructions are hermetic (no Redis, no
// Postgres) and independent of the fixtures in the existing gate suites.

// stubStore is a configurable BackendStore double: it returns one canned
// outcome per test and records that the exact layer consulted it.
type stubStore struct {
	entry         *Entry
	err           error
	getExactCalls int
	lastOrgID     string
	lastModel     string
}

func (s *stubStore) GetExact(ctx context.Context, orgID, modelTier, promptHash, modelVer string) (*Entry, error) {
	s.getExactCalls++
	s.lastOrgID = orgID
	s.lastModel = modelTier
	if s.err != nil {
		return nil, s.err
	}
	return s.entry, nil // mirrors Store.GetExact: nil entry + nil error = not found
}

func (s *stubStore) PurgeExpired(ctx context.Context) (int, error) { return 0, nil }

func (s *stubStore) PurgeExpiredWithLock(ctx context.Context) (int, bool, error) {
	return 0, false, nil
}

// recordingEmbedder is a configurable embeddings.Client double that records
// whether the lookup path reached the embedding stage at all.
type recordingEmbedder struct {
	calls int
	vec   []float32
	err   error
}

func (e *recordingEmbedder) Embed(ctx context.Context, text string) ([]float32, error) {
	e.calls++
	return e.vec, e.err
}

// newSemanticLookupService wires a hermetic CacheService: policy loader
// returns pol, the exact layer dials a refused port (instant miss), the
// semantic layer gets a nil pool (safe because the tests never let a
// non-empty embedding reach it), and lookups consult the stub store.
func newSemanticLookupService(pol OrgPolicy, store BackendStore, emb embeddings.Client) *CacheService {
	pc := NewPolicyCache(60 * time.Second)
	pc.loader = func(context.Context, string) (*OrgPolicy, error) {
		return &pol, nil
	}
	return &CacheService{
		exact:          NewRedisStore(refusedRedis(), 24*time.Hour),
		semantic:       NewSemanticCache(nil, 0, 0),
		store:          store,
		policy:         pc,
		embedder:       emb,
		log:            slogDiscard(),
		pgExactEnabled: true,
	}
}

func semanticBody() []byte {
	return []byte(`{"messages":[{"role":"user","content":"semantic contract"}]}`)
}

func semanticIdentity() RouteIdentity {
	return RouteIdentity{OrgID: "org-sem", Model: "gpt-sem"}
}

func semanticResponse() []byte {
	return []byte(`{"choices":[{"message":{"role":"assistant","content":"cached"}}]}`)
}

// sealedSemanticEntry seals resp under the given identity, as the product's
// write path would have stored it.
func sealedSemanticEntry(t *testing.T, resp []byte, ri RouteIdentity) *Entry {
	t.Helper()
	sealed, err := SealEntry(resp, ri.Resolved())
	require.NoError(t, err)
	return &Entry{OrgID: ri.OrgID, ModelTier: ri.Model, Response: sealed}
}

// A policy-disabled org is a miss, not an error, and touches no cache layer.
func TestSemanticLookupPrivacyDisabledIsMissAndReadsNothing(t *testing.T) {
	store := &stubStore{}
	emb := &recordingEmbedder{err: errors.New("must not be called")}
	cs := newSemanticLookupService(OrgPolicy{Mode: PrivacyDisabled, Semantic: true}, store, emb)

	hit, err := cs.LookupWithResult(context.Background(), semanticIdentity(), semanticBody())
	require.NoError(t, err)
	assert.Nil(t, hit, "privacy-disabled is a documented miss")
	assert.Zero(t, store.getExactCalls, "a disabled org must not be read from the store")
	assert.Zero(t, emb.calls, "a disabled org must not be embedded")
}

// With the policy-regime binding armed, an enforcement-off answer (empty
// fingerprint) gates the lookup before any cache layer is touched — the
// resolver itself is still consulted once.
func TestSemanticLookupEnforcementOffGatesBeforeAnyRead(t *testing.T) {
	store := &stubStore{}
	emb := &recordingEmbedder{err: errors.New("must not be called")}
	cs := newSemanticLookupService(OrgPolicy{Mode: PrivacyEnabled, Semantic: true}, store, emb)
	resolverCalls := 0
	cs.SetPolicyRegimeResolver(func(context.Context, string) string {
		resolverCalls++
		return ""
	})

	hit, err := cs.LookupWithResult(context.Background(), semanticIdentity(), semanticBody())
	require.NoError(t, err)
	assert.Nil(t, hit, "enforcement-off is a documented miss, not an error")
	assert.Equal(t, 1, resolverCalls, "the regime fingerprint must be resolved once per lookup")
	assert.Zero(t, store.getExactCalls, "an enforcement-off lookup must not read the store")
	assert.Zero(t, emb.calls, "an enforcement-off lookup must not be embedded")
}

// Under an armed resolver an org-less identity is gated before the resolver
// runs (no fingerprint may be requested for an identity that cannot own one).
func TestSemanticLookupOrglessIdentityIsGatedWithoutFingerprint(t *testing.T) {
	store := &stubStore{}
	emb := &recordingEmbedder{err: errors.New("must not be called")}
	cs := newSemanticLookupService(OrgPolicy{Mode: PrivacyEnabled, Semantic: true}, store, emb)
	resolverCalls := 0
	cs.SetPolicyRegimeResolver(func(context.Context, string) string {
		resolverCalls++
		return "regime-a"
	})

	ri := semanticIdentity()
	ri.OrgID = ""
	hit, err := cs.LookupWithResult(context.Background(), ri, semanticBody())
	require.NoError(t, err)
	assert.Nil(t, hit)
	assert.Zero(t, resolverCalls, "no fingerprint may be requested for an org-less identity")
	assert.Zero(t, store.getExactCalls)
}

// A cold lookup on every layer is a plain miss: the embedding stage runs,
// the store is consulted, nothing is served and no error is raised.
func TestSemanticLookupColdIsMiss(t *testing.T) {
	store := &stubStore{}
	emb := &recordingEmbedder{vec: []float32{}} // empty vector: semantic layer reports a miss
	cs := newSemanticLookupService(OrgPolicy{Mode: PrivacyEnabled, Semantic: true}, store, emb)

	hit, err := cs.LookupWithResult(context.Background(), semanticIdentity(), semanticBody())
	require.NoError(t, err)
	assert.Nil(t, hit)
	assert.Equal(t, 1, store.getExactCalls, "the exact layer must be consulted on a cold lookup")
	assert.Equal(t, 1, emb.calls, "the embedding stage must run for a semantic-enabled org")
	assert.Equal(t, "org-sem", store.lastOrgID, "the store must be consulted under the caller's org")
	assert.Equal(t, "gpt-sem", store.lastModel, "the store must be consulted under the caller's model")
}

// An embedding failure degrades the semantic stage to a miss; the exact
// layers were still consulted before it.
func TestSemanticLookupEmbedderFailureDegradesToMiss(t *testing.T) {
	store := &stubStore{}
	emb := &recordingEmbedder{err: errors.New("embedder down")}
	cs := newSemanticLookupService(OrgPolicy{Mode: PrivacyEnabled, Semantic: true}, store, emb)

	hit, err := cs.LookupWithResult(context.Background(), semanticIdentity(), semanticBody())
	require.NoError(t, err, "an embedder failure is a degraded miss, never a lookup error")
	assert.Nil(t, hit)
}

// An org without the semantic stage skips embedding entirely.
func TestSemanticLookupSemanticDisabledSkipsEmbedding(t *testing.T) {
	store := &stubStore{}
	emb := &recordingEmbedder{err: errors.New("must not be called")}
	cs := newSemanticLookupService(OrgPolicy{Mode: PrivacyEnabled, Semantic: false}, store, emb)

	hit, err := cs.LookupWithResult(context.Background(), semanticIdentity(), semanticBody())
	require.NoError(t, err)
	assert.Nil(t, hit)
	assert.Zero(t, emb.calls, "the embedding stage must not run for a non-semantic org")
	assert.Equal(t, 1, store.getExactCalls, "the exact layer still runs for a non-semantic org")
}

// Read-cache-only still performs lookups; the write side is gated elsewhere.
func TestSemanticLookupReadCacheOnlyStillLooksUp(t *testing.T) {
	store := &stubStore{}
	emb := &recordingEmbedder{vec: []float32{}}
	cs := newSemanticLookupService(OrgPolicy{Mode: PrivacyReadCacheOnly, Semantic: true}, store, emb)

	hit, err := cs.LookupWithResult(context.Background(), semanticIdentity(), semanticBody())
	require.NoError(t, err)
	assert.Nil(t, hit)
	assert.Equal(t, 1, store.getExactCalls, "read-cache-only must still read")
}

// A failing backend store is the only lookup outcome that surfaces an error.
func TestSemanticLookupStoreErrorIsSurfaced(t *testing.T) {
	boom := errors.New("store down")
	store := &stubStore{err: boom}
	emb := &recordingEmbedder{err: errors.New("must not be reached")}
	cs := newSemanticLookupService(OrgPolicy{Mode: PrivacyEnabled, Semantic: true}, store, emb)

	hit, err := cs.LookupWithResult(context.Background(), semanticIdentity(), semanticBody())
	assert.Nil(t, hit)
	require.ErrorIs(t, err, boom, "a store failure must propagate to the caller")
}

// A stored entry whose provenance matches the caller's route identity is
// served from the pg exact layer with similarity 1.0 and the recorded
// ModelUsed.
func TestSemanticLookupServesVerifiedEntryUnderMatchingIdentity(t *testing.T) {
	ri := semanticIdentity()
	store := &stubStore{entry: sealedSemanticEntry(t, semanticResponse(), ri)}
	emb := &recordingEmbedder{err: errors.New("exact hit must not embed")}
	cs := newSemanticLookupService(OrgPolicy{Mode: PrivacyEnabled, Semantic: true}, store, emb)

	hit, err := cs.LookupWithResult(context.Background(), ri, semanticBody())
	require.NoError(t, err)
	require.NotNil(t, hit, "a verified entry under the caller's identity must serve")
	assert.Equal(t, "pg_exact", hit.SourceType)
	assert.InDelta(t, 1.0, hit.Similarity, 1e-9)
	assert.Equal(t, "gpt-sem", hit.ModelUsed, "the served response is attributed to the recorded model")
	assert.JSONEq(t, string(semanticResponse()), string(hit.Data))
	assert.Zero(t, emb.calls, "an exact hit must not run the embedding stage")
}

// Foreign provenance (another org) is ignored in place: a miss, never an
// error and never a cross-tenant serve.
func TestSemanticLookupForeignEntryIsMiss(t *testing.T) {
	ri := semanticIdentity()
	other := ri
	other.OrgID = "org-other"
	store := &stubStore{entry: sealedSemanticEntry(t, semanticResponse(), other)}
	emb := &recordingEmbedder{vec: []float32{}}
	cs := newSemanticLookupService(OrgPolicy{Mode: PrivacyEnabled, Semantic: true}, store, emb)

	hit, err := cs.LookupWithResult(context.Background(), ri, semanticBody())
	require.NoError(t, err, "a foreign entry is a governed miss, not an error")
	assert.Nil(t, hit)
}

// Legacy raw payloads without a seal degrade to misses.
func TestSemanticLookupLegacyUnsealedEntryIsMiss(t *testing.T) {
	store := &stubStore{entry: &Entry{OrgID: "org-sem", ModelTier: "gpt-sem", Response: semanticResponse()}}
	emb := &recordingEmbedder{vec: []float32{}}
	cs := newSemanticLookupService(OrgPolicy{Mode: PrivacyEnabled, Semantic: true}, store, emb)

	hit, err := cs.LookupWithResult(context.Background(), semanticIdentity(), semanticBody())
	require.NoError(t, err)
	assert.Nil(t, hit)
}

// With the regime binding armed, the serving identity is composed with the
// regime fingerprint: an entry sealed under the plain identity stops
// serving, and an entry sealed under the composed identity serves.
func TestSemanticLookupRegimeRescopesServingIdentity(t *testing.T) {
	regime := func(context.Context, string) string { return "regime-a" }
	ri := semanticIdentity()
	plain := ri
	composed := ri
	composed.GenParams = composeRegimeGenParams("", "regime-a")

	cases := []struct {
		name  string
		entry *Entry
		want  string // "" = miss, else expected SourceType
	}{
		{
			name:  "entry sealed under the plain identity no longer serves",
			entry: sealedSemanticEntry(t, semanticResponse(), plain),
			want:  "",
		},
		{
			name:  "entry sealed under the regime-composed identity serves",
			entry: sealedSemanticEntry(t, semanticResponse(), composed),
			want:  "pg_exact",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &stubStore{entry: tc.entry}
			emb := &recordingEmbedder{err: errors.New("exact hits must not embed")}
			cs := newSemanticLookupService(OrgPolicy{Mode: PrivacyEnabled, Semantic: true}, store, emb)
			cs.SetPolicyRegimeResolver(regime)

			hit, err := cs.LookupWithResult(context.Background(), ri, semanticBody())
			require.NoError(t, err)
			if tc.want == "" {
				assert.Nil(t, hit, "a provenance mismatch under a valid regime is a governed miss")
				return
			}
			require.NotNil(t, hit)
			assert.Equal(t, tc.want, hit.SourceType)
		})
	}
}

// The compatibility wrapper reports a miss as (nil data, nil error).
func TestSemanticLookupWrapperReturnsMissAsNilData(t *testing.T) {
	store := &stubStore{}
	emb := &recordingEmbedder{vec: []float32{}}
	cs := newSemanticLookupService(OrgPolicy{Mode: PrivacyEnabled, Semantic: true}, store, emb)

	data, err := cs.Lookup(context.Background(), "org-sem", "gpt-sem", semanticBody())
	require.NoError(t, err)
	assert.Nil(t, data, "the wrapper must surface a miss as nil data, not an error")
}
