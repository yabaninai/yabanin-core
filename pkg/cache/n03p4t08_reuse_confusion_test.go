package cache

// Recovery × admission intersection for the semantic cache: the repeat &
// recovery axis of n03p4t08_repeat_recovery_test.go crossed with the
// near-miss admission corpus frozen by n03p4t06_joint_scenario_test.go and
// n03p4t07_boundary_corpus_test.go. The existing repeat/recovery pins cover
// SAME-prompt retry/resume; this file pins what happens when the retried
// write or the resumed lookup is a DIFFERENT prompt — one decisive field
// apart (a date, a number, an access marker):
//
//   - a retried write with a CORRECTED prompt must not resurrect, overwrite
//     or be absorbed by the interrupted original: the outage heals exactly
//     one row for the original, the corrected prompt misses on the
//     decisive-content guard and lands its own row, and afterwards each
//     prompt is served its own answer through the semantic path;
//   - a NEAR-MISS lookup resumed while the interrupted original's detached
//     embedding flight is still parked must open its OWN flight (distinct
//     normalized hashes are distinct flight keys), be rejected by the
//     decisive-content guard, and leave no poisoned flights behind — while
//     the original's entry stays intact and servable;
//   - a full write-outage recovery must preserve provenance (qualified
//     space stamp, admission epoch, decisive fingerprint) and reproduce the
//     corpus confusion split on the recovery axis: structural pairs stay
//     guard-owned misses and the seven documented dc2-blind reuses still
//     manifest, with the examples the packet report needs.
//
// REAL/MOCK split (honest, same seams as the repeat/recovery file): REAL =
// Postgres/pgvector + Redis through the testdb containers and the real
// Write/LookupWithResult seams; MOCK = the embedder only (qualified flaky /
// gated wrappers around the deterministic holdout stub). Unlike the
// version-blind wrappers of the repeat/recovery file, these wrappers embed
// holdoutEmbedder, so SpaceVersion() and InputQualifierTag() resolve exactly
// as on the healthy path: every row carries the qualified space stamp the
// lookups SpaceMatch against, and a miss is attributable to the
// decisive-content guard — never to a space mismatch or a threshold
// artifact.

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	pgxpool "github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/embeddings"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Fixtures: qualified flaky/gated embedders, per-pair org, changed answer
// ---------------------------------------------------------------------------

// n03p4t08RecoverFlaky fails the first failsRemaining Embed calls (the
// embedder outage window of a recovery replay) and then serves the SAME
// qualified holdout geometry as the healthy path: the embedded
// holdoutEmbedder resolves SpaceVersion() and InputQualifierTag(), so every
// row written after recovery carries the qualified space stamp.
type n03p4t08RecoverFlaky struct {
	holdoutEmbedder
	failsRemaining atomic.Int64
	calls          atomic.Int64
}

func (e *n03p4t08RecoverFlaky) Embed(_ context.Context, text string) ([]float32, error) {
	c := e.calls.Add(1)
	if e.failsRemaining.Load() > 0 {
		e.failsRemaining.Add(-1)
		return nil, fmt.Errorf("n03p4t08: embedder outage (call %d)", c)
	}
	return holdoutEmbedText(text), nil
}

// n03p4t08GatedHoldout parks every Embed call on gate (honouring the given
// context) and then serves the SAME qualified holdout geometry as the
// healthy path — the interruption point for the near-miss resume pin.
type n03p4t08GatedHoldout struct {
	holdoutEmbedder
	gate  chan struct{}
	calls atomic.Int64
}

func (e *n03p4t08GatedHoldout) Embed(ctx context.Context, text string) ([]float32, error) {
	e.calls.Add(1)
	select {
	case <-e.gate:
		return holdoutEmbedText(text), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

var (
	_ embeddings.Client         = &n03p4t08RecoverFlaky{}
	_ embeddings.SpaceVersioner = &n03p4t08RecoverFlaky{}
	_ embeddings.InputQualifier = &n03p4t08RecoverFlaky{}
	_ embeddings.Client         = &n03p4t08GatedHoldout{}
	_ embeddings.SpaceVersioner = &n03p4t08GatedHoldout{}
	_ embeddings.InputQualifier = &n03p4t08GatedHoldout{}
)

// n03p4t08ReuseOrg seeds a per-pair org under a unique name (unique slug)
// and purges its cache_entries rows on cleanup; no FK ties cache_entries to
// organizations, so the entry purge is this helper's own responsibility.
func n03p4t08ReuseOrg(ctx context.Context, t *testing.T, pool *pgxpool.Pool, name string) string {
	t.Helper()
	orgID := n03p4t07SeedOrg(ctx, t, pool, name)
	t.Cleanup(func() { //nolint:contextcheck // fixture owns its context lifetime: cleanup fires after the test ctx may be canceled (seedCacheOrg idiom)
		_, _ = pool.Exec(context.Background(), "DELETE FROM cache_entries WHERE org_id::text = $1", orgID)
	})
	return orgID
}

// n03p4t08ChangedAnswer seals a distinct response under the corrected
// prompt: any cross-serving would return the original's body instead.
func n03p4t08ChangedAnswer(id string) string {
	return fmt.Sprintf(`{"id":"cmpl-n03p4t08-changed-%s","choices":[{"message":{"content":"changed answer for %s"}}]}`, id, id)
}

// ---------------------------------------------------------------------------
// Unit pin (always-on, -short safe): identity separation over the whole
// near-miss corpus
// ---------------------------------------------------------------------------

// TestN03P04T08_ReuseCorpusFlightAndStampSeparation pins, for every pair of
// the frozen near-miss corpus, the identity facts the recovery pins rely on:
// cached and lookup prompts hash differently (the SAME normalized hash keys
// both the exact layer and the embedding flight table, so hash separation is
// flight separation — a resumed lookup of a different prompt can never join
// the interrupted original's flight by construction, including the residual
// pairs whose DECISIVE stamps collide); structural pairs differ on the
// decisive stamp at admitted geometry (the guard owns the miss), residual
// pairs collide on it (the documented reuse). The printed counts and the
// seven residual examples are the recovery report's corpus-side baseline.
func TestN03P04T08_ReuseCorpusFlightAndStampSeparation(t *testing.T) {
	near := n03p4t07NearMiss()
	attrs := n03p4t06Attrs(holdoutEmbedder{}, near)
	threshold := float64(DefaultSimilarityThreshold)

	require.Len(t, near, 23)
	structural, residual := 0, 0
	perClass := map[string]int{}
	var residualIDs []string

	for _, p := range near {
		attr := attrs[p.ID]

		require.NotEqual(t, attr.cachedHash, attr.lookupHash,
			"%s: cached and lookup prompts must hash differently — this one hash keys both the exact layer and the embed-flight table", p.ID)

		if p.Residual {
			residual++
			residualIDs = append(residualIDs, p.ID)
			require.Contains(t, n03p4t06DC2, p.DC2Class,
				"%s: residual pair must name a documented dc2 class", p.ID)
			require.True(t, attr.sameDecisive(),
				"%s: residual pair must collide on the decisive stamp — that is what makes its reuse documented", p.ID)
		} else {
			structural++
			require.False(t, attr.sameDecisive(),
				"%s: structural pair must differ on the decisive stamp — the guard must own the miss", p.ID)
			assert.GreaterOrEqual(t, holdoutCosine(attr.cachedVec, attr.lookupVec), threshold,
				"%s: structural pair must stay above the admission threshold so the guard, not the threshold, owns the miss", p.ID)
		}
		perClass[p.Class]++
	}

	require.Equal(t, 16, structural)
	require.Equal(t, 7, residual)
	assert.Equal(t, map[string]int{
		holdoutClassNearDate:   9,
		holdoutClassNearNumber: 6,
		holdoutClassNearAccess: 3,
		holdoutClassNearEntity: 5,
	}, perClass)

	for _, id := range residualIDs {
		for _, p := range near {
			if p.ID == id {
				t.Logf("RESIDUAL reuse example: id=%s class=%s dc2=%s (%s) — stamps equal, the lookup is served the cached answer",
					p.ID, p.Class, p.DC2Class, n03p4t06DC2[p.DC2Class])
			}
		}
	}
	t.Logf("REUSE/RECOVERY corpus separation: pairs=%d structural=%d residual=%d per_class=date:%d number:%d access:%d entity:%d flight_and_exact_keys=distinct_for_all",
		len(near), structural, residual, perClass[holdoutClassNearDate], perClass[holdoutClassNearNumber],
		perClass[holdoutClassNearAccess], perClass[holdoutClassNearEntity])
}

// ---------------------------------------------------------------------------
// Docker pins: recovery × admission on the write side, lookup side, and the
// full recovery confusion replay
// ---------------------------------------------------------------------------

// n03p4t08ChangedRetryPairs selects one structural pair per decisive class
// (date / number / access marker) for the changed-retry walk.
func n03p4t08ChangedRetryPairs(t *testing.T) []n03p4t06Pair {
	t.Helper()
	want := map[string]bool{"nd-en-iso": true, "nn-en-decimal": true, "na-en-marker": true}
	var pairs []n03p4t06Pair
	for _, p := range n03p4t07NearMiss() {
		if want[p.ID] {
			pairs = append(pairs, p)
		}
	}
	require.Len(t, pairs, 3)
	return pairs
}

// TestN03P04T08_ChangedRetryNoCrossReuse walks the recovery × admission
// intersection on the WRITE side: a client whose first write died inside an
// embedder outage retries with a CORRECTED prompt (one decisive field
// changed). The corrected retry must not resurrect, overwrite or be absorbed
// by the interrupted original: the outage resolves every retry failed with
// zero rows, the healed retry lands exactly the original's row, the
// corrected prompt misses on the decisive-content guard, then lands its OWN
// row — and after the exact copies are dropped, each prompt is served
// exactly its own answer through the semantic path, never the other's.
func TestN03P04T08_ChangedRetryNoCrossReuse(t *testing.T) {
	pool := testdb.Postgres(t)
	rdb := redisContainer(t)

	for _, p := range n03p4t08ChangedRetryPairs(t) {
		t.Run(p.ID, func(t *testing.T) {
			ctx := context.Background()
			orgID := n03p4t08ReuseOrg(ctx, t, pool, "n03p4t08-chg-"+p.ID)
			attr := n03p4t06Attrs(holdoutEmbedder{}, []n03p4t06Pair{p})[p.ID]
			ri := RouteIdentity{OrgID: orgID, Model: holdoutModel}
			resolved := ri.Resolved()
			corrAnswer := json.RawMessage(n03p4t08ChangedAnswer(p.ID))
			rows := func(hash string) int64 {
				return n03p4t08RowCount(ctx, t, pool, orgID, ri.Model, hash, resolved.Version)
			}

			// Outage: three retries of the ORIGINAL prompt, all dying at the
			// embedder seam — nothing persists under either hash and the
			// writer resolves every job failed closed.
			flaky := &n03p4t08RecoverFlaky{}
			flaky.failsRemaining.Store(3)
			svcOut := n03p4t08Service(ctx, t, pool, rdb, flaky)
			for i := 0; i < 3; i++ {
				require.NoError(t, svcOut.Write(ctx, ri, []byte(p.Cached), json.RawMessage(p.Answer), 10, 5))
			}
			require.True(t, svcOut.writer.Stop(), "drain must complete")
			q, d, w := svcOut.writer.Stats()
			f, _ := svcOut.writer.OutcomeStats()
			require.EqualValues(t, 3, q)
			require.Zero(t, d)
			require.Zero(t, w, "the outage must resolve every retried write failed")
			require.EqualValues(t, 3, f)
			require.EqualValues(t, 3, flaky.calls.Load(), "each retry surfaced the outage exactly once — no internal write retry")
			require.Zero(t, rows(attr.cachedHash), "no row may survive the outage")
			require.Zero(t, rows(attr.lookupHash))

			// Heal: the fourth retry (the SAME original prompt) restores
			// exactly one row — the outage never promoted the corrected one.
			svc := n03p4t08Service(ctx, t, pool, rdb, flaky)
			require.NoError(t, svc.Write(ctx, ri, []byte(p.Cached), json.RawMessage(p.Answer), 10, 5))
			require.True(t, svc.writer.Stop(), "drain must complete")
			_, _, w = svc.writer.Stats()
			require.EqualValues(t, 1, w)
			require.EqualValues(t, 1, rows(attr.cachedHash))
			require.Zero(t, rows(attr.lookupHash))

			// Negative control: the corrected prompt must miss — only the
			// original's row exists and the decisive stamps differ. (The
			// lookups run on the heal service; its writer is drained but a
			// stopped writer only stops accepting WRITES.)
			hit, lerr := svc.LookupWithResult(ctx, ri, []byte(p.Lookup))
			require.NoError(t, lerr)
			require.Nil(t, hit, "the corrected prompt must not be served the original's answer before its own write")

			// The corrected retry lands its OWN row (a fresh service: the
			// drained heal writer no longer accepts jobs): no overwrite of
			// the original, no absorption into it.
			svcCorr := n03p4t08Service(ctx, t, pool, rdb, flaky)
			require.NoError(t, svcCorr.Write(ctx, ri, []byte(p.Lookup), corrAnswer, 10, 5))
			require.True(t, svcCorr.writer.Stop(), "drain must complete")
			_, _, w = svcCorr.writer.Stats()
			require.EqualValues(t, 1, w)
			require.EqualValues(t, 1, rows(attr.cachedHash), "the corrected retry must not touch the original's row")
			require.EqualValues(t, 1, rows(attr.lookupHash))

			// Drop the exact copies so both lookups take the semantic path:
			// each prompt must be served its OWN answer, never the other's.
			require.NoError(t, svcCorr.Delete(ctx, orgID, ri.Model, []byte(p.Cached)))
			require.NoError(t, svcCorr.Delete(ctx, orgID, ri.Model, []byte(p.Lookup)))
			hitC, lerrC := svcCorr.LookupWithResult(ctx, ri, []byte(p.Cached))
			require.NoError(t, lerrC)
			require.NotNil(t, hitC)
			require.Equal(t, "semantic", hitC.SourceType)
			require.JSONEq(t, p.Answer, string(hitC.Data), "the original prompt must be served its own answer")
			require.GreaterOrEqual(t, hitC.Similarity, float32(DefaultSimilarityThreshold))
			hitL, lerrL := svcCorr.LookupWithResult(ctx, ri, []byte(p.Lookup))
			require.NoError(t, lerrL)
			require.NotNil(t, hitL)
			require.Equal(t, "semantic", hitL.SourceType)
			require.JSONEq(t, string(corrAnswer), string(hitL.Data), "the corrected prompt must be served its own answer")
			require.GreaterOrEqual(t, hitL.Similarity, float32(DefaultSimilarityThreshold))
			t.Logf("PIN changed-retry %s: outage_failed=3 rows_during_outage=0 healed_rows=1 corrected_rows=1 cross_served=0 own_answers=2", p.ID)
		})
	}
}

// TestN03P04T08_NearMissResumeOwnFlight walks the recovery × admission
// intersection on the LOOKUP side: a caller cancelled mid-embedding of its
// own prompt, then a NEAR-MISS prompt (one decisive field apart) resumes
// while the original's detached flight is still parked on the embedder. The
// resumed prompt must open its OWN flight — distinct normalized hashes are
// distinct flight keys, so it cannot join the abandoned flight even while
// that flight still occupies a table slot — and the decisive-content guard,
// not the threshold, must reject it against the original's row. No poisoned
// flights may survive, and the original's entry must stay intact and
// servable afterwards.
func TestN03P04T08_NearMissResumeOwnFlight(t *testing.T) {
	pool := testdb.Postgres(t)
	rdb := redisContainer(t)

	for _, p := range n03p4t08ChangedRetryPairs(t) {
		t.Run(p.ID, func(t *testing.T) {
			ctx := context.Background()
			orgID := n03p4t08ReuseOrg(ctx, t, pool, "n03p4t08-res-"+p.ID)
			attr := n03p4t06Attrs(holdoutEmbedder{}, []n03p4t06Pair{p})[p.ID]
			ri := RouteIdentity{OrgID: orgID, Model: holdoutModel}
			resolved := ri.Resolved()

			// Seed the original entry, then drop its exact copy so the
			// interrupted lookup takes the semantic path. Seed and lookup
			// embedders BOTH resolve the qualified holdout geometry (same
			// space family, same tags), so the space stamps match and the
			// decisive guard owns the near-miss outcome below.
			svcSeed := n03p4t08Service(ctx, t, pool, rdb, holdoutEmbedder{})
			require.NoError(t, svcSeed.Write(ctx, ri, []byte(p.Cached), json.RawMessage(p.Answer), 10, 5))
			require.True(t, svcSeed.writer.Stop(), "seed drain must complete")
			require.EqualValues(t, 1, n03p4t08RowCount(ctx, t, pool, orgID, ri.Model, attr.cachedHash, resolved.Version))
			require.NoError(t, svcSeed.Delete(ctx, orgID, ri.Model, []byte(p.Cached)))

			gated := &n03p4t08GatedHoldout{gate: make(chan struct{})}
			svc := n03p4t08Service(ctx, t, pool, rdb, gated)

			type lookupRes struct {
				hit *CacheHit
				err error
			}

			// Caller A: cancelled mid-embedding — the documented local miss.
			ctxA, cancelA := context.WithCancel(ctx)
			doneA := make(chan lookupRes, 1)
			go func() {
				hit, err := svc.LookupWithResult(ctxA, ri, []byte(p.Cached))
				doneA <- lookupRes{hit: hit, err: err}
			}()
			waitFor(t, func() bool { return gated.calls.Load() == 1 }, 2*time.Second)
			cancelA()
			resA := <-doneA
			require.NoError(t, resA.err, "a cancelled lookup degrades to a miss, never an error")
			require.Nil(t, resA.hit)
			// A's detached flight stays parked in the table (the load runs on
			// a context detached from A's cancellation) — that parked slot is
			// exactly the temptation the resumed near-miss must not join.

			// Caller B: the near-miss prompt resumes. It must open a SECOND
			// flight: its embed call runs, and both flights occupy the table.
			// (waiting() counts only JOINED callers — a creator never shows —
			// so flight separation is pinned by the table size plus the empty
			// waiter counts, and would read active()==1 with a joined waiter
			// if the resumed prompt ever joined the abandoned flight.)
			doneB := make(chan lookupRes, 1)
			go func() {
				hit, err := svc.LookupWithResult(ctx, ri, []byte(p.Lookup))
				doneB <- lookupRes{hit: hit, err: err}
			}()
			waitFor(t, func() bool { return gated.calls.Load() == 2 }, 2*time.Second)
			require.Equal(t, 2, svc.embedFlight.active(), "the resumed near-miss prompt owns a separate flight")
			require.EqualValues(t, 0, svc.embedFlight.waiting(attr.cachedHash), "nobody joined the abandoned original flight")
			require.EqualValues(t, 0, svc.embedFlight.waiting(attr.lookupHash), "nobody joined the resumed prompt's own flight either")

			// Both flights resolve. B's admission walk finds the original's
			// row above the threshold — the decisive-content guard must
			// reject it; the resumed near-miss is never served A's answer.
			close(gated.gate)
			resB := <-doneB
			require.NoError(t, resB.err)
			require.Nil(t, resB.hit, "a near-miss prompt resumed after a cancellation must not be served the original's answer")
			waitFor(t, func() bool { return svc.embedFlight.active() == 0 }, 2*time.Second)

			// The original's entry survived the resume attempt untouched.
			hitOwn, lerrOwn := svc.LookupWithResult(ctx, ri, []byte(p.Cached))
			require.NoError(t, lerrOwn)
			require.NotNil(t, hitOwn)
			require.Equal(t, "semantic", hitOwn.SourceType)
			require.JSONEq(t, p.Answer, string(hitOwn.Data))
			require.GreaterOrEqual(t, hitOwn.Similarity, float32(DefaultSimilarityThreshold))

			// And the near-miss outcome is stable, not a race artifact.
			hitB2, lerrB2 := svc.LookupWithResult(ctx, ri, []byte(p.Lookup))
			require.NoError(t, lerrB2)
			require.Nil(t, hitB2)
			t.Logf("PIN near-miss-resume %s: cancelled=1 resumed_flights_joined=0 flights_peak=2 foreign_answers=0 own_entry_intact=true resumed_miss_stable=true cos=%.4f",
				p.ID, holdoutCosine(attr.cachedVec, attr.lookupVec))
		})
	}
}

// TestN03P04T08_RecoveryConfusionReplay replays the WHOLE frozen near-miss
// corpus through a recovery: every cached write first dies inside an
// embedder outage (the retry axis), then heals via the retried Write seam,
// and only then faces its near-miss lookup. The report separates guard-owned
// misses (structural) from the documented dc2-blind reuses (residual): a
// structural pair served after recovery is a defect; a residual pair must
// still be served the pair's OWN cached answer; a residual pair that missed
// anyway is an honest TN (the residue did not manifest under this geometry).
// This proves the erroneous-reuse examples the packet report needs manifest
// AFTER a full write-outage recovery, not only on the healthy path.
func TestN03P04T08_RecoveryConfusionReplay(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Postgres(t)
	rdb := redisContainer(t)

	near := n03p4t07NearMiss()
	attrs := n03p4t06Attrs(holdoutEmbedder{}, near)
	require.Len(t, near, 23)

	orgs := make(map[string]string, len(near))
	for _, p := range near {
		orgs[p.ID] = n03p4t08ReuseOrg(ctx, t, pool, "n03p4t08-rec-"+p.ID)
	}

	// Outage: every write dies at the embedder seam — nothing persists.
	flaky := &n03p4t08RecoverFlaky{}
	flaky.failsRemaining.Store(int64(len(near)))
	svcOut := n03p4t08Service(ctx, t, pool, rdb, flaky)
	for _, p := range near {
		ri := RouteIdentity{OrgID: orgs[p.ID], Model: holdoutModel}
		require.NoError(t, svcOut.Write(ctx, ri, []byte(p.Cached), json.RawMessage(p.Answer), 10, 5))
	}
	require.True(t, svcOut.writer.Stop(), "outage drain must complete")
	q, d, w := svcOut.writer.Stats()
	f, _ := svcOut.writer.OutcomeStats()
	require.EqualValues(t, len(near), q)
	require.Zero(t, d)
	require.Zero(t, w, "the outage must resolve every write failed closed — no half-entries")
	require.EqualValues(t, len(near), f)
	for _, p := range near {
		ri := RouteIdentity{OrgID: orgs[p.ID], Model: holdoutModel}.Resolved()
		require.Zero(t, n03p4t08RowCount(ctx, t, pool, orgs[p.ID], ri.Model, attrs[p.ID].cachedHash, ri.Version),
			"%s: no row may survive the outage", p.ID)
	}

	// Heal: one retried write per pair lands exactly one row per org.
	svc := n03p4t08Service(ctx, t, pool, rdb, flaky)
	for _, p := range near {
		ri := RouteIdentity{OrgID: orgs[p.ID], Model: holdoutModel}
		require.NoError(t, svc.Write(ctx, ri, []byte(p.Cached), json.RawMessage(p.Answer), 10, 5))
	}
	require.True(t, svc.writer.Stop(), "heal drain must complete")
	_, _, w = svc.writer.Stats()
	f, _ = svc.writer.OutcomeStats()
	require.EqualValues(t, len(near), w)
	require.Zero(t, f)

	// Receipts: every recovered row carries the qualified space stamp, the
	// admission epoch and the decisive fingerprint the lookups compare
	// against — a recovery must not degrade provenance.
	store := NewStore(pool)
	for _, p := range near {
		attr := attrs[p.ID]
		ri := RouteIdentity{OrgID: orgs[p.ID], Model: holdoutModel}.Resolved()
		entry, err := store.GetExact(ctx, ri.OrgID, ri.Model, attr.cachedHash, ri.Version)
		require.NoError(t, err, p.ID)
		require.NotNil(t, entry, "%s: the healed write must have persisted a row", p.ID)
		prov, _, ok := OpenEntry(entry.Response)
		require.True(t, ok, p.ID)
		assert.Equal(t, embeddings.QualifiedSpaceVersion(holdoutSpaceVer, attr.cachedTag), prov.EmbedVer,
			"%s: recovered row must carry the qualifier-extended space stamp", p.ID)
		assert.Equal(t, SemanticAdmissionVersion(), prov.ThresholdVer,
			"%s: recovered row must carry the current admission epoch", p.ID)
		assert.Equal(t, DecisiveContentVer, prov.DecisiveVer,
			"%s: recovered row must carry the decisive-content detector version", p.ID)
		assert.Equal(t, attr.cachedDec, prov.DecisiveFP,
			"%s: recovered row must carry the decisive fingerprint of the normalized cached prompt", p.ID)
	}

	// Lookup phase: the confusion counts on the recovery axis, same labeling
	// contract as the joint scenario file (structural hit = defect,
	// residual hit = documented FP with the pair's own answer, residual
	// miss = honest TN).
	threshold := float64(DefaultSimilarityThreshold)
	tn, fp, defects := 0, 0, 0
	for _, p := range near {
		attr := attrs[p.ID]
		ri := RouteIdentity{OrgID: orgs[p.ID], Model: holdoutModel}
		cos := holdoutCosine(attr.cachedVec, attr.lookupVec)
		hit, lerr := svc.LookupWithResult(ctx, ri, []byte(p.Lookup))
		require.NoError(t, lerr, "%s: a replay lookup must never error", p.ID)
		switch {
		case hit != nil && p.Residual:
			fp++
			require.JSONEq(t, p.Answer, string(hit.Data),
				"%s: even a documented reuse must serve the pair's own cached answer", p.ID)
			t.Logf("FP (documented erroneous reuse): id=%s class=%s dc2=%s (%s) sim=%.4f cos=%.4f — stamps equal, the recovery-served answer IS the erroneous one",
				p.ID, p.Class, p.DC2Class, n03p4t06DC2[p.DC2Class], hit.Similarity, cos)
		case hit != nil:
			defects++
			t.Errorf("%s: structural near-miss HIT after recovery (source=%s sim=%.4f) — the decisive-content guard must own this miss",
				p.ID, hit.SourceType, hit.Similarity)
		case p.Residual:
			tn++
			t.Logf("TN: id=%s dc2=%s did not manifest after recovery (cos=%.4f < %.2f)", p.ID, p.DC2Class, cos, threshold)
		default:
			tn++
			assert.GreaterOrEqual(t, cos, threshold,
				"%s: a guard-owned miss requires admitted geometry (cos %.4f)", p.ID, cos)
			t.Logf("TN (guard-owned): id=%s class=%s cos=%.4f — decisive stamps differ", p.ID, p.Class, cos)
		}
	}

	t.Logf("RECOVERY-AXIS CONFUSION (pairs=%d, threshold=%.2f): TN=%d FP=%d defects=%d — %d documented erroneous reuses served after a full write-outage recovery",
		len(near), threshold, tn, fp, defects, fp)
	require.Zero(t, defects, "no structural pair may be served after recovery")
	require.Equal(t, 7, fp,
		"the seven documented dc2-blind reuses must still manifest after recovery (a change here means the corpus geometry or the detector moved — re-pin deliberately)")
	require.Equal(t, 16, tn, "guard-owned misses")
}
