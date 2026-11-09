package cache

// N03-P04-T08: semantic-cache quality — repeat & recovery ("Повтор и
// восстановление"). The card pins interruption/retry/resume and result
// recovery WITHOUT duplicates and losses on the semantic-cache write/lookup
// path, with the confusion-style counts the packet report needs.
//
// DISTINCTNESS (no existing corpus is duplicated or weakened):
//   - T06 (n03p4t06_joint_scenario_test.go) owns the joint 30-pair confusion
//     scenario; T07 (n03p4t07_boundary_corpus_test.go) owns the threshold/
//     qualifier/near-miss boundary edges. Both freeze admission GUARDS; this
//     file freezes the REPEAT/RECOVERY behavior of the write+lookup pipeline:
//     retried writes, interrupted writes, interrupted lookups.
//   - n03p5t08_recovery_test.go (packet N03-P05) owns invalidation/stampede
//     recovery (partition flights, leadership mandates, lock round-trips).
//     This file never touches invalidation or stampede machinery.
//
// Pins (each with an observable outcome, never a vacuous assertion):
//
//	(1) repeat — a retried identical Write (client resend after timeout,
//	    sequential and concurrent) resolves to EXACTLY ONE pgvector row (the
//	    uq_cache_exact upsert), ONE exact-layer key and byte-identical sealed
//	    payloads; hit_count survives a rewrite (no counter loss), created_at
//	    is preserved, expires_at is refreshed — recorded factually.
//	(2) interruption (embedder outage) — the write fails closed: NO
//	    half-entry (embedding is NOT NULL and vectorToSQL rejects empty
//	    vectors, so a vector-less row cannot persist), the exact layer
//	    already holds the sealed response (client loss-free), the writer
//	    counts the job failed; after recovery the RETRIED write heals the
//	    semantic layer via upsert with zero duplicate rows.
//	(3) interruption (DB outage, writer seam) — same shape via a flaky
//	    entryStore: exact layer serves during the outage; the retry after
//	    recovery restores the semantic layer without duplicates or losses.
//	(4) lookup interruption/resume — a caller cancelled mid-embedding gets
//	    the documented local miss; the detached shared flight completes; a
//	    resumed caller joins the SAME flight and is served the written
//	    answer with NO second upstream embedding call (no duplicate work,
//	    no poisoned state).
//
// REAL/MOCK split (honest): REAL = Postgres/pgvector + Redis through the
// testdb containers and the real CacheService.Write/LookupWithResult seams;
// MOCK = the embedder (the deterministic version-blind holdout stub, and
// flaky/gated wrappers around it) and the writer's entryStore seam (flaky
// wrapper over the real *Store). Outages are modeled at the embedder and
// store seams — the same boundaries a real outage surfaces at — so the pins
// cover production orchestration, not test internals.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pgxpool "github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Fixtures: flaky/gated embedders and a flaky/capturing store
// ---------------------------------------------------------------------------

// n03p4t08FlakyEmbedder fails the first `failsRemaining` Embed calls (the
// outage window) and then delegates to the deterministic holdout stub. It is
// deliberately VERSION-BLIND (no SpaceVersioner/InputQualifier methods), so
// the repeat/recovery axis is isolated from the version guards that T07 owns.
type n03p4t08FlakyEmbedder struct {
	failsRemaining atomic.Int64
	calls          atomic.Int64
}

func (e *n03p4t08FlakyEmbedder) Embed(_ context.Context, text string) ([]float32, error) {
	c := e.calls.Add(1)
	if e.failsRemaining.Load() > 0 {
		e.failsRemaining.Add(-1)
		return nil, fmt.Errorf("n03p4t08: embedder outage (call %d)", c)
	}
	return holdoutEmbedText(text), nil
}

// n03p4t08GatedEmbedder parks every Embed call on gate (honouring the
// caller's/detached context) and then serves the deterministic holdout
// vector — the interruption point for the lookup-resume pin.
type n03p4t08GatedEmbedder struct {
	gate  chan struct{}
	calls atomic.Int64
}

func (e *n03p4t08GatedEmbedder) Embed(ctx context.Context, text string) ([]float32, error) {
	e.calls.Add(1)
	select {
	case <-e.gate:
		return holdoutEmbedText(text), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// n03p4t08FlakyStore fails the first `failsRemaining` Put calls (the DB
// outage window) and then delegates to the real store.
type n03p4t08FlakyStore struct {
	inner          entryStore
	failsRemaining atomic.Int64
	calls          atomic.Int64
}

func (s *n03p4t08FlakyStore) Put(ctx context.Context, e *Entry) (string, error) {
	c := s.calls.Add(1)
	if s.failsRemaining.Load() > 0 {
		s.failsRemaining.Add(-1)
		return "", fmt.Errorf("n03p4t08: db outage (put %d)", c)
	}
	return s.inner.Put(ctx, e)
}

// n03p4t08CaptureStore records every Put payload (unit pin only).
type n03p4t08CaptureStore struct {
	mu      sync.Mutex
	entries []*Entry
}

func (s *n03p4t08CaptureStore) Put(_ context.Context, e *Entry) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored := *e
	s.entries = append(s.entries, &stored)
	return fmt.Sprintf("n03p4t08-id-%d", len(s.entries)), nil
}

func (s *n03p4t08CaptureStore) snapshot() []*Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*Entry(nil), s.entries...)
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

func n03p4t08Service(ctx context.Context, t *testing.T, pool *pgxpool.Pool, rdb *redis.Client, emb interface {
	Embed(ctx context.Context, text string) ([]float32, error)
}) *CacheService {
	t.Helper()
	return NewCacheService(ctx, pool, rdb, emb, slog.New(slog.DiscardHandler), false)
}

func n03p4t08RowCount(ctx context.Context, t *testing.T, pool *pgxpool.Pool, orgID, model, hash, modelVer string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM cache_entries
		 WHERE org_id::text = $1 AND model_tier = $2 AND prompt_hash = $3 AND model_version = $4`,
		orgID, model, hash, modelVer).Scan(&n))
	return n
}

func n03p4t08HitCount(ctx context.Context, t *testing.T, pool *pgxpool.Pool, orgID, model, hash, modelVer string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT hit_count FROM cache_entries
		 WHERE org_id::text = $1 AND model_tier = $2 AND prompt_hash = $3 AND model_version = $4`,
		orgID, model, hash, modelVer).Scan(&n))
	return n
}

func n03p4t08Timestamps(ctx context.Context, t *testing.T, pool *pgxpool.Pool, orgID, model, hash, modelVer string) (time.Time, time.Time) {
	t.Helper()
	var created, expires time.Time
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT created_at, expires_at FROM cache_entries
		 WHERE org_id::text = $1 AND model_tier = $2 AND prompt_hash = $3 AND model_version = $4`,
		orgID, model, hash, modelVer).Scan(&created, &expires))
	return created, expires
}

// n03p4t08SeedOrg seeds the corpus org and purges its cache_entries rows on
// cleanup (no FK ties cache_entries to organizations, so the entry cleanup
// is this file's own responsibility — the container is shared per binary).
func n03p4t08SeedOrg(ctx context.Context, t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	orgID := n03p4t07SeedOrg(ctx, t, pool, t.Name())
	t.Cleanup(func() { //nolint:contextcheck // fixture owns its context lifetime: cleanup fires after the test ctx may be canceled (seedCacheOrg idiom)
		_, _ = pool.Exec(context.Background(), "DELETE FROM cache_entries WHERE org_id::text = $1", orgID)
	})
	return orgID
}

// ---------------------------------------------------------------------------
// Unit pin (always-on, -short safe): repeated writes seal byte-identical
// payloads
// ---------------------------------------------------------------------------

// TestN03P04T08_RetrySealsByteIdenticalPayload pins the writer half of
// "repeat without duplicates": every retry of an identical job seals the SAME
// bytes (provenance envelope + response + decisive stamp are deterministic),
// so the DB upsert is content-idempotent — after any retry storm the single
// row holds exactly the response the client received, never a divergent mix.
func TestN03P04T08_RetrySealsByteIdenticalPayload(t *testing.T) {
	cap := &n03p4t08CaptureStore{}
	w := NewWriter(context.Background(), nil, holdoutEmbedder{}, slog.New(slog.DiscardHandler))
	w.store = cap

	job := writerJob{
		orgID:      "org-n03p4t08",
		modelTier:  holdoutModel,
		modelVer:   RouteVersion,
		promptJSON: json.RawMessage(holdoutPrompt("N03-P04-T08 retry: invoice run on 2025-03-31 for the repeat payload pin.")),
		response:   json.RawMessage(`{"id":"cmpl-n03p4t08-retry","choices":[{"message":{"content":"retry answer"}}]}`),
		tokensIn:   10,
		tokensOut:  5,
	}

	const retries = 5
	for i := 0; i < retries; i++ {
		require.True(t, w.Submit(job), "retry %d must be admitted", i+1)
	}
	require.True(t, w.Stop(), "drain must complete")

	queued, dropped, written := w.Stats()
	failed, skipped := w.OutcomeStats()
	require.EqualValues(t, retries, queued)
	require.Zero(t, dropped)
	require.EqualValues(t, retries, written, "every retried job resolves written")
	require.Zero(t, failed)
	require.Zero(t, skipped)

	entries := cap.snapshot()
	require.Len(t, entries, retries)
	ri := RouteIdentity{OrgID: job.orgID, Model: job.modelTier, Version: job.modelVer}
	for i, e := range entries {
		assert.Equal(t, entries[0].PromptHash, e.PromptHash, "entry %d: retries share one prompt hash", i)
		assert.True(t, bytesEqual(entries[0].Response, e.Response), "entry %d: retries seal byte-identical payloads", i)
		assert.True(t, vectorsEqual(entries[0].Embedding, e.Embedding), "entry %d: retries produce identical embeddings", i)
		prov, unsealed, ok := OpenEntry(e.Response)
		require.True(t, ok, "entry %d: payload opens", i)
		assert.True(t, prov.Matches(ri), "entry %d: provenance matches the route", i)
		assert.True(t, bytesEqual(unsealed, job.response), "entry %d: sealed bytes carry the client response", i)
	}
	t.Logf("PIN repeat-writer retries=%d identical_payloads=%d distinct_hashes=1", retries, len(entries))
}

// ---------------------------------------------------------------------------
// Docker pins (testdb/redisContainer skip in -short)
// ---------------------------------------------------------------------------

// TestN03P04T08_RepeatWriteUpsertsNoDuplicates walks the repeat axis on real
// backends: sequential retries, a concurrent retry storm, and the
// hit_count/created_at/expires_at behavior of the surviving row. Confusion
// counts for the packet report: duplicate rows observed, distinct responses
// observed, answer repeats consistent.
func TestN03P04T08_RepeatWriteUpsertsNoDuplicates(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Postgres(t)
	rdb := redisContainer(t)
	orgID := n03p4t08SeedOrg(ctx, t, pool)

	prompt := holdoutPrompt("N03-P04-T08 repeat: the same completion resent by the client after a timeout must not duplicate the cached answer.")
	response := json.RawMessage(`{"id":"cmpl-n03p4t08-repeat","choices":[{"message":{"content":"repeat answer"}}]}`)
	ri := RouteIdentity{OrgID: orgID, Model: holdoutModel}
	resolved := ri.Resolved()
	hash := ComputePromptHash(normalizeForCache([]byte(prompt)))

	// Phase 1 — five sequential identical Writes (client retry model).
	svc := n03p4t08Service(ctx, t, pool, rdb, holdoutEmbedder{})
	for i := 0; i < 5; i++ {
		require.NoError(t, svc.Write(ctx, ri, []byte(prompt), response, 10, 5), "sequential retry %d", i+1)
	}
	require.True(t, svc.writer.Stop(), "drain must complete")
	queued, dropped, written := svc.writer.Stats()
	failed, skipped := svc.writer.OutcomeStats()
	require.EqualValues(t, 5, queued)
	require.Zero(t, dropped)
	require.EqualValues(t, 5, written)
	require.Zero(t, failed)
	require.Zero(t, skipped)
	require.EqualValues(t, 1, n03p4t08RowCount(ctx, t, pool, orgID, ri.Model, hash, resolved.Version),
		"five sequential retries must upsert into exactly one row")

	// The exact layer holds one openable value whose provenance matches and
	// whose payload is the client response.
	sealed, err := svc.exact.Get(ctx, orgID, ri.Model, hash)
	require.NoError(t, err)
	require.NotEmpty(t, sealed, "exact layer must hold the retried write")
	prov, unsealed, ok := OpenEntry(sealed)
	require.True(t, ok, "exact payload opens")
	require.True(t, prov.Matches(ri), "exact provenance matches the route")
	require.True(t, bytesEqual(unsealed, response), "exact layer serves the client response")

	// Phase 2 — a concurrent retry storm (8 identical Writers racing).
	svcStorm := n03p4t08Service(ctx, t, pool, rdb, holdoutEmbedder{})
	const storm = 8
	var wg sync.WaitGroup
	errs := make(chan error, storm)
	for i := 0; i < storm; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- svcStorm.Write(ctx, ri, []byte(prompt), response, 10, 5)
		}()
	}
	wg.Wait()
	close(errs)
	for werr := range errs {
		require.NoError(t, werr, "concurrent retry must not error the caller")
	}
	require.True(t, svcStorm.writer.Stop(), "drain must complete")
	sq, sd, sw := svcStorm.writer.Stats()
	sf, ssk := svcStorm.writer.OutcomeStats()
	require.EqualValues(t, storm, sq)
	require.Zero(t, sd)
	require.EqualValues(t, storm, sw, "every concurrent retry resolves written")
	require.Zero(t, sf)
	require.Zero(t, ssk)
	require.EqualValues(t, 1, n03p4t08RowCount(ctx, t, pool, orgID, ri.Model, hash, resolved.Version),
		"the retry storm must still leave exactly one row — no duplicates")

	// Phase 3 — hit_count survives a rewrite; created_at is preserved and
	// expires_at refreshed (facts for the record).
	svcLookup := n03p4t08Service(ctx, t, pool, rdb, holdoutEmbedder{})
	require.NoError(t, svcLookup.Delete(ctx, orgID, ri.Model, []byte(prompt)), "drop the exact copy to force the semantic path")
	hit, lerr := svcLookup.LookupWithResult(ctx, ri, []byte(prompt))
	require.NoError(t, lerr)
	require.NotNil(t, hit, "repeat lookup after retries must hit")
	require.Equal(t, "semantic", hit.SourceType)
	// The PG round-trip (jsonb) normalizes JSON whitespace; equality here is
	// JSON equality. The Redis exact layer is the byte-verbatim tier — the
	// byte-level pins above cover it.
	require.JSONEq(t, string(response), string(hit.Data), "repeated answer equals the stored response")
	assert.GreaterOrEqual(t, hit.Similarity, float32(DefaultSimilarityThreshold))
	waitFor(t, func() bool { return n03p4t08HitCount(ctx, t, pool, orgID, ri.Model, hash, resolved.Version) == 1 }, 2*time.Second)

	createdBefore, expiresBefore := n03p4t08Timestamps(ctx, t, pool, orgID, ri.Model, hash, resolved.Version)
	require.NoError(t, svcLookup.Write(ctx, ri, []byte(prompt), response, 10, 5), "rewrite after a hit")
	require.True(t, svcLookup.writer.Stop(), "drain must complete")
	require.EqualValues(t, 1, n03p4t08RowCount(ctx, t, pool, orgID, ri.Model, hash, resolved.Version))
	require.EqualValues(t, 1, n03p4t08HitCount(ctx, t, pool, orgID, ri.Model, hash, resolved.Version),
		"the rewrite must NOT reset hit_count (DO UPDATE preserves the counter)")
	createdAfter, expiresAfter := n03p4t08Timestamps(ctx, t, pool, orgID, ri.Model, hash, resolved.Version)
	assert.Equal(t, createdBefore, createdAfter, "rewrite preserves created_at")
	assert.GreaterOrEqual(t, expiresAfter, expiresBefore, "rewrite refreshes the TTL")
	t.Logf("PIN repeat-lookup: repeats=5+8+%d duplicate_rows=0 distinct_responses=1 hit_count_after_rewrite=1 created_at_preserved=%v expires_refresh=%v",
		1, createdBefore.Equal(createdAfter), expiresAfter.Sub(expiresBefore))
}

// TestN03P04T08_EmbedderOutageRetryHeals walks the interruption axis at the
// embedder seam: an embedder outage must fail the semantic write CLOSED (no
// half-entry can exist — the embedding column is NOT NULL and vectorToSQL
// rejects empty vectors), keep the client loss-free through the exact layer,
// and the retried write after recovery must heal the semantic layer via
// upsert without duplicate rows or repeated upstream calls.
func TestN03P04T08_EmbedderOutageRetryHeals(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Postgres(t)
	rdb := redisContainer(t)
	orgID := n03p4t08SeedOrg(ctx, t, pool)

	prompt := holdoutPrompt("N03-P04-T08 outage: the embedder is down when the first answer arrives, recovered before the retry.")
	response := json.RawMessage(`{"id":"cmpl-n03p4t08-outage","choices":[{"message":{"content":"outage answer"}}]}`)
	ri := RouteIdentity{OrgID: orgID, Model: holdoutModel}
	resolved := ri.Resolved()
	hash := ComputePromptHash(normalizeForCache([]byte(prompt)))

	emb := &n03p4t08FlakyEmbedder{}
	emb.failsRemaining.Store(1)
	svc := n03p4t08Service(ctx, t, pool, rdb, emb)

	// The outage window: Write returns nil (the exact layer is synchronous),
	// the async semantic write fails closed.
	require.NoError(t, svc.Write(ctx, ri, []byte(prompt), response, 10, 5), "the caller is never told the async semantic write failed")
	require.True(t, svc.writer.Stop(), "drain must complete")
	queued, dropped, written := svc.writer.Stats()
	failed, _ := svc.writer.OutcomeStats()
	require.EqualValues(t, 1, queued)
	require.Zero(t, dropped)
	require.EqualValues(t, 0, written, "a vector-less entry must not persist")
	require.EqualValues(t, 1, failed, "the outage resolves the job failed — no half-state")
	require.EqualValues(t, 0, n03p4t08RowCount(ctx, t, pool, orgID, ri.Model, hash, resolved.Version),
		"no half-entry: the NOT NULL embedding + vectorToSQL guard reject vector-less writes")
	require.EqualValues(t, 1, emb.calls.Load(), "the writer made no internal retry of the failed embedding — the outage surfaced exactly once")

	// The client is loss-free during the outage: the exact layer serves.
	hit, lerr := svc.LookupWithResult(ctx, ri, []byte(prompt))
	require.NoError(t, lerr)
	require.NotNil(t, hit, "exact layer serves during the embedder outage")
	require.Equal(t, "exact", hit.SourceType)
	require.True(t, bytesEqual(hit.Data, response))

	// Recovery + retry: the same Write heals the semantic layer.
	svcRetry := n03p4t08Service(ctx, t, pool, rdb, emb) // failsRemaining exhausted — healthy
	require.NoError(t, svcRetry.Write(ctx, ri, []byte(prompt), response, 10, 5))
	require.True(t, svcRetry.writer.Stop(), "drain must complete")
	rq, _, rw := svcRetry.writer.Stats()
	rf, _ := svcRetry.writer.OutcomeStats()
	require.EqualValues(t, 1, rq)
	require.EqualValues(t, 1, rw)
	require.Zero(t, rf)
	require.EqualValues(t, 1, n03p4t08RowCount(ctx, t, pool, orgID, ri.Model, hash, resolved.Version),
		"the retried write heals the semantic layer — exactly one row, no duplicate")
	require.EqualValues(t, 2, emb.calls.Load(), "the retry write embeds exactly once more")

	// The recovered semantic layer serves the stored answer.
	require.NoError(t, svcRetry.Delete(ctx, orgID, ri.Model, []byte(prompt)), "drop the exact copy to force the semantic path")
	hit2, lerr2 := svcRetry.LookupWithResult(ctx, ri, []byte(prompt))
	require.NoError(t, lerr2)
	require.NotNil(t, hit2, "semantic result recovered after the retry")
	require.Equal(t, "semantic", hit2.SourceType)
	// jsonb normalization: PG-sourced payloads compare by JSON equality.
	require.JSONEq(t, string(response), string(hit2.Data), "recovered semantic result is the stored answer")
	require.GreaterOrEqual(t, hit2.Similarity, float32(DefaultSimilarityThreshold))
	require.EqualValues(t, 3, emb.calls.Load(), "the recovered semantic lookup embeds exactly once more — no call multiplication")
	t.Logf("PIN embedder-outage: written=0 failed=1 rows_during_outage=0 upstream_calls=1(failed)+1(retry)+1(lookup) rows_after_retry=1 duplicate_rows=0 recovered=semantic")
}

// TestN03P04T08_DBOutageRetryRestores walks the interruption axis at the
// persistence seam (a flaky entryStore wrapping the real *Store): a DB outage
// after the exact layer is warm must count the job failed (never written),
// keep the exact layer loss-free, and the retry after recovery must restore
// the semantic layer without duplicates.
func TestN03P04T08_DBOutageRetryRestores(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Postgres(t)
	rdb := redisContainer(t)
	orgID := n03p4t08SeedOrg(ctx, t, pool)

	prompt := holdoutPrompt("N03-P04-T08 db outage: postgres rejects the first write, the client retries after recovery.")
	response := json.RawMessage(`{"id":"cmpl-n03p4t08-dboutage","choices":[{"message":{"content":"db outage answer"}}]}`)
	ri := RouteIdentity{OrgID: orgID, Model: holdoutModel}
	resolved := ri.Resolved()
	hash := ComputePromptHash(normalizeForCache([]byte(prompt)))

	svc := n03p4t08Service(ctx, t, pool, rdb, holdoutEmbedder{})
	flaky := &n03p4t08FlakyStore{inner: NewStore(pool)}
	flaky.failsRemaining.Store(1)
	svc.writer.store = flaky // the writer's persistence seam (same package; happens-before via Submit)

	// The outage window: the exact layer is warm, the semantic write fails.
	require.NoError(t, svc.Write(ctx, ri, []byte(prompt), response, 10, 5))
	require.True(t, svc.writer.Stop(), "drain must complete")
	queued, dropped, written := svc.writer.Stats()
	failed, _ := svc.writer.OutcomeStats()
	require.EqualValues(t, 1, queued)
	require.Zero(t, dropped)
	require.EqualValues(t, 0, written, "a failed persistence must not count written")
	require.EqualValues(t, 1, failed)
	require.EqualValues(t, 1, flaky.calls.Load(), "the outage surfaced at the store seam exactly once")
	require.EqualValues(t, 0, n03p4t08RowCount(ctx, t, pool, orgID, ri.Model, hash, resolved.Version),
		"nothing persisted under the outage — no half-entry")

	// The client is loss-free during the DB outage.
	hit, lerr := svc.LookupWithResult(ctx, ri, []byte(prompt))
	require.NoError(t, lerr)
	require.NotNil(t, hit, "exact layer serves during the DB outage")
	require.Equal(t, "exact", hit.SourceType)
	require.True(t, bytesEqual(hit.Data, response))

	// Recovery + retry: the semantic layer is restored by the same Write seam.
	svcRetry := n03p4t08Service(ctx, t, pool, rdb, holdoutEmbedder{}) // healthy writer, real store
	require.NoError(t, svcRetry.Write(ctx, ri, []byte(prompt), response, 10, 5))
	require.True(t, svcRetry.writer.Stop(), "drain must complete")
	rq, _, rw := svcRetry.writer.Stats()
	rf, _ := svcRetry.writer.OutcomeStats()
	require.EqualValues(t, 1, rq)
	require.EqualValues(t, 1, rw)
	require.Zero(t, rf)
	require.EqualValues(t, 1, n03p4t08RowCount(ctx, t, pool, orgID, ri.Model, hash, resolved.Version),
		"the retry restores the semantic layer — exactly one row, no duplicate")

	require.NoError(t, svcRetry.Delete(ctx, orgID, ri.Model, []byte(prompt)))
	hit2, lerr2 := svcRetry.LookupWithResult(ctx, ri, []byte(prompt))
	require.NoError(t, lerr2)
	require.NotNil(t, hit2, "semantic result restored after the retry")
	require.Equal(t, "semantic", hit2.SourceType)
	require.JSONEq(t, string(response), string(hit2.Data)) // jsonb-normalized equality
	require.GreaterOrEqual(t, hit2.Similarity, float32(DefaultSimilarityThreshold))
	t.Logf("PIN db-outage: written=0 failed=1 rows_during_outage=0 rows_after_retry=1 duplicate_rows=0 recovered=semantic")
}

// TestN03P04T08_LookupInterruptedResumes walks the interruption axis on the
// lookup side: a caller cancelled mid-embedding gets the documented local
// miss; the shared flight is detached from that cancellation and completes;
// a resumed caller JOINS THE SAME FLIGHT and is served the written answer
// with no second upstream embedding call, no duplicate work and no poisoned
// state left behind (flight table empty afterwards).
func TestN03P04T08_LookupInterruptedResumes(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Postgres(t)
	rdb := redisContainer(t)
	orgID := n03p4t08SeedOrg(ctx, t, pool)

	prompt := holdoutPrompt("N03-P04-T08 resume: the first request is cancelled mid-embedding, the retried request resumes the same flight.")
	response := json.RawMessage(`{"id":"cmpl-n03p4t08-resume","choices":[{"message":{"content":"resume answer"}}]}`)
	ri := RouteIdentity{OrgID: orgID, Model: holdoutModel}
	hash := ComputePromptHash(normalizeForCache([]byte(prompt)))

	// Store the entry, then drop the exact copy so the lookup must take the
	// semantic path. The seed writer deliberately uses a VERSION-BLIND
	// embedder (the healthy flaky stub): the gated lookup embedder is also
	// version-blind, so both sides embed the same raw normalized input and
	// the pin stays on the repeat/recovery axis, not on space-version
	// admission (T07's domain).
	svcSeed := n03p4t08Service(ctx, t, pool, rdb, &n03p4t08FlakyEmbedder{})
	require.NoError(t, svcSeed.Write(ctx, ri, []byte(prompt), response, 10, 5))
	require.True(t, svcSeed.writer.Stop(), "drain must complete")
	seedQ, _, seedW := svcSeed.writer.Stats()
	seedF, _ := svcSeed.writer.OutcomeStats()
	require.EqualValues(t, 1, seedQ)
	require.EqualValues(t, 1, seedW, "the seed write must land before the interruption pin")
	require.Zero(t, seedF)
	require.EqualValues(t, 1, n03p4t08RowCount(ctx, t, pool, orgID, ri.Model, hash, ri.Resolved().Version))
	require.NoError(t, svcSeed.Delete(ctx, orgID, ri.Model, []byte(prompt)))

	gated := &n03p4t08GatedEmbedder{gate: make(chan struct{})}
	svc := n03p4t08Service(ctx, t, pool, rdb, gated)

	// Caller A: cancelled mid-embedding — local miss, no error.
	ctxA, cancelA := context.WithCancel(ctx)
	type t08res struct {
		hit *CacheHit
		err error
	}
	doneA := make(chan t08res, 1)
	go func() {
		hit, err := svc.LookupWithResult(ctxA, ri, []byte(prompt))
		doneA <- t08res{hit: hit, err: err}
	}()
	waitFor(t, func() bool { return gated.calls.Load() == 1 }, 2*time.Second)
	cancelA()
	resA := <-doneA
	require.NoError(t, resA.err, "a cancelled lookup degrades to a miss, never an error")
	require.Nil(t, resA.hit, "the cancelled caller is not served")

	// Caller B (the resumed request) joins the SAME in-flight embedding
	// before the gate opens.
	doneB := make(chan t08res, 1)
	go func() {
		hit, err := svc.LookupWithResult(ctx, ri, []byte(prompt))
		doneB <- t08res{hit: hit, err: err}
	}()
	waitFor(t, func() bool { return svc.embedFlight.waiting(hash) == 1 }, 2*time.Second)

	// The detached flight completes — A's cancellation could not abort it.
	close(gated.gate)
	resB := <-doneB
	require.NoError(t, resB.err)
	require.NotNil(t, resB.hit, "the resumed caller is served")
	require.Equal(t, "semantic", resB.hit.SourceType)
	require.JSONEq(t, string(response), string(resB.hit.Data), "the resumed caller gets exactly the stored answer") // jsonb-normalized equality
	require.GreaterOrEqual(t, resB.hit.Similarity, float32(DefaultSimilarityThreshold))
	require.EqualValues(t, 1, gated.calls.Load(), "resume consumed the shared flight — no second upstream embedding call")
	waitFor(t, func() bool { return svc.embedFlight.active() == 0 }, 2*time.Second)
	t.Logf("PIN lookup-resume: cancelled_callers=1 resumed_hits=1 upstream_calls=%d flights_left=0 poisoned_state=none", gated.calls.Load())
}

// bytesEqual is a tiny nil-safe helper (tests assert RawMessage payloads).
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// vectorsEqual is the nil-safe float32 twin of bytesEqual.
func vectorsEqual(a, b []float32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
