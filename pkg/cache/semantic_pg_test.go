package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgxpool "github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	testpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

// AF-15: hnsw.ef_search must actually be in force on the connection that
// executes the semantic ANN SELECT, must be applied with parameter-safe SQL,
// must surface configuration errors explicitly, and must never leak to the
// next pool borrower after release.

const af15EmbeddingDim = 384 // schema: cache_entries.embedding vector(384)

// efSearchTracer captures current_setting('hnsw.ef_search') as observed on
// the exact connection that runs the ANN SELECT. The nested query executes
// inside TraceQueryStart — before the traced statement is sent — on the same
// connection (and inside the same transaction, once the lookup uses one).
type efSearchTracer struct {
	mu       sync.Mutex
	observed []string
}

func (t *efSearchTracer) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.Contains(data.SQL, "FROM cache_entries") && strings.Contains(data.SQL, "cosine_distance") {
		rows, err := conn.Query(ctx, "SELECT current_setting('hnsw.ef_search')")
		if err == nil {
			for rows.Next() {
				var v string
				if err := rows.Scan(&v); err == nil {
					t.mu.Lock()
					t.observed = append(t.observed, v)
					t.mu.Unlock()
				}
			}
			rows.Close()
		}
	}
	return ctx
}

func (t *efSearchTracer) TraceQueryEnd(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryEndData) {
}

func (t *efSearchTracer) snapshot() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.observed...)
}

// newSemanticPGPool boots a disposable pgvector Postgres, applies the schema
// and returns a pool whose connections trace through tr (may be nil).
func newSemanticPGPool(t *testing.T, tr pgx.QueryTracer) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()

	pgContainer, err := testpostgres.Run(ctx, "pgvector/pgvector:pg16",
		testpostgres.WithDatabase("testsemantic"),
		testpostgres.WithUsername("postgres"),
		testpostgres.WithPassword("postgres"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pgContainer.Terminate(ctx) })

	pgHost, err := pgContainer.Host(ctx)
	require.NoError(t, err)
	pgPort, err := pgContainer.MappedPort(ctx, "5432")
	require.NoError(t, err)
	pgPortStr := pgPort.Port()
	if i := len(pgPortStr) - 4; i > 0 && pgPortStr[i:] == "/tcp" {
		pgPortStr = pgPortStr[:i]
	}

	cfg, err := pgxpool.ParseConfig("postgres://postgres:postgres@" + pgHost + ":" + pgPortStr + "/testsemantic?sslmode=disable")
	require.NoError(t, err)
	if tr != nil {
		cfg.ConnConfig.Tracer = tr
	}
	// A single connection: custom GUC validation (hnsw.ef_search range) only
	// applies in sessions where pgvector is registered, and the migration
	// (CREATE EXTENSION) runs on this very connection.
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { pool.Close() })

	for i := 0; i < 20; i++ {
		if err := pool.Ping(ctx); err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	require.NoError(t, pool.Ping(ctx))

	migrationSQL, err := os.ReadFile(migrationPath(t, "0001_init.up.sql")) // squashed baseline
	require.NoError(t, err)
	_, err = pool.Exec(ctx, string(migrationSQL))
	require.NoError(t, err)

	return pool
}

// af15EFSearchOnConn runs an HNSW plan on the given borrowed connection (this
// loads pgvector's library and registers its custom GUC in the session), then
// reports the hnsw.ef_search value visible on that exact connection.
func af15EFSearchOnConn(t *testing.T, ctx context.Context, conn *pgxpool.Conn) string {
	t.Helper()
	var scanned int
	require.NoError(t, conn.QueryRow(ctx, `
		SELECT count(*) FROM (
			SELECT 1 FROM cache_entries
			ORDER BY embedding <=> (SELECT array_fill(0.001, ARRAY[384])::vector)
			LIMIT 1
		) s`).Scan(&scanned))
	var v string
	require.NoError(t, conn.QueryRow(ctx, "SELECT current_setting('hnsw.ef_search')").Scan(&v))
	return v
}

func TestSemanticLookup_EFSearchOnQueryConnection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testcontainers (Postgres) test in -short mode")
	}
	ctx := context.Background()
	tr := &efSearchTracer{}
	pool := newSemanticPGPool(t, tr)

	// The hnsw.ef_search custom GUC only exists in sessions that already
	// loaded pgvector's HNSW library, so warm the borrowed connection with an
	// HNSW plan before reading its session default.
	defaultEF := func() string {
		warmConn, err := pool.Acquire(ctx)
		require.NoError(t, err)
		defer warmConn.Release()
		return af15EFSearchOnConn(t, ctx, warmConn)
	}()

	orgID := "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
	store := NewStore(pool)
	now := time.Now()
	_, err := store.Put(ctx, &Entry{
		OrgID:      orgID,
		ModelTier:  "smart",
		PromptHash: "af15-ef-search",
		Embedding:  makeTestEmbedding(af15EmbeddingDim, 0.25),
		Response:   json.RawMessage(`{"id":"af15-hit"}`),
		ModelVer:   "v1",
		CreatedAt:  now,
		ExpiresAt:  now.Add(time.Hour),
	})
	require.NoError(t, err)

	sc := NewSemanticCache(pool, DefaultSimilarityThreshold, 100)
	res, err := sc.Lookup(ctx, orgID, "smart", "v1", makeTestEmbedding(af15EmbeddingDim, 0.25))
	require.NoError(t, err)
	require.NotNil(t, res, "identical embedding must hit")

	observed := tr.snapshot()
	require.NotEmpty(t, observed, "tracer must observe the connection state of the ANN SELECT")
	for i, v := range observed {
		require.Equal(t, "100", v,
			"lookup #%d: hnsw.ef_search on the query connection must equal the configured value (session default %s)", i, defaultEF)
	}

	// The setting must not leak to the next pool borrower. The closure keeps
	// the release deferred even when an assertion inside fails.
	func() {
		conn, err := pool.Acquire(ctx)
		require.NoError(t, err)
		defer conn.Release()
		assert.Equal(t, defaultEF, af15EFSearchOnConn(t, ctx, conn),
			"hnsw.ef_search must not leak to the next borrower after release")
	}()

	// An out-of-range ef_search must surface as an explicit error — silently
	// ignoring the setting would run the ANN search under the default.
	scBad := &SemanticCache{pool: pool, threshold: DefaultSimilarityThreshold, efSearch: math.MaxInt32}
	_, err = scBad.Lookup(ctx, orgID, "smart", "v1", makeTestEmbedding(af15EmbeddingDim, 0.25))
	require.Error(t, err, "out-of-range hnsw.ef_search must not be ignored")
	require.ErrorContains(t, err, "hnsw.ef_search")

	// A cancelled context is an explicit error, never a silent miss.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	_, err = sc.Lookup(cctx, orgID, "smart", "v1", makeTestEmbedding(af15EmbeddingDim, 0.25))
	require.ErrorIs(t, err, context.Canceled)
}

// ---------------------------------------------------------------------------
// Recall/latency measurement (AF-15 acceptance): real pgvector HNSW index,
// real multi-tenant cardinality and query distribution. Gated behind
// AF15_RECALL_BENCH=1 so routine race/shuffle runs stay fast.
// ---------------------------------------------------------------------------

func TestSemanticLookup_RecallAndLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testcontainers (Postgres) test in -short mode")
	}
	if os.Getenv("AF15_RECALL_BENCH") == "" {
		t.Skip("set AF15_RECALL_BENCH=1 to run the recall/latency measurement")
	}

	const (
		dim         = af15EmbeddingDim // actual embedding dimension (vector(384) schema)
		orgs        = 50               // multi-tenant: orgs share near-identical prompts
		clusters    = 10               // topical clusters ("query distribution")
		perOrg      = 180              // entries per (org, cluster) -> ~90k cardinality
		cardinality = orgs * clusters * perOrg
		queries     = 60
		entryNoise  = 0.01 // per-dim noise amplitude of stored embeddings
		queryNoise  = 0.005
	)

	ctx := context.Background()
	pool := newSemanticPGPool(t, nil)

	rng := rand.New(rand.NewSource(42)) //nolint:gosec // G404: deterministic synthetic dataset, not security-sensitive
	centers := make([][]float32, clusters)
	for c := range centers {
		centers[c] = af15UnitVector(rng, dim)
	}

	orgIDs := make([]string, orgs)
	for o := range orgIDs {
		orgIDs[o] = fmt.Sprintf("af150000-0000-4000-8000-%012x", o)
	}

	// Ground truth kept in memory for exact brute-force recall.
	type gtEntry struct {
		id  string
		vec []float32
	}
	groundTruth := make(map[string][]gtEntry, orgs)

	insertSQL := `INSERT INTO cache_entries
		(org_id, model_tier, prompt_hash, embedding, response, tokens_in, tokens_out, hit_count, model_version, created_at, expires_at)
		VALUES ($1, 'smart', $2, $3::vector, '{"id":1}'::jsonb, 1, 1, 0, 'v1', now(), now() + interval '24 hours')`

	batch := &pgx.Batch{}
	queued := 0
	flush := func() {
		if queued == 0 {
			return
		}
		br := pool.SendBatch(ctx, batch)
		for i := 0; i < queued; i++ {
			_, err := br.Exec()
			require.NoError(t, err)
		}
		require.NoError(t, br.Close())
		batch = &pgx.Batch{}
		queued = 0
	}

	for c := 0; c < clusters; c++ {
		for o := 0; o < orgs; o++ {
			for k := 0; k < perOrg; k++ {
				vec := af15AddNoise(centers[c], entryNoise, rng)
				embSQL, err := vectorToSQL(vec)
				require.NoError(t, err)
				batch.Queue(insertSQL, orgIDs[o], fmt.Sprintf("af15-%d-%d-%d", c, o, k), embSQL)
				queued++
				if queued >= 1000 {
					flush()
				}
			}
		}
	}
	flush()
	t.Logf("inserted %d vectors (dim=%d, orgs=%d, clusters=%d)", cardinality, dim, orgs, clusters)

	// Re-read stored embeddings for exact ground truth.
	rows, err := pool.Query(ctx, `SELECT id, org_id, embedding::text FROM cache_entries`)
	require.NoError(t, err)
	for rows.Next() {
		var id, orgID, embText string
		require.NoError(t, rows.Scan(&id, &orgID, &embText))
		vec, err := vectorFromSQL(embText)
		require.NoError(t, err)
		groundTruth[orgID] = append(groundTruth[orgID], gtEntry{id: id, vec: vec})
	}
	require.NoError(t, rows.Err())
	rows.Close()

	// Build the query set: near-duplicate requests (queryNoise) targeting a
	// specific (org, cluster) — the realistic multi-tenant distribution where
	// all orgs ask near-identical questions in the same topic region.
	type query struct {
		org    string
		vec    []float32
		expect string // ground-truth nearest entry id of this org
	}
	queriesSet := make([]query, 0, queries)
	for q := 0; q < queries; q++ {
		c := rng.Intn(clusters)
		o := rng.Intn(orgs)
		qvec := af15AddNoise(centers[c], queryNoise, rng)
		bestID, bestSim := "", math.Inf(-1)
		for _, e := range groundTruth[orgIDs[o]] {
			if sim := af15CosineSim(qvec, e.vec); sim > bestSim {
				bestSim, bestID = sim, e.id
			}
		}
		require.GreaterOrEqual(t, bestSim, 0.95, "ground truth nearest must pass the 0.95 threshold")
		queriesSet = append(queriesSet, query{org: orgIDs[o], vec: qvec, expect: bestID})
	}

	measure := func(efSearch int) (recall float64, p50, p95, p99 time.Duration) {
		sc := NewSemanticCache(pool, DefaultSimilarityThreshold, efSearch)
		hits := 0
		lat := make([]time.Duration, 0, len(queriesSet))
		for _, q := range queriesSet {
			start := time.Now()
			res, err := sc.Lookup(ctx, q.org, "smart", "v1", q.vec)
			lat = append(lat, time.Since(start))
			if errors.Is(err, ErrMiss) {
				// Below-threshold row (contract: a cache miss) — counts as
				// an effective miss, not a test failure.
				continue
			}
			require.NoError(t, err)
			if res != nil && res.Entry.ID == q.expect {
				hits++
			}
		}
		sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
		pick := func(p float64) time.Duration { return lat[int(math.Ceil(p*float64(len(lat))))-1] }
		return float64(hits) / float64(len(queriesSet)), pick(0.50), pick(0.95), pick(0.99)
	}

	recall40, p50_40, p95_40, p99_40 := measure(40) // pgvector default — what the broken code effectively ran with
	recall100, p50_100, p95_100, p99_100 := measure(100)
	recall200, _, _, _ := measure(200) // headroom reference

	// Transaction overhead the AF-15 fix adds per lookup (Begin + set_config + Commit).
	overhead := make([]time.Duration, 0, 200)
	for i := 0; i < 200; i++ {
		start := time.Now()
		tx, err := pool.Begin(ctx)
		require.NoError(t, err)
		_, err = tx.Exec(ctx, "SELECT set_config('hnsw.ef_search', $1, true)", "100")
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		overhead = append(overhead, time.Since(start))
	}
	sort.Slice(overhead, func(i, j int) bool { return overhead[i] < overhead[j] })

	t.Logf("cardinality=%d orgs=%d clusters=%d dim=%d queries=%d", cardinality, orgs, clusters, dim, len(queriesSet))
	t.Logf("ef_search=40  (pgvector default): recall@1=%.3f  p50=%v p95=%v p99=%v", recall40, p50_40, p95_40, p99_40)
	t.Logf("ef_search=100 (configured):      recall@1=%.3f  p50=%v p95=%v p99=%v", recall100, p50_100, p95_100, p99_100)
	t.Logf("ef_search=200 (headroom ref):    recall@1=%.3f", recall200)
	t.Logf("tx overhead Begin+set_config+Commit: p50=%v p95=%v", overhead[len(overhead)/2], overhead[int(0.95*float64(len(overhead)))-1])

	// One-query slack: with a deterministic dataset these numbers are stable,
	// but a strict > is too brittle for near-equal recall on small query sets.
	assert.GreaterOrEqual(t, recall100, recall40-float64(1)/float64(len(queriesSet)),
		"configured ef_search=100 must not lose recall versus the pgvector default")
}

// af15UnitVector returns a deterministic unit-norm random vector.
func af15UnitVector(rng *rand.Rand, dim int) []float32 {
	v := make([]float32, dim)
	var norm float64
	for i := range v {
		v[i] = float32(rng.NormFloat64())
		norm += float64(v[i]) * float64(v[i])
	}
	norm = math.Sqrt(norm)
	for i := range v {
		v[i] = float32(float64(v[i]) / norm)
	}
	return v
}

func af15AddNoise(base []float32, amp float64, rng *rand.Rand) []float32 {
	v := make([]float32, len(base))
	var norm float64
	for i := range v {
		v[i] = base[i] + float32(rng.NormFloat64()*amp)
		norm += float64(v[i]) * float64(v[i])
	}
	norm = math.Sqrt(norm)
	for i := range v {
		v[i] = float32(float64(v[i]) / norm)
	}
	return v
}

func af15CosineSim(a, b []float32) float64 {
	var dot float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
	}
	return dot
}
