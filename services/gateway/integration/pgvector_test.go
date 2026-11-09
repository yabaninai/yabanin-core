//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	testpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/reireirei/yabanin/pkg/cache"
)

// makeEmbedding creates a 384-dim embedding with the given seed value.
func makeEmbedding(dim int, seed float32) []float32 {
	e := make([]float32, dim)
	for i := range e {
		e[i] = seed * float32((i+1)%7) / 7.0 // vary values to be non-constant
	}
	return e
}

func pgvectorContainer(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()

	container, err := testpostgres.Run(ctx, "pgvector/pgvector:pg16",
		testpostgres.WithDatabase("testcache"),
		testpostgres.WithUsername("postgres"),
		testpostgres.WithPassword("postgres"),
	)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = container.Terminate(ctx)
	})

	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "5432")
	require.NoError(t, err)

	portStr := port.Port() // e.g., "5432/tcp" — extract just the number
	parts := strings.Split(portStr, "/")
	connStr := fmt.Sprintf("postgres://postgres:postgres@%s:%s/testcache?sslmode=disable", host, parts[0])

	pool, err := pgxpool.New(ctx, connStr)
	require.NoError(t, err)
	t.Cleanup(func() { pool.Close() })

	// Healthcheck poll: testcontainers images on macOS may need extra time
	// to start; wait by deadline, not a fixed retry-count sleep loop.
	waitForPoolReady(t, ctx, pool)

	return pool
}

func runPGVectorMigration(_ context.Context, t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	// Applies the full discovered migration set (0001_init already creates
	// the vector extension and embedding table); see applyMigrations.
	applyMigrations(t, pool)
}

func TestPGVector_ExtensionAndTable(t *testing.T) {
	ctx := context.Background()
	pool := pgvectorContainer(t)

	runPGVectorMigration(ctx, t, pool)

	// Verify vector extension is loaded.
	var version string
	err := pool.QueryRow(ctx, "SELECT extversion FROM pg_extension WHERE extname = 'vector'").Scan(&version)
	require.NoError(t, err)
	assert.NotEmpty(t, version)

	// Verify cache_entries table exists.
	var count int
	err = pool.QueryRow(ctx, "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'cache_entries'").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Verify HNSW index exists.
	var idxCount int
	err = pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM pg_indexes WHERE tablename = 'cache_entries' AND indexname = 'idx_cache_embedding_hnsw'
	`).Scan(&idxCount)
	require.NoError(t, err)
	assert.Equal(t, 1, idxCount)

	t.Log("pgvector extension and cache_entries table created successfully")
}

func TestPGVector_StorePutAndGetExact(t *testing.T) {
	ctx := context.Background()
	pool := pgvectorContainer(t)

	runPGVectorMigration(ctx, t, pool)

	store := cache.NewStore(pool)

	now := time.Now()
	entry := &cache.Entry{
		OrgID:      "b1f0c3d4-e5a6-4b7c-8d9e-0f1a2b3c4d5e",
		ModelTier:  "smart",
		PromptHash: "sha256abc",
		Embedding:  makeEmbedding(384, 0.1),
		Response:   json.RawMessage(`{"id":"chat-1","choices":[{"message":{"content":"hello"}}]}`),
		TokensIn:   10,
		TokensOut:  5,
		ModelVer:   "v1",
		CreatedAt:  now,
		ExpiresAt:  now.Add(24 * time.Hour),
	}

	id, err := store.Put(ctx, entry)
	require.NoError(t, err)
	assert.NotEmpty(t, id)

	// Get exact lookup.
	got, err := store.GetExact(ctx, "b1f0c3d4-e5a6-4b7c-8d9e-0f1a2b3c4d5e", "smart", "sha256abc", "v1")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, entry.OrgID, got.OrgID)
	assert.Equal(t, entry.ModelTier, got.ModelTier)
	assert.Equal(t, entry.PromptHash, got.PromptHash)
	assert.Equal(t, 10, got.TokensIn)
	assert.Equal(t, 5, got.TokensOut)
}

func TestPGVector_StoreGetExactMiss(t *testing.T) {
	ctx := context.Background()
	pool := pgvectorContainer(t)

	runPGVectorMigration(ctx, t, pool)

	store := cache.NewStore(pool)

	got, err := store.GetExact(ctx, "00000000-0000-0000-0000-000000000000", "cheap", "nohash", "v1")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestPGVector_StoreDeleteAndPurgeExpired(t *testing.T) {
	ctx := context.Background()
	pool := pgvectorContainer(t)

	runPGVectorMigration(ctx, t, pool)

	store := cache.NewStore(pool)

	now := time.Now()
	entry := &cache.Entry{
		OrgID:      "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		ModelTier:  "cheap",
		PromptHash: "del-hash",
		Embedding:  makeEmbedding(384, 0.5),
		Response:   json.RawMessage(`{"id":"x","choices":[]}`),
		TokensIn:   1,
		TokensOut:  1,
		ModelVer:   "v1",
		CreatedAt:  now,
		ExpiresAt:  now.Add(-1 * time.Hour), // expired!
	}

	id, err := store.Put(ctx, entry)
	require.NoError(t, err)
	assert.NotEmpty(t, id)

	// Should be purged.
	count, err := store.PurgeExpired(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// After purge, GetExact should return nil.
	got, err := store.GetExact(ctx, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "cheap", "del-hash", "v1")
	require.NoError(t, err)
	assert.Nil(t, got)

	// Test Delete.
	entry2 := &cache.Entry{
		OrgID:      "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
		ModelTier:  "smart",
		PromptHash: "del2-hash",
		Embedding:  makeEmbedding(384, 0.9),
		Response:   json.RawMessage(`{"id":"y","choices":[]}`),
		TokensIn:   2,
		TokensOut:  2,
		ModelVer:   "v1",
		CreatedAt:  now,
		ExpiresAt:  now.Add(24 * time.Hour), // not expired
	}

	id2, err := store.Put(ctx, entry2)
	require.NoError(t, err)
	assert.NotEmpty(t, id2)

	err = store.Delete(ctx, id2)
	require.NoError(t, err)

	got2, err := store.GetExact(ctx, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "smart", "del2-hash", "v1")
	require.NoError(t, err)
	assert.Nil(t, got2)
}
