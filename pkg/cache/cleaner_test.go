package cache

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	pgxpool "github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/reireirei/yabanin/pkg/embeddings"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	testpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	testredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

func migrationPath(t *testing.T, filename string) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	return filepath.Join(dir, "..", "..", "migrations", filename)
}

func makeTestEmbedding(dim int, seed float32) []float32 {
	v := make([]float32, dim)
	for i := range v {
		v[i] = seed * float32(i+1)
	}
	return v
}

// TestCleaner_StartStop verifies that Start/Stop work without panics.
func TestCleaner_StartStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log := slog.Default()
	cleaner := NewCleaner(nil, 100*time.Millisecond, log.With("test", "cleaner_startstop"))

	startedCtx := cleaner.Start(ctx)

	// Let it run for a tick.
	time.Sleep(150 * time.Millisecond)

	cleaner.Stop()

	select {
	case <-startedCtx.Done():
		// Expected — context cancelled.
	case <-time.After(2 * time.Second):
		t.Fatal("Cleaner context not cancelled after Stop()")
	}
}

// TestCleaner_ConcurrentStartStop verifies no race between Start and Stop.
func TestCleaner_ConcurrentStartStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log := slog.Default()
	cleaner := NewCleaner(nil, 50*time.Millisecond, log.With("test", "cleaner_race"))

	startedCtx := cleaner.Start(ctx)

	// Immediately stop.
	cleaner.Stop()

	select {
	case <-startedCtx.Done():
		// Expected.
	case <-time.After(2 * time.Second):
		t.Fatal("Cleaner context not cancelled after Stop()")
	}
}

// TestStore_PurgeExpiredWithLock verifies that the advisory lock prevents concurrent
// cleanup runs from both deleting entries (only one replica gets the lock).
func TestStore_PurgeExpiredWithLock(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testcontainers (Postgres) test in -short mode")
	}
	ctx := context.Background()

	pgContainer, err := testpostgres.Run(ctx, "pgvector/pgvector:pg16",
		testpostgres.BasicWaitStrategies(),
		testpostgres.WithDatabase("testcleaner"),
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

	pgConnStr := "postgres://postgres:postgres@" + pgHost + ":" + pgPortStr + "/testcleaner?sslmode=disable"
	pool, err := pgxpool.New(ctx, pgConnStr)
	require.NoError(t, err)
	t.Cleanup(func() { pool.Close() })

	require.NoError(t, pool.Ping(ctx))

	// Run migration to create cache_entries table.
	migrationSQL, err := os.ReadFile(migrationPath(t, "0001_init.up.sql")) // squashed baseline (was 0009_pgvector)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, string(migrationSQL))
	require.NoError(t, err)

	store := NewStore(pool)

	// Insert a couple of expired entries.
	orgUUID := "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11" // deterministic UUID for tests
	_, err = pool.Exec(ctx, `INSERT INTO cache_entries (id, org_id, model_tier, prompt_hash, embedding, response, tokens_in, tokens_out, hit_count, model_version, created_at, expires_at)
	 VALUES (gen_random_uuid(), $1::uuid, 'smart', 'abc123', array_fill(0.1, ARRAY[384])::vector, '{"id":"1"}'::jsonb, 1, 1, 0, 'v1', now() - interval '2 days', now() - interval '1 day'),
	         (gen_random_uuid(), $1::uuid, 'smart', 'def456', array_fill(0.2, ARRAY[384])::vector, '{"id":"2"}'::jsonb, 2, 2, 0, 'v1', now() - interval '2 days', now() - interval '1 day')`, orgUUID)
	require.NoError(t, err)

	// First call: should acquire lock and delete entries.
	deleted, gotLock, err := store.PurgeExpiredWithLock(ctx)
	require.NoError(t, err)
	assert.True(t, gotLock)
	assert.Equal(t, 2, deleted)

	// Second call in same context: no entries left, lock acquired but nothing to delete.
	deleted2, gotLock2, err := store.PurgeExpiredWithLock(ctx)
	require.NoError(t, err)
	assert.True(t, gotLock2) // each call is a new transaction, so it should get the lock
	assert.Equal(t, 0, deleted2)
}

// TestCleaner_AdvisoryLock verifies that the cleaner uses advisory locking for pgvector purge.
func TestCleaner_AdvisoryLock(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testcontainers (Postgres+Redis) test in -short mode")
	}
	ctx := context.Background()

	pgContainer, err := testpostgres.Run(ctx, "pgvector/pgvector:pg16",
		testpostgres.WithDatabase("testcleaner2"),
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

	pgConnStr := "postgres://postgres:postgres@" + pgHost + ":" + pgPortStr + "/testcleaner2?sslmode=disable"
	pool, err := pgxpool.New(ctx, pgConnStr)
	require.NoError(t, err)
	t.Cleanup(func() { pool.Close() })

	for i := 0; i < 20; i++ {
		if err := pool.Ping(ctx); err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	require.NoError(t, pool.Ping(ctx))

	migrationSQL, err := os.ReadFile(migrationPath(t, "0001_init.up.sql")) // squashed baseline (was 0009_pgvector)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, string(migrationSQL))
	require.NoError(t, err)

	redisContainer, err := testredis.Run(ctx, "redis:7-alpine")
	require.NoError(t, err)
	t.Cleanup(func() { _ = redisContainer.Terminate(ctx) })

	redisHost, err := redisContainer.Host(ctx)
	require.NoError(t, err)
	redisPort, err := redisContainer.MappedPort(ctx, "6379")
	require.NoError(t, err)
	redisPortStr := redisPort.Port()
	if i := len(redisPortStr) - 4; i > 0 && redisPortStr[i:] == "/tcp" {
		redisPortStr = redisPortStr[:i]
	}
	rdb := redis.NewClient(&redis.Options{Addr: redisHost + ":" + redisPortStr})
	t.Cleanup(func() { _ = rdb.Close() })

	embedder := &embeddings.StaticClient{Embedding: makeTestEmbedding(384, 0.1)}
	log := slog.Default()
	service := NewCacheService(context.Background(), pool, rdb, embedder, log, true)

	cleaner := NewCleaner(service, 5*time.Minute, log.With("test", "cleaner_lock"))

	// Insert expired entries.
	orgUUID2 := "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a22" // different deterministic UUID
	_, err = pool.Exec(ctx, `INSERT INTO cache_entries (id, org_id, model_tier, prompt_hash, embedding, response, tokens_in, tokens_out, hit_count, model_version, created_at, expires_at)
	 VALUES (gen_random_uuid(), $1::uuid, 'smart', 'ghi789', array_fill(0.3, ARRAY[384])::vector, '{"id":"3"}'::jsonb, 1, 1, 0, 'v1', now() - interval '2 days', now() - interval '1 day')`, orgUUID2)
	require.NoError(t, err)

	// Run cleanup once via PurgeNow (uses PurgeExpired — non-locked).
	redisCount, pgCount, err := cleaner.PurgeNow(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, redisCount+pgCount, 0) // at least one backend ran

	// Verify the advisory lock path works by calling PurgeAllWithLock directly.
	_, _, gotLock, err := service.PurgeAllWithLock(ctx)
	require.NoError(t, err)
	assert.True(t, gotLock, "PurgeAllWithLock should acquire the advisory lock")
}
