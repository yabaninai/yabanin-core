package resolver

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// boundaryPool is the model_test.go mockPool shape with a controllable
// failure mode: it serves registry rows until fault is set, then every
// query fails with a non-ErrNoRows error — a registry outage, distinct
// from a missing row (pgx.ErrNoRows).
type boundaryPool struct {
	mu      sync.Mutex
	rows    map[string][]any
	fault   error // non-nil → every query fails with this error
	queries atomic.Int64
}

func (p *boundaryPool) QueryRow(_ context.Context, _ string, args ...any) pgx.Row {
	p.queries.Add(1)
	p.mu.Lock()
	fault := p.fault
	rows := p.rows
	p.mu.Unlock()

	if fault != nil {
		return mockRow{scanFn: func(...any) error { return fault }}
	}
	name, _ := args[0].(string)
	vals, ok := rows[name]
	if !ok {
		return mockRow{scanFn: func(...any) error { return pgx.ErrNoRows }}
	}
	v := vals
	return mockRow{scanFn: func(dest ...any) error { return fillDest(dest, v...) }}
}

func (p *boundaryPool) Close() {}

// localRow returns the models_registry column values for a local
// llama.cpp-style row (SELECT column order per lookupDBChecked).
func localRow(url string) []any {
	return []any{"local-qwen", "Local Qwen", "smart", url, "", "llamacpp", nil, true, int64(2000), "GLOBAL"}
}

// TestLocalRow_DisappearsMidFlight_FallsBackFlagged pins the resolver side
// of the boundary "local model row disappears mid-flight": after an
// admin deletes the row and invalidates the cache (the CRUD path), a new
// resolve must observe the disappearance as a FLAGGED fallback — never as a
// success that still carries the deleted row's routing data (partial /
// unknown must not read as success).
func TestLocalRow_DisappearsMidFlight_FallsBackFlagged(t *testing.T) {
	ctx := context.Background()
	pool := &boundaryPool{rows: map[string][]any{
		"local-qwen": localRow("http://127.0.0.1:8081"),
	}}
	r := NewResolver(pool, "fb", time.Minute, nil)

	got, err := r.ResolveChecked(ctx, "local-qwen")
	require.NoError(t, err)
	require.Equal(t, "llamacpp", got.Provider)
	require.Equal(t, "http://127.0.0.1:8081", got.UpstreamURL)

	// The row disappears (admin delete) and the resolver cache is
	// invalidated, mirroring the production CRUD invalidation.
	pool.mu.Lock()
	delete(pool.rows, "local-qwen")
	pool.mu.Unlock()
	r.Invalidate("local-qwen")

	got, err = r.ResolveChecked(ctx, "local-qwen")
	require.NoError(t, err, "a missing row is a genuine not-found, not an outage")
	assert.Equal(t, "fb", got.ModelName)
	require.True(t, got.Fallback,
		"the substitution must be flagged: an unknown name must never read as the requested local model")
	assert.Empty(t, got.UpstreamURL, "the deleted row's URL must not leak through the fallback shape")
	assert.Empty(t, got.UpstreamAPIKey)
	assert.Empty(t, got.Provider)

	// The legacy Resolve wrapper degrades to the same flagged fallback.
	legacy := r.Resolve(ctx, "local-qwen")
	assert.Equal(t, "fb", legacy.ModelName)
	require.True(t, legacy.Fallback)
	assert.Empty(t, legacy.UpstreamURL)
}

// TestLocalRow_RegistryOutage_IsNeverSuccess pins the outage boundary: when
// the registry fails after the local row's cache entry is invalidated, the
// next resolve must ERROR (ErrModelUnavailable) — an outage is neither a
// not-found nor a success, must never yield a routable ModelInfo, and must
// never be cached (recovery is immediate once the registry is back).
func TestLocalRow_RegistryOutage_IsNeverSuccess(t *testing.T) {
	ctx := context.Background()
	pool := &boundaryPool{rows: map[string][]any{
		"local-qwen": localRow("http://127.0.0.1:8081"),
	}}
	r := NewResolver(pool, "fb", time.Minute, nil)

	got, err := r.ResolveChecked(ctx, "local-qwen")
	require.NoError(t, err)
	require.Equal(t, "llamacpp", got.Provider)

	// Registry outage mid-flight + cache invalidation.
	outage := errors.New("db connection reset")
	pool.mu.Lock()
	pool.fault = outage
	pool.mu.Unlock()
	r.Invalidate("local-qwen")

	got, err = r.ResolveChecked(ctx, "local-qwen")
	require.Error(t, err, "registry outage must refuse the route, not serve a partial or empty ModelInfo")
	require.ErrorIs(t, err, ErrModelUnavailable)
	assert.Empty(t, got.ModelName, "the error result must carry no routable data")

	// The legacy wrapper degrades loudly to the name-only fallback shape —
	// flagged, with none of the local row's routing data.
	legacy := r.Resolve(ctx, "local-qwen")
	assert.Equal(t, "fb", legacy.ModelName)
	require.True(t, legacy.Fallback)
	assert.Empty(t, legacy.UpstreamURL)
	assert.Empty(t, legacy.Provider)

	// The outage result was never cached: the first resolve after recovery
	// queries the registry again and serves the row.
	pool.mu.Lock()
	pool.fault = nil
	pool.mu.Unlock()
	got, err = r.ResolveChecked(ctx, "local-qwen")
	require.NoError(t, err)
	assert.Equal(t, "llamacpp", got.Provider)
	assert.Greater(t, pool.queries.Load(), int64(1),
		"an outage result must not be served from cache; recovery must re-query")
}
