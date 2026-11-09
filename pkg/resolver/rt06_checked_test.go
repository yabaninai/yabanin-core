package resolver

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RT-06 regression tests: the checked-resolution contract.
//
// Outage (DB failure) and cancellation are terminal errors that are NEVER
// cached — neither as a success nor as a not-found fallback. Only genuine
// registry hits and genuine missing/disabled models (RM-09) are cached.

// rt06Row builds the mockPool row set for a fully populated registry model.
func rt06Row(name, provider, region, url string) []any {
	return []any{name, name + " display", "standard", url, "", provider, nil, true, int64(0), region}
}

func TestResolveChecked_Found(t *testing.T) {
	pool := &mockPool{rows: map[string][]any{
		"gpt-4": rt06Row("gpt-4", "openai", "SG", "https://up"),
	}}
	r := NewResolver(pool, "fb", time.Minute, nil)
	info, err := r.ResolveChecked(context.Background(), "gpt-4")
	require.NoError(t, err)
	assert.Equal(t, "gpt-4", info.ModelName)
	assert.Equal(t, "openai", info.Provider)
	assert.Equal(t, "SG", info.Region)
	assert.Equal(t, "https://up", info.UpstreamURL)
	assert.False(t, info.Fallback)
}

func TestResolveChecked_MissingModelIsGenuineFallback_Cached(t *testing.T) {
	pool := &mockPool{rows: map[string][]any{
		"fb": rt06Row("fb", "openai", "EU", "https://fb"),
	}}
	r := NewResolver(pool, "fb", time.Minute, nil)

	info, err := r.ResolveChecked(context.Background(), "ghost")
	require.NoError(t, err, "a genuinely missing model is not an error (RM-09)")
	assert.Equal(t, "fb", info.ModelName)
	assert.True(t, info.Fallback)
	// RT-06: the substituted candidate keeps the fallback row's own data.
	assert.Equal(t, "openai", info.Provider)
	assert.Equal(t, "EU", info.Region)

	// The genuine negative is cached: the second resolve does not re-query.
	info2, err := r.ResolveChecked(context.Background(), "ghost")
	require.NoError(t, err)
	assert.True(t, info2.Fallback)
	assert.Equal(t, 2, int(pool.queries.Load()), "ghost + fb rows cached after the first resolve")
}

func TestResolveChecked_DisabledModelIsGenuineFallback(t *testing.T) {
	pool := &mockPool{rows: map[string][]any{
		"off": {"off", "Off", "standard", "", "", "", nil, false, int64(0), "GLOBAL"},
	}}
	r := NewResolver(pool, "fb", time.Minute, nil)
	info, err := r.ResolveChecked(context.Background(), "off")
	require.NoError(t, err)
	assert.Equal(t, "fb", info.ModelName)
	assert.True(t, info.Fallback)
}

func TestResolveChecked_DBCacheHitAvoidsSecondQuery(t *testing.T) {
	pool := &mockPool{rows: map[string][]any{
		"c1": rt06Row("c1", "openai", "GLOBAL", "https://up"),
	}}
	r := NewResolver(pool, "fb", time.Minute, nil)
	_, err := r.ResolveChecked(context.Background(), "c1")
	require.NoError(t, err)
	_, err = r.ResolveChecked(context.Background(), "c1")
	require.NoError(t, err)
	assert.Equal(t, 1, int(pool.queries.Load()))
}

// failingOncePool fails every query while fail is true, then reports not-found.
type failingOncePool struct {
	mu      sync.Mutex
	fail    bool
	queries atomic.Int64
}

func (p *failingOncePool) QueryRow(_ context.Context, _ string, _ ...interface{}) pgx.Row {
	p.queries.Add(1)
	p.mu.Lock()
	fail := p.fail
	p.mu.Unlock()
	if fail {
		return mockRow{scanFn: func(...any) error { return errors.New("db connection refused") }}
	}
	return mockRow{}
}

func (p *failingOncePool) Close() {}

func TestResolveChecked_OutageIsErrorAndNeverCached(t *testing.T) {
	pool := &failingOncePool{fail: true}
	r := NewResolver(pool, "fb", time.Minute, nil)

	_, err := r.ResolveChecked(context.Background(), "m")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrModelUnavailable, "outage must be classified as unavailable")

	// The outage result was NOT cached: the very next call re-queries the DB.
	pool.mu.Lock()
	pool.fail = false
	pool.mu.Unlock()
	info, err := r.ResolveChecked(context.Background(), "m")
	require.NoError(t, err, "a recovered registry must serve the request — the outage was not cached")
	assert.Equal(t, "fb", info.ModelName, "after recovery the resolve follows RM-09, not the outage")
	assert.True(t, info.Fallback)
	assert.Equal(t, 3, int(pool.queries.Load()), "outage (1) + recovered resolve of m and fb — nothing cached from the failure")
}

func TestResolveChecked_CancelledContextIsTerminalAndNeverCached(t *testing.T) {
	pool := &mockPool{rows: map[string][]any{
		"m": rt06Row("m", "openai", "GLOBAL", "https://up"),
	}}
	r := NewResolver(pool, "fb", time.Minute, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := r.ResolveChecked(ctx, "m")
	require.Error(t, err)
	require.ErrorIs(t, err, context.Canceled, "cancel must surface as the context error")
	assert.Zero(t, pool.queries.Load(), "a dead context must not reach the DB")

	// Nothing was cached as a result of the cancel.
	info, err := r.ResolveChecked(context.Background(), "m")
	require.NoError(t, err)
	assert.Equal(t, "m", info.ModelName)
	assert.Equal(t, 1, int(pool.queries.Load()))
}

func TestResolveChecked_AutoCarriesRegistryData(t *testing.T) {
	pool := &mockPool{rows: map[string][]any{
		"smart": rt06Row("smart", "anthropic", "EU", "https://eu"),
	}}
	r := NewResolver(pool, "smart", time.Minute, nil)
	info, err := r.ResolveChecked(context.Background(), "auto")
	require.NoError(t, err)
	assert.Equal(t, "smart", info.ModelName)
	assert.Equal(t, "anthropic", info.Provider, "default candidate must keep registry data for the policy gate")
	assert.Equal(t, "EU", info.Region)
	assert.False(t, info.Fallback, "the default is not an unknown-model substitution")
}

func TestResolveChecked_UnknownFallbackKeepsRegistryDataAndAlias(t *testing.T) {
	pool := &mockPool{rows: map[string][]any{
		"fb": rt06Row("fb", "openai", "US", "https://fb"),
	}}
	r := NewResolver(pool, "fb", time.Minute, nil)
	info, err := r.ResolveChecked(context.Background(), "ghost")
	require.NoError(t, err)
	assert.Equal(t, "fb", info.ModelName)
	assert.Equal(t, "openai", info.Provider)
	assert.Equal(t, "US", info.Region)
	assert.True(t, info.Fallback)
	// Alias is applied by ResolveChecked above the cache layer.
	info, err = r.ResolveChecked(context.Background(), "ghost")
	require.NoError(t, err)
	assert.Empty(t, info.Alias, "the cached negative must not leak an alias into a fresh resolve")
}

func TestResolveChecked_RequestedFallbackItselfMissing_NoRecursion(t *testing.T) {
	pool := &mockPool{}
	r := NewResolver(pool, "fb", time.Minute, nil)
	info, err := r.ResolveChecked(context.Background(), "fb")
	require.NoError(t, err)
	assert.Equal(t, "fb", info.ModelName)
	assert.True(t, info.Fallback)
	assert.Equal(t, "smart", info.Tier, "legacy name-only shape")
}

func TestResolveChecked_OutageWhileResolvingFallbackIsUnavailable(t *testing.T) {
	pool := &mockPool{rows: map[string][]any{
		// Requested model genuinely missing; the fallback lookup then fails.
	}}
	p := &flakyFallbackPool{inner: pool, failFallback: true}
	r := NewResolver(p, "fb", time.Minute, nil)
	_, err := r.ResolveChecked(context.Background(), "ghost")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrModelUnavailable, "an outage during fallback resolution is not a successful fallback")
}

// flakyFallbackPool answers not-found for the requested model and fails when
// the fallback row is queried.
type flakyFallbackPool struct {
	inner        *mockPool
	failFallback bool
}

func (p *flakyFallbackPool) QueryRow(ctx context.Context, q string, args ...interface{}) pgx.Row {
	name, _ := args[0].(string)
	if name == "fb" && p.failFallback {
		return mockRow{scanFn: func(...any) error { return errors.New("db down") }}
	}
	return p.inner.QueryRow(ctx, q, args...)
}

func (p *flakyFallbackPool) Close() {}

func TestResolve_LegacyWrapperOnOutage_Uncached(t *testing.T) {
	pool := &failingOncePool{fail: true}
	r := NewResolver(pool, "fb", time.Minute, nil)

	info := r.Resolve(context.Background(), "m")
	assert.Equal(t, "fb", info.ModelName)
	assert.True(t, info.Fallback, "legacy contract: fallback info on failure")

	// RT-06: the failure result must not be cached — the next call queries again.
	info = r.Resolve(context.Background(), "m")
	assert.Equal(t, "fb", info.ModelName)
	assert.True(t, info.Fallback)
	assert.Equal(t, 2, int(pool.queries.Load()), "legacy degrade must not populate the cache")
}

func TestResolveChecked_AliasTargetResolvedChecked(t *testing.T) {
	pool := &mockPool{rows: map[string][]any{
		"target": rt06Row("target", "openai", "EU", "https://up"),
	}}
	r := NewResolver(pool, "fb", time.Minute, nil)
	r.UseAliases(NewAliasBook(time.Hour, func(context.Context) (map[string]string, error) {
		return map[string]string{"alias-x": "target"}, nil
	}, nil))
	info, err := r.ResolveChecked(context.Background(), "alias-x")
	require.NoError(t, err)
	assert.Equal(t, "target", info.ModelName)
	assert.Equal(t, "alias-x", info.Alias)
}

func TestResolveChecked_TTLExpiryRequeries(t *testing.T) {
	pool := &mockPool{rows: map[string][]any{
		"m": rt06Row("m", "openai", "GLOBAL", "https://up"),
	}}
	r := NewResolver(pool, "fb", time.Millisecond, nil)
	_, err := r.ResolveChecked(context.Background(), "m")
	require.NoError(t, err)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
		if _, err = r.ResolveChecked(context.Background(), "m"); err != nil {
			t.Fatal(err)
		}
		if pool.queries.Load() >= 2 {
			return
		}
	}
	t.Fatalf("TTL expiry must re-query the DB (queries=%d)", pool.queries.Load())
}

func TestResolveChecked_ConcurrentCallersSafe(t *testing.T) {
	pool := &mockPool{rows: map[string][]any{
		"m": rt06Row("m", "openai", "GLOBAL", "https://up"),
	}}
	r := NewResolver(pool, "fb", time.Minute, nil)
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			info, err := r.ResolveChecked(context.Background(), "m")
			if err != nil {
				errs <- err
				return
			}
			if info.ModelName != "m" {
				errs <- fmt.Errorf("unexpected model %q", info.ModelName)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}
