package resolver

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockRow simulates pgx.Row: the stored scanFn fills dests or reports an error.
type mockRow struct {
	scanFn func(dest ...any) error
}

func (r mockRow) Scan(dest ...any) error {
	if r.scanFn == nil {
		return pgx.ErrNoRows
	}
	return r.scanFn(dest...)
}

// fillDest copies vals into dest pointers in SELECT column order.
func fillDest(dests []any, vals ...any) error {
	for i, d := range dests {
		if i >= len(vals) {
			return errors.New("not enough values")
		}
		if vals[i] == nil { // NULL column: leave destination at its zero value
			continue
		}
		switch dp := d.(type) {
		case *string:
			dp2, ok := vals[i].(string)
			if !ok {
				return fmt.Errorf("want string at %d", i)
			}
			*dp = dp2
		case *[]string:
			v, ok := vals[i].([]string)
			if !ok {
				return fmt.Errorf("want []string at %d", i)
			}
			*dp = v
		case *bool:
			v, ok := vals[i].(bool)
			if !ok {
				return fmt.Errorf("want bool at %d", i)
			}
			*dp = v
		case *int64:
			v, ok := vals[i].(int64)
			if !ok {
				return fmt.Errorf("want int64 at %d", i)
			}
			*dp = v
		default:
			return fmt.Errorf("unsupported dest type %T", d)
		}
	}
	return nil
}

// mockPool implements the resolver's private pgxpool interface. rows maps
// model name -> values in SELECT column order.
type mockPool struct {
	rows    map[string][]any
	queries atomic.Int64 // concurrent resolves are valid (RT-06), so the counter is atomic
}

func (p *mockPool) QueryRow(_ context.Context, _ string, args ...any) pgx.Row {
	p.queries.Add(1)
	name, _ := args[0].(string)
	vals, ok := p.rows[name]
	if !ok {
		return mockRow{scanFn: func(...any) error { return pgx.ErrNoRows }}
	}
	v := vals
	return mockRow{scanFn: func(dest ...any) error { return fillDest(dest, v...) }}
}

func (p *mockPool) Close() {}

type fakeDecrypter struct {
	val string
	err error
}

func (f fakeDecrypter) Decrypt(_ string) (string, error) { return f.val, f.err }

// TestResolve covers the pure resolution contract: "auto"/"" short-circuit,
// DB mapping, fallback on miss/disabled, key decryption, and caching.
func TestResolve(t *testing.T) {
	ctx := context.Background()

	t.Run("auto resolves the fallback registry row (gate-consistent data)", func(t *testing.T) {
		pool := &mockPool{rows: map[string][]any{
			"smart-model": {"smart-model", "Smart", "standard", "https://up", "", "openai", nil, true, int64(0), "EU"},
		}}
		r := NewResolver(pool, "smart-model", time.Minute, nil)
		got := r.Resolve(ctx, "auto")
		assert.Equal(t, "smart-model", got.ModelName)
		// RT-06: the default candidate carries the registry row's provider/
		// region data so the shared final-candidate gate sees consistent data.
		assert.Equal(t, "openai", got.Provider)
		assert.Equal(t, "EU", got.Region)
		require.True(t, got.Enabled)
		assert.False(t, got.Fallback)
		assert.Equal(t, 1, int(pool.queries.Load()))
		// Second resolve is served from cache.
		_ = r.Resolve(ctx, "auto")
		assert.Equal(t, 1, int(pool.queries.Load()))
	})

	t.Run("auto with unregistered fallback keeps the name-only shape", func(t *testing.T) {
		pool := &mockPool{}
		r := NewResolver(pool, "smart-model", time.Minute, nil)
		got := r.Resolve(ctx, "auto")
		assert.Equal(t, "smart-model", got.ModelName)
		assert.Equal(t, "smart", got.Tier)
		require.True(t, got.Enabled)
		assert.False(t, got.Fallback)
		assert.Equal(t, 1, int(pool.queries.Load()))
	})

	t.Run("empty name returns fallback without touching DB when unregistered", func(t *testing.T) {
		pool := &mockPool{}
		r := NewResolver(pool, "fb", time.Minute, nil)
		got := r.Resolve(ctx, "")
		assert.Equal(t, "fb", got.ModelName)
		assert.False(t, got.Fallback)
		assert.Equal(t, 1, int(pool.queries.Load()))
	})

	t.Run("DB row maps to full ModelInfo", func(t *testing.T) {
		pool := &mockPool{rows: map[string][]any{
			"gpt-4": {"gpt-4", "GPT 4", "standard", "https://up", "", "openai",
				[]string{"gpt-3.5"}, true, int64(1200), "SG"},
		}}
		r := NewResolver(pool, "fb", time.Minute, nil)
		got := r.Resolve(ctx, "gpt-4")
		assert.Equal(t, "GPT 4", got.DisplayName)
		assert.Equal(t, "standard", got.Tier)
		assert.Equal(t, "https://up", got.UpstreamURL)
		assert.Empty(t, got.UpstreamAPIKey)
		assert.Equal(t, "openai", got.Provider)
		assert.Equal(t, []string{"gpt-3.5"}, got.FailoverModels)
		require.True(t, got.Enabled)
		assert.Equal(t, 1200*time.Millisecond, got.UpstreamTimeout)
		assert.Equal(t, "SG", got.Region)
		assert.False(t, got.Fallback)
	})

	t.Run("missing model falls back", func(t *testing.T) {
		pool := &mockPool{}
		r := NewResolver(pool, "fb", time.Minute, nil)
		got := r.Resolve(ctx, "ghost")
		assert.Equal(t, "fb", got.ModelName)
		assert.True(t, got.Fallback)
	})

	t.Run("disabled model falls back", func(t *testing.T) {
		pool := &mockPool{rows: map[string][]any{
			"off": {"off", "Off", "standard", "", "", "", nil, false, int64(0), "GLOBAL"},
		}}
		r := NewResolver(pool, "fb", time.Minute, nil)
		got := r.Resolve(ctx, "off")
		assert.Equal(t, "fb", got.ModelName)
		assert.True(t, got.Fallback)
	})

	t.Run("encrypted key decrypted when decrypter supplied", func(t *testing.T) {
		pool := &mockPool{rows: map[string][]any{
			"k1": {"k1", "K1", "standard", "", "cipher", "openai", nil, true, int64(0), "GLOBAL"},
		}}
		r := NewResolver(pool, "fb", time.Minute, nil, fakeDecrypter{val: "plain-key"})
		got := r.Resolve(ctx, "k1")
		assert.Equal(t, "plain-key", got.UpstreamAPIKey)
	})

	t.Run("decrypt failure fails closed (no global-key leak)", func(t *testing.T) {
		pool := &mockPool{rows: map[string][]any{
			"k2": {"k2", "K2", "standard", "https://foreign", "cipher", "openai", nil, true, int64(0), "GLOBAL"},
		}}
		r := NewResolver(pool, "fb", time.Minute, nil, fakeDecrypter{err: errors.New("bad nonce")})
		got, err := r.ResolveChecked(ctx, "k2")
		require.Error(t, err, "an unusable own key must refuse routing, not fall back to the global key")
		require.ErrorIs(t, err, ErrModelUnavailable)
		assert.Empty(t, got.ModelName)
		// The legacy Resolve wrapper degrades to the name-only fallback; it
		// must NOT return the model with an empty key (that shape would send
		// the global key to the model's upstream_url).
		legacy := r.Resolve(ctx, "k2")
		assert.Equal(t, "fb", legacy.ModelName)
		assert.True(t, legacy.Fallback)
	})

	t.Run("decrypt failure degrades only with YABANIN_ALLOW_KEY_FALLBACK", func(t *testing.T) {
		t.Setenv("YABANIN_ALLOW_KEY_FALLBACK", "1")
		pool := &mockPool{rows: map[string][]any{
			"k2": {"k2", "K2", "standard", "https://foreign", "cipher", "openai", nil, true, int64(0), "GLOBAL"},
		}}
		r := NewResolver(pool, "fb", time.Minute, nil, fakeDecrypter{err: errors.New("bad nonce")})
		got, err := r.ResolveChecked(ctx, "k2")
		require.NoError(t, err)
		assert.Equal(t, "k2", got.ModelName)
		assert.Empty(t, got.UpstreamAPIKey)
		require.True(t, got.Enabled)
	})

	t.Run("encrypted key without decrypter fails closed", func(t *testing.T) {
		pool := &mockPool{rows: map[string][]any{
			"k3": {"k3", "K3", "standard", "https://foreign", "cipher", "openai", nil, true, int64(0), "GLOBAL"},
		}}
		r := NewResolver(pool, "fb", time.Minute, nil)
		got, err := r.ResolveChecked(ctx, "k3")
		require.Error(t, err, "a row with an encrypted key but no decrypter must refuse routing")
		require.ErrorIs(t, err, ErrModelUnavailable)
		assert.Empty(t, got.ModelName)
	})

	t.Run("encrypted key without decrypter degrades only with YABANIN_ALLOW_KEY_FALLBACK", func(t *testing.T) {
		t.Setenv("YABANIN_ALLOW_KEY_FALLBACK", "1")
		pool := &mockPool{rows: map[string][]any{
			"k3": {"k3", "K3", "standard", "https://foreign", "cipher", "openai", nil, true, int64(0), "GLOBAL"},
		}}
		r := NewResolver(pool, "fb", time.Minute, nil)
		got, err := r.ResolveChecked(ctx, "k3")
		require.NoError(t, err)
		assert.Equal(t, "k3", got.ModelName)
		assert.Empty(t, got.UpstreamAPIKey)
		require.True(t, got.Enabled)
	})

	t.Run("cache hit avoids second DB query", func(t *testing.T) {
		pool := &mockPool{rows: map[string][]any{
			"c1": {"c1", "C1", "standard", "", "", "openai", nil, true, int64(0), "GLOBAL"},
		}}
		r := NewResolver(pool, "fb", time.Minute, nil)
		first := r.Resolve(ctx, "c1")
		second := r.Resolve(ctx, "c1")
		assert.Equal(t, first.ModelName, second.ModelName)
		assert.Equal(t, 1, int(pool.queries.Load()), "second resolve must be served from cache")
	})
}

func TestResolve_UnknownSetsFallbackFlag(t *testing.T) {
	ctx := context.Background()
	r := NewResolver(&mockPool{}, "fb-model", time.Minute, nil)
	got := r.Resolve(ctx, "claude-sonnet-4-6")
	assert.Equal(t, "fb-model", got.ModelName)
	assert.True(t, got.Fallback)

	pool := &mockPool{rows: map[string][]any{
		"off": {"off", "Off", "standard", "", "", "", nil, false, int64(0), "GLOBAL"},
	}}
	r = NewResolver(pool, "fb-model", time.Minute, nil)
	got = r.Resolve(ctx, "off")
	assert.True(t, got.Fallback)
	assert.Equal(t, "fb-model", got.ModelName)
}

func TestResolve_AutoNotFlagged(t *testing.T) {
	ctx := context.Background()
	r := NewResolver(&mockPool{}, "smart-model", time.Minute, nil)
	for _, name := range []string{"", "auto"} {
		got := r.Resolve(ctx, name)
		assert.Equal(t, "smart-model", got.ModelName)
		assert.False(t, got.Fallback, name)
	}
}

// TestResolveCheckedEmptyFallback pins the unknown-model substitution when no
// fallback is configured (a programmatic config may omit FallbackModel — the
// N07-P01-T06 REAL leg boots exactly such a stand). Substituting an EMPTY
// name corrupted attribution and forwarding: the chat JSON path publishes
// completed events with model_requested="" (the stream path carried the
// client's model — per-turn divergence, T06 defect 2, 2026-11-03 record),
// and the upstream body rewrite blanks the model field. The requested name
// must survive as the substituted candidate, flagged Fallback=true so the
// unknown-model policy and the org-model seam still see the substitution.
func TestResolveCheckedEmptyFallback(t *testing.T) {
	ctx := context.Background()
	r := NewResolver(&mockPool{}, "", time.Minute, nil)

	got, err := r.ResolveChecked(ctx, "gpt-4")
	require.NoError(t, err)
	assert.Equal(t, "gpt-4", got.ModelName,
		"no configured fallback: keep the requested name, never substitute an empty one")
	assert.True(t, got.Fallback, "the substitution must stay flagged so policy sees it")
	assert.True(t, got.Enabled)
	assert.Equal(t, "smart", got.Tier)

	// The legacy wrapper (callers that cannot surface errors) agrees.
	legacy := r.Resolve(ctx, "gpt-4")
	assert.Equal(t, "gpt-4", legacy.ModelName)
	assert.True(t, legacy.Fallback)
}
