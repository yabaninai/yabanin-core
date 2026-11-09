package pricing

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDBPricer_NewPricer(t *testing.T) {
	p := NewDBPricer(nil) // nil pool is fine for constructor test
	assert.NotNil(t, p)
	assert.Equal(t, 5*time.Minute, p.ttl)
}

func TestDBPricer_LookupKeyFormat(t *testing.T) {
	// Verify key format matches the lookup pattern
	key := "openai:gpt-4o"
	assert.Contains(t, key, ":")
}

// stubPricerRow is a pgx.Row stub: it either returns a fixed error or runs
// a custom function (e.g. blocking until the test releases it).
type stubPricerRow struct {
	err error
	fn  func(...any) error
}

func (r stubPricerRow) Scan(dest ...any) error {
	if r.fn != nil {
		return r.fn(dest...)
	}
	return r.err
}

// stubPricerDB captures the context each query received.
type stubPricerDB struct {
	mu     sync.Mutex
	gotCtx context.Context
	row    pgx.Row
}

func (s *stubPricerDB) QueryRow(ctx context.Context, _ string, _ ...any) pgx.Row {
	s.mu.Lock()
	s.gotCtx = ctx
	s.mu.Unlock()
	return s.row
}

// context fails the lookup before any DB round-trip — the query must not
// even be reached (a nil pool therefore cannot panic).
func TestDBPricer_LookupContextCancelledFailsFast(t *testing.T) {
	db := &stubPricerDB{}
	p := &DBPricer{pool: db, cache: make(map[string]cachedPrice), ttl: time.Minute}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	price, ok := p.LookupContext(ctx, "openai", "gpt-4o")
	assert.False(t, ok)
	assert.Equal(t, Price{}, price)

	db.mu.Lock()
	reached := db.gotCtx != nil
	db.mu.Unlock()
	assert.False(t, reached, "cancelled context must short-circuit before the DB query")

	// The legacy Pricer entry point stays usable for no-context callers —
	// it reaches the DB and surfaces the stub's error as unknown price.
	db.mu.Lock()
	db.row = stubPricerRow{err: assert.AnError}
	db.mu.Unlock()
	_, ok = p.Lookup("openai", "gpt-4o")
	assert.False(t, ok)
}

// DB read runs under the CALLER's context — cancelling it aborts the wait
// for the row and the lookup returns unknown instead of blocking forever.
func TestDBPricer_LookupContextHonorsCancellation(t *testing.T) {
	db := &stubPricerDB{}
	p := &DBPricer{pool: db, cache: make(map[string]cachedPrice), ttl: time.Minute}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	started := make(chan struct{})
	db.mu.Lock()
	// The stub models pgx behavior: the query aborts when the context it
	// was given is cancelled. With the old context.Background() wiring the
	// caller's cancellation never reached this point.
	db.row = stubPricerRow{fn: func(...any) error {
		close(started)
		db.mu.Lock()
		qctx := db.gotCtx
		db.mu.Unlock()
		if qctx == nil {
			return context.Canceled
		}
		<-qctx.Done()
		return qctx.Err()
	}}
	db.mu.Unlock()

	type result struct {
		price Price
		ok    bool
	}
	done := make(chan result, 1)
	go func() {
		price, ok := p.LookupContext(ctx, "openai", "gpt-4o")
		done <- result{price, ok}
	}()

	<-started
	cancel() // the request went away while the price row was being read
	select {
	case res := <-done:
		assert.False(t, res.ok, "cancelled context must fail the lookup, not block")
		assert.Equal(t, Price{}, res.price)
	case <-time.After(3 * time.Second):
		t.Fatal("LookupContext blocked past context cancellation")
	}

	// The DB query must have received a context derived from the caller's —
	// it is cancelled exactly when the caller's is.
	db.mu.Lock()
	got := db.gotCtx
	db.mu.Unlock()
	assert.NotNil(t, got)
	select {
	case <-got.Done():
	default:
		t.Fatal("query context is not derived from the caller's context")
	}
}

// priceSwitch serves a mutable models_pricing row: the test swaps the
// underlying price to model a pricing update between lookups.
type priceSwitch struct {
	mu    sync.Mutex
	price Price
}

func (s *priceSwitch) set(p Price) {
	s.mu.Lock()
	s.price = p
	s.mu.Unlock()
}

func (s *priceSwitch) row() stubPricerRow {
	return stubPricerRow{fn: func(dest ...any) error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if len(dest) < 4 {
			return errors.New("unexpected scan dest")
		}
		*dest[0].(*float64) = s.price.InputPerM
		*dest[1].(*float64) = s.price.OutputPerM
		*dest[2].(*float64) = s.price.CacheWritePerM
		*dest[3].(*float64) = s.price.CacheReadPerM
		return nil
	}}
}

// TestDBPricer_PriceChangeVisibleAfterPerEntryTTL (W-MONEY): the TTL is
// judged per cached entry, so a models_pricing update becomes visible once
// the entry's own TTL lapses — the old single cacheTime refreshed on every
// miss of ANY key and kept existing entries effectively immortal.
func TestDBPricer_PriceChangeVisibleAfterPerEntryTTL(t *testing.T) {
	sw := &priceSwitch{price: Price{InputPerM: 1, OutputPerM: 2}}
	p := &DBPricer{pool: &stubPricerDB{row: sw.row()}, cache: make(map[string]cachedPrice), ttl: 20 * time.Millisecond}

	price, ok := p.LookupContext(context.Background(), "openai", "gpt-4o")
	require.True(t, ok)
	assert.InDelta(t, 1.0, price.InputPerM, 1e-9)

	// The DB price changes; inside the entry's TTL the cached value still
	// answers (by design — that is what the cache is for).
	sw.set(Price{InputPerM: 9, OutputPerM: 9})
	price, ok = p.LookupContext(context.Background(), "openai", "gpt-4o")
	require.True(t, ok)
	assert.InDelta(t, 1.0, price.InputPerM, 1e-9, "a fresh entry serves within its TTL")

	// After the entry's own TTL lapses the new price is picked up.
	time.Sleep(60 * time.Millisecond)
	price, ok = p.LookupContext(context.Background(), "openai", "gpt-4o")
	require.True(t, ok)
	assert.InDelta(t, 9.0, price.InputPerM, 1e-9, "a price change must surface after the entry TTL")

	// ClearCache invalidates immediately, without waiting out any TTL.
	sw.set(Price{InputPerM: 10, OutputPerM: 10})
	p.ClearCache()
	price, ok = p.LookupContext(context.Background(), "openai", "gpt-4o")
	require.True(t, ok)
	assert.InDelta(t, 10.0, price.InputPerM, 1e-9, "ClearCache forces an immediate reload")
}

// AUDIT-P1-04: the per-entry TTL is the promotion propagation property.
// A durable rates promotion rewrites models_pricing; a gateway process with
// a warm DBPricer cache must serve the promoted price no later than one TTL
// after the DB row changed — without restart and without explicit
// invalidation — while a NEW pricer (fresh gateway process or replica)
// reads the promoted price immediately on cache miss.
func TestDBPricer_PromotedPriceVisibleAfterPerEntryTTL(t *testing.T) {
	var inputPerM = 1.0
	var mu sync.Mutex
	db := &stubPricerDB{row: stubPricerRow{fn: func(dest ...any) error {
		mu.Lock()
		defer mu.Unlock()
		*(dest[0].(*float64)) = inputPerM
		*(dest[1].(*float64)) = 2.0
		*(dest[2].(*float64)) = 0
		*(dest[3].(*float64)) = 0
		return nil
	}}}
	p := &DBPricer{pool: db, cache: make(map[string]cachedPrice), ttl: 30 * time.Millisecond}

	price, ok := p.Lookup("openai", "gpt-4o")
	require.True(t, ok)
	assert.InDelta(t, 1.0, price.InputPerM, 1e-12)

	// The promotion lands in models_pricing while the cache entry is warm:
	// the warm read serves the stale (pre-promotion) price.
	mu.Lock()
	inputPerM = 9.5
	mu.Unlock()
	price, ok = p.Lookup("openai", "gpt-4o")
	require.True(t, ok)
	assert.InDelta(t, 1.0, price.InputPerM, 1e-12,
		"a warm cache entry serves the pre-promotion price until its TTL expires")

	// A fresh pricer instance (fresh gateway process / replica) reads the
	// promoted price immediately — no restart or invalidation involved.
	fresh := &DBPricer{pool: db, cache: make(map[string]cachedPrice), ttl: 5 * time.Minute}
	freshPrice, ok := fresh.Lookup("openai", "gpt-4o")
	require.True(t, ok)
	assert.InDelta(t, 9.5, freshPrice.InputPerM, 1e-12)

	// The warm pricer converges within its per-entry TTL: poll until the
	// entry expires instead of sleeping a fixed budget (no flake under load).
	deadline := time.Now().Add(5 * time.Second)
	for {
		price, ok = p.Lookup("openai", "gpt-4o")
		require.True(t, ok)
		if price.InputPerM == 9.5 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("promoted price not visible within the per-entry TTL: got %v", price.InputPerM)
		}
		time.Sleep(2 * time.Millisecond)
	}
	assert.InDelta(t, 9.5, price.InputPerM, 1e-12)
}
