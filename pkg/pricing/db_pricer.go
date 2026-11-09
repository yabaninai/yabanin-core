package pricing

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// pricerDB is the minimal database surface DBPricer needs; *pgxpool.Pool
// satisfies it. Keeping it an interface lets tests inject a stub that
// observes the context passed down to the query.
type pricerDB interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// cachedPrice is one cached lookup with its own load time. The TTL is
// judged per entry: a price change becomes visible for a key after that
// key's TTL expires, while unrelated keys keep their fresh entries. (The
// old single cacheTime refreshed on every miss of ANY key, so entries that
// kept missing elsewhere stayed effectively immortal.)
type cachedPrice struct {
	price    Price
	loadedAt time.Time
}

// DBPricer loads pricing from models_pricing table with in-memory cache.
type DBPricer struct {
	pool    pricerDB
	cache   map[string]cachedPrice // key = "provider:model"
	cacheMu sync.RWMutex
	ttl     time.Duration
}

// NewDBPricer creates a DB-backed pricer with 5-minute cache TTL.
func NewDBPricer(pool *pgxpool.Pool) *DBPricer {
	return &DBPricer{
		pool:  pool,
		cache: make(map[string]cachedPrice),
		ttl:   5 * time.Minute,
	}
}

// Lookup returns the price for a provider:model pair. It is the legacy
// no-context entry point required by the Pricer interface — callers that
// have a request context should use LookupContext so a cancelled request
// does not pay a DB round-trip.
func (p *DBPricer) Lookup(provider, model string) (Price, bool) {
	return p.LookupContext(context.Background(), provider, model)
}

// LookupContext returns the price for a provider:model pair and honors ctx:
// a cancelled or expired context fails the lookup immediately, and the
// cache-miss DB read runs under it.
func (p *DBPricer) LookupContext(ctx context.Context, provider, model string) (Price, bool) {
	if err := ctx.Err(); err != nil {
		return Price{}, false
	}
	key := provider + ":" + model

	// Check cache first — per-entry loadedAt (pattern: MarkupPricer.getOverride).
	p.cacheMu.RLock()
	if cp, ok := p.cache[key]; ok && cp.loadedAt.Add(p.ttl).After(time.Now()) {
		p.cacheMu.RUnlock()
		return cp.price, true
	}
	p.cacheMu.RUnlock()

	// Cache miss — load from DB
	price, err := p.loadFromDB(ctx, provider, model)
	if err != nil {
		// catalog namespace differs (azure-openai → azure) get exactly one
		// more read before the lookup is declared unknown.
		if c := CanonicalProvider(provider); c != provider {
			price, err = p.loadFromDB(ctx, c, model)
		}
		if err != nil {
			return Price{}, false
		}
	}

	p.cacheMu.Lock()
	p.cache[key] = cachedPrice{price: price, loadedAt: time.Now()}
	p.cacheMu.Unlock()

	return price, true
}

func (p *DBPricer) loadFromDB(ctx context.Context, provider, model string) (Price, error) {
	var inputPerM, outputPerM, cacheWritePerM, cacheReadPerM float64
	err := p.pool.QueryRow(ctx, `
		SELECT input_per_m, output_per_m, COALESCE(cache_write_per_m, 0), COALESCE(cache_read_per_m, 0)
		FROM models_pricing
		WHERE provider = $1 AND model = $2 AND effective_to IS NULL
		ORDER BY effective_from DESC LIMIT 1
	`, provider, model).Scan(&inputPerM, &outputPerM, &cacheWritePerM, &cacheReadPerM)
	if err != nil {
		return Price{}, fmt.Errorf("pricing lookup: %w", err)
	}

	return Price{
		InputPerM:      inputPerM,
		OutputPerM:     outputPerM,
		CacheWritePerM: cacheWritePerM,
		CacheReadPerM:  cacheReadPerM,
	}, nil
}

// IsKnown checks if a provider:model pair has pricing data.
func (p *DBPricer) IsKnown(provider, model string) bool {
	_, ok := p.Lookup(provider, model)
	return ok
}

// ClearCache invalidates the in-memory pricing cache.
// Call this after CREATE/UPDATE/DELETE on models_pricing to ensure fresh reads.
func (p *DBPricer) ClearCache() {
	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()
	p.cache = make(map[string]cachedPrice)
}
