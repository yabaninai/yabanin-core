package provider

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Jurisdiction describes where a provider operates legally + physically.
type Jurisdiction struct {
	Provider               string   // adapter key ("openai", "anthropic", ...)
	CorpCountry            string   // vendor HQ ISO-3166-1 alpha-2
	DefaultInferenceRegion string   // fallback region when endpoint unknown
	DataCenterRegions      []string // known data-center countries
}

// DefaultUnknownJurisdiction is returned when a provider is not in the registry.
// Sovereignty posture is fail-CLOSED toward US (most restrictive default).
var DefaultUnknownJurisdiction = Jurisdiction{
	Provider:               "",
	CorpCountry:            "US",
	DefaultInferenceRegion: "US",
	DataCenterRegions:      nil,
}

// JurisdictionRegistry caches provider_jurisdictions rows in-process.
// Safe for concurrent use; shared gateway-wide.
type JurisdictionRegistry struct {
	mu     sync.RWMutex
	cache  map[string]Jurisdiction
	loaded time.Time
	ttl    time.Duration
	pool   *pgxpool.Pool
}

// NewJurisdictionRegistry builds a registry. ttl==0 → 5 minutes.
func NewJurisdictionRegistry(pool *pgxpool.Pool, ttl time.Duration) *JurisdictionRegistry {
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	return &JurisdictionRegistry{pool: pool, ttl: ttl, cache: make(map[string]Jurisdiction)}
}

// Get returns the cached Jurisdiction for a provider name. Falls back to the
// conservative US default when the provider is unknown (fail-CLOSED).
func (r *JurisdictionRegistry) Get(ctx context.Context, providerName string) Jurisdiction {
	if j, ok := r.snapshot(providerName); ok {
		return j
	}
	_ = r.refresh(ctx)
	if j, ok := r.snapshot(providerName); ok {
		return j
	}
	j := DefaultUnknownJurisdiction
	j.Provider = providerName
	return j
}

func (r *JurisdictionRegistry) snapshot(p string) (Jurisdiction, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.cache) == 0 || time.Since(r.loaded) > r.ttl {
		return Jurisdiction{}, false
	}
	j, ok := r.cache[strings.ToLower(p)]
	return j, ok
}

func (r *JurisdictionRegistry) refresh(ctx context.Context) error {
	if r.pool == nil {
		return nil
	}
	rows, err := r.pool.Query(ctx,
		`SELECT provider, corp_country, default_inference_region, data_center_regions FROM provider_jurisdictions`)
	if err != nil {
		return err
	}
	defer rows.Close()
	next := make(map[string]Jurisdiction)
	for rows.Next() {
		var j Jurisdiction
		if err := rows.Scan(&j.Provider, &j.CorpCountry, &j.DefaultInferenceRegion, &j.DataCenterRegions); err != nil {
			return err
		}
		next[strings.ToLower(j.Provider)] = j
	}
	if err := rows.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	r.cache = next
	r.loaded = time.Now()
	r.mu.Unlock()
	return nil
}
