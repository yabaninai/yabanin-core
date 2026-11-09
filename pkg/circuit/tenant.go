// Per-tenant circuit-breaker attribution: failure windows and half-open
// probe slots keyed by BOTH the tenant identity and the upstream endpoint,
// so one tenant's failure storm can never consume another tenant's recovery
// budget.
package circuit

import (
	"log/slog"
	"strconv"
	"sync"
	"time"
)

// DefaultMaxTenants bounds the tenant-scoped breaker map (LRU eviction).
// Composite tenant×endpoint cardinality is larger than endpoint cardinality,
// so the default is looser than DefaultMaxEndpoints.
const DefaultMaxTenants = 1024

// TenantKey composes a tenant identity from the authenticated org and the
// derived workload key. The org is length-prefixed, so distinct
// (org, workload) pairs can never concatenate into the same key
// (("a","bc") ≠ ("ab","c")). An empty org/workload pair is a valid key: all
// unattributed traffic for an endpoint shares one bucket instead of
// bypassing attribution.
func TenantKey(orgID, workloadID string) string {
	return strconv.Itoa(len(orgID)) + ":" + orgID + workloadID
}

// TenantMap is a bounded, thread-safe (tenant, endpoint)→Breaker map.
//
// Scope-per-endpoint (Map) aggregates every tenant's failures into one
// breaker per endpoint: a single tenant's failure storm can trip the shared
// circuit and starve other tenants of its half-open probe slots. TenantMap
// gives every tenant its own breaker per endpoint: a noisy tenant trips only
// its own circuit and burns only its own probe budget, while other tenants
// keep using the endpoint untouched. The trade is shared-health detection:
// when an endpoint is genuinely down, every active tenant trips its own
// breaker for it and probe traffic aggregates to at most one probe per
// tenant per open timeout, bounded by the map's tenant limit.
//
// Metric labels stay endpoint-scoped: a tenant's breaker for an endpoint
// reuses the endpoint key as its metric Name, so breaker metrics cardinality
// is bounded by the endpoint count, not tenants × endpoints.
type TenantMap struct {
	cfg Config
	log *slog.Logger // nil = no open/recover logging

	mu  sync.Mutex
	lru *breakerLRU
}

// NewTenantMap builds a TenantMap with the given shared breaker config.
// maxTenants <= 0 falls back to DefaultMaxTenants. The logger receives
// open/recover events with the endpoint and tenant keys; nil disables that
// logging.
func NewTenantMap(cfg Config, maxTenants int, log *slog.Logger) *TenantMap {
	if maxTenants <= 0 {
		maxTenants = DefaultMaxTenants
	}
	return &TenantMap{
		cfg: cfg,
		log: log,
		lru: newBreakerLRU(maxTenants),
	}
}

// Breaker returns the breaker for the tenant/endpoint pair, creating it on
// first use and touching LRU recency. The endpoint is normalized with
// EndpointKey, so callers may pass raw upstream URLs. The returned breaker
// is safe for concurrent use.
func (t *TenantMap) Breaker(tenant, rawEndpoint string) *Breaker {
	endpoint := EndpointKey(rawEndpoint)
	key := TenantKey(tenant, endpoint)

	t.mu.Lock()
	defer t.mu.Unlock()

	if b, ok := t.lru.get(key); ok {
		return b
	}

	bcfg := t.cfg
	// Metric label stays the endpoint: every tenant's breaker for the same
	// endpoint shares one label value, keeping breaker metrics bounded by
	// endpoints.
	bcfg.Name = endpoint
	if t.log != nil {
		lg := t.log
		tenantLog := tenant
		bcfg.OnOpen = func(name string) {
			lg.Warn("circuit breaker open", "endpoint", name, "tenant", tenantLog)
		}
		bcfg.OnRecover = func(name string) {
			lg.Info("circuit breaker recovered", "endpoint", name, "tenant", tenantLog)
		}
	}

	b := NewBreaker(bcfg)
	t.lru.put(key, b)
	return b
}

// Allow reports whether a request from tenant to rawEndpoint may proceed
// (Breaker.Allow on the pair's breaker).
func (t *TenantMap) Allow(tenant, rawEndpoint string) error {
	return t.Breaker(tenant, rawEndpoint).Allow()
}

// RecordSuccess records a successful outcome for the tenant/endpoint pair.
func (t *TenantMap) RecordSuccess(tenant, rawEndpoint string) {
	t.Breaker(tenant, rawEndpoint).RecordSuccess()
}

// RecordFailure records a failed outcome for the tenant/endpoint pair. Only
// this tenant's breaker for this endpoint is affected.
func (t *TenantMap) RecordFailure(tenant, rawEndpoint string) {
	t.Breaker(tenant, rawEndpoint).RecordFailure()
}

// RecordCanceled records a canceled outcome for the tenant/endpoint pair
// (Breaker.RecordCanceled): the attempt ended because its context was
// canceled or its deadline elapsed. Cancellation stays out of the health
// signal, so one tenant's cancel storm neither trips its own breaker nor, by
// extension, anyone else's.
func (t *TenantMap) RecordCanceled(tenant, rawEndpoint string) {
	t.Breaker(tenant, rawEndpoint).RecordCanceled()
}

// State snapshots the pair's breaker state without mutation.
func (t *TenantMap) State(tenant, rawEndpoint string) State {
	return t.Breaker(tenant, rawEndpoint).State()
}

// RetryAfter reports the remaining refusal time of an Open breaker for the
// tenant/endpoint pair (Breaker.RetryAfter); 0 when it is not open.
func (t *TenantMap) RetryAfter(tenant, rawEndpoint string) time.Duration {
	return t.Breaker(tenant, rawEndpoint).RetryAfter()
}

// Len returns the number of tracked tenant/endpoint breakers.
func (t *TenantMap) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lru.len()
}
