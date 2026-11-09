package eventpublisher

// N02-P06 T03/T06 (core): the org original-text retention toggle, shared by
// every producer/consumer boundary that can durably persist an original
// capture. ONE semantic, two call sites:
//
//  1. RedisPublisher.Publish — the PRODUCER boundary (this package): the
//     upstream captures are stripped before the XADD, so under retention OFF
//     (the fail-closed default) raw originals never enter the Redis durable
//     buffer at all. PRODUCT-CONTRACT: "retention применяется до записи в
//     buffer/storage".
//  2. services/loggerd/consumer — the durable-history writer boundary: the
//     same resolution gates the request_logs columns (and the DLQ envelope
//     values, so a poisoned entry can never re-introduce captures the
//     producer withheld — pre-fix in-flight entries included).
//
// The resolver is moved verbatim from the consumer (it was implemented there
// first, N02-P06 T03); the consumer now aliases this type so the effective
// value has exactly one definition in the codebase.
//
// Contract (N02-P06 contract.md + PRODUCT-CONTRACT §5):
//   - default OFF (fail closed): history persists processed text only. The
//     processed response snapshot, the prompt digest and every metadata
//     column keep flowing; the full-fidelity ORIGINAL captures
//     (upstream_request / upstream_response) are withheld.
//   - Lookup errors, an unwired store and an empty org all resolve to OFF —
//     the same fail-closed default as adminstore.OriginalRetentionPlatformDefault.
//     Lookup errors are NOT cached, so a transient DB blip cannot pin the
//     fail-closed answer for a full TTL window.
//   - Explicit opt-in (ON) keeps the byte-identical pre-toggle capture
//     behavior; the read side (payload.read_originals + effective retention)
//     governs exposure.

import (
	"context"
	"sync"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// OriginalRetentionStore is the resolution surface of the org toggle.
// *adminstore.Store satisfies it structurally; tests use fakes.
type OriginalRetentionStore interface {
	GetOrgOriginalRetention(ctx context.Context, orgID string) (*adminstore.OrgOriginalRetention, error)
}

// AdminOriginalRetentionStore adapts *adminstore.Store to the resolution
// surface. The adminstore method owns the tri-state semantics (NULL override
// inherits OriginalRetentionPlatformDefault), so the effective value has
// exactly one definition in the codebase.
type AdminOriginalRetentionStore struct {
	Store *adminstore.Store
}

// GetOrgOriginalRetention delegates to the store.
func (s AdminOriginalRetentionStore) GetOrgOriginalRetention(ctx context.Context, orgID string) (*adminstore.OrgOriginalRetention, error) {
	return s.Store.GetOrgOriginalRetention(ctx, orgID)
}

const (
	// DefaultOriginalRetentionTTL bounds how long one org's resolved value
	// serves callers before the next store read. A toggle flip propagates
	// within this window plus the delivery backlog; the value mirrors the
	// short-lived org-policy caches elsewhere in the delivery path
	// (cache.PolicyCache uses 60s).
	DefaultOriginalRetentionTTL = 30 * time.Second
	// MaxOriginalRetentionOrgs bounds the resolver map (org churn cannot
	// grow it without bound). Reaching the cap resets the map: entries are
	// pure caches, so a reset only costs fresh lookups, never correctness.
	MaxOriginalRetentionOrgs = 4096
)

// originalRetentionEntry is one cached resolved value with its load time.
type originalRetentionEntry struct {
	enabled bool
	at      time.Time
}

// OriginalRetentionResolver is the single per-process source of the
// effective org toggle per boundary. The mutex guards the map only; lookups
// run outside it so one slow org read never serializes other orgs'
// resolutions. A nil resolver (or a nil store) keeps the fail-closed all-OFF
// behavior; production wires the adminstore adapter.
type OriginalRetentionResolver struct {
	store OriginalRetentionStore
	ttl   time.Duration
	now   func() time.Time

	mu    sync.Mutex
	cache map[string]originalRetentionEntry
}

// NewOriginalRetentionResolver builds the resolver; a nil store keeps the
// fail-closed all-OFF behavior.
func NewOriginalRetentionResolver(store OriginalRetentionStore) *OriginalRetentionResolver {
	return &OriginalRetentionResolver{
		store: store,
		ttl:   DefaultOriginalRetentionTTL,
		now:   time.Now,
		cache: map[string]originalRetentionEntry{},
	}
}

// Enabled resolves the effective toggle for one org: cache hit within the
// TTL wins; otherwise the store answers and the resolved value is cached.
// Fail-closed matrix: nil resolver, nil store, empty org, lookup error → false.
func (r *OriginalRetentionResolver) Enabled(ctx context.Context, orgID string) bool {
	if r == nil || r.store == nil || orgID == "" {
		return false
	}
	now := r.now()
	r.mu.Lock()
	entry, ok := r.cache[orgID]
	r.mu.Unlock()
	if ok && now.Sub(entry.at) < r.ttl {
		return entry.enabled
	}

	setting, err := r.store.GetOrgOriginalRetention(ctx, orgID)
	if err != nil {
		// Fail closed and leave the stale/absent entry untouched: an error
		// must not refresh the cache, and a previously resolved value keeps
		// serving only until its TTL expires.
		return false
	}
	enabled := setting.Effective

	r.mu.Lock()
	if len(r.cache) >= MaxOriginalRetentionOrgs {
		r.cache = map[string]originalRetentionEntry{}
	}
	r.cache[orgID] = originalRetentionEntry{enabled: enabled, at: now}
	r.mu.Unlock()
	return enabled
}
