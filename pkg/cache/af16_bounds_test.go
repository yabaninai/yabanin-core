package cache

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AF-16: org/model churn must not grow the in-memory analytics collector
// without bound. Both maps are LRU-bounded (order = last recorded event);
// misses shares the tier LRU, so garbage tier names cannot outgrow the cap.
func TestAF16_Analytics_OrgChurnBoundedLRU(t *testing.T) {
	a := NewAnalytics()
	a.maxOrgs = 100
	a.maxTiers = 64

	for i := 0; i < 500; i++ {
		a.RecordHit(fmt.Sprintf("org-%03d", i), "tier-a", "exact", 1)
	}
	snap := a.Snapshot()
	assert.Equal(t, 100, snap["org_count"], "org churn is capped")

	// Recording for the most recent org refreshes it: it must survive the
	// next (sub-cap) churn wave while untouched orgs are evicted.
	a.RecordHit("org-499", "tier-a", "exact", 1)
	for i := 500; i < 599; i++ {
		a.RecordHit(fmt.Sprintf("org-%03d", i), "tier-a", "exact", 1)
	}
	assert.NotNil(t, a.GetOrgAnalytics("org-499"), "recently recorded org survives LRU eviction")
	assert.Nil(t, a.GetOrgAnalytics("org-400"), "untouched org is evicted least-recently-recorded first")

	snap = a.Snapshot()
	assert.Equal(t, 100, snap["org_count"])
	counts := snap["total_hits"].(map[string]int)
	assert.Greater(t, counts["exact"], 100, "global counters survive org eviction (they are not per-org)")
}

func TestAF16_Analytics_TierChurnBoundedIncludingMisses(t *testing.T) {
	a := NewAnalytics()
	a.maxOrgs = 64
	a.maxTiers = 32

	// Garbage tier names (attacker-supplied model strings on misses) must
	// not mint unbounded entries in tierStats OR misses.
	for i := 0; i < 300; i++ {
		a.RecordMiss("org-1", fmt.Sprintf("garbage-tier-%d", i))
	}
	snap := a.Snapshot()
	assert.Equal(t, 32, snap["tier_count"])

	a.mu.RLock()
	assert.LessOrEqual(t, len(a.misses), 32, "misses map shares the tier LRU cap")
	a.mu.RUnlock()
}

// AF-16: the PolicyCache is LRU-bounded; eviction drops the cached snapshot
// and the generation guard, which only ever forces a reload (fail-closed on
// loader error) — it can never serve a stale permissive policy.
func TestAF16_PolicyCache_OrgChurnBounded(t *testing.T) {
	pc := NewPolicyCache(time.Minute)
	pc.maxEntries = 64

	var loads int64
	var mu sync.Mutex
	loader := func(context.Context, string) (*OrgPolicy, error) {
		mu.Lock()
		loads++
		mu.Unlock()
		return &OrgPolicy{Mode: PrivacyEnabled, Semantic: true}, nil
	}

	for i := 0; i < 300; i++ {
		pol := pc.Get(context.Background(), fmt.Sprintf("org-%03d", i), loader)
		require.NotNil(t, pol)
		require.Equal(t, PrivacyEnabled, pol.Mode)
	}

	pc.mu.Lock()
	policies, generations, lruLen := len(pc.policies), len(pc.generations), pc.lru.Len()
	pc.mu.Unlock()
	assert.LessOrEqual(t, policies, 64, "policies map is capped")
	assert.LessOrEqual(t, generations, 64, "generation guards of evicted orgs are dropped")
	assert.Equal(t, policies, lruLen, "LRU list tracks exactly the live entries (no ghosts)")

	// An evicted org reloads from the loader on the next Get (cache miss —
	// eviction must not freeze a stale copy in place).
	before := loads
	pol := pc.Get(context.Background(), "org-000", loader)
	mu.Lock()
	reloaded := loads > before
	mu.Unlock()
	assert.True(t, reloaded, "evicted org is reloaded from the loader")
	require.Equal(t, PrivacyEnabled, pol.Mode)
}

// Eviction racing an in-flight load must preserve the invalidate/revoke
// contract: the specific result a loader computed before the Invalidate is
// never published — even when the LRU evicted the org's generation guard in
// between. A post-invalidation load publishes its own (fresh) result.
func TestAF16_PolicyCache_EvictionDoesNotBreakInvalidate(t *testing.T) {
	pc := NewPolicyCache(time.Minute)
	pc.maxEntries = 8

	release := make(chan struct{})
	var mu sync.Mutex
	calls := 0
	loader := func(context.Context, string) (*OrgPolicy, error) {
		mu.Lock()
		n := calls
		calls++
		mu.Unlock()
		switch n {
		case 0:
			return &OrgPolicy{Mode: PrivacyEnabled, Semantic: true}, nil // instant seed
		case 1:
			<-release                                                    // hold the pre-invalidation load open
			return &OrgPolicy{Mode: PrivacyEnabled, Semantic: true}, nil // stale permissive result
		default:
			return &OrgPolicy{Mode: PrivacyDisabled}, nil // what the org was revoked to
		}
	}

	// Warm the cache so the org has an LRU node, then make entries expire
	// immediately and start the slow flight — the flight runs while the
	// org's stale entry (and generation guard) are still evictable.
	pol := pc.Get(context.Background(), "org-x", loader)
	mu.Lock()
	warmed := calls
	mu.Unlock()
	require.Equal(t, 1, warmed, "sanity: exactly one seeding load happened")
	require.NotNil(t, pol)
	pc.ttl = time.Nanosecond

	flightDone := make(chan *OrgPolicy, 1)
	go func() { flightDone <- pc.Get(context.Background(), "org-x", loader) }()

	// Wait until the slow flight is registered, then evict org-x's entries
	// via churn and invalidate it mid-flight.
	waitForFlight(t, pc, "org-x")
	for i := 0; i < 64; i++ {
		pc.Get(context.Background(), fmt.Sprintf("churn-%d", i), loader)
	}
	pc.Invalidate("org-x")
	close(release)

	got := <-flightDone
	require.NotNil(t, got)
	assert.Equal(t, PrivacyDisabled, got.Mode,
		"stale permissive result computed before the Invalidate must not be served")

	final := pc.Get(context.Background(), "org-x", loader)
	assert.Equal(t, PrivacyDisabled, final.Mode, "post-invalidation state stays revoked")
}

func waitForFlight(t *testing.T, pc *PolicyCache, orgID string) {
	t.Helper()
	for i := 0; i < 2000; i++ {
		pc.mu.Lock()
		_, ok := pc.inflight[orgID]
		pc.mu.Unlock()
		if ok {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("flight was never registered")
}
