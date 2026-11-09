// Package cache provides semantic cache storage with Redis and pgvector backends.
package cache

import (
	"container/list"
	"crypto/sha256"
	"sort"
	"sync"
	"time"
)

// AF-16 entry caps for the in-memory analytics. Org/model churn must not
// grow the collector without bound: entries beyond the cap are evicted
// least-recently-recorded first. These structures are best-effort operations
// telemetry — eviction loses that org's/tier's running counters, it never
// affects cache correctness or billing (authoritative analytics come from the
// request_logs DB rollups).
const (
	defaultMaxOrgEntries  = 4096
	defaultMaxTierEntries = 1024
)

// Analytics tracks cache performance metrics across orgs and models.
// The per-org and per-tier maps are LRU-bounded (AF-16): LRU order is the
// last RecordHit/RecordMiss time; read-only GetOrgAnalytics does not refresh
// it. Snapshot exposes the live org_count/tier_count so operators can see
// the caps at work.
type Analytics struct {
	mu        sync.RWMutex
	hits      map[string]int // type -> count
	misses    map[string]int // tier -> count
	orgStats  map[string]*OrgAnalytics
	orgOrder  *list.List // front = most recently recorded org
	tierStats map[string]*TierAnalytics
	tierOrder *list.List // front = most recently recorded tier; shared with misses
	maxOrgs   int
	maxTiers  int
}

// OrgAnalytics holds per-organization analytics.
type OrgAnalytics struct {
	HitsExact      int
	HitsSemantic   int
	Misses         int
	CacheHitRate   float64
	AvgTokensSaved int
	LastAccess     time.Time

	elem *list.Element // LRU node in Analytics.orgOrder
}

// TierAnalytics holds per-tier analytics.
type TierAnalytics struct {
	Size        int64
	HitRate     float64
	TotalHits   int
	TotalMisses int

	elem *list.Element // LRU node in Analytics.tierOrder (shared with misses)
}

// NewAnalytics creates a new analytics collector.
func NewAnalytics() *Analytics {
	return &Analytics{
		hits:      make(map[string]int),
		misses:    make(map[string]int),
		orgStats:  make(map[string]*OrgAnalytics),
		orgOrder:  list.New(),
		tierStats: make(map[string]*TierAnalytics),
		tierOrder: list.New(),
		maxOrgs:   defaultMaxOrgEntries,
		maxTiers:  defaultMaxTierEntries,
	}
}

// RecordHit records a cache hit.
func (a *Analytics) RecordHit(orgID, tierName, hitType string, tokensSaved int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.hits[hitType]++

	org := a.touchOrgLocked(orgID)
	switch hitType {
	case "exact":
		org.HitsExact++
	case "semantic":
		org.HitsSemantic++
	}
	org.AvgTokensSaved += tokensSaved
	org.LastAccess = time.Now()
	a.updateOrgHitRate(org)

	tierStat := a.touchTierLocked(tierName)
	tierStat.TotalHits++
	total := tierStat.TotalHits + tierStat.TotalMisses
	if total > 0 {
		tierStat.HitRate = float64(tierStat.TotalHits) / float64(total)
	}
}

// RecordMiss records a cache miss.
func (a *Analytics) RecordMiss(orgID, tierName string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.misses[tierName]++

	org := a.touchOrgLocked(orgID)
	org.Misses++
	a.updateOrgHitRate(org)

	tierStat := a.touchTierLocked(tierName)
	tierStat.TotalMisses++
	total := tierStat.TotalHits + tierStat.TotalMisses
	if total > 0 {
		tierStat.HitRate = float64(tierStat.TotalHits) / float64(total)
	}
}

// touchOrgLocked returns the org entry, creating it (and evicting the
// least-recently-recorded entry when over the cap) as needed. Callers must
// hold a.mu for writing.
func (a *Analytics) touchOrgLocked(orgID string) *OrgAnalytics {
	if org, ok := a.orgStats[orgID]; ok {
		a.orgOrder.MoveToFront(org.elem)
		return org
	}
	org := &OrgAnalytics{LastAccess: time.Now()}
	org.elem = a.orgOrder.PushFront(orgID)
	a.orgStats[orgID] = org
	for a.orgOrder.Len() > a.maxOrgs {
		oldest := a.orgOrder.Back()
		delete(a.orgStats, oldest.Value.(string))
		a.orgOrder.Remove(oldest)
	}
	return org
}

// touchTierLocked returns the tier entry, keeping misses and tierStats on one
// shared LRU order so both stay bounded by the same cap. Callers must hold
// a.mu for writing.
func (a *Analytics) touchTierLocked(tierName string) *TierAnalytics {
	if t, ok := a.tierStats[tierName]; ok {
		a.tierOrder.MoveToFront(t.elem)
		return t
	}
	t := &TierAnalytics{}
	t.elem = a.tierOrder.PushFront(tierName)
	a.tierStats[tierName] = t
	for a.tierOrder.Len() > a.maxTiers {
		oldest := a.tierOrder.Back()
		key := oldest.Value.(string)
		delete(a.tierStats, key)
		delete(a.misses, key)
		a.tierOrder.Remove(oldest)
	}
	return t
}

func (a *Analytics) updateOrgHitRate(org *OrgAnalytics) {
	total := org.HitsExact + org.HitsSemantic + org.Misses
	if total > 0 {
		org.CacheHitRate = float64(org.HitsExact+org.HitsSemantic) / float64(total)
	}
}

// Snapshot returns a point-in-time copy of all analytics. The maps are
// deep-copied under the lock: handing out the live maps would race
// RecordHit/RecordMiss writers and let callers mutate shared state.
func (a *Analytics) Snapshot() map[string]interface{} {
	a.mu.RLock()
	defer a.mu.RUnlock()

	hits := make(map[string]int, len(a.hits))
	for k, v := range a.hits {
		hits[k] = v
	}
	misses := make(map[string]int, len(a.misses))
	for k, v := range a.misses {
		misses[k] = v
	}
	return map[string]interface{}{
		"total_hits":   hits,
		"total_misses": misses,
		"org_count":    len(a.orgStats),
		"tier_count":   len(a.tierStats),
	}
}

// GetOrgAnalytics returns a copy of the analytics for a specific org, or nil
// when the org has no entry. The copy decouples the caller from the live
// struct RecordHit/RecordMiss keep mutating under the lock.
func (a *Analytics) GetOrgAnalytics(orgID string) *OrgAnalytics {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if org, ok := a.orgStats[orgID]; ok {
		cp := *org
		cp.elem = nil // internal LRU node never leaks to callers
		return &cp
	}
	return nil
}

// ---------------------------------------------------------------------------
// A/B Test Harness for cache configurations.
// ---------------------------------------------------------------------------

// ABTest defines an A/B test variant for cache behavior.
type ABTest struct {
	Name     string
	Variants map[string]float64 // variant name -> traffic percentage
	names    []string           // sorted variant names for deterministic access
}

// NewABTest creates a new A/B test with the given variants.
func NewABTest(name string, variants map[string]float64) *ABTest {
	t := &ABTest{
		Name:     name,
		Variants: variants,
		names:    variantNamesSorted(variants),
	}
	return t
}

// Assign returns a deterministic variant assignment based on orgID hash.
func (t *ABTest) Assign(orgID string) string {
	if len(t.names) == 0 {
		return ""
	}
	h := sha256.Sum256([]byte(orgID))
	idx := int(h[0]) % len(t.names)
	if idx < 0 {
		idx = -idx
	}
	return t.names[idx]
}

// GetVariant returns the current variant for an org.
func (t *ABTest) GetVariant(orgID string) string {
	return t.Assign(orgID) // deterministic — same input always yields same output
}

func variantNamesSorted(v map[string]float64) []string {
	names := make([]string, 0, len(v))
	for name := range v {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ---------------------------------------------------------------------------
// Package-level analytics singleton (used by admin API).
// ---------------------------------------------------------------------------

var globalAnalytics *Analytics

func init() {
	globalAnalytics = NewAnalytics()
}

// GetAnalyticsSnapshot returns a point-in-time copy of the global analytics snapshot.
func GetAnalyticsSnapshot() map[string]interface{} {
	if globalAnalytics == nil {
		return map[string]interface{}{"error": "analytics not initialized"}
	}
	return globalAnalytics.Snapshot()
}

// RecordGlobalHit records a cache hit to the global analytics singleton.
func RecordGlobalHit(orgID, tierName, hitType string, tokensSaved int) {
	if globalAnalytics != nil {
		globalAnalytics.RecordHit(orgID, tierName, hitType, tokensSaved)
	}
}

// RecordGlobalMiss records a cache miss to the global analytics singleton.
func RecordGlobalMiss(orgID, tierName string) {
	if globalAnalytics != nil {
		globalAnalytics.RecordMiss(orgID, tierName)
	}
}
