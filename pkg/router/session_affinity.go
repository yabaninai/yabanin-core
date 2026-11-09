package router

import (
	"context"
	"sort"
	"sync"
	"time"
)

// affinityEntry remembers the last model that served a session with a warm
// provider KV cache.
type affinityEntry struct {
	model    string
	lastSeen time.Time
}

// SessionAffinity tracks, per (org, chat session), which model recently got
// cache-read hits. Tier selection may then prefer that model: repeated
// prefixes on the same model are billed at the provider's cached-input rate.
// Entries are keyed by org+session: the same sessionID in two orgs is two
// independent stickiness entries. Pure in-memory; losing it only costs
// stickiness, never correctness.
type SessionAffinity struct {
	mu         sync.RWMutex
	m          map[string]affinityEntry
	ttl        time.Duration
	minTokens  int64
	maxEntries int
	now        func() time.Time // injectable for tests
}

// NewSessionAffinity applies defaults for zero values: ttl=10m,
// minTokens=512, maxEntries=10000.
func NewSessionAffinity(ttl time.Duration, minTokens int64, maxEntries int) *SessionAffinity {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if minTokens <= 0 {
		minTokens = 512
	}
	if maxEntries <= 0 {
		maxEntries = 10000
	}
	return &SessionAffinity{
		m:          make(map[string]affinityEntry),
		ttl:        ttl,
		minTokens:  minTokens,
		maxEntries: maxEntries,
		now:        time.Now,
	}
}

// affinityMapKey is the in-memory entry key: org+session, separated by a
// unit-separator byte that cannot appear in header-derived identifiers.
func affinityMapKey(orgID, sessionID string) string {
	return orgID + "\x1f" + sessionID
}

// Record notes that model just served orgID's sessionID with cacheReadTokens
// of cached input. cacheReadTokens >= minTokens sets/refreshes the model;
// a lower value still refreshes lastSeen (session alive, model remembered).
// The context is accepted for the shared AffinityStore surface; the in-memory
// store performs no I/O, so there is nothing to cancel (RT-06).
func (a *SessionAffinity) Record(_ context.Context, orgID, sessionID, model string, cacheReadTokens int64) {
	if orgID == "" || sessionID == "" || model == "" {
		return
	}
	now := a.now()
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.m) >= a.maxEntries {
		a.evictLocked(now)
	}

	key := affinityMapKey(orgID, sessionID)
	e := a.m[key]
	if cacheReadTokens >= a.minTokens {
		e.model = model
	}
	e.lastSeen = now
	a.m[key] = e
}

// Preferred returns orgID's sticky model for the session, or "" when absent,
// expired (lazy delete on read) — or when the org/session is empty: an empty
// org must never read another org's entry. The context is accepted for the
// shared AffinityStore surface; the in-memory store performs no I/O (RT-06).
func (a *SessionAffinity) Preferred(_ context.Context, orgID, sessionID string) string {
	if orgID == "" || sessionID == "" {
		return ""
	}
	now := a.now()
	key := affinityMapKey(orgID, sessionID)
	a.mu.RLock()
	e, ok := a.m[key]
	a.mu.RUnlock()
	if !ok {
		return ""
	}
	if now.Sub(e.lastSeen) > a.ttl {
		a.mu.Lock()
		// Re-check under write lock: another goroutine may have refreshed.
		if cur, still := a.m[key]; still && now.Sub(cur.lastSeen) > a.ttl {
			delete(a.m, key)
		}
		a.mu.Unlock()
		return ""
	}
	return e.model
}

// evictLocked removes the oldest half of the entries. Caller holds the write
// lock.
func (a *SessionAffinity) evictLocked(now time.Time) {
	type kv struct {
		id       string
		lastSeen time.Time
	}
	items := make([]kv, 0, len(a.m))
	for id, e := range a.m {
		items = append(items, kv{id: id, lastSeen: e.lastSeen})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].lastSeen.Before(items[j].lastSeen) })
	remove := len(items) / 2
	for i := 0; i < remove; i++ {
		delete(a.m, items[i].id)
	}
}
