package circuit

import (
	"container/list"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Scope selects whether circuit breakers are shared globally or isolated per upstream endpoint.
type Scope int

const (
	// ScopePerEndpoint gives every normalized upstream endpoint
	// (scheme://host) its own independent breaker: a flapping provider opens
	// only its own circuit and fallback candidates elsewhere stay reachable.
	// This is the default (W-VER fix).
	ScopePerEndpoint Scope = iota
	// ScopeGlobal is shared by every upstream (kill-switch compatibility mode).
	ScopeGlobal
)

// GlobalBreakerKey is the single map key used in ScopeGlobal. It is
// single-breaker setup (the old breaker never set Config.Name).
const GlobalBreakerKey = ""

// DefaultMaxEndpoints bounds the per-endpoint breaker map (LRU eviction).
const DefaultMaxEndpoints = 256

// EndpointKey normalizes an upstream URL to its breaker identity:
// lowercased scheme://host[:port] — path, query, fragment and userinfo are
// dropped (OP-2 callout parity, minus the path: one breaker per endpoint,
// not per model or per route). Values that do not parse as absolute URLs
// degrade to the lowercased trimmed input so a caller never gets a silently
// shared key from malformed input.
func EndpointKey(raw string) string {
	trimmed := strings.TrimSpace(raw)
	u, err := url.Parse(trimmed)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return strings.ToLower(trimmed)
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

// breakerLRU is the bounded key→breaker store behind Map and TenantMap.
// Entries beyond max are evicted least-recently-used; an evicted key re-arms
// as Closed when it is seen again — the bound trades stale open-state memory
// for a hard cardinality limit.
//
// A breakerLRU is not safe for concurrent use on its own; its owner guards
// it with a mutex.
type breakerLRU struct {
	breakers map[string]*Breaker
	elems    map[string]*list.Element // Value = key; front = most recent
	order    *list.List
	max      int
}

func newBreakerLRU(max int) *breakerLRU {
	if max <= 0 {
		max = DefaultMaxEndpoints
	}
	return &breakerLRU{
		breakers: make(map[string]*Breaker),
		elems:    make(map[string]*list.Element),
		order:    list.New(),
		max:      max,
	}
}

// get returns the breaker for key and touches LRU recency.
func (l *breakerLRU) get(key string) (*Breaker, bool) {
	el, ok := l.elems[key]
	if !ok {
		return nil, false
	}
	l.order.MoveToFront(el)
	return l.breakers[key], true
}

// put inserts a freshly created breaker, then evicts least-recently-used
// entries while the bound is exceeded.
func (l *breakerLRU) put(key string, b *Breaker) {
	l.breakers[key] = b
	l.elems[key] = l.order.PushFront(key)

	for l.order.Len() > l.max {
		victim := l.order.Back()
		if victim == nil {
			break
		}
		l.order.Remove(victim)
		victimKey := victim.Value.(string)
		delete(l.breakers, victimKey)
		delete(l.elems, victimKey)
	}
}

func (l *breakerLRU) len() int {
	return len(l.breakers)
}

// Map is a bounded, thread-safe key→Breaker map. All breakers differ only
// in Name (the endpoint key, used for metric labels) and the open/recover
// log hooks.
type Map struct {
	cfg Config
	log *slog.Logger // nil = no open/recover logging

	mu  sync.Mutex
	lru *breakerLRU
}

// NewMap builds a Map with the given shared breaker config.
// maxEntries <= 0 falls back to DefaultMaxEndpoints. The logger receives
// open/recover events with the endpoint key; nil disables that logging.
func NewMap(cfg Config, maxEntries int, log *slog.Logger) *Map {
	return &Map{
		cfg: cfg,
		log: log,
		lru: newBreakerLRU(maxEntries),
	}
}

// Breaker returns the breaker for key, creating it on first use and touching
// LRU recency. The returned breaker is safe for concurrent use.
func (m *Map) Breaker(key string) *Breaker {
	m.mu.Lock()
	defer m.mu.Unlock()

	if b, ok := m.lru.get(key); ok {
		return b
	}

	b := NewBreaker(m.breakerConfig(key))
	m.lru.put(key, b)
	return b
}

// breakerConfig derives the per-entry breaker config: the key doubles as the
// metric label, and the shared logger (if any) receives open/recover events
// with the key.
func (m *Map) breakerConfig(key string) Config {
	bcfg := m.cfg
	bcfg.Name = key
	if m.log != nil {
		lg := m.log
		bcfg.OnOpen = func(name string) {
			lg.Warn("circuit breaker open", "endpoint", name)
		}
		bcfg.OnRecover = func(name string) {
			lg.Info("circuit breaker recovered", "endpoint", name)
		}
	}
	return bcfg
}

// Allow reports whether a request to key may proceed (Breaker.Allow).
func (m *Map) Allow(key string) error {
	return m.Breaker(key).Allow()
}

// RecordSuccess records a successful outcome for key.
func (m *Map) RecordSuccess(key string) {
	m.Breaker(key).RecordSuccess()
}

// RecordFailure records a failed outcome for key.
func (m *Map) RecordFailure(key string) {
	m.Breaker(key).RecordFailure()
}

// RecordCanceled records a canceled outcome for key (Breaker.RecordCanceled):
// the attempt ended because its context was canceled or its deadline elapsed.
// Cancellation is never attributed as an upstream failure, so a client cancel
// storm cannot trip the endpoint's breaker.
func (m *Map) RecordCanceled(key string) {
	m.Breaker(key).RecordCanceled()
}

// State snapshots the breaker state for key without mutation.
func (m *Map) State(key string) State {
	return m.Breaker(key).State()
}

// RetryAfter reports the remaining refusal time of an Open breaker for key
// (Breaker.RetryAfter); 0 when the breaker is not open. Overload responses
// built from this value let clients back off instead of amplifying the
// outage window.
func (m *Map) RetryAfter(key string) time.Duration {
	return m.Breaker(key).RetryAfter()
}

// Len returns the number of tracked endpoint breakers.
func (m *Map) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lru.len()
}
