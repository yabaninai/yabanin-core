package upstream

import (
	"fmt"
	"sync"
)

// DefaultPoolMaxSize bounds how many distinct upstream clients a single Pool
// will cache. The value is high enough to cover typical multi-provider
// deployments (10s of providers × few model endpoints each) while still
// protecting against unbounded growth from misconfigured per-request URLs.
const DefaultPoolMaxSize = 256

// Pool caches one *Client per unique (providerName, url) pair. Initialisation
// is lazy and thread-safe (RWMutex + double-checked locking). The API key is
// NOT part of the cache key: one HTTP client may serve requests with different
// keys since Authorization / x-api-key is set per-request by the adapter.
//
// Eviction is simple "delete one arbitrary entry" once maxSize is reached.
// A real LRU based on health-state lands in P3.10.
type Pool struct {
	mu       sync.RWMutex
	clients  map[string]*Client
	defaults Options
	maxSize  int
}

// NewPool builds an empty Pool. The supplied Options are used as defaults for
// every lazily-created Client; Get(url, provider) overrides only BaseURL and
// ProviderName, keeping the rest (timeouts, idle conns, SSRF allowlist, ...)
// uniform across the pool.
func NewPool(defaults Options) *Pool {
	if defaults.Timeout == 0 {
		defaults.Timeout = DefaultNonStreamTimeout
	}
	return &Pool{
		clients:  make(map[string]*Client),
		defaults: defaults,
		maxSize:  DefaultPoolMaxSize,
	}
}

// WithMaxSize configures the maximum number of cached clients. Values <= 0 are
// ignored so the default is kept. Returns the receiver for chaining.
func (p *Pool) WithMaxSize(n int) *Pool {
	if n > 0 {
		p.mu.Lock()
		p.maxSize = n
		p.mu.Unlock()
	}
	return p
}

// poolKey returns the cache key for a (url, provider) tuple.
//
// An empty url falls back to defaults.BaseURL; an empty provider falls back
// to defaults.ProviderName (which itself defaults to OpenAI via the adapter
// factory).
func (p *Pool) poolKey(url, providerName string) (string, string) {
	if url == "" {
		url = p.defaults.BaseURL
	}
	if providerName == "" {
		providerName = p.defaults.ProviderName
	}
	return url, providerName + "::" + url
}

// Get returns the *Client for the given upstream URL and provider adapter.
// If no client exists yet, one is created under the write lock (double-checked
// pattern). When the pool is at capacity, a single arbitrary entry is evicted
// before insertion.
//
// Empty url falls back to defaults.BaseURL; empty providerName falls back to
// defaults.ProviderName (typically "openai").
// Callers must pass only URLs from trusted operator configuration: either
// defaults.BaseURL or a custom-model URL explicitly admitted by the
// adminstore custom-models contract. Pool.Get treats a URL it receives as an
// approved origin when defaults.AllowedUpstreams is empty; determining
// whether a caller-supplied URL was authorized is the caller's responsibility.
//
// client cannot be initialised — unknown provider adapter, SSRF-allowlist
// violation or malformed URL. On error the pool is left unchanged and remains
// usable.
func (p *Pool) Get(url, providerName string) (*Client, error) {
	url, key := p.poolKey(url, providerName)

	// A custom base URL is the configured egress boundary for a local/
	// self-hosted (or any) model row. Validate it HERE so the refusal
	// carries the precise reason at the pool boundary: the construction
	// error below would be re-labeled by the unknown-provider wrapper and
	// read as an adapter problem instead of a URL problem (N08-P04-T04).
	// This also covers the pool defaults (the resolved URL is validated,
	// not just caller overrides).
	if url != "" {
		if verr := ValidateBaseURL(url); verr != nil {
			return nil, fmt.Errorf("upstream pool: %w", verr)
		}
	}

	p.mu.RLock()
	c, ok := p.clients[key]
	p.mu.RUnlock()
	if ok {
		return c, nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	// Double-check after acquiring the write lock: another goroutine may have
	// created the client between our RUnlock and Lock.
	if c, ok := p.clients[key]; ok {
		return c, nil
	}
	if len(p.clients) >= p.maxSize {
		for k := range p.clients {
			delete(p.clients, k)
			break
		}
	}
	opts := p.defaults
	opts.BaseURL = url
	opts.ProviderName = providerNameFromKey(key)
	// An empty operator allowlist is not "egress open": each lazily-created
	// client approves exactly its own configured origin (the default
	// provider URL, or an operator-defined custom-model URL). Every other
	// destination — including redirect targets and re-resolved IPs — stays
	// refused and re-validated; an explicit non-empty allowlist keeps its
	// strict "must be listed" meaning. This is safe only under Get's contract:
	// callers pass URLs from trusted operator configuration, not request input.
	if len(opts.AllowedUpstreams) == 0 && url != "" {
		opts.AllowedUpstreams = []string{url}
	}
	c, err := NewClientWithAdapter(opts)
	if err != nil {
		// Unknown provider, SSRF-allowlist violation or malformed URL — a
		// configuration error, not a transient condition. Surface it to the
		// unchanged and the failed key is not cached.
		return nil, fmtPoolAdapterError(providerName, err)
	}
	p.clients[key] = c
	return c, nil
}

// Size returns the current number of cached clients. Mostly useful in tests
// and admin/debug introspection.
func (p *Pool) Size() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.clients)
}

// Close drops all cached clients. The Pool is still usable after Close — new
// Get calls will recreate clients on demand.
func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clients = make(map[string]*Client)
}

// providerNameFromKey extracts the provider prefix from a "provider::url" key.
func providerNameFromKey(key string) string {
	for i := 0; i < len(key); i++ {
		if key[i] == ':' && i+1 < len(key) && key[i+1] == ':' {
			return key[:i]
		}
	}
	return ""
}

// fmtPoolAdapterError keeps the error construction out of the hot path so the
// compiler doesn't allocate formatting overhead when Get succeeds.
func fmtPoolAdapterError(providerName string, err error) error {
	return fmt.Errorf("upstream pool: unknown provider %s: %w", providerName, err)
}
