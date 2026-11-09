package regionrouter

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// HealthChecker pings peer gateways' /healthz and caches the result.
type HealthChecker struct {
	peers  []PeerURL
	client *http.Client
	cache  atomic.Pointer[healthSnapshot]
}

// PeerURL is a region + reachable gateway URL.
type PeerURL struct {
	Region string
	URL    string
}

type healthSnapshot struct {
	healthy map[string]bool
	at      time.Time
}

// NewHealthChecker creates a checker that pings each peer's /health endpoint.
func NewHealthChecker(peers []PeerURL) *HealthChecker {
	h := &HealthChecker{
		peers:  peers,
		client: &http.Client{Timeout: 3 * time.Second},
	}
	return h
}

// CheckAll pings each peer's /healthz, returns list of healthy region names.
func (h *HealthChecker) CheckAll(ctx context.Context) []string {
	if snap := h.cache.Load(); snap != nil && time.Since(snap.at) < 5*time.Second {
		var out []string
		for r, ok := range snap.healthy {
			if ok {
				out = append(out, r)
			}
		}
		return out
	}
	healthy := map[string]bool{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, p := range h.peers {
		wg.Add(1)
		go func(p PeerURL) {
			defer wg.Done()
			ok := h.ping(ctx, p.URL)
			mu.Lock()
			healthy[p.Region] = ok
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	h.cache.Store(&healthSnapshot{healthy: healthy, at: time.Now()})
	var out []string
	for r, ok := range healthy {
		if ok {
			out = append(out, r)
		}
	}
	return out
}

// HealthyRegions returns the list of healthy peer regions.
func (h *HealthChecker) HealthyRegions(ctx context.Context) []string {
	return h.CheckAll(ctx)
}

func (h *HealthChecker) ping(ctx context.Context, url string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"/health", nil)
	if err != nil {
		return false
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode == http.StatusOK
}
