package router

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/classifier"
)

// countingModelLoader counts ListModels calls so the test can prove the
// refresh path actually ran.
type countingModelLoader struct {
	*mockModelLoader
	calls atomic.Int64
}

func (c *countingModelLoader) ListModels(ctx context.Context) ([]ModelInfo, error) {
	c.calls.Add(1)
	return c.mockModelLoader.ListModels(ctx)
}

// TestTierRouter_ConcurrentRefreshAndSelect_NoRace reproduces the audit race
// in SelectModelWithAffinity: it used to index tr.pools after ensureLoaded
// returned, outside the lock, while a concurrent TTL refresh replaced the map
// under the write lock. Selection must only read the snapshot ensureLoaded
// handed back.
func TestTierRouter_ConcurrentRefreshAndSelect_NoRace(t *testing.T) {
	loader := &countingModelLoader{mockModelLoader: &mockModelLoader{models: []ModelInfo{
		{Name: "cheap-a", TierPool: []string{"easy"}, Weight: 1, Enabled: true},
		{Name: "cheap-b", TierPool: []string{"easy"}, Weight: 1, Enabled: true},
		{Name: "hard-a", TierPool: []string{"hard"}, Weight: 1, Enabled: true},
	}}}
	router := NewTierRouter(loader, nil)
	router.ttl = time.Millisecond

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Writer: repeatedly expire the cache so refreshes rewrite tr.pools.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			router.mu.Lock()
			router.loaded = time.Time{}
			router.mu.Unlock()
			time.Sleep(time.Millisecond)
		}
	}()

	valid := map[string]bool{"cheap-a": true, "cheap-b": true, "hard-a": true}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Odd readers hit an empty pool so the fallback chain is exercised.
			cls := classifier.ClassEasy
			if i%2 == 1 {
				cls = classifier.ClassHard
			}
			for {
				select {
				case <-stop:
					return
				default:
				}
				sel, err := router.SelectModel(context.Background(), cls, "org-1")
				if err != nil {
					t.Errorf("SelectModel(%s) error: %v", cls, err)
					return
				}
				if !valid[sel.Name] {
					t.Errorf("SelectModel(%s) returned unknown model %q", cls, sel.Name)
					return
				}
			}
		}(i)
	}

	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()

	require.Greater(t, loader.calls.Load(), int64(1), "refresh path must have run repeatedly")
}
