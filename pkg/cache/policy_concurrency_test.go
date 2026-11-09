package cache

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Ported from the 2026-10-02 audit reproduction
// (TestReview_SlowOrgLoadMustNotBlockOtherOrgCacheHit): while the loader of
// one org is held on a barrier, a warm cache hit of another org must still
// complete promptly. The policy cache must never hold a cache-wide lock
// across loader I/O.
func TestPolicyCache_SlowOrgLoaderDoesNotBlockWarmOrgHit(t *testing.T) {
	pc := NewPolicyCache(time.Minute)

	// Warm the cache for warm-org (loader nil → default enabled policy).
	pc.Get(context.Background(), "warm-org", nil)

	entered := make(chan struct{})
	release := make(chan struct{})
	slowDone := make(chan struct{})
	defer close(release)

	go func() {
		defer close(slowDone)
		pc.Get(context.Background(), "slow-org", func(context.Context, string) (*OrgPolicy, error) {
			close(entered)
			<-release
			return &OrgPolicy{Mode: PrivacyEnabled}, nil
		})
	}()
	<-entered

	hitDone := make(chan struct{})
	go func() {
		pc.Get(context.Background(), "warm-org", nil)
		close(hitDone)
	}()

	select {
	case <-hitDone:
	case <-time.After(250 * time.Millisecond):
		t.Error("warm-org cache hit blocked by slow-org loader")
	}
}

// A loader that started before Invalidate must not publish its stale
// (permissive) policy: the in-flight Get must observe the post-invalidation
// policy instead.
func TestPolicyCache_InvalidateDuringLoad_OldLoadDoesNotPublishStalePolicy(t *testing.T) {
	pc := NewPolicyCache(time.Minute)

	started := make(chan struct{})
	release := make(chan struct{})
	calls := atomic.Int32{}
	loader := func(context.Context, string) (*OrgPolicy, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
			return &OrgPolicy{Mode: PrivacyEnabled}, nil // stale pre-invalidate load
		}
		return &OrgPolicy{Mode: PrivacyDisabled}, nil // post-invalidate state
	}

	res := make(chan *OrgPolicy, 1)
	go func() { res <- pc.Get(context.Background(), "org-race", loader) }()
	<-started
	pc.Invalidate("org-race")
	close(release) // the stale pre-invalidate load completes after the invalidate

	select {
	case pol := <-res:
		if pol.Mode != PrivacyDisabled {
			t.Fatalf("stale permissive policy published after invalidate: got %v", pol.Mode)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Get did not complete after invalidation racing the load")
	}

	if got := pc.Get(context.Background(), "org-race", loader); got.Mode != PrivacyDisabled {
		t.Fatalf("fresh lookup after invalidate: got %v, want disabled", got.Mode)
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("loader calls=%d, want exactly 2 (stale load + reload)", n)
	}
}

// Concurrent cold misses of one org share a single loader run.
func TestPolicyCache_ConcurrentColdMissesSingleFlight(t *testing.T) {
	pc := NewPolicyCache(time.Minute)

	var calls atomic.Int32
	release := make(chan struct{})
	loader := func(context.Context, string) (*OrgPolicy, error) {
		calls.Add(1)
		<-release
		return &OrgPolicy{Mode: PrivacyReadCacheOnly}, nil
	}

	const callers = 16
	started := make(chan struct{})
	var wg sync.WaitGroup
	res := make([]chan *OrgPolicy, callers)
	for i := 0; i < callers; i++ {
		res[i] = make(chan *OrgPolicy, 1)
		wg.Add(1)
		go func(out chan<- *OrgPolicy) {
			defer wg.Done()
			<-started
			out <- pc.Get(context.Background(), "org-sf", loader)
		}(res[i])
	}
	close(started)
	time.Sleep(50 * time.Millisecond) // let all callers pile up on the cold miss
	close(release)
	wg.Wait()

	for _, out := range res {
		if pol := <-out; pol.Mode != PrivacyReadCacheOnly {
			t.Fatalf("waiter got mode %v, want read-only", pol.Mode)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("loader invoked %d times for one concurrent cold miss, want 1", n)
	}
}

// A cancelled caller fails closed immediately; its cancellation must not kill
// the shared load for others and must not poison the cache with a disabled
// policy.
func TestPolicyCache_CallerCancelIsIndependentOfSharedLoad(t *testing.T) {
	pc := NewPolicyCache(time.Minute)

	started := make(chan struct{})
	release := make(chan struct{})
	loader := func(context.Context, string) (*OrgPolicy, error) {
		close(started)
		<-release
		return &OrgPolicy{Mode: PrivacyEnabled}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	res := make(chan *OrgPolicy, 1)
	go func() { res <- pc.Get(ctx, "org-cancel", loader) }()
	<-started
	cancel()

	select {
	case pol := <-res:
		if pol.Mode != PrivacyDisabled {
			t.Fatalf("cancelled caller: got %v, want fail-closed disabled", pol.Mode)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled caller blocked on shared load")
	}

	// The shared load survives the cancellation; a fresh caller gets the
	// loaded policy — the cancelled caller did not poison the cache.
	close(release)
	if pol := pc.Get(context.Background(), "org-cancel", loader); pol.Mode != PrivacyEnabled {
		t.Fatalf("fresh caller: got %v, want enabled from the shared load", pol.Mode)
	}
}
