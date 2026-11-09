package router

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func testAffinityClock(t *testing.T) (*SessionAffinity, *time.Time) {
	t.Helper()
	sa := NewSessionAffinity(time.Minute, 512, 100)
	var now time.Time
	sa.now = func() time.Time { return now }
	t.Cleanup(func() { sa.now = time.Now })
	return sa, &now
}

func TestSessionAffinity_RecordPreferred_Roundtrip(t *testing.T) {
	sa, now := testAffinityClock(t)
	sa.Record(context.Background(), "org-1", "s1", "gpt-5.2", 1000)
	if got := sa.Preferred(context.Background(), "org-1", "s1"); got != "gpt-5.2" {
		t.Fatalf("Preferred = %q, want %q", got, "gpt-5.2")
	}
	// Same session, different model, above threshold → replaces.
	sa.Record(context.Background(), "org-1", "s1", "haiku", 2000)
	if got := sa.Preferred(context.Background(), "org-1", "s1"); got != "haiku" {
		t.Fatalf("Preferred = %q, want %q", got, "haiku")
	}
	// Unknown session → "".
	if got := sa.Preferred(context.Background(), "org-1", "unknown"); got != "" {
		t.Fatalf("Preferred(unknown) = %q, want empty", got)
	}
	// Empty session id is a no-op.
	sa.Record(context.Background(), "org-1", "", "model-x", 9999)
	if got := sa.Preferred(context.Background(), "org-1", ""); got != "" {
		t.Fatalf("Preferred(\"\") = %q, want empty", got)
	}
	_ = now
}

func TestSessionAffinity_BelowThreshold_RefreshesOnlyLastSeen(t *testing.T) {
	sa, now := testAffinityClock(t)
	// No prior model: below-threshold record must NOT set a model.
	sa.Record(context.Background(), "org-1", "s1", "small-model", 10)
	if got := sa.Preferred(context.Background(), "org-1", "s1"); got != "" {
		t.Fatalf("Preferred below threshold on new session = %q, want empty", got)
	}
	// Above-threshold record sets the model.
	sa.Record(context.Background(), "org-1", "s1", "big-model", 512)
	if got := sa.Preferred(context.Background(), "org-1", "s1"); got != "big-model" {
		t.Fatalf("Preferred = %q, want big-model", got)
	}
	// Below-threshold with a DIFFERENT model: lastSeen refreshed, model kept.
	*now = now.Add(30 * time.Second)
	sa.Record(context.Background(), "org-1", "s1", "other-model", 10)
	if got := sa.Preferred(context.Background(), "org-1", "s1"); got != "big-model" {
		t.Fatalf("Preferred after below-threshold = %q, want big-model (kept)", got)
	}
}

func TestSessionAffinity_TTL_ExpiredAndLazyDelete(t *testing.T) {
	sa, now := testAffinityClock(t)
	sa.Record(context.Background(), "org-1", "s1", "m", 9999)
	// Just under TTL: still valid.
	*now = now.Add(time.Minute - time.Millisecond)
	if got := sa.Preferred(context.Background(), "org-1", "s1"); got != "m" {
		t.Fatalf("Preferred just under TTL = %q, want m", got)
	}
	// Expired: "" and entry lazily deleted.
	*now = now.Add(time.Millisecond * 2)
	if got := sa.Preferred(context.Background(), "org-1", "s1"); got != "" {
		t.Fatalf("Preferred expired = %q, want empty", got)
	}
	sa.mu.RLock()
	_, exists := sa.m[affinityMapKey("org-1", "s1")]
	sa.mu.RUnlock()
	if exists {
		t.Fatalf("expired entry not lazily deleted")
	}
}

func TestSessionAffinity_Eviction_OldestHalfRemoved(t *testing.T) {
	sa := NewSessionAffinity(time.Minute, 1, 4)
	var now time.Time
	sa.now = func() time.Time { return now }
	t.Cleanup(func() { sa.now = time.Now })

	// Fill to maxEntries (4). 5th and 6th records trigger eviction of the
	// oldest half (2) each time.
	for i, id := range []string{"a", "b", "c", "d"} {
		sa.Record(context.Background(), "org-1", id, "m", 1)
		now = now.Add(time.Second)
		_ = i
	}
	if len(sa.m) != 4 {
		t.Fatalf("len = %d, want 4 before eviction", len(sa.m))
	}
	// 5th: evict 2 oldest (a, b) → c, d, e.
	sa.Record(context.Background(), "org-1", "e", "m", 1)
	now = now.Add(time.Second)
	if got := len(sa.m); got != 3 {
		t.Fatalf("len after 5th = %d, want 3", got)
	}
	if _, ok := sa.m[affinityMapKey("org-1", "a")]; ok {
		t.Fatalf("oldest entry a not evicted")
	}
	if _, ok := sa.m[affinityMapKey("org-1", "e")]; !ok {
		t.Fatalf("new entry e missing")
	}
	// 6th: size 3 < maxEntries 4 → no eviction, just added → 4 entries.
	sa.Record(context.Background(), "org-1", "f", "m", 1)
	if got := len(sa.m); got != 4 {
		t.Fatalf("len after 6th = %d, want 4 (below max, no eviction)", got)
	}
	// 7th: size 4 >= maxEntries → evict oldest half (2 of d, e, f) → add g → 3.
	sa.Record(context.Background(), "org-1", "g", "m", 1)
	if got := len(sa.m); got != 3 {
		t.Fatalf("len after 7th = %d, want 3 (evicted half, added new)", got)
	}
	if _, ok := sa.m[affinityMapKey("org-1", "d")]; ok {
		t.Fatalf("oldest d not evicted on 7th")
	}
	if _, ok := sa.m[affinityMapKey("org-1", "g")]; !ok {
		t.Fatalf("new entry g missing after 7th")
	}
}

func TestSessionAffinity_Concurrent_100Goroutines(t *testing.T) {
	sa := NewSessionAffinity(time.Minute, 512, 10000)
	const n = 100
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("sess-%d", i%26)
			for j := 0; j < 50; j++ {
				sa.Record(context.Background(), "org-1", id, "model", 1024)
				_ = sa.Preferred(context.Background(), "org-1", id)
			}
		}(i)
	}
	wg.Wait()
}

func TestSessionAffinity_NewDefaults(t *testing.T) {
	sa := NewSessionAffinity(0, 0, 0)
	if sa.ttl != 10*time.Minute || sa.minTokens != 512 || sa.maxEntries != 10000 {
		t.Fatalf("defaults = ttl=%v minTokens=%d maxEntries=%d", sa.ttl, sa.minTokens, sa.maxEntries)
	}
}
