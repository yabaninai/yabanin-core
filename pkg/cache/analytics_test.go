package cache

import (
	"sync"
	"testing"
)

// TestAnalytics_RecordHitMiss verifies hit/miss counting and hit rate calculation.
func TestAnalytics_RecordHitMiss(t *testing.T) {
	a := NewAnalytics()

	a.RecordHit("org-1", "gpt-4", "exact", 100)
	a.RecordHit("org-1", "gpt-4", "semantic", 200)
	a.RecordMiss("org-1", "gpt-4")

	snap := a.Snapshot()
	if snap["total_hits"] == nil {
		t.Fatal("expected total_hits in snapshot")
	}

	org := a.GetOrgAnalytics("org-1")
	if org == nil {
		t.Fatal("expected org analytics for org-1")
	}
	if org.HitsExact != 1 {
		t.Errorf("expected HitsExact=1, got %d", org.HitsExact)
	}
	if org.HitsSemantic != 1 {
		t.Errorf("expected HitsSemantic=1, got %d", org.HitsSemantic)
	}
	if org.Misses != 1 {
		t.Errorf("expected Misses=1, got %d", org.Misses)
	}
	expectedRate := 2.0 / 3.0
	if org.CacheHitRate < expectedRate-0.01 || org.CacheHitRate > expectedRate+0.01 {
		t.Errorf("expected hit rate ~%.2f, got %.4f", expectedRate, org.CacheHitRate)
	}

	// Non-existent org returns nil.
	if a.GetOrgAnalytics("org-999") != nil {
		t.Error("non-existent org should return nil")
	}
}

// TestABTest_AssignDeterministic verifies same orgID always gets the same variant.
func TestABTest_AssignDeterministic(t *testing.T) {
	variants := map[string]float64{
		"control":   0.5,
		"treatment": 0.5,
	}
	test := NewABTest("cache_test", variants)

	v1 := test.Assign("org-1")
	v2 := test.Assign("org-1")
	if v1 != v2 {
		t.Errorf("same orgID should get same variant: got %q and %q", v1, v2)
	}

	// GetVariant returns the already-assigned variant (must be one of the known variants).
	v3 := test.GetVariant("org-1")
	if v3 == "" {
		t.Errorf("GetVariant should return a variant, got empty string")
	}
	found := false
	for name := range variants {
		if v3 == name {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("GetVariant returned unknown variant %q", v3)
	}

	// GetVariant is now deterministic (hash-based), so it always returns a variant.
	v4 := test.GetVariant("org-unknown")
	if v4 == "" {
		t.Error("GetVariant should return a variant even for unassigned orgs (deterministic hash)")
	}
}

// TestGetAnalyticsSnapshot verifies the package-level singleton returns data.
func TestGetAnalyticsSnapshot(t *testing.T) {
	snap := GetAnalyticsSnapshot()
	if snap == nil {
		t.Fatal("GetAnalyticsSnapshot should not return nil")
	}
	if _, ok := snap["error"]; ok {
		t.Error("analytics should be initialized: ", snap["error"])
	}
}

// TestRecordGlobalHitMiss verifies package-level recording functions.
func TestRecordGlobalHitMiss(t *testing.T) {
	a := NewAnalytics()

	RecordGlobalHit("org-1", "gpt-4", "exact", 50)
	RecordGlobalMiss("org-1", "gpt-4")

	snap := a.Snapshot()
	hits := snap["total_hits"]
	if hits == nil {
		t.Fatal("expected total_hits after recording")
	}
}

// TestAnalytics_SnapshotReturnsCopies verifies Snapshot and GetOrgAnalytics
// hand out deep copies: mutating the returned maps/structs must not corrupt
// the collector's live state.
func TestAnalytics_SnapshotReturnsCopies(t *testing.T) {
	a := NewAnalytics()
	a.RecordHit("org-1", "gpt-4", "exact", 10)

	snap := a.Snapshot()
	hits := snap["total_hits"].(map[string]int)
	hits["exact"] = 999
	hits["injected"] = 1

	fresh := a.Snapshot()
	freshHits := fresh["total_hits"].(map[string]int)
	if freshHits["exact"] != 1 {
		t.Errorf("Snapshot must not expose live maps: exact = %d, want 1", freshHits["exact"])
	}
	if _, ok := freshHits["injected"]; ok {
		t.Error("Snapshot must not expose live maps: injected key leaked into collector")
	}

	org := a.GetOrgAnalytics("org-1")
	org.HitsExact = 999
	org.Misses = -5

	if again := a.GetOrgAnalytics("org-1"); again.HitsExact != 1 || again.Misses != 0 {
		t.Errorf("GetOrgAnalytics must return a copy, got HitsExact=%d Misses=%d", again.HitsExact, again.Misses)
	}
}

// TestAnalytics_SnapshotVsRecordRace exercises concurrent recording against
// concurrent Snapshot/GetOrgAnalytics readers; run under -race this fails if
// the read paths touch live (unlocked) state.
func TestAnalytics_SnapshotVsRecordRace(t *testing.T) {
	a := NewAnalytics()

	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				if i%2 == 0 {
					a.RecordHit("org-race", "tier-race", "exact", 1)
				} else {
					a.RecordMiss("org-race", "tier-race")
				}
			}
		}(w)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			_ = a.Snapshot()
			_ = a.GetOrgAnalytics("org-race")
		}
	}()
	wg.Wait()

	org := a.GetOrgAnalytics("org-race")
	if org == nil {
		t.Fatal("expected org analytics for org-race")
	}
	if got := org.HitsExact + org.Misses; got != 4*500 {
		t.Errorf("recorded events = %d, want %d (reads must never drop writes)", got, 4*500)
	}
}
