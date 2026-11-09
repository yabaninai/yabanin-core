package evaluator

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRT01_Snapshot_BarrierInterleave_EachOrgUsesOwnSnapshot(t *testing.T) {
	rulesByOrg := map[string][]Rule{
		"org-a": {{ID: "ra", OrgID: "org-a", MatchExpr: `model_requested == "gpt-4"`, TargetModel: "target-a", Priority: 10, Enabled: true}},
		"org-b": {{ID: "rb", OrgID: "org-b", MatchExpr: `model_requested == "gpt-4"`, TargetModel: "target-b", Priority: 10, Enabled: true}},
	}

	var barrier sync.WaitGroup
	var wg sync.WaitGroup
	results := make(map[string]string, 2)
	var mu sync.Mutex

	start := func(org string) {
		defer wg.Done()
		snap := NewSnapshot(org, rulesByOrg[org])
		barrier.Done() // arrive
		barrier.Wait() // proceed only once both orgs hold their snapshot
		for i := 0; i < 100; i++ {
			got := snap.Evaluate(Context{OrgID: org}, "gpt-4")
			mu.Lock()
			results[org] = got
			mu.Unlock()
			if got == "" {
				t.Errorf("org %s: evaluate must not lose its own snapshot", org)
				return
			}
		}
	}

	barrier.Add(2)
	wg.Add(2)
	go start("org-a")
	go start("org-b")
	wg.Wait()

	assert.Equal(t, "target-a", results["org-a"])
	assert.Equal(t, "target-b", results["org-b"])
}

func TestRT01_Snapshot_ForeignOrgIDNoMatch(t *testing.T) {
	snap := NewSnapshot("org-b", []Rule{
		{ID: "rb", OrgID: "org-b", MatchExpr: `model_requested == "gpt-4"`, TargetModel: "target-b", Priority: 10, Enabled: true},
	})
	assert.Empty(t, snap.Evaluate(Context{OrgID: "org-a"}, "gpt-4"),
		"a context from another org must never match a foreign org's snapshot")
}

func TestRT01_Snapshot_ForeignOrgRuleDropped(t *testing.T) {
	// A snapshot built for org-a must ignore (not match on) a rule row of
	// org-b even if the store accidentally returns it.
	snap := NewSnapshot("org-a", []Rule{
		{ID: "rb", OrgID: "org-b", MatchExpr: `model_requested == "gpt-4"`, TargetModel: "target-b", Priority: 10, Enabled: true},
	})
	assert.Empty(t, snap.Evaluate(Context{OrgID: "org-a"}, "gpt-4"))
}

func TestRT01_Snapshot_ReplacementDoesNotMutateActiveSnapshot(t *testing.T) {
	rules := []Rule{
		{ID: "r1", OrgID: "org-a", MatchExpr: `model_requested == "gpt-4"`, TargetModel: "target-a", Priority: 10, Enabled: true},
	}
	snap := NewSnapshot("org-a", rules)

	// Mutating the input slice after creation must not affect the snapshot.
	rules[0].TargetModel = "tampered"
	assert.Equal(t, "target-a", snap.Evaluate(Context{OrgID: "org-a"}, "gpt-4"))

	// Building a replacement snapshot must not affect the active one.
	replacement := NewSnapshot("org-a", []Rule{
		{ID: "r2", OrgID: "org-a", MatchExpr: `model_requested == "gpt-4"`, TargetModel: "target-b", Priority: 10, Enabled: true},
	})
	assert.Equal(t, "target-b", replacement.Evaluate(Context{OrgID: "org-a"}, "gpt-4"))
	assert.Equal(t, "target-a", snap.Evaluate(Context{OrgID: "org-a"}, "gpt-4"))
}

func TestRT01_Snapshot_PriorityAndOrderSemantics(t *testing.T) {
	rules := []Rule{
		{ID: "low", OrgID: "org-a", MatchExpr: `model_requested == "gpt-4"`, TargetModel: "low", Priority: 1, Enabled: true},
		{ID: "high", OrgID: "org-a", MatchExpr: `model_requested == "gpt-4"`, TargetModel: "high", Priority: 10, Enabled: true},
		{ID: "eq1", OrgID: "org-a", MatchExpr: `model_requested == "gpt-4"`, TargetModel: "eq-first", Priority: 5, Enabled: true},
		{ID: "eq2", OrgID: "org-a", MatchExpr: `model_requested == "gpt-4"`, TargetModel: "eq-second", Priority: 5, Enabled: true},
	}
	got := NewSnapshot("org-a", rules).Evaluate(Context{OrgID: "org-a"}, "gpt-4")
	assert.Equal(t, "high", got, "highest priority must win")

	tie := NewSnapshot("org-a", []Rule{
		{ID: "eq2", OrgID: "org-a", MatchExpr: `model_requested == "gpt-4"`, TargetModel: "eq-second", Priority: 5, Enabled: true},
		{ID: "eq1", OrgID: "org-a", MatchExpr: `model_requested == "gpt-4"`, TargetModel: "eq-first", Priority: 5, Enabled: true},
	})
	assert.Equal(t, "eq-second", tie.Evaluate(Context{OrgID: "org-a"}, "gpt-4"),
		"equal priorities must keep input (DB) order")
}

func TestRT01_Snapshot_MalformedDisabledEmpty_NeverMatchNeverPanic(t *testing.T) {
	rules := []Rule{
		{ID: "malformed", OrgID: "org-a", MatchExpr: `model_requested == `, TargetModel: "bad", Priority: 10, Enabled: true},
		{ID: "dangling", OrgID: "org-a", MatchExpr: `model_requested == "gpt-4" || `, TargetModel: "bad", Priority: 9, Enabled: true},
		{ID: "disabled", OrgID: "org-a", MatchExpr: `model_requested == "gpt-4"`, TargetModel: "off", Priority: 8, Enabled: false},
		{ID: "empty", OrgID: "org-a", MatchExpr: "", TargetModel: "blank", Priority: 7, Enabled: true},
		{ID: "good", OrgID: "org-a", MatchExpr: `model_requested == "gpt-4"`, TargetModel: "good", Priority: 1, Enabled: true},
	}
	snap := NewSnapshot("org-a", rules)
	assert.Equal(t, "good", snap.Evaluate(Context{OrgID: "org-a"}, "gpt-4"),
		"malformed, disabled and empty-expr rules must be skipped, not fatal")
	assert.Empty(t, snap.Evaluate(Context{OrgID: "org-a"}, "claude-3"))
}

func TestRT01_Snapshot_EmptyRules(t *testing.T) {
	snap := NewSnapshot("org-a", nil)
	require.NotNil(t, snap)
	assert.Empty(t, snap.Evaluate(Context{OrgID: "org-a"}, "gpt-4"))
}

func TestRT01_SnapshotCache_ReusesSameRevision(t *testing.T) {
	c := NewSnapshotCache(0, 0)
	rules := []Rule{{ID: "r1", OrgID: "org-a", MatchExpr: `model_requested == "gpt-4"`, TargetModel: "target-a", Priority: 1, Enabled: true}}

	first := c.Get("org-a", rules)
	second := c.Get("org-a", rules)
	assert.Same(t, first, second, "unchanged rules must reuse the compiled snapshot")
}

func TestRT01_SnapshotCache_RebuildsOnRuleChange(t *testing.T) {
	c := NewSnapshotCache(0, 0)
	old := []Rule{{ID: "r1", OrgID: "org-a", MatchExpr: `model_requested == "gpt-4"`, TargetModel: "old", Priority: 1, Enabled: true}}
	updated := []Rule{{ID: "r1", OrgID: "org-a", MatchExpr: `model_requested == "gpt-4"`, TargetModel: "new", Priority: 1, Enabled: true}}

	assert.Equal(t, "old", c.Get("org-a", old).Evaluate(Context{OrgID: "org-a"}, "gpt-4"))
	assert.Equal(t, "new", c.Get("org-a", updated).Evaluate(Context{OrgID: "org-a"}, "gpt-4"),
		"changed rules must rebuild the snapshot (revision hash)")
}

func TestRT01_SnapshotCache_Invalidate(t *testing.T) {
	c := NewSnapshotCache(0, 0)
	rules := []Rule{{ID: "r1", OrgID: "org-a", MatchExpr: `model_requested == "gpt-4"`, TargetModel: "target-a", Priority: 1, Enabled: true}}
	first := c.Get("org-a", rules)
	c.Invalidate("org-a")
	second := c.Get("org-a", rules)
	assert.NotSame(t, first, second, "invalidated org must get a freshly compiled snapshot")
	c.Invalidate("unknown-org") // must be a no-op, not a panic
}

func TestRT01_SnapshotCache_TTLExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	c := NewSnapshotCache(time.Minute, 0)
	c.now = func() time.Time { return now }
	rules := []Rule{{ID: "r1", OrgID: "org-a", MatchExpr: `model_requested == "gpt-4"`, TargetModel: "target-a", Priority: 1, Enabled: true}}

	first := c.Get("org-a", rules)
	now = now.Add(30 * time.Second)
	assert.Same(t, first, c.Get("org-a", rules), "entry must live until TTL")
	now = now.Add(31 * time.Second)
	assert.NotSame(t, first, c.Get("org-a", rules), "expired entry must be rebuilt")
}

func TestRT01_SnapshotCache_MaxEntriesBounded(t *testing.T) {
	c := NewSnapshotCache(0, 2)
	mkRules := func(org string) []Rule {
		return []Rule{{ID: "r", OrgID: org, MatchExpr: `model_requested == "gpt-4"`, TargetModel: org, Priority: 1, Enabled: true}}
	}
	c.Get("org-a", mkRules("org-a"))
	c.Get("org-b", mkRules("org-b"))
	c.Get("org-c", mkRules("org-c")) // evicts org-a (LRU)

	assert.Len(t, c.entries, 2, "cache must stay within maxEntries")
	assert.NotContains(t, c.entries, "org-a")
	c.Invalidate("org-c")
	assert.NotContains(t, c.entries, "org-c")
}

func TestRT01_SnapshotCache_ConcurrentGetSameRevision(t *testing.T) {
	c := NewSnapshotCache(0, 0)
	rules := []Rule{{ID: "r1", OrgID: "org-a", MatchExpr: `model_requested == "gpt-4"`, TargetModel: "target-a", Priority: 1, Enabled: true}}

	var wg sync.WaitGroup
	snaps := make([]*Snapshot, 8)
	for i := range snaps {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			snaps[i] = c.Get("org-a", rules)
		}(i)
	}
	wg.Wait()
	for _, s := range snaps {
		assert.Same(t, snaps[0], s, "concurrent Gets of the same revision must agree on one snapshot")
	}
}

func TestRT01_Snapshot_NilSafety(t *testing.T) {
	var snap *Snapshot
	assert.Empty(t, snap.OrgID())
	assert.Empty(t, snap.Evaluate(Context{OrgID: "org-a"}, "gpt-4"),
		"nil snapshot must degrade to no override, not panic")
}
