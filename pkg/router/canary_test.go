package router

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/classifier"
)

// --- deterministic arm (D2) ---------------------------------------------------

func TestCanaryArm_StickySameSession(t *testing.T) {
	// 100 sessions, 5 resolutions each, two different percents: every
	// session keeps its arm within a percent, and a session in the canary
	// arm at 10% stays in the canary arm at 20% (monotone ramping — the
	// bucket is a pure function of the session id).
	for s := 0; s < 100; s++ {
		id := "sess-" + string(rune('a'+s%26)) + "-" + time.Duration(s).String()
		first10 := CanaryArm(id, 10)
		for rep := 0; rep < 5; rep++ {
			assert.Equal(t, first10, CanaryArm(id, 10), "session %q flipped arms", id)
		}
		if first10 {
			assert.True(t, CanaryArm(id, 20), "session %q left the canary arm on ramp-up", id)
		}
	}
}

func TestCanaryArm_SplitAccuracy(t *testing.T) {
	// Whole-percent accuracy: 20k distinct sessions against percents
	// 1/10/30/50/99 — the measured share stays within ±2 percentage points
	// (the deterministic hash makes the split exact up to bucket quantization;
	// the tolerance guards the hash, not a distribution claim).
	for _, percent := range []int{1, 10, 30, 50, 99} {
		n := 20000
		canary := 0
		for i := 0; i < n; i++ {
			if CanaryArm("split-"+time.Duration(i).String(), percent) {
				canary++
			}
		}
		share := 100 * float64(canary) / float64(n)
		assert.InDelta(t, float64(percent), share, 2.0,
			"percent=%d measured share %.2f", percent, share)
	}
}

func TestCanaryArm_EmptySessionNeverCanary(t *testing.T) {
	assert.False(t, CanaryArm("", 99), "a session without identity must never take the canary arm")
	assert.False(t, CanaryArm("real-session", 0), "percent 0 is all-base")
	assert.True(t, CanaryArm("real-session", 100), "percent 100 is all-canary (store forbids it; the split itself is total)")
}

// fakeCanaryLoader counts loads and returns a switchable rollout set.
type fakeCanaryLoader struct {
	loads    int
	rollouts []CanaryRollout
	err      error
}

func (f *fakeCanaryLoader) LoadCanaryRollouts(_ context.Context, _ string) ([]CanaryRollout, error) {
	f.loads++
	if f.err != nil {
		return nil, f.err
	}
	return f.rollouts, nil
}

// fakeCanaryVersions is the version-key probe with a settable value and
// optional forced failure.
type fakeCanaryVersions struct {
	version int64
	fail    bool
}

func (f *fakeCanaryVersions) GetCanaryVersion(_ context.Context, _ string) (int64, error) {
	if f.fail {
		return 0, errors.New("version probe down")
	}
	return f.version, nil
}

func TestCanaryRolloutCache_VersionInvalidation(t *testing.T) {
	loader := &fakeCanaryLoader{rollouts: []CanaryRollout{{RolloutID: "r1", Name: "roll", Version: 1, BaseModel: "base", CanaryModel: "can", Percent: 10}}}
	versions := &fakeCanaryVersions{version: 1}
	c := NewCanaryRolloutCache(loader, versions, time.Minute, nil)

	got, err := c.Resolve(context.Background(), "org-1")
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, 1, loader.loads, "first resolve loads")

	// Unchanged version + within TTL: cached, no load.
	for i := 0; i < 10; i++ {
		_, err := c.Resolve(context.Background(), "org-1")
		require.NoError(t, err)
	}
	assert.Equal(t, 1, loader.loads, "unchanged version must not reload")

	// A bump invalidates immediately — the whole point of the version key.
	versions.version = 2
	_, err = c.Resolve(context.Background(), "org-1")
	require.NoError(t, err)
	assert.Equal(t, 2, loader.loads, "version bump must drop the cache")
}

func TestCanaryRolloutCache_TTLFallbackWhenProbeDown(t *testing.T) {
	loader := &fakeCanaryLoader{rollouts: nil}
	versions := &fakeCanaryVersions{version: 1}
	c := NewCanaryRolloutCache(loader, versions, time.Minute, nil)

	_, err := c.Resolve(context.Background(), "org-1")
	require.NoError(t, err)
	assert.Equal(t, 1, loader.loads)

	// Probe failure inside the TTL: serve cached, no load.
	versions.fail = true
	_, err = c.Resolve(context.Background(), "org-1")
	require.NoError(t, err)
	assert.Equal(t, 1, loader.loads, "probe failure must degrade to TTL")

	// Past the TTL with the probe still down: reload anyway.
	c.mu.Lock()
	for _, e := range c.orgs {
		e.loadedAt = time.Now().Add(-2 * time.Minute)
	}
	c.mu.Unlock()
	_, err = c.Resolve(context.Background(), "org-1")
	require.NoError(t, err)
	assert.Equal(t, 2, loader.loads)
}

func TestCanaryRolloutCache_LoadFailureKeepsStale(t *testing.T) {
	loader := &fakeCanaryLoader{rollouts: []CanaryRollout{{RolloutID: "r1", BaseModel: "base", CanaryModel: "can", Percent: 10, Version: 1}}}
	c := NewCanaryRolloutCache(loader, nil, time.Minute, nil)

	_, err := c.Resolve(context.Background(), "org-1")
	require.NoError(t, err)

	// Version bump forces a reload that fails: the stale snapshot serves
	// (fail-open bounded by TTL), never an error to the request path.
	loader.err = errors.New("snapshot load down")
	got, err := c.Resolve(context.Background(), "org-1")
	require.NoError(t, err)
	require.Len(t, got, 1, "stale snapshot must serve after a failed reload")
}

func TestCanaryRolloutCache_ActivationChurnRetries(t *testing.T) {
	// The double-probe (before/after the load) catches an activation racing
	// the load: the first attempt observes a moved version key, retries, and
	// installs a snapshot pinned to the post-activation version — a mixed
	// snapshot is never installed (PolicyRuntime.refreshWithOutcome parity).
	loader := &fakeCanaryLoader{rollouts: []CanaryRollout{{RolloutID: "r1", BaseModel: "base", CanaryModel: "can", Percent: 10, Version: 1}}}
	versions := &fakeCanaryVersions{}
	c := NewCanaryRolloutCache(loader, versions, time.Minute, nil)

	// Probe sequence on the first refresh: before=1, after=2 (activation
	// raced), retry: before=2, after=2 (stable).
	seq := []int64{1, 2, 2, 2}
	i := 0
	c.versions = churningVersions{get: func() (int64, error) {
		v := seq[i]
		i++
		return v, nil
	}}

	got, err := c.Resolve(context.Background(), "org-1")
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, 2, loader.loads, "a raced load must be retried once")

	c.mu.Lock()
	pinned := c.orgs["org-1"]
	c.mu.Unlock()
	require.NotNil(t, pinned)
	assert.Equal(t, int64(2), pinned.version, "the installed snapshot must be pinned to the post-activation version")
}

type churningVersions struct {
	get func() (int64, error)
}

func (c churningVersions) GetCanaryVersion(context.Context, string) (int64, error) { return c.get() }

func TestCanaryRolloutCache_EmptyOrgIsCached(t *testing.T) {
	// No-rollout → zero overhead: one snapshot load per TTL, then cached.
	loader := &fakeCanaryLoader{}
	c := NewCanaryRolloutCache(loader, nil, time.Minute, nil)

	for i := 0; i < 25; i++ {
		got, err := c.Resolve(context.Background(), "org-empty")
		require.NoError(t, err)
		assert.Empty(t, got)
	}
	assert.Equal(t, 1, loader.loads, "the empty answer must cache like any other")
}

// --- split point ----------------------------------------------------------------

// canaryTestPool builds a router whose pool deterministically selects the
// base model: base carries all the weight, canary sits in the pool at weight
// 0 (member but never picked by round-robin), so the canary traffic arrives
// ONLY through the session-hash swap.
func canaryTestRouter(rollouts []CanaryRollout) (*TierRouter, *fakeCanaryLoader) {
	loader := &mockModelLoader{models: []ModelInfo{
		{Name: "base-model", Tier: "smart", TierPool: []string{"medium"}, Weight: 1, Enabled: true},
		{Name: "canary-model", Tier: "smart", TierPool: []string{"medium"}, Weight: 0, Enabled: true},
	}}
	tr := NewTierRouter(loader, newMockRedis())
	cache := NewCanaryRolloutCache(&fakeCanaryLoader{rollouts: rollouts}, nil, time.Minute, nil)
	tr.WithCanaryRollouts(cache)
	return tr, cache.loader.(*fakeCanaryLoader)
}

// canarySessionFor finds a session id whose arm matches want at percent.
func canarySessionFor(t *testing.T, percent int, want bool, salt string) string {
	t.Helper()
	for i := 0; i < 100000; i++ {
		id := salt + time.Duration(i).String()
		if CanaryArm(id, percent) == want {
			return id
		}
	}
	t.Fatalf("no session found for want=%v percent=%d", want, percent)
	return ""
}

func TestSelectModelForSession_CanarySwapAndStickiness(t *testing.T) {
	rollout := []CanaryRollout{{RolloutID: "r1", Name: "roll", Version: 1, BaseModel: "base-model", CanaryModel: "canary-model", Percent: 30}}
	tr, _ := canaryTestRouter(rollout)

	canarySession := canarySessionFor(t, 30, true, "swap-")
	baseSession := canarySessionFor(t, 30, false, "swap-")

	sel, dec, err := tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", canarySession)
	require.NoError(t, err)
	assert.Equal(t, "canary-model", sel.Name, "canary-arm session must get the canary model")
	assert.True(t, dec.Active())
	assert.Equal(t, "canary", dec.Arm)
	assert.Equal(t, "base-model", dec.From)
	assert.Equal(t, "canary-model", dec.To)
	assert.Equal(t, 30, dec.Percent)
	assert.True(t, dec.Swapped())

	// Stickiness through the full router: 100 repeats of the same session,
	// same arm every time (and same model).
	for i := 0; i < 100; i++ {
		sel, dec, err := tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", canarySession)
		require.NoError(t, err)
		assert.Equal(t, "canary-model", sel.Name)
		assert.Equal(t, "canary", dec.Arm)
	}

	sel, dec, err = tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", baseSession)
	require.NoError(t, err)
	assert.Equal(t, "base-model", sel.Name, "base-arm session must keep the base model")
	assert.True(t, dec.Active())
	assert.Equal(t, "base", dec.Arm)
	assert.False(t, dec.Swapped())
}

func TestSelectModelForSession_CanaryOutsidePoolStaysBase(t *testing.T) {
	// The canary model is not servable from this pool (different tier pool):
	// the hash may put the session in the canary arm, the filter never
	// bypasses — base serves, the decision records the base arm.
	loader := &mockModelLoader{models: []ModelInfo{
		{Name: "base-model", Tier: "smart", TierPool: []string{"medium"}, Weight: 1, Enabled: true},
		{Name: "canary-model", Tier: "smart", TierPool: []string{"hard"}, Weight: 1, Enabled: true},
	}}
	tr := NewTierRouter(loader, newMockRedis())
	tr.WithCanaryRollouts(NewCanaryRolloutCache(&fakeCanaryLoader{
		rollouts: []CanaryRollout{{RolloutID: "r1", Name: "roll", Version: 1, BaseModel: "base-model", CanaryModel: "canary-model", Percent: 50}},
	}, nil, time.Minute, nil))

	canarySession := canarySessionFor(t, 50, true, "oob-")
	sel, dec, err := tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", canarySession)
	require.NoError(t, err)
	assert.Equal(t, "base-model", sel.Name)
	assert.True(t, dec.Active())
	assert.Equal(t, "base", dec.Arm, "an unservable canary model must keep the request on base")
}

func TestSelectModelForSession_ZeroOverheadPaths(t *testing.T) {
	rollout := []CanaryRollout{{RolloutID: "r1", Name: "roll", Version: 1, BaseModel: "base-model", CanaryModel: "canary-model", Percent: 50}}

	t.Run("no cache wired behaves like SelectModelWithAffinity", func(t *testing.T) {
		loader := &mockModelLoader{models: []ModelInfo{
			{Name: "base-model", TierPool: []string{"medium"}, Weight: 1, Enabled: true},
		}}
		tr := NewTierRouter(loader, newMockRedis())
		sel, dec, err := tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", "any-session")
		require.NoError(t, err)
		assert.Equal(t, "base-model", sel.Name)
		assert.False(t, dec.Active(), "unwired canary must produce an inactive decision")
	})

	t.Run("sessionless request never resolves rollouts", func(t *testing.T) {
		tr, loader := canaryTestRouter(rollout)
		sel, dec, err := tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", "")
		require.NoError(t, err)
		assert.Equal(t, "base-model", sel.Name)
		assert.False(t, dec.Active())
		assert.Equal(t, 0, loader.loads, "an empty session id must not even load the rollout snapshot")
	})

	t.Run("unmatched selection skips the rollout", func(t *testing.T) {
		loader := &mockModelLoader{models: []ModelInfo{
			{Name: "other-model", TierPool: []string{"medium"}, Weight: 1, Enabled: true},
		}}
		tr2 := NewTierRouter(loader, newMockRedis())
		tr2.WithCanaryRollouts(NewCanaryRolloutCache(&fakeCanaryLoader{rollouts: rollout}, nil, time.Minute, nil))
		sel2, dec2, err := tr2.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", "some-session")
		require.NoError(t, err)
		assert.Equal(t, "other-model", sel2.Name)
		assert.False(t, dec2.Active(), "a selection no rollout targets must stay decision-free")
	})
}

func TestSelectModelForSession_RollbackDropsRollout(t *testing.T) {
	// Manual rollback = the store flips enabled (the snapshot stops carrying
	// the rollout); after the version bump the resolver reloads and the same
	// canary-arm session routes base. The already-made decision of an
	// earlier request is out of scope here by construction (it is pinned in
	// the gateway chatContext at routing time — see the gateway tests).
	loader := &fakeCanaryLoader{rollouts: []CanaryRollout{{RolloutID: "r1", Name: "roll", Version: 1, BaseModel: "base-model", CanaryModel: "canary-model", Percent: 99}}}
	versions := &fakeCanaryVersions{version: 1}
	tr := NewTierRouter(&mockModelLoader{models: []ModelInfo{
		{Name: "base-model", TierPool: []string{"medium"}, Weight: 1, Enabled: true},
		{Name: "canary-model", TierPool: []string{"medium"}, Weight: 0, Enabled: true},
	}}, newMockRedis())
	tr.WithCanaryRollouts(NewCanaryRolloutCache(loader, versions, time.Minute, nil))

	session := canarySessionFor(t, 99, true, "rb-")
	sel, _, err := tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", session)
	require.NoError(t, err)
	assert.Equal(t, "canary-model", sel.Name)

	// Rollback: snapshot no longer carries the rollout; version bumped.
	loader.rollouts = nil
	versions.version = 2

	sel, dec, err := tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", session)
	require.NoError(t, err)
	assert.Equal(t, "base-model", sel.Name, "after rollback the canary-arm session must route base")
	assert.False(t, dec.Active())
}

func TestSelectModelForSession_NewVersionChangesPercent(t *testing.T) {
	// — sessions between the old and new percent move to the canary arm on
	// their NEXT request; sessions already canary stay canary (monotone).
	loader := &fakeCanaryLoader{rollouts: []CanaryRollout{{RolloutID: "r1", Name: "roll", Version: 1, BaseModel: "base-model", CanaryModel: "canary-model", Percent: 10}}}
	versions := &fakeCanaryVersions{version: 1}
	tr := NewTierRouter(&mockModelLoader{models: []ModelInfo{
		{Name: "base-model", TierPool: []string{"medium"}, Weight: 1, Enabled: true},
		{Name: "canary-model", TierPool: []string{"medium"}, Weight: 0, Enabled: true},
	}}, newMockRedis())
	tr.WithCanaryRollouts(NewCanaryRolloutCache(loader, versions, time.Minute, nil))

	between := canarySessionFor(t, 20, true, "ramp-") // canary at 20%, base at 10%
	sel, _, err := tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", between)
	require.NoError(t, err)
	assert.Equal(t, "base-model", sel.Name, "at 10% the session is base")

	loader.rollouts = []CanaryRollout{{RolloutID: "r1", Name: "roll", Version: 2, BaseModel: "base-model", CanaryModel: "canary-model", Percent: 20}}
	versions.version = 2

	sel, dec, err := tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", between)
	require.NoError(t, err)
	assert.Equal(t, "canary-model", sel.Name, "after activating the 20% version the session moves to canary")
	assert.Equal(t, 2, dec.Version)
	assert.Equal(t, 20, dec.Percent)
}

// orgSplitCanaryLoader serves a different rollout set per org (the D1
// per-org resolution seam).
type orgSplitCanaryLoader struct {
	byOrg map[string][]CanaryRollout
}

func (f *orgSplitCanaryLoader) LoadCanaryRollouts(_ context.Context, orgID string) ([]CanaryRollout, error) {
	return f.byOrg[orgID], nil
}

func TestSelectModelForSession_PerOrgRolloutIsolation(t *testing.T) {
	// D1×D2 seam: the bucket is a pure function of the session id, but the
	// rollout (percent, version, models) is the ORG's row. One session id
	// shared by two orgs must resolve against each org's own rollout — never
	// another org's percent/version — and keep a stable arm per org.
	loader := &mockModelLoader{models: []ModelInfo{
		{Name: "base-model", TierPool: []string{"medium"}, Weight: 1, Enabled: true},
		{Name: "canary-model", TierPool: []string{"medium"}, Weight: 0, Enabled: true},
	}}
	tr := NewTierRouter(loader, newMockRedis())
	tr.WithCanaryRollouts(NewCanaryRolloutCache(&orgSplitCanaryLoader{byOrg: map[string][]CanaryRollout{
		"org-a": {{RolloutID: "r-a", Name: "ramp-a", Version: 7, BaseModel: "base-model", CanaryModel: "canary-model", Percent: 50}},
		"org-b": {{RolloutID: "r-b", Name: "ramp-b", Version: 3, BaseModel: "base-model", CanaryModel: "canary-model", Percent: 30}},
	}}, nil, time.Minute, nil))

	// A deterministic shared identity whose bucket sits strictly between the
	// two percents: canary for org-a (37 < 50), base for org-b (37 >= 30) —
	// the per-org outcomes differ by the ORG's percent, not by chance.
	shared := "iso-session"
	for i := 0; canaryBucket(shared) != 37; i++ {
		shared = "iso-session-" + time.Duration(i).String()
	}
	require.Equal(t, 37, canaryBucket(shared))

	for i := 0; i < 5; i++ {
		selA, decA, err := tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-a", "", shared)
		require.NoError(t, err)
		assert.Equal(t, "canary-model", selA.Name, "org-a: bucket 37 < 50 → canary, every repeat")
		assert.Equal(t, CanaryDecisionArmCanary, decA.Arm)
		assert.Equal(t, "base-model", decA.From)
		assert.Equal(t, "canary-model", decA.To)
		assert.Equal(t, "r-a", decA.RolloutID)
		assert.Equal(t, 7, decA.Version, "org-a resolves ITS rollout version, never org-b's")
		assert.Equal(t, 50, decA.Percent)

		selB, decB, err := tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-b", "", shared)
		require.NoError(t, err)
		assert.Equal(t, "base-model", selB.Name, "org-b: bucket 37 >= 30 → base, every repeat")
		assert.Equal(t, CanaryDecisionArmBase, decB.Arm)
		assert.Equal(t, "r-b", decB.RolloutID, "org-b must never see org-a's rollout id")
		assert.Equal(t, 3, decB.Version)
		assert.Equal(t, 30, decB.Percent)
	}

	// An org without rollouts takes the inactive per-org path for the same
	// session — the other orgs' rollouts do not leak into its decision.
	_, decC, err := tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-c", "", shared)
	require.NoError(t, err)
	assert.False(t, decC.Active(), "org-c has no rollouts: the decision must be inactive, not another org's")
}

// --- resolver hardening: constructor, eviction, first-load failures ----------

func TestNewCanaryRolloutCache_Defaults(t *testing.T) {
	assert.Nil(t, NewCanaryRolloutCache(nil, nil, time.Minute, nil),
		"a nil loader must yield a nil cache (feature off)")

	c := NewCanaryRolloutCache(&fakeCanaryLoader{}, nil, 0, nil)
	require.NotNil(t, c)
	assert.Equal(t, canaryCacheTTL, c.ttl, "ttl<=0 must fall back to the documented default")
	assert.NotNil(t, c.log, "a nil logger must fall back to slog.Default()")
	assert.NotNil(t, c.now)
}

func TestCanaryRolloutCache_FirstLoadFailureSurfaces(t *testing.T) {
	// No prior snapshot: a failed load must surface as an error (the caller
	// fail-opens to base; a silent empty answer would look like "org has no
	// rollouts" and pin that for a TTL).
	loader := &fakeCanaryLoader{err: errors.New("snapshot down")}
	c := NewCanaryRolloutCache(loader, nil, time.Minute, nil)

	got, err := c.Resolve(context.Background(), "org-1")
	require.Error(t, err)
	assert.Nil(t, got)
	assert.Equal(t, 1, loader.loads)
}

func TestCanaryRolloutCache_ChurnWithoutStaleErrors(t *testing.T) {
	// Every probe observes a moving version (activation storm): after the
	// single retry the refresh gives up. With no stale snapshot to serve it
	// must return errCanarySnapshotChurn, never install a mixed snapshot.
	loader := &fakeCanaryLoader{rollouts: []CanaryRollout{{RolloutID: "r1", BaseModel: "b", CanaryModel: "c", Percent: 5, Version: 1}}}
	c := NewCanaryRolloutCache(loader, nil, time.Minute, nil)
	n := int64(0)
	c.versions = churningVersions{get: func() (int64, error) {
		n++
		return n, nil // before != after on every attempt
	}}

	_, err := c.Resolve(context.Background(), "org-1")
	require.ErrorIs(t, err, errCanarySnapshotChurn)
	assert.Equal(t, 2, loader.loads, "exactly one retry, then give up")

	c.mu.Lock()
	installed := c.orgs["org-1"]
	c.mu.Unlock()
	assert.Nil(t, installed, "a churned snapshot must never be installed")
}

func TestCanaryRolloutCache_EvictsOverCap(t *testing.T) {
	// The org map is capped (canaryMaxOrgs); the eviction drops the
	// oldest-loaded entries. Seeded directly for determinism: the clock and
	// load order fully decide the victim set.
	loader := &fakeCanaryLoader{}
	c := NewCanaryRolloutCache(loader, nil, time.Minute, nil)

	base := time.Now().Add(-time.Hour)
	c.mu.Lock()
	for i := 0; i < canaryMaxOrgs+5; i++ {
		c.orgs["org-"+time.Duration(i).String()] = &canaryEntry{
			rollouts: nil, loadedAt: base.Add(time.Duration(i) * time.Second),
		}
	}
	c.mu.Unlock()

	// One fresh resolve installs one entry and trips the eviction.
	_, err := c.Resolve(context.Background(), "org-fresh")
	require.NoError(t, err)

	c.mu.Lock()
	size := len(c.orgs)
	_, oldestPresent := c.orgs["org-"+time.Duration(0).String()]
	_, newestPresent := c.orgs["org-"+time.Duration(canaryMaxOrgs+4).String()]
	_, freshPresent := c.orgs["org-fresh"]
	c.mu.Unlock()
	assert.Equal(t, canaryMaxOrgs, size, "the org map must stay at the cap")
	assert.False(t, oldestPresent, "the oldest entries must be evicted first")
	assert.True(t, newestPresent, "the newest entries must survive")
	assert.True(t, freshPresent, "the just-loaded entry must survive")
}

func TestSelectModelForSession_EmptyClassPoolErrors(t *testing.T) {
	// The canary split never masks selection errors: an empty registry (no
	// pool for any class after the fallback chain) surfaces exactly like
	// SelectModelWithAffinity.
	loader := &mockModelLoader{models: nil}
	tr := NewTierRouter(loader, newMockRedis())
	tr.WithCanaryRollouts(NewCanaryRolloutCache(&fakeCanaryLoader{}, nil, time.Minute, nil))

	_, _, err := tr.SelectModelForSession(context.Background(), classifier.ClassEasy, "org-1", "", "sess")
	require.Error(t, err, "no models for the class must surface, not fail-open to a rollout")
}

func TestSelectModelForSession_ResolverFailureFailsOpenToBase(t *testing.T) {
	// First resolution fails (store down, no cached snapshot): the request
	// still routes on base — rollout infrastructure never fails a request.
	loader := &mockModelLoader{models: []ModelInfo{
		{Name: "base-model", TierPool: []string{"medium"}, Weight: 1, Enabled: true},
		{Name: "canary-model", TierPool: []string{"medium"}, Weight: 0, Enabled: true},
	}}
	tr := NewTierRouter(loader, newMockRedis())
	tr.WithCanaryRollouts(NewCanaryRolloutCache(
		&fakeCanaryLoader{err: errors.New("canarystore down")}, nil, time.Minute, nil))

	sel, dec, err := tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", "any-session")
	require.NoError(t, err, "a resolver failure must not fail the request")
	assert.Equal(t, "base-model", sel.Name)
	assert.False(t, dec.Active())
}

// --- log rendering -------------------------------------------------------------

func TestCanaryDecisionString(t *testing.T) {
	assert.Equal(t, "inactive", CanaryDecisionString(CanaryDecision{}))

	d := CanaryDecision{
		RolloutID: "0123456789abcd", Name: "migration", Version: 3,
		Arm: CanaryDecisionArmCanary, Percent: 25, From: "base", To: "canary",
	}
	assert.Equal(t,
		"rollout=migration version=3 arm=canary percent=25 from=base to=canary",
		CanaryDecisionString(d))

	// An empty name falls back to the rollout id prefix (stable log labels).
	anon := d
	anon.Name = ""
	assert.Contains(t, CanaryDecisionString(anon), "rollout=01234567 ")
	anon.RolloutID = "short"
	assert.Contains(t, CanaryDecisionString(anon), "rollout=short ")
}
