package router

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/classifier"
	"github.com/reireirei/yabanin/pkg/sovereign"
)

// each cell reproduced safely at the unit seam.
//
//   - version-cache churn (activation racing the snapshot load)
//   - canary model filtered out by sovereignty → never serves
//   - percent edges (0/100, exact bucket boundary)
//   - concurrent activation during in-flight requests (entry immutability)
//   - resolver error → fail-open to base

// --- percent edges ---------------------------------------------------------------

func TestCanaryBoundary_BucketEdge(t *testing.T) {
	// The split is a strict `<` over the whole-percent bucket: a session in
	// bucket percent-1 is the LAST canary session, a session in bucket
	// percent is the FIRST base session. Pinning the exact edge (not just a
	// statistical share) makes any off-by-one in the comparison detectable.
	percent := 37
	var lastCanary, firstBase string
	for i := 0; ; i++ {
		id := "edge-" + time.Duration(i).String()
		switch canaryBucket(id) {
		case percent - 1:
			lastCanary = id
		case percent:
			firstBase = id
		}
		if lastCanary != "" && firstBase != "" {
			break
		}
	}
	assert.True(t, CanaryArm(lastCanary, percent), "bucket %d (percent-1) must be canary", percent-1)
	assert.False(t, CanaryArm(firstBase, percent), "bucket %d (percent) must be base", percent)

	// Degenerate percents the store refuses to persist (CHECK 1..99): the
	// split function itself is total — 0 is all-base, 100 all-canary — so a
	// bypassed validation degrades to a (wrong but bounded) full arm, never
	// to a crash or an undefined arm.
	assert.False(t, CanaryArm(lastCanary, 0), "percent 0 must be all-base")
	assert.True(t, CanaryArm(firstBase, 100), "percent 100 must be all-canary")
}

// --- churn with a stale snapshot present ------------------------------------------

func TestCanaryBoundary_ChurnWithStaleServesOldNeverMixed(t *testing.T) {
	// An activation storm racing every refresh: after the single retry the
	// resolver gives up on installing and serves the STALE snapshot. The
	// installed entry pointer is untouched — a mixed snapshot is never
	// installed and the old answer keeps serving (bounded by TTL).
	loader := &fakeCanaryLoader{rollouts: []CanaryRollout{{RolloutID: "r1", Name: "roll", Version: 1, BaseModel: "base-model", CanaryModel: "canary-model", Percent: 10}}}
	versions := &fakeCanaryVersions{version: 1}
	c := NewCanaryRolloutCache(loader, versions, time.Minute, nil)

	got, err := c.Resolve(context.Background(), "org-1")
	require.NoError(t, err)
	require.Len(t, got, 1)
	c.mu.Lock()
	staleEntry := c.orgs["org-1"]
	c.mu.Unlock()
	require.NotNil(t, staleEntry)

	// Every probe observes a moving version (activation racing each load).
	loader.rollouts = []CanaryRollout{{RolloutID: "r1", Name: "roll", Version: 2, BaseModel: "base-model", CanaryModel: "canary-model", Percent: 20}}
	n := int64(1)
	c.versions = churningVersions{get: func() (int64, error) { n++; return n, nil }}

	got, err = c.Resolve(context.Background(), "org-1")
	require.NoError(t, err, "with a stale snapshot the churn must fail-open, not error")
	require.Len(t, got, 1)
	assert.Equal(t, 1, got[0].Version, "the stale (pre-activation) snapshot serves — never a mixture")
	assert.Equal(t, 10, got[0].Percent)

	c.mu.Lock()
	sameEntry := c.orgs["org-1"]
	c.mu.Unlock()
	assert.Same(t, staleEntry, sameEntry, "a churned refresh must not replace the installed entry")
}

// switchableVersions is a thread-safe version probe double with forced
// failure and a settable value.
type switchableVersions struct {
	mu      sync.Mutex
	version int64
	fail    bool
}

func (s *switchableVersions) GetCanaryVersion(context.Context, string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return 0, errors.New("redis unreachable")
	}
	return s.version, nil
}

func (s *switchableVersions) set(version int64, fail bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.version, s.fail = version, fail
}

func TestCanaryBoundary_ProbeOutageDuringRefreshInstallsUnpinned(t *testing.T) {
	// Redis dies BETWEEN the resolve and the refresh load probes: the
	// refresh still installs the fresh snapshot, but UNPINNED (no version
	// observed around the load). An unpinned entry ignores later version
	// changes until its TTL — the documented bounded-staleness fallback —
	// and the first TTL-expired refresh with a healthy probe re-pins.
	loader := &fakeCanaryLoader{rollouts: []CanaryRollout{{RolloutID: "r1", Name: "roll", Version: 1, BaseModel: "b", CanaryModel: "c", Percent: 10}}}
	versions := &switchableVersions{fail: true}
	c := NewCanaryRolloutCache(loader, versions, time.Minute, nil)

	got, err := c.Resolve(context.Background(), "org-1")
	require.NoError(t, err)
	require.Len(t, got, 1)
	c.mu.Lock()
	installed := c.orgs["org-1"]
	c.mu.Unlock()
	require.NotNil(t, installed)
	assert.False(t, installed.haveVer, "a refresh with a failing probe installs unpinned")
	assert.Equal(t, 1, loader.loads)

	// Redis recovers and carries a NEWER version: the unpinned entry still
	// serves until the TTL (bounded staleness, no error).
	versions.set(99, false)
	got, err = c.Resolve(context.Background(), "org-1")
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, 1, got[0].Version)
	assert.Equal(t, 1, loader.loads, "an unpinned entry must not reload on a version change inside the TTL")

	// TTL expiry with the probe healthy: refresh double-probes the stable
	// version 99 and installs a PINNED entry — invalidation resumes.
	loader.rollouts = []CanaryRollout{{RolloutID: "r1", Name: "roll", Version: 2, BaseModel: "b", CanaryModel: "c", Percent: 20}}
	c.mu.Lock()
	installed.loadedAt = time.Now().Add(-2 * time.Minute)
	c.mu.Unlock()
	got, err = c.Resolve(context.Background(), "org-1")
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, 2, got[0].Version, "the TTL-expired refresh picks up the new snapshot")
	c.mu.Lock()
	reinstalled := c.orgs["org-1"]
	c.mu.Unlock()
	assert.True(t, reinstalled.haveVer, "a healthy-probe refresh re-pins the entry")
	assert.Equal(t, int64(99), reinstalled.version)

	// A subsequent version bump invalidates immediately again.
	loader.rollouts = []CanaryRollout{{RolloutID: "r1", Name: "roll", Version: 3, BaseModel: "b", CanaryModel: "c", Percent: 30}}
	versions.set(100, false)
	got, err = c.Resolve(context.Background(), "org-1")
	require.NoError(t, err)
	assert.Equal(t, 3, got[0].Version, "re-pinned entries resume immediate invalidation")
}

func TestCanaryBoundary_ProbeAndLoadOutageServesStale(t *testing.T) {
	// Total outage (version probe AND snapshot load down) with a prior
	// entry: the stale snapshot serves, the request never sees an error —
	// rollout infrastructure failing cannot fail routing.
	loader := &fakeCanaryLoader{rollouts: []CanaryRollout{{RolloutID: "r1", Name: "roll", Version: 1, BaseModel: "b", CanaryModel: "c", Percent: 10}}}
	versions := &switchableVersions{version: 1}
	c := NewCanaryRolloutCache(loader, versions, time.Minute, nil)

	_, err := c.Resolve(context.Background(), "org-1")
	require.NoError(t, err)

	loader.err = errors.New("snapshot load down")
	versions.set(0, true)
	got, err := c.Resolve(context.Background(), "org-1")
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, 1, got[0].Version, "total outage serves the stale snapshot")
}

// --- sovereignty: filtered canary never serves -------------------------------------

func TestCanaryBoundary_SovereigntyFilteredCanaryNeverServes(t *testing.T) {
	// The canary model is CN-flagged and the wired policy store applies the
	// default sovereignty policy (cn_allowed=false): the canary model never
	// enters ANY pool. The rollout may put a session in the canary arm, the
	// pool-membership check keeps the request on base — the filter is never
	// bypassed for a rollout (contract acceptance example 3).
	loader := &mockModelLoader{models: []ModelInfo{
		{Name: "base-model", TierPool: []string{"medium"}, Weight: 1, Enabled: true},
		{Name: "canary-model", TierPool: []string{"medium"}, Weight: 1, Enabled: true, CNFlagged: true},
	}}
	tr := NewTierRouter(loader, newMockRedis()).WithPolicyStore(sovereign.NewPolicyStore(nil, nil))
	tr.WithCanaryRollouts(NewCanaryRolloutCache(&fakeCanaryLoader{
		rollouts: []CanaryRollout{{RolloutID: "r1", Name: "roll", Version: 1, BaseModel: "base-model", CanaryModel: "canary-model", Percent: 90}},
	}, nil, time.Minute, nil))

	// Every canary-arm session of a wide sample stays on base: 90 percent
	// of sessions hash into the canary arm, none of them may leak.
	servedCanary := 0
	for i := 0; i < 200; i++ {
		session := "sov-" + time.Duration(i).String()
		if !CanaryArm(session, 90) {
			continue
		}
		sel, dec, err := tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", session)
		require.NoError(t, err)
		assert.Equal(t, "base-model", sel.Name, "session %q: a sovereignty-filtered canary must never serve", session)
		require.True(t, dec.Active(), "the rollout still matched — the decision must be visible")
		assert.Equal(t, CanaryDecisionArmBase, dec.Arm)
		assert.False(t, dec.Swapped())
		servedCanary++
	}
	require.Greater(t, servedCanary, 100, "the sample must actually exercise canary-arm sessions")
}

// --- entry immutability under concurrent activation ---------------------------------

// lockedCanaryLoader is the thread-safe loader double for concurrency tests.
type lockedCanaryLoader struct {
	mu       sync.Mutex
	rollouts []CanaryRollout
	loads    int
}

func (l *lockedCanaryLoader) set(v []CanaryRollout) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rollouts = append([]CanaryRollout(nil), v...)
}

func (l *lockedCanaryLoader) LoadCanaryRollouts(_ context.Context, _ string) ([]CanaryRollout, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.loads++
	return append([]CanaryRollout(nil), l.rollouts...), nil
}

func TestCanaryBoundary_EntryImmutabilityUnderConcurrentActivation(t *testing.T) {
	// Concurrent activations flip the store between v1 and v2 while
	// readers resolve. Guarantees under -race:
	//   - a snapshot handed out earlier NEVER mutates in place (entries
	//     are replaced, not written);
	//   - every resolve observes a WHOLE v1 or a WHOLE v2 snapshot, never a
	//     mixture (version/percent always agree);
	//   - no resolve errors (fail-open to the stale snapshot).
	v1 := []CanaryRollout{{RolloutID: "r1", Name: "roll", Version: 1, BaseModel: "base-model", CanaryModel: "canary-model", Percent: 10}}
	v2 := []CanaryRollout{{RolloutID: "r1", Name: "roll", Version: 2, BaseModel: "base-model", CanaryModel: "canary-model", Percent: 20}}
	loader := &lockedCanaryLoader{}
	loader.set(v1)
	versions := &switchableVersions{version: 1}
	c := NewCanaryRolloutCache(loader, versions, time.Minute, nil)

	held, err := c.Resolve(context.Background(), "org-1")
	require.NoError(t, err)
	require.Len(t, held, 1)

	const readers = 8
	const iterations = 200
	type observation struct {
		version int
		percent int
		err     error
	}
	obs := make(chan observation, readers*iterations)
	var readersWG sync.WaitGroup
	for i := 0; i < readers; i++ {
		readersWG.Add(1)
		go func() {
			defer readersWG.Done()
			for j := 0; j < iterations; j++ {
				got, err := c.Resolve(context.Background(), "org-1")
				if err != nil {
					obs <- observation{err: err}
					continue
				}
				if len(got) != 1 {
					obs <- observation{version: -1, percent: -1}
					continue
				}
				obs <- observation{version: got[0].Version, percent: got[0].Percent}
			}
		}()
	}

	// The mutator plays the store: flip snapshot + bump the version key,
	// forever racing the readers (each bump invalidates their cache).
	stop := make(chan struct{})
	var mutatorWG sync.WaitGroup
	mutatorWG.Add(1)
	go func() {
		defer mutatorWG.Done()
		flip := false
		for {
			select {
			case <-stop:
				return
			default:
			}
			if flip {
				loader.set(v1)
			} else {
				loader.set(v2)
			}
			versions.bump()
			flip = !flip
		}
	}()

	readersWG.Wait()
	close(stop)
	mutatorWG.Wait()

	// The held snapshot is byte-for-byte what it was: in-place mutation of
	// a live entry would be visible here (and to the race detector).
	require.Len(t, held, 1)
	assert.Equal(t, 1, held[0].Version)
	assert.Equal(t, 10, held[0].Percent)

	// Every observation is a whole v1 or a whole v2.
	for i := 0; i < readers*iterations; i++ {
		o := <-obs
		if o.err != nil {
			t.Fatalf("a concurrent resolve must never error: %v", o.err)
		}
		valid := (o.version == 1 && o.percent == 10) || (o.version == 2 && o.percent == 20)
		if !valid {
			t.Fatalf("mixed snapshot observed: version=%d percent=%d", o.version, o.percent)
		}
	}
}

// bump atomically advances the version (a store mutation's key bump).
func (s *switchableVersions) bump() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.version++
}

func TestCanaryBoundary_ConcurrentResolveSteadyState(t *testing.T) {
	// A calmer variant with a stable version: pure concurrent reads of one
	// entry (the steady-state hot path) must be error-free and share the
	// cached entry — exactly one snapshot load regardless of reader count.
	loader := &lockedCanaryLoader{}
	loader.set([]CanaryRollout{{RolloutID: "r1", Name: "roll", Version: 1, BaseModel: "b", CanaryModel: "c", Percent: 10}})
	versions := &switchableVersions{version: 5}
	c := NewCanaryRolloutCache(loader, versions, time.Minute, nil)

	// Warm the cache first: the cold path has no singleflight, so concurrent
	// first misses may race a second load (last write wins, still correct).
	// The steady-state invariant under test is that WARM resolves never
	// re-load the store.
	if _, err := c.Resolve(context.Background(), "org-1"); err != nil {
		t.Fatalf("warm-up resolve: %v", err)
	}
	warm := loader.snapshotLoads()

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				got, err := c.Resolve(context.Background(), "org-1")
				if err != nil {
					errs <- fmt.Errorf("resolve: %w", err)
					return
				}
				if len(got) != 1 {
					errs <- fmt.Errorf("unexpected snapshot len %d", len(got))
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("steady-state concurrent resolve failed: %v", err)
	}
	assert.Equal(t, warm, loader.snapshotLoads(), "800 concurrent warm resolves must not re-load the store (cold-path singleflight is not guaranteed; warm-path sharing is)")
}

// snapshotLoads reports the number of snapshot loads performed.
func (l *lockedCanaryLoader) snapshotLoads() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.loads
}
