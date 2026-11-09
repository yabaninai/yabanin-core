package router

// N09-P04-T03 tests — session→version pin layer.
//
// Deterministic: the pin clock is injected (fixed epoch + explicit advance),
// the rollout snapshot is switched by hand with version-key bumps, and every
// concurrent test uses synchronized doubles with bounded iteration counts.
// The recurring invariant (requireNoSilentMix): whatever the rollback/promote
// race does, a decision always names the version that governed it, and a
// released pin never keeps serving the canary model.

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/classifier"
)

// pinTestRouter builds a canary-wired router with the version-pin layer over
// a controllable snapshot (loader + version key) and an injected pin clock.
// advance moves the pin clock; the rollout-cache TTL stays on the real clock
// (fresh cache, never expires mid-test — the pin bound is what's under test).
func pinTestRouter(rollouts []CanaryRollout) (tr *TierRouter, loader *fakeCanaryLoader, versions *fakeCanaryVersions, pins *CanaryVersionPins, advance func(time.Duration)) {
	loader = &fakeCanaryLoader{rollouts: rollouts}
	versions = &fakeCanaryVersions{version: 1}
	models := &mockModelLoader{models: []ModelInfo{
		{Name: "base-model", Tier: "smart", TierPool: []string{"medium"}, Weight: 1, Enabled: true},
		{Name: "canary-model", Tier: "smart", TierPool: []string{"medium"}, Weight: 0, Enabled: true},
		{Name: "canary-model-v2", Tier: "smart", TierPool: []string{"medium"}, Weight: 0, Enabled: true},
	}}
	tr = NewTierRouter(models, nil)
	pins = NewCanaryVersionPins(30*time.Minute, 10000)
	cur := time.Unix(1700000000, 0)
	pins.now = func() time.Time { return cur }
	advance = func(d time.Duration) { cur = cur.Add(d) }
	tr.WithCanaryRollouts(NewCanaryRolloutCache(loader, versions, time.Minute, nil))
	tr.WithCanaryVersionPins(pins)
	return tr, loader, versions, pins, advance
}

// requireNoSilentMix asserts the per-decision invariants that keep version
// handling explicit: the served model always equals the decision's To, the
// pin status always explains WHICH version governed the resolution, and a
// released pin never serves the canary model.
func requireNoSilentMix(t *testing.T, sel ModelInfo, dec CanaryDecision, base, canary string) {
	t.Helper()
	if dec.Pin == CanaryPinNone && !dec.Active() {
		// The zero-overhead path (no resolver / no org / no session) returns
		// the zero decision by contract; only then may To be empty.
		assert.Equal(t, CanaryDecision{}, dec, "a zero decision is only allowed wholesale")
		return
	}
	assert.Equal(t, dec.To, sel.Name, "served model must equal the decision's To")
	switch dec.Pin {
	case CanaryPinNone:
		assert.Zero(t, dec.PinnedVersion, "no pin involvement must leave the pinned version empty")
	case CanaryPinHeld:
		require.True(t, dec.Active(), "a held pin must ride an active rollout decision")
		assert.Equal(t, dec.PinnedVersion, dec.Version, "a held pin must serve exactly the pinned version")
		assert.NotEqual(t, 0, dec.PinnedVersion)
		switch dec.Arm {
		case CanaryDecisionArmCanary:
			assert.Equal(t, canary, sel.Name, "held canary pin must serve the pinned canary model")
		case CanaryDecisionArmBase:
			assert.Equal(t, base, sel.Name, "held base pin must serve base")
		default:
			t.Fatalf("held pin with unknown arm %q", dec.Arm)
		}
	case CanaryPinReleased:
		assert.Equal(t, base, sel.Name, "after a pin release the canary model must not serve")
	case CanaryPinNew, CanaryPinExpired, CanaryPinRebound:
		require.True(t, dec.Active(), "a fresh hash resolution must ride the matched rollout")
		assert.Equal(t, dec.Version, dec.PinnedVersion, "a fresh resolution pins exactly the version it resolved")
		assert.Equal(t, dec.Version, dec.ActiveVersion, "a fresh resolution resolves the ACTIVE version")
		if dec.Arm == CanaryDecisionArmCanary {
			assert.Equal(t, canary, sel.Name)
		} else {
			assert.Equal(t, base, sel.Name)
		}
	default:
		t.Fatalf("unknown pin status %q", dec.Pin)
	}
}

// --- store-level: bound, cap, org scope, manual release ------------------------

func TestNewCanaryVersionPins_Defaults(t *testing.T) {
	p := NewCanaryVersionPins(0, 0)
	require.NotNil(t, p)
	assert.Equal(t, canaryPinTTLDefault, p.ttl, "ttl<=0 must fall back to the documented default")
	assert.Equal(t, canaryPinMaxDefault, p.maxEntries, "maxEntries<=0 must fall back to the documented default")
	assert.NotNil(t, p.now)
	assert.Equal(t, 0, p.Len())
}

func TestCanaryVersionPins_TTLBoundIsFixedFromFirstPin(t *testing.T) {
	// The bound is a fixed window from the pin timestamp: the last moment
	// INSIDE the window is still live (inclusive bound — "up to the set
	// bound"), one tick past it the pin has expired and is dropped lazily.
	p := NewCanaryVersionPins(time.Minute, 100)
	cur := time.Unix(1700000000, 0)
	p.now = func() time.Time { return cur }

	entry := canaryPinEntry{rolloutID: "r1", version: 3, arm: CanaryDecisionArmCanary, model: "canary-model", percent: 10}
	p.store("org-1", "s1", entry)

	cur = cur.Add(time.Minute)
	_, state := p.lookup("org-1", "s1")
	assert.Equal(t, pinLive, state, "the bound is inclusive: ttl exactly reached is still live")

	cur = cur.Add(time.Nanosecond)
	e, state := p.lookup("org-1", "s1")
	assert.Equal(t, pinExpired, state, "one tick past the bound the pin has expired")
	assert.Equal(t, 3, e.version, "the expired entry is still reported (the decision names the expiry)")
	assert.Equal(t, 0, p.Len(), "an expired pin is dropped lazily on read")

	_, state = p.lookup("org-1", "s1")
	assert.Equal(t, pinAbsent, state, "the next read sees it gone")
}

func TestCanaryVersionPins_StoreRePinsAndRestartsTheWindow(t *testing.T) {
	// store() is a full re-pin: a fresh resolution restarts the bound from
	// the new timestamp (there is no refresh-by-traffic by design — the
	// bound must stay reachable under load).
	p := NewCanaryVersionPins(time.Minute, 100)
	cur := time.Unix(1700000000, 0)
	p.now = func() time.Time { return cur }

	p.store("org-1", "s1", canaryPinEntry{rolloutID: "r1", version: 1})
	cur = cur.Add(50 * time.Second)
	p.store("org-1", "s1", canaryPinEntry{rolloutID: "r1", version: 2})

	cur = cur.Add(50 * time.Second) // 100s after the first pin, 10s after the re-pin
	e, state := p.lookup("org-1", "s1")
	assert.Equal(t, pinLive, state, "the re-pin restarted the window")
	assert.Equal(t, 2, e.version, "the re-pin replaced the entry")
}

func TestCanaryVersionPins_EmptyKeysAreNoOps(t *testing.T) {
	p := NewCanaryVersionPins(time.Minute, 10)
	entry := canaryPinEntry{rolloutID: "r1", version: 1, arm: CanaryDecisionArmBase, model: "base-model", percent: 5}
	p.store("", "s1", entry)
	p.store("org-1", "", entry)
	assert.Equal(t, 0, p.Len(), "an empty org or session must never store a pin")

	_, state := p.lookup("", "s1")
	assert.Equal(t, pinAbsent, state)
	_, state = p.lookup("org-1", "")
	assert.Equal(t, pinAbsent, state)

	assert.False(t, p.Release("", "s1"))
	assert.False(t, p.Release("org-1", ""))
	assert.Equal(t, 0, p.ReleaseOrg(""))
}

func TestCanaryVersionPins_OrgIsolation(t *testing.T) {
	// Same session id, two orgs: two independent pins (SessionAffinity
	// parity) — one org's release or bound never touches the other.
	p := NewCanaryVersionPins(time.Minute, 100)
	cur := time.Unix(1700000000, 0)
	p.now = func() time.Time { return cur }

	p.store("org-a", "shared", canaryPinEntry{rolloutID: "r-a", version: 7, arm: CanaryDecisionArmCanary, model: "can-a", percent: 50})
	p.store("org-b", "shared", canaryPinEntry{rolloutID: "r-b", version: 3, arm: CanaryDecisionArmBase, model: "base-b", percent: 30})

	ea, state := p.lookup("org-a", "shared")
	assert.Equal(t, pinLive, state)
	assert.Equal(t, 7, ea.version)
	eb, state := p.lookup("org-b", "shared")
	assert.Equal(t, pinLive, state)
	assert.Equal(t, 3, eb.version)

	assert.True(t, p.Release("org-a", "shared"))
	_, state = p.lookup("org-a", "shared")
	assert.Equal(t, pinAbsent, state)
	eb, state = p.lookup("org-b", "shared")
	assert.Equal(t, pinLive, state, "org-b's pin must survive org-a's release")
	assert.Equal(t, 3, eb.version)
}

func TestCanaryVersionPins_ReleaseOrgIsTheManualSweep(t *testing.T) {
	p := NewCanaryVersionPins(time.Minute, 100)
	p.store("org-a", "s1", canaryPinEntry{rolloutID: "r1", version: 1})
	p.store("org-a", "s2", canaryPinEntry{rolloutID: "r1", version: 1})
	p.store("org-b", "s1", canaryPinEntry{rolloutID: "r1", version: 1})

	assert.False(t, p.Release("org-a", "missing"), "releasing a missing pin reports false")
	assert.True(t, p.Release("org-a", "s1"), "single-session manual release reports the dropped pin")
	assert.Equal(t, 1, p.ReleaseOrg("org-a"), "the org sweep drops the remaining org-a pin")
	assert.Equal(t, 0, p.ReleaseOrg("org-a"), "a second sweep has nothing to drop")
	assert.Equal(t, 1, p.Len(), "org-b's pin must survive org-a's sweep")
	_, state := p.lookup("org-b", "s1")
	assert.Equal(t, pinLive, state)
}

func TestCanaryVersionPins_EvictsOldestHalfOverCap(t *testing.T) {
	// Seeded deterministically: the injected clock decides the victims.
	// Steady state stays at or under the cap; the oldest-pinned half goes
	// first (SessionAffinity.evictLocked parity).
	p := NewCanaryVersionPins(time.Minute, 4)
	cur := time.Unix(1700000000, 0)
	p.now = func() time.Time { return cur }

	for i := 0; i < 6; i++ {
		p.store("org-1", "s"+fmt.Sprint(i), canaryPinEntry{rolloutID: "r1", version: i})
		cur = cur.Add(time.Second)
	}

	assert.LessOrEqual(t, p.Len(), 4, "the map must stay at the cap")
	_, state := p.lookup("org-1", "s0")
	assert.Equal(t, pinAbsent, state, "the oldest pin must be evicted first")
	_, state = p.lookup("org-1", "s1")
	assert.Equal(t, pinAbsent, state)
	_, state = p.lookup("org-1", "s5")
	assert.Equal(t, pinLive, state, "the newest pins must survive")
}

// --- resolution: the acceptance bound -------------------------------------------

func TestSelectModelForSession_PinHoldsBaseArmAcrossPercentRamp(t *testing.T) {
	// THE ACCEPTANCE: a session pinned by v1 keeps v1's semantics when v2
	// ramps the percent — a base-arm session must NOT flip to canary on the
	// ramp; both versions ride the decision (served vs active). Past the
	// bound the session re-resolves by hash against the active version.
	tr, loader, versions, _, advance := pinTestRouter([]CanaryRollout{
		{RolloutID: "r1", Name: "ramp", Version: 1, BaseModel: "base-model", CanaryModel: "canary-model", Percent: 10},
	})

	// A session in the canary arm at 20% but in the BASE arm at 10%.
	between := canarySessionFor(t, 20, true, "ramp-pin-")
	require.False(t, CanaryArm(between, 10), "fixture: the session must be base-arm at v1's 10%%")

	sel, dec, err := tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", between)
	require.NoError(t, err)
	requireNoSilentMix(t, sel, dec, "base-model", "canary-model")
	assert.Equal(t, "base-model", sel.Name)
	assert.Equal(t, CanaryPinNew, dec.Pin)
	assert.Equal(t, 1, dec.Version)

	// v2 ramps to 20%: the hash would flip this session to canary — the pin
	// holds it on v1 (base) up to the bound.
	loader.rollouts = []CanaryRollout{{RolloutID: "r1", Name: "ramp", Version: 2, BaseModel: "base-model", CanaryModel: "canary-model", Percent: 20}}
	versions.version = 2

	for i := 0; i < 5; i++ {
		sel, dec, err = tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", between)
		require.NoError(t, err)
		requireNoSilentMix(t, sel, dec, "base-model", "canary-model")
		assert.Equal(t, "base-model", sel.Name, "within the bound the session keeps its pinned v1 base arm")
		assert.Equal(t, CanaryPinHeld, dec.Pin)
		assert.Equal(t, 1, dec.Version, "the SERVED version is the pinned one")
		assert.Equal(t, 1, dec.PinnedVersion)
		assert.Equal(t, 2, dec.ActiveVersion, "the ACTIVE version is reported next to it, never mixed in")
		assert.Equal(t, 10, dec.Percent, "the pinned version's percent governs the decision")
	}

	// Past the bound: re-resolve by hash against the active version — the
	// session moves to the canary arm, explicitly marked expired.
	advance(30*time.Minute + time.Nanosecond)
	sel, dec, err = tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", between)
	require.NoError(t, err)
	requireNoSilentMix(t, sel, dec, "base-model", "canary-model")
	assert.Equal(t, "canary-model", sel.Name, "past the bound the session follows the active version")
	assert.Equal(t, CanaryPinExpired, dec.Pin)
	assert.Equal(t, 2, dec.Version)
	assert.Equal(t, 2, dec.ActiveVersion)
	assert.Equal(t, 20, dec.Percent)

	// And the new pin holds the new version again.
	sel, dec, err = tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", between)
	require.NoError(t, err)
	requireNoSilentMix(t, sel, dec, "base-model", "canary-model")
	assert.Equal(t, CanaryPinHeld, dec.Pin)
	assert.Equal(t, 2, dec.Version)
}

func TestSelectModelForSession_PinHoldsCanaryModelAcrossModelChange(t *testing.T) {
	// v2 changes the canary MODEL: a canary-arm session pinned to v1 keeps
	// serving v1's canary model within the bound (its warm-cache stability
	// is the point of the pin), explicitly held at the old version.
	tr, loader, versions, _, _ := pinTestRouter([]CanaryRollout{
		{RolloutID: "r1", Name: "swap", Version: 1, BaseModel: "base-model", CanaryModel: "canary-model", Percent: 30},
	})
	session := canarySessionFor(t, 30, true, "model-pin-")

	sel, dec, err := tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", session)
	require.NoError(t, err)
	require.Equal(t, "canary-model", sel.Name)
	require.Equal(t, CanaryPinNew, dec.Pin)

	loader.rollouts = []CanaryRollout{{RolloutID: "r1", Name: "swap", Version: 2, BaseModel: "base-model", CanaryModel: "canary-model-v2", Percent: 30}}
	versions.version = 2

	for i := 0; i < 3; i++ {
		sel, dec, err = tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", session)
		require.NoError(t, err)
		requireNoSilentMix(t, sel, dec, "base-model", "canary-model")
		assert.Equal(t, "canary-model", sel.Name, "within the bound the session keeps its pinned canary model")
		assert.Equal(t, "canary-model", dec.To)
		assert.Equal(t, CanaryPinHeld, dec.Pin)
		assert.Equal(t, 1, dec.Version)
		assert.Equal(t, 2, dec.ActiveVersion)
	}
}

// --- negative: manual rollback, races, missing session --------------------------

func TestSelectModelForSession_RollbackReleasesPinObservably(t *testing.T) {
	// Manual rollback (enabled=false → snapshot drops the rollout + version
	// key bump): the pinned canary session must go back to base IMMEDIATELY,
	// with the release visible on the decision — the rollback never waits
	// for the pin TTL behind a silently held version.
	tr, loader, versions, pins, _ := pinTestRouter([]CanaryRollout{
		{RolloutID: "r1", Name: "rb", Version: 1, BaseModel: "base-model", CanaryModel: "canary-model", Percent: 99},
	})
	session := canarySessionFor(t, 99, true, "rb-pin-")

	sel, _, err := tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", session)
	require.NoError(t, err)
	require.Equal(t, "canary-model", sel.Name)
	require.Equal(t, 1, pins.Len())

	// Rollback: the admin flip removes the rollout and bumps the version key.
	loader.rollouts = nil
	versions.version = 2

	sel, dec, err := tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", session)
	require.NoError(t, err)
	requireNoSilentMix(t, sel, dec, "base-model", "canary-model")
	assert.Equal(t, "base-model", sel.Name, "after rollback the pinned session routes base immediately")
	assert.False(t, dec.Active(), "the rollout is gone: the decision stays inactive")
	assert.Equal(t, CanaryPinReleased, dec.Pin, "the release is observable")
	assert.Equal(t, 1, dec.PinnedVersion, "the released pin's version is reported")
	assert.Equal(t, 0, pins.Len(), "the pin is dropped, not kept until TTL")
	assert.Equal(t, 0, dec.ActiveVersion, "no active version exists after the rollback")

	// The next request is a plain no-rollout resolution: no repeated release.
	sel, dec, err = tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", session)
	require.NoError(t, err)
	assert.Equal(t, "base-model", sel.Name)
	assert.Equal(t, CanaryPinNone, dec.Pin)
	assert.False(t, dec.Active())
}

func TestSelectModelForSession_RollbackPromoteRaceNoSilentMix(t *testing.T) {
	// The rollback/promote race, step by step: pin → rollback → release →
	// re-promote (new version) → fresh hash resolution. Every state change
	// is a NAMED pin status; no step can serve the canary model of a version
	// that is not explicitly reported on the decision.
	tr, loader, versions, pins, _ := pinTestRouter([]CanaryRollout{
		{RolloutID: "r1", Name: "race", Version: 3, BaseModel: "base-model", CanaryModel: "canary-model", Percent: 50},
	})
	session := canarySessionFor(t, 50, true, "race-pin-")

	sel, dec, err := tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", session)
	require.NoError(t, err)
	requireNoSilentMix(t, sel, dec, "base-model", "canary-model")
	require.Equal(t, "canary-model", sel.Name)
	require.Equal(t, 3, dec.Version)

	// Rollback and promote race: the operator rolls back (v3 gone) while a
	// promote activates v4 — observed in one order here, the reverse order
	// is the same state machine (snapshot either carries a rollout or not).
	loader.rollouts = nil // rollback window
	versions.version = 4
	sel, dec, err = tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", session)
	require.NoError(t, err)
	requireNoSilentMix(t, sel, dec, "base-model", "canary-model")
	require.Equal(t, CanaryPinReleased, dec.Pin)
	require.Equal(t, "base-model", sel.Name)

	loader.rollouts = []CanaryRollout{{RolloutID: "r1", Name: "race", Version: 4, BaseModel: "base-model", CanaryModel: "canary-model-v2", Percent: 40}}
	versions.version = 5
	sel, dec, err = tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", session)
	require.NoError(t, err)
	requireNoSilentMix(t, sel, dec, "base-model", "canary-model-v2")
	// The release already dropped the old pin: this resolution is a fresh
	// hash resolution of v4 (status new) — it can never masquerade as the
	// still-held v3 pin.
	assert.Equal(t, CanaryPinNew, dec.Pin)
	assert.Equal(t, 4, dec.Version)
	assert.Equal(t, 40, dec.Percent, "the percent comes from the active v4 rollout, not the released v3 pin")
	assert.Equal(t, 1, pins.Len(), "exactly the fresh pin is held now")
}

func TestSelectModelForSession_PinReboundOnRolloutSwitch(t *testing.T) {
	// The operator switches rollouts (r1 out, r2 in): a session still pinned
	// to r1 must NOT let that pin suppress r2's resolution — the pin is
	// rebound with an explicit status, resolving r2 by hash.
	tr, loader, versions, pins, _ := pinTestRouter([]CanaryRollout{
		{RolloutID: "r1", Name: "old", Version: 1, BaseModel: "base-model", CanaryModel: "canary-model", Percent: 30},
	})
	session := canarySessionFor(t, 30, true, "rebind-")

	_, dec, err := tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", session)
	require.NoError(t, err)
	require.Equal(t, CanaryPinNew, dec.Pin)
	require.Equal(t, 1, dec.Version)

	loader.rollouts = []CanaryRollout{{RolloutID: "r2", Name: "new", Version: 9, BaseModel: "base-model", CanaryModel: "canary-model-v2", Percent: 90}}
	versions.version = 2

	sel, dec, err := tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", session)
	require.NoError(t, err)
	requireNoSilentMix(t, sel, dec, "base-model", "canary-model-v2")
	assert.Equal(t, CanaryPinRebound, dec.Pin, "the foreign pin is reported as a rebound, never silently reused")
	assert.Equal(t, "r2", dec.RolloutID)
	assert.Equal(t, 9, dec.Version, "the resolution is r2's version, not the stale r1 pin")
	assert.Equal(t, 90, dec.Percent)

	// The rebound replaced the pin: the next request is held on r2.
	sel, dec, err = tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", session)
	require.NoError(t, err)
	requireNoSilentMix(t, sel, dec, "base-model", "canary-model-v2")
	assert.Equal(t, CanaryPinHeld, dec.Pin)
	assert.Equal(t, 9, dec.Version)
	assert.Equal(t, 1, pins.Len())
}

func TestSelectModelForSession_PinnedCanaryUnservableReleasesNotBypasses(t *testing.T) {
	// A pin never bypasses the filtered pool: the pinned canary model left
	// the pool (disabled/sovereignty) → the pin is released explicitly and
	// base serves. Driven at the applyCanary seam with a hand-built pool so
	// the pool change is deterministic (no registry-cache waits).
	tr, _, _, pins, _ := pinTestRouter([]CanaryRollout{
		{RolloutID: "r1", Name: "filt", Version: 1, BaseModel: "base-model", CanaryModel: "canary-model", Percent: 50},
	})
	ctx := context.Background()
	session := canarySessionFor(t, 50, true, "filt-pin-")
	base := ModelInfo{Name: "base-model", TierPool: []string{"medium"}, Weight: 1, Enabled: true}

	// Pin the session through the full path (canary model in the pool).
	pool := []ModelInfo{base, {Name: "canary-model", TierPool: []string{"medium"}, Weight: 0, Enabled: true}}
	sel, dec, err := tr.applyCanary(ctx, pool, base, "org-1", session)
	require.NoError(t, err)
	require.Equal(t, "canary-model", sel.Name)
	require.Equal(t, CanaryPinNew, dec.Pin)
	require.Equal(t, 1, pins.Len())

	// The canary model is no longer servable from the pool: released, base.
	shrunk := []ModelInfo{base}
	sel, dec, err = tr.applyCanary(ctx, shrunk, base, "org-1", session)
	require.NoError(t, err)
	requireNoSilentMix(t, sel, dec, "base-model", "canary-model")
	assert.Equal(t, "base-model", sel.Name, "the filter is never bypassed for a pin")
	assert.Equal(t, CanaryPinReleased, dec.Pin)
	assert.True(t, dec.Active(), "the rollout still exists — the release is about the pool, not a rollback")
	assert.Equal(t, 0, pins.Len(), "the un-honorable pin is dropped")
	assert.Equal(t, "base-model", dec.To, "the decision reports base as served")

	// With the model back, a fresh resolution re-pins normally.
	sel, dec, err = tr.applyCanary(ctx, pool, base, "org-1", session)
	require.NoError(t, err)
	require.Equal(t, "canary-model", sel.Name)
	assert.Equal(t, CanaryPinNew, dec.Pin)
}

func TestSelectModelForSession_SessionlessNeverTouchesPins(t *testing.T) {
	// NEGATIVE: a missing session id never pins, never reads pins, and its
	// decision carries no pin fields — a sessionless request cannot silently
	// inherit or create version state.
	tr, loader, _, pins, _ := pinTestRouter([]CanaryRollout{
		{RolloutID: "r1", Name: "sess", Version: 1, BaseModel: "base-model", CanaryModel: "canary-model", Percent: 99},
	})

	for i := 0; i < 10; i++ {
		sel, dec, err := tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", "")
		require.NoError(t, err)
		assert.Equal(t, "base-model", sel.Name)
		assert.False(t, dec.Active())
		requireNoSilentMix(t, sel, dec, "base-model", "canary-model")
	}
	assert.Equal(t, 0, loader.loads, "sessionless must stay the zero-overhead path (no snapshot loads)")
	assert.Equal(t, 0, pins.Len(), "sessionless must never create pins")

	// Same for a missing org scope: no org, no pin.
	_, dec, err := tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "", "", "some-session")
	require.NoError(t, err)
	assert.Equal(t, CanaryPinNone, dec.Pin)
	assert.Equal(t, 0, pins.Len())
}

func TestSelectModelForSession_PinLayerUnwiredKeepsPlainHashPath(t *testing.T) {
	// pins == nil must behave exactly like the pre-pin router: no pin
	// fields on any decision (regression guard for the zero-value wiring).
	tr, _, versions, _, _ := pinTestRouter([]CanaryRollout{
		{RolloutID: "r1", Name: "off", Version: 1, BaseModel: "base-model", CanaryModel: "canary-model", Percent: 30},
	})
	tr.pins = nil
	session := canarySessionFor(t, 30, true, "off-")

	sel, dec, err := tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", session)
	require.NoError(t, err)
	assert.Equal(t, "canary-model", sel.Name)
	assert.Equal(t, CanaryPinNone, dec.Pin)
	assert.Zero(t, dec.PinnedVersion)
	assert.Zero(t, dec.ActiveVersion)

	versions.version = 2
	_, dec, err = tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", session)
	require.NoError(t, err)
	assert.Equal(t, CanaryPinNone, dec.Pin)
}

// --- concurrency: the race never produces a silent mix --------------------------

// raceCanaryLoader / raceCanaryVersions: synchronized doubles so the flipper
// goroutines can race the resolvers without the harness itself data-racing.
type raceCanaryLoader struct {
	mu       sync.Mutex
	rollouts []CanaryRollout
	loads    int
}

func (l *raceCanaryLoader) LoadCanaryRollouts(_ context.Context, _ string) ([]CanaryRollout, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.loads++
	return l.rollouts, nil
}

func (l *raceCanaryLoader) set(rs []CanaryRollout) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rollouts = rs
}

type raceCanaryVersions struct {
	mu      sync.Mutex
	version int64
}

func (v *raceCanaryVersions) GetCanaryVersion(_ context.Context, _ string) (int64, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.version, nil
}

func (v *raceCanaryVersions) set(n int64) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.version = n
}

func TestSelectModelForSession_ConcurrentRollbackPromote_NoSilentMix(t *testing.T) {
	// Rollback/promote storm against live resolvers: resolvers and flippers
	// run concurrently; every observed decision must satisfy the
	// no-silent-mix invariants (requireNoSilentMix). In particular: whenever
	// the snapshot is rolled back, the canary model must not serve under any
	// pin status; whenever a pin is held, the served version is the pinned
	// one and both versions are on the decision.
	v1 := []CanaryRollout{{RolloutID: "r1", Name: "storm", Version: 1, BaseModel: "base-model", CanaryModel: "canary-model", Percent: 50}}
	v2 := []CanaryRollout{{RolloutID: "r1", Name: "storm", Version: 2, BaseModel: "base-model", CanaryModel: "canary-model", Percent: 50}}

	loader := &raceCanaryLoader{rollouts: v1}
	versions := &raceCanaryVersions{version: 1}
	models := &mockModelLoader{models: []ModelInfo{
		{Name: "base-model", TierPool: []string{"medium"}, Weight: 1, Enabled: true},
		{Name: "canary-model", TierPool: []string{"medium"}, Weight: 0, Enabled: true},
	}}
	tr := NewTierRouter(models, nil) // nil rdb: the weighted pick takes the deterministic fallback (race-free)
	pins := NewCanaryVersionPins(time.Hour, 10000)
	tr.WithCanaryRollouts(NewCanaryRolloutCache(loader, versions, time.Hour, nil))
	tr.WithCanaryVersionPins(pins)

	canarySess := canarySessionFor(t, 50, true, "storm-c-")
	baseSess := canarySessionFor(t, 50, false, "storm-b-")

	const resolvers = 4
	const iterations = 60
	type observed struct {
		sel ModelInfo
		dec CanaryDecision
	}
	results := make(chan observed, resolvers*iterations*2)
	var wg sync.WaitGroup

	for g := 0; g < resolvers; g++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				sel, dec, err := tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", canarySess)
				assert.NoError(t, err)
				results <- observed{sel, dec}
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				sel, dec, err := tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", baseSess)
				assert.NoError(t, err)
				results <- observed{sel, dec}
			}
		}()
	}

	// Flipper: rollback (empty snapshot, version bump) alternating with
	// promote (v2 snapshot, version bump) — every intermediate state is a
	// legitimate thing for the resolvers to observe.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			loader.set(nil)
			versions.set(int64(10 + 2*i))
			loader.set(v2)
			versions.set(int64(11 + 2*i))
			loader.set(v1)
			versions.set(int64(12 + 2*i))
		}
	}()

	wg.Wait()
	close(results)

	seen := map[string]int{}
	for o := range results {
		requireNoSilentMix(t, o.sel, o.dec, "base-model", "canary-model")
		seen[o.dec.Pin]++
		if o.dec.Pin == CanaryPinReleased {
			assert.NotEqual(t, "canary-model", o.sel.Name)
		}
	}
	assert.Positive(t, seen[CanaryPinNone]+seen[CanaryPinNew]+seen[CanaryPinHeld]+seen[CanaryPinExpired]+seen[CanaryPinRebound]+seen[CanaryPinReleased],
		"the storm must have produced decisions")
	assert.Equal(t, 2, pins.Len(), "both sessions match the rollout's base model: two pins")

	// Settled state: snapshot back on v1 — a fresh resolution is coherent.
	loader.set(v1)
	versions.set(99)
	sel, dec, err := tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", canarySess)
	require.NoError(t, err)
	requireNoSilentMix(t, sel, dec, "base-model", "canary-model")
}

// --- decision rendering ----------------------------------------------------------

func TestCanaryDecisionString_PinStatuses(t *testing.T) {
	// No pin involvement: byte-identical to the pre-pin rendering.
	plain := CanaryDecision{RolloutID: "r1", Name: "roll", Version: 3, Arm: CanaryDecisionArmCanary, Percent: 25, From: "base", To: "canary"}
	assert.Equal(t, "rollout=roll version=3 arm=canary percent=25 from=base to=canary", CanaryDecisionString(plain))

	// Held under a newer active version: both versions visible.
	held := plain
	held.Pin, held.PinnedVersion, held.ActiveVersion = CanaryPinHeld, 3, 4
	assert.Equal(t,
		"rollout=roll version=3 arm=canary percent=25 from=base to=canary pin=held active_version=4",
		CanaryDecisionString(held))

	// Released after a rollback: inactive rollout, named release.
	released := CanaryDecision{Pin: CanaryPinReleased, PinnedVersion: 3, Arm: CanaryDecisionArmCanary, Percent: 25}
	assert.Equal(t, "inactive pin=released pinned_version=3", CanaryDecisionString(released))

	// Released with no version recorded (nothing was pinned): plain inactive.
	assert.Equal(t, "inactive", CanaryDecisionString(CanaryDecision{Pin: CanaryPinNone}))
}
