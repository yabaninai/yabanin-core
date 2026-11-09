package router

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/classifier"
	"github.com/reireirei/yabanin/pkg/metrics"
)

// catch. Two pins:
//
//   - a SEEDED arm fixture: twelve named sessions × five percents with the
//     exact arm outcome and bucket of the ratified D2 implementation
//     (sha256(session)[0:8]BE % 100 < percent). Any change to the hash
//     input, digest slice, byte order, or comparison flips at least one
//     pinned expectation — deterministic detection, no distribution
//     tolerance to hide in.
//   - metrics deltas: every arm decision increments
//     metrics.CanaryArmTotal{arm,rollout,model} — the measurable traffic
//     share of the packet criterion. Dropping the instrumentation fails.
//
// Weight changes without restart (both gateways) are covered end-to-end by
// half of the same fixture is pinned.

// regressionSessions are the fixed seed identities of the fixture.
var regressionSessions = []string{
	"regression-alpha-1", "regression-alpha-2", "regression-alpha-3",
	"regression-beta-1", "regression-beta-2", "regression-beta-3",
	"regression-beta-4", "regression-gamma-1", "regression-gamma-2",
	"regression-delta-1", "regression-delta-2", "regression-delta-3",
}

// regressionBuckets pins canaryBucket for the seed sessions (sha256-based,
// ratified 2026-10-16 D2). Changing the bucket function changes these.
var regressionBuckets = map[string]int{
	"regression-alpha-1": 24,
	"regression-alpha-2": 97,
	"regression-alpha-3": 99,
	"regression-beta-1":  67,
	"regression-beta-2":  70,
	"regression-beta-3":  72,
	"regression-beta-4":  38,
	"regression-gamma-1": 90,
	"regression-gamma-2": 15,
	"regression-delta-1": 44,
	"regression-delta-2": 81,
	"regression-delta-3": 58,
}

// regressionArms pins CanaryArm(session, percent) for every seed session at
// the five ramp percents, in regressionSessions order.
var regressionArms = []struct {
	percent int
	arms    []bool
}{
	// percent 1
	{1, []bool{false, false, false, false, false, false, false, false, false, false, false, false}},
	// percent 10
	{10, []bool{false, false, false, false, false, false, false, false, false, false, false, false}},
	// percent 30
	{30, []bool{true, false, false, false, false, false, false, false, true, false, false, false}},
	// percent 50
	{50, []bool{true, false, false, false, false, false, true, false, true, true, false, false}},
	// percent 99
	{99, []bool{true, true, false, true, true, true, true, true, true, true, true, true}},
}

func TestCanaryRegression_SeededArmFixture(t *testing.T) {
	for _, session := range regressionSessions {
		assert.Equal(t, regressionBuckets[session], canaryBucket(session),
			"seed session %q: the bucket function changed", session)
	}
	for _, row := range regressionArms {
		for i, session := range regressionSessions {
			assert.Equal(t, row.arms[i], CanaryArm(session, row.percent),
				"seed session %q at percent %d: the sticky arm assignment changed", session, row.percent)
		}
	}
	// Monotone ramp over the fixture: a canary session stays canary as the
	// percent grows (the bucket is a pure function of the session id).
	for _, session := range regressionSessions {
		wasCanary := false
		for _, p := range []int{1, 10, 30, 50, 99} {
			isCanary := CanaryArm(session, p)
			assert.False(t, wasCanary && !isCanary,
				"seed session %q left the canary arm on ramp-up", session)
			wasCanary = wasCanary || isCanary
		}
	}
}

func TestCanaryRegression_MetricsArmsCounted(t *testing.T) {
	// The measured traffic share (packet criterion) is
	// canary_arm_total{arm="canary",...} / (canary + base) per rollout
	// label. Three observable outcomes are pinned by delta:
	//   canary swap, base stay, and canary-arm-but-unservable (pool check
	//   keeps base — counted base, never silently dropped).
	mk := func(arm, rollout, model string) float64 {
		return testutil.ToFloat64(metrics.CanaryArmTotal.WithLabelValues(arm, rollout, model))
	}

	// 1) canary swap + base stay through the full router.
	tr, _ := canaryTestRouter([]CanaryRollout{{RolloutID: "r1", Name: "reg-roll", Version: 1, BaseModel: "base-model", CanaryModel: "canary-model", Percent: 50}})
	canarySession := canarySessionFor(t, 50, true, "reg-metrics-")
	baseSession := canarySessionFor(t, 50, false, "reg-metrics-")

	beforeCanary := mk("canary", "reg-roll", "canary-model")
	beforeBase := mk("base", "reg-roll", "base-model")
	_, dec, err := tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", canarySession)
	require.NoError(t, err)
	require.True(t, dec.Swapped())
	_, dec, err = tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", baseSession)
	require.NoError(t, err)
	require.False(t, dec.Swapped())
	assert.InDelta(t, beforeCanary+1, mk("canary", "reg-roll", "canary-model"), 0,
		"a canary-arm swap must increment canary_arm_total{arm=canary}")
	assert.InDelta(t, beforeBase+1, mk("base", "reg-roll", "base-model"), 0,
		"a base-arm stay must increment canary_arm_total{arm=base}")

	// 2) canary arm but the canary model is outside the pool: base serves
	// AND the base counter increments (the decision is still observable).
	loader := &mockModelLoader{models: []ModelInfo{
		{Name: "base-model", TierPool: []string{"medium"}, Weight: 1, Enabled: true},
		{Name: "canary-model", TierPool: []string{"hard"}, Weight: 1, Enabled: true},
	}}
	tr2 := NewTierRouter(loader, newMockRedis())
	tr2.WithCanaryRollouts(NewCanaryRolloutCache(&fakeCanaryLoader{
		rollouts: []CanaryRollout{{RolloutID: "r1", Name: "reg-roll", Version: 1, BaseModel: "base-model", CanaryModel: "canary-model", Percent: 90}},
	}, nil, time.Minute, nil))
	oobBefore := mk("base", "reg-roll", "base-model")
	_, dec, err = tr2.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", canarySessionFor(t, 90, true, "reg-oob-"))
	require.NoError(t, err)
	require.True(t, dec.Active())
	assert.Equal(t, CanaryDecisionArmBase, dec.Arm)
	assert.InDelta(t, oobBefore+1, mk("base", "reg-roll", "base-model"), 0,
		"an unservable canary must be counted as a base decision, not dropped")
}

func TestCanaryRegression_WeightChangeWithoutRestart(t *testing.T) {
	// changes for NEW selections the moment the version key bumps — no
	// router rebuild, no process restart. (The both-gateways half is
	loader := &fakeCanaryLoader{rollouts: []CanaryRollout{{RolloutID: "r1", Name: "reg-roll", Version: 1, BaseModel: "base-model", CanaryModel: "canary-model", Percent: 10}}}
	versions := &fakeCanaryVersions{version: 1}
	tr := NewTierRouter(&mockModelLoader{models: []ModelInfo{
		{Name: "base-model", TierPool: []string{"medium"}, Weight: 1, Enabled: true},
		{Name: "canary-model", TierPool: []string{"medium"}, Weight: 0, Enabled: true},
	}}, newMockRedis())
	tr.WithCanaryRollouts(NewCanaryRolloutCache(loader, versions, time.Minute, nil))

	// A session between the two percents: base at 10, canary at 50.
	between := ""
	for i := 0; i < 100000; i++ {
		id := "reg-weight-" + time.Duration(i).String()
		if !CanaryArm(id, 10) && CanaryArm(id, 50) {
			between = id
			break
		}
	}
	require.NotEmpty(t, between, "no session found between the two percents")
	sel, _, err := tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", between)
	require.NoError(t, err)
	assert.Equal(t, "base-model", sel.Name)

	loader.rollouts = []CanaryRollout{{RolloutID: "r1", Name: "reg-roll", Version: 2, BaseModel: "base-model", CanaryModel: "canary-model", Percent: 50}}
	versions.version = 2

	sel, dec, err := tr.SelectModelForSession(context.Background(), classifier.ClassMedium, "org-1", "", between)
	require.NoError(t, err)
	assert.Equal(t, "canary-model", sel.Name, "the bumped weight must apply to the next selection without restart")
	assert.Equal(t, 2, dec.Version)
	assert.Equal(t, 50, dec.Percent)
}
