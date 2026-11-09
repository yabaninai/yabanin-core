package cli

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// N03-P02-T03: the cache identity's tenant-policy fingerprint. The digest
// must be deterministic and stable for an unchanged snapshot, must change on
// any material snapshot change (store version bump, plan set change, plan
// version change, judge change), and the gateway resolver must degrade to ""
// (binding off) whenever the runtime cannot vouch for a snapshot.

func TestPolicySnapshotFingerprint_IsStableAndSensitive(t *testing.T) {
	base := &orgPolicyEntry{
		version: 5,
		haveVer: true,
		plans: []policyPlan{
			{policyID: "p1", version: 2, judgeVersion: "j1"},
			{policyID: "p2", version: 1},
		},
	}
	fp := policySnapshotFingerprint(base)
	require.Len(t, fp, 16, "the digest is a truncated sha256 (8 bytes hex)")
	assert.Equal(t, fp, policySnapshotFingerprint(base), "deterministic for an unchanged snapshot")

	// Plan order must not matter: the runtime loads plans in priority order,
	// but the fingerprint identifies the SET.
	reordered := &orgPolicyEntry{
		version: 5,
		haveVer: true,
		plans: []policyPlan{
			{policyID: "p2", version: 1},
			{policyID: "p1", version: 2, judgeVersion: "j1"},
		},
	}
	assert.Equal(t, fp, policySnapshotFingerprint(reordered), "plan order must not change the digest")

	for name, variant := range map[string]*orgPolicyEntry{
		"store version bump": {
			version: 6,
			haveVer: true,
			plans: []policyPlan{
				{policyID: "p1", version: 2, judgeVersion: "j1"},
				{policyID: "p2", version: 1},
			},
		},
		"plan version bump": {
			version: 5,
			haveVer: true,
			plans: []policyPlan{
				{policyID: "p1", version: 3, judgeVersion: "j1"},
				{policyID: "p2", version: 1},
			},
		},
		"judge version change": {
			version: 5,
			haveVer: true,
			plans: []policyPlan{
				{policyID: "p1", version: 2, judgeVersion: "j2"},
				{policyID: "p2", version: 1},
			},
		},
		"plan added": {
			version: 5,
			haveVer: true,
			plans: []policyPlan{
				{policyID: "p1", version: 2, judgeVersion: "j1"},
				{policyID: "p2", version: 1},
				{policyID: "p3", version: 1},
			},
		},
		"plan removed": {
			version: 5,
			haveVer: true,
			plans:   []policyPlan{{policyID: "p1", version: 2, judgeVersion: "j1"}},
		},
		"unknown store version": {
			version: 5,
			haveVer: false,
			plans: []policyPlan{
				{policyID: "p1", version: 2, judgeVersion: "j1"},
				{policyID: "p2", version: 1},
			},
		},
		"no plans at all": {
			version: 5,
			haveVer: true,
		},
	} {
		assert.NotEqual(t, fp, policySnapshotFingerprint(variant),
			"%s must change the regime digest", name)
	}
}

func TestGatewayPolicyCacheRegime_TracksRuntimeSnapshot(t *testing.T) {
	ctx := context.Background()
	store := newFakePolicyStore()
	versions := &fakeOrgPolicyVersions{versions: map[string]int64{testOrg: 7, "other-org": 9}}
	rt := newTestRuntime(t, store, versions, PolicyModeEnforce)
	gw := testHookGateway(rt)

	fp0 := gw.policyCacheRegime(ctx, testOrg)
	require.NotEmpty(t, fp0, "an org with a loadable snapshot must fingerprint")
	assert.Equal(t, fp0, gw.policyCacheRegime(ctx, testOrg), "stable while the snapshot is unchanged")
	assert.NotEqual(t, fp0, gw.policyCacheRegime(ctx, "other-org"),
		"orgs with different published versions must fingerprint differently")

	// The control-plane bumper publishes a new version key: the runtime must
	// reload the snapshot and the fingerprint must move (this is the exact
	// path a policy tighten takes in production).
	versions.bump(testOrg)
	fp1 := gw.policyCacheRegime(ctx, testOrg)
	assert.NotEqual(t, fp0, fp1, "a published version bump must change the fingerprint")
	assert.Equal(t, fp1, gw.policyCacheRegime(ctx, testOrg))
	assert.NotEqual(t, fp1, gw.policyCacheRegime(ctx, "other-org"),
		"the bump must stay scoped to its org")
}

func TestGatewayPolicyCacheRegime_DisarmedCases(t *testing.T) {
	ctx := context.Background()

	unwired := &gateway{}
	assert.Empty(t, unwired.policyCacheRegime(ctx, "org-1"),
		"no runtime means no binding")

	cold := testHookGateway(newUnavailablePolicyRuntime(PolicyModeEnforce, PolicyColdFailureFailClosed, testLogger()))
	assert.Empty(t, cold.policyCacheRegime(ctx, "org-1"),
		"a cold-unavailable runtime must not invent a fingerprint (fail-safe)")

	rt := newTestRuntime(t, newFakePolicyStore(), &fakePolicyVersions{v: 1}, PolicyModeEnforce)
	assert.Empty(t, testHookGateway(rt).policyCacheRegime(ctx, ""),
		"an empty org must not fingerprint")
}

// N03-P02-T04: the resolver's "" answer means "enforcement off or
// unverifiable" and the cache service then performs no lookup and no write
// for the org. The gateway must answer "" whenever policy checking is off —
// including a runtime explicitly configured with policy mode off — while
// shadow mode (checking active, denies converted) keeps the cache
// regime-bound.
func TestGatewayPolicyCacheRegime_OffAndShadowModes(t *testing.T) {
	ctx := context.Background()
	store := newFakePolicyStore()
	versions := &fakeOrgPolicyVersions{versions: map[string]int64{testOrg: 7}}

	off := testHookGateway(newTestRuntime(t, store, versions, PolicyModeOff))
	assert.Empty(t, off.policyCacheRegime(ctx, testOrg),
		"policy mode off means enforcement is off — the cache must see no regime and stay silent")

	shadow := testHookGateway(newTestRuntime(t, store, versions, PolicyModeShadow))
	assert.NotEmpty(t, shadow.policyCacheRegime(ctx, testOrg),
		"shadow mode still checks policies — the cache stays regime-bound")
}

// TestGatewayPolicyCacheRegime_PerOrgLoadFailureAnswersEmpty completes the
// T04/T05 disarm case table for the per-org dimension: when ONE org's policy
// snapshot becomes unloadable at lookup time (store read error — the runtime
// itself is healthy and other orgs keep fingerprinting), the resolver must
// answer "" so the cache gates the org (no lookup, no write) instead of
// serving warm entries whose governing snapshot cannot be vouched for.
// Recovery must re-fingerprint the org, and stably so.
func TestGatewayPolicyCacheRegime_PerOrgLoadFailureAnswersEmpty(t *testing.T) {
	ctx := context.Background()
	store := newFakePolicyStore()
	store.mu.Lock()
	store.listErr = errors.New("adminstore read failed")
	store.mu.Unlock()
	versions := &fakeOrgPolicyVersions{versions: map[string]int64{testOrg: 7}}
	rt := newTestRuntime(t, store, versions, PolicyModeEnforce)
	gw := testHookGateway(rt)

	assert.Empty(t, gw.policyCacheRegime(ctx, testOrg),
		"a per-org snapshot load failure must answer \"\" — the cache must gate, not serve warm content unverifiable")

	// Recovery: once the store read succeeds the org is fingerprinted again,
	// and the fingerprint is stable while the snapshot is unchanged.
	store.mu.Lock()
	store.listErr = nil
	store.mu.Unlock()
	fp := gw.policyCacheRegime(ctx, testOrg)
	assert.NotEmpty(t, fp, "recovery must re-arm the regime binding for the org")
	assert.Equal(t, fp, gw.policyCacheRegime(ctx, testOrg),
		"the fingerprint must be stable for an unchanged snapshot")
}
