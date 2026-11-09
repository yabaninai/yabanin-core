package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/pipeline"
)

// Snapshot adapters keep the existing fixtures and their error/call
// assertions meaningful while the runtime consumes one aggregate operation.
func (f *fakePolicyStore) LoadPolicySnapshot(ctx context.Context, orgID string) (adminstore.PolicyPipelineSnapshot, error) {
	f.mu.Lock()
	block, started, listErr := f.listCtxBlock, f.listStarted, f.listErr
	if listErr != nil {
		f.mu.Unlock()
		return adminstore.PolicyPipelineSnapshot{}, listErr
	}
	policies := append([]adminstore.PolicyPipeline(nil), f.policies[orgID]...)
	snapshot := adminstore.PolicyPipelineSnapshot{
		Policies:    policies,
		Versions:    make(map[string]adminstore.PolicyVersion),
		Attachments: make(map[string][]adminstore.PolicyAttachment, len(policies)),
	}
	for _, p := range policies {
		snapshot.Attachments[p.ID] = append([]adminstore.PolicyAttachment(nil), f.atts[orgID][p.ID]...)
		if p.Enabled && p.CurrentVersion > 0 {
			if yaml, ok := f.versions[orgID][p.ID][p.CurrentVersion]; ok {
				snapshot.Versions[p.ID] = adminstore.PolicyVersion{
					PolicyID: p.ID, OrgID: orgID, Version: p.CurrentVersion, YAML: yaml,
				}
			}
		}
	}
	f.mu.Unlock()
	if block {
		if started != nil {
			started <- struct{}{}
		}
		<-ctx.Done()
		return adminstore.PolicyPipelineSnapshot{}, ctx.Err()
	}
	return snapshot, nil
}

func (s *countedPolicyStore) LoadPolicySnapshot(ctx context.Context, orgID string) (adminstore.PolicyPipelineSnapshot, error) {
	s.listCalls.Add(1)
	return s.fakePolicyStore.LoadPolicySnapshot(ctx, orgID)
}

func (s *countingPolicyReader) LoadPolicySnapshot(ctx context.Context, orgID string) (adminstore.PolicyPipelineSnapshot, error) {
	s.listCalls.Add(1)
	return s.PolicyPipelineReader.LoadPolicySnapshot(ctx, orgID)
}

func (s *faultPolicyReader) LoadPolicySnapshot(ctx context.Context, orgID string) (adminstore.PolicyPipelineSnapshot, error) {
	if s.listErr != nil {
		return adminstore.PolicyPipelineSnapshot{}, s.listErr
	}
	if s.versionErr != nil {
		if errors.Is(s.versionErr, adminstore.ErrNotFound) {
			return adminstore.PolicyPipelineSnapshot{}, invalidPolicyConfig(policyConfigStageActiveReference)
		}
		return adminstore.PolicyPipelineSnapshot{}, fmt.Errorf("get policy version: %w", s.versionErr)
	}
	if s.attachmentsErr != nil {
		if errors.Is(s.attachmentsErr, adminstore.ErrNotFound) {
			return adminstore.PolicyPipelineSnapshot{}, invalidPolicyConfig(policyConfigStageActiveReference)
		}
		return adminstore.PolicyPipelineSnapshot{}, fmt.Errorf("list policy attachments: %w", s.attachmentsErr)
	}
	return s.PolicyPipelineReader.LoadPolicySnapshot(ctx, orgID)
}

func (s *reentryOrgRecordingStore) LoadPolicySnapshot(ctx context.Context, orgID string) (adminstore.PolicyPipelineSnapshot, error) {
	s.mu.Lock()
	s.orgs = append(s.orgs, orgID)
	s.mu.Unlock()
	return s.countedPolicyStore.LoadPolicySnapshot(ctx, orgID)
}

type snapshotHookStore struct {
	*fakePolicyStore
	loads atomic.Int64
	after func(int64)
}

func (s *snapshotHookStore) LoadPolicySnapshot(ctx context.Context, orgID string) (adminstore.PolicyPipelineSnapshot, error) {
	snapshot, err := s.fakePolicyStore.LoadPolicySnapshot(ctx, orgID)
	n := s.loads.Add(1)
	if err == nil && s.after != nil {
		s.after(n)
	}
	return snapshot, err
}

type countedSnapshotVersionReader struct {
	fakePolicyVersions
	reads atomic.Int64
}

func (v *countedSnapshotVersionReader) GetPolicyVersion(ctx context.Context, orgID string) (int64, error) {
	v.reads.Add(1)
	return v.fakePolicyVersions.GetPolicyVersion(ctx, orgID)
}

type failingSnapshotVersionBumper struct {
	calls atomic.Int64
	err   error
}

func (b *failingSnapshotVersionBumper) SetPolicyVersion(context.Context, string, int64) error {
	b.calls.Add(1)
	return b.err
}

func TestPolicyRuntime_ActivationBetweenSnapshotAndVersionProbeRetries(t *testing.T) {
	multiHookYAML := func(marker string) string {
		return strings.Replace(
			denyWordYAML("atomic", marker),
			"  - pre_upstream\n",
			"  - pre_upstream\n  - post_upstream\n  - stream_prefix\n  - stream_final\n",
			1,
		)
	}
	base := newFakePolicyStore()
	base.add(testOrg, adminstore.PolicyPipeline{ID: "atomic", OrgID: testOrg, Name: "atomic", Enabled: true, CurrentVersion: 1},
		map[int]string{1: multiHookYAML("old-marker"), 2: multiHookYAML("new-marker")},
		[]adminstore.PolicyAttachment{{ID: "atomic-old", PolicyID: "atomic", OrgID: testOrg, ModelPattern: "old-*", Endpoint: "chat", Priority: 2}})
	versions := &fakePolicyVersions{v: 1}
	store := &snapshotHookStore{fakePolicyStore: base}
	store.after = func(load int64) {
		if load == 1 {
			base.mu.Lock()
			base.policies[testOrg][0].CurrentVersion = 2
			base.atts[testOrg]["atomic"] = []adminstore.PolicyAttachment{{ID: "atomic-new", PolicyID: "atomic", OrgID: testOrg, ModelPattern: "new-*", Endpoint: "messages", Priority: 8}}
			base.mu.Unlock()
			versions.bump()
		}
	}
	rt := newTestRuntime(t, store, versions, PolicyModeEnforce)
	outcome := rt.refreshWithOutcome(context.Background(), testOrg, nil, rt.now())
	if outcome.loadErr != nil || outcome.entry == nil {
		t.Fatalf("refresh outcome = %+v, want successful coherent retry", outcome)
	}
	if got := store.loads.Load(); got != 2 {
		t.Fatalf("snapshot loads = %d, want exactly 2", got)
	}
	if len(outcome.entry.plans) != 1 || outcome.entry.plans[0].version != 2 {
		t.Fatalf("installed plans = %+v, want only active version 2", outcome.entry.plans)
	}
	if len(outcome.entry.plans[0].atts) != 1 || outcome.entry.plans[0].atts[0].ID != "atomic-new" || outcome.entry.plans[0].atts[0].ModelPattern != "new-*" || outcome.entry.plans[0].atts[0].Endpoint != "messages" || outcome.entry.plans[0].atts[0].Priority != 8 {
		t.Fatalf("retried snapshot attachments = %+v, want the complete new attachment bundle", outcome.entry.plans[0].atts)
	}
	currentToken, _ := versions.GetPolicyVersion(context.Background(), testOrg)
	if !outcome.entry.haveVer || outcome.entry.version != currentToken {
		t.Fatalf("installed token = (%d, %v), want (%d, true)", outcome.entry.version, outcome.entry.haveVer, currentToken)
	}
	requestCtx := withPolicyEntryOutcome(context.Background(), rt, testOrg, outcome)
	queries := []policyQuery{
		{endpoint: "messages", hook: pipeline.HookPreUpstream, model: "new-model"},
		{endpoint: "messages", hook: pipeline.HookPostUpstream, model: "new-model"},
		{endpoint: "messages", hook: pipeline.HookStreamPrefix, model: "new-model"},
		{endpoint: "messages", hook: pipeline.HookStreamFinal, model: "new-model"},
	}
	for _, query := range queries {
		decisions, _, denied := rt.evaluate(requestCtx, testOrg, query, &pipeline.Payload{
			Kind: pipeline.KindRequest, Endpoint: query.endpoint, Body: []byte("new-marker"),
		})
		if !denied || len(decisions) != 1 || decisions[0].Version != 2 {
			t.Errorf("hook %s outcome = (decisions=%+v denied=%v), want v2 deny from pinned compiled YAML", query.hook, decisions, denied)
		}
	}
	oldDecisions, _, oldDenied := rt.evaluate(requestCtx, testOrg, queries[0], &pipeline.Payload{
		Kind: pipeline.KindRequest, Endpoint: queries[0].endpoint, Body: []byte("old-marker"),
	})
	if oldDenied || len(oldDecisions) != 1 || oldDecisions[0].Version != 2 {
		t.Fatalf("old marker against pinned v2 = (decisions=%+v denied=%v), want v2 allow", oldDecisions, oldDenied)
	}
	if got := store.loads.Load(); got != 2 {
		t.Fatalf("selectors reloaded aggregate snapshot %d times, want only the two bounded attempts", got)
	}
}

func TestPolicyRuntime_StableSnapshotWhenVersionBumpIsUnavailable(t *testing.T) {
	base := newFakePolicyStore()
	base.add(testOrg, adminstore.PolicyPipeline{ID: "stable", OrgID: testOrg, Name: "stable", Enabled: true, CurrentVersion: 1},
		map[int]string{1: denyWordYAML("stable", "old-marker")}, []adminstore.PolicyAttachment{{ID: "old-attachment", PolicyID: "stable", OrgID: testOrg, ModelPattern: "old-*", Endpoint: "chat", Priority: 1}})
	store := &snapshotHookStore{fakePolicyStore: base}
	versions := &countedSnapshotVersionReader{fakePolicyVersions: fakePolicyVersions{v: 7}}
	bumpErr := errors.New("synthetic Redis SET failure")
	bumper := &failingSnapshotVersionBumper{err: bumpErr}
	store.after = func(load int64) {
		if load != 1 {
			return
		}
		base.mu.Lock()
		base.policies[testOrg][0].CurrentVersion = 2
		base.versions[testOrg]["stable"][2] = denyWordYAML("stable", "new-marker")
		base.atts[testOrg]["stable"] = []adminstore.PolicyAttachment{{ID: "new-attachment", PolicyID: "stable", OrgID: testOrg, ModelPattern: "new-*", Endpoint: "messages", Priority: 9}}
		base.mu.Unlock()
		if err := bumper.SetPolicyVersion(context.Background(), testOrg, 8); !errors.Is(err, bumpErr) {
			t.Errorf("synthetic invalidation SET error = %v, want %v", err, bumpErr)
		}
	}
	rt := newTestRuntime(t, store, versions, PolicyModeEnforce)
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	rt.now = func() time.Time { return now }
	initial := rt.entryWithOutcome(context.Background(), testOrg)
	if initial.loadErr != nil || initial.entry == nil {
		t.Fatalf("initial refresh outcome = %+v, want coherent old snapshot", initial)
	}
	if got := store.loads.Load(); got != 1 {
		t.Fatalf("snapshot loads after failed SET = %d, want 1; unchanged GETs must not detect the failed bump", got)
	}
	if !initial.entry.haveVer || initial.entry.version != 7 || len(initial.entry.plans) != 1 || initial.entry.plans[0].version != 1 || initial.entry.plans[0].atts[0].ID != "old-attachment" {
		t.Fatalf("first installed snapshot = %+v, want coherent v1/old attachments at unchanged token 7", initial.entry)
	}
	if got := bumper.calls.Load(); got != 1 {
		t.Fatalf("attempted invalidation SET calls = %d, want 1", got)
	}

	// Equal Redis GETs cannot reveal the failed SET. The old entry stays in
	// force before its hard TTL, even though PostgreSQL now has version 2.
	now = now.Add(policyCacheTTL - time.Nanosecond)
	beforeTTL := rt.entryWithOutcome(context.Background(), testOrg)
	if beforeTTL.entry != initial.entry || store.loads.Load() != 1 {
		t.Fatalf("pre-TTL refresh = %+v, loads=%d; want unchanged last-good entry and no store reread", beforeTTL, store.loads.Load())
	}

	// At the hard TTL, a later coherent snapshot observes the committed v2
	// bundle. This proves eventual freshness only, not failed-bump detection.
	now = now.Add(time.Nanosecond)
	afterTTL := rt.entryWithOutcome(context.Background(), testOrg)
	if afterTTL.loadErr != nil || afterTTL.entry == nil || afterTTL.entry == initial.entry {
		t.Fatalf("at-TTL refresh = %+v, want a new coherent entry", afterTTL)
	}
	if len(afterTTL.entry.plans) != 1 || afterTTL.entry.plans[0].version != 2 || afterTTL.entry.plans[0].atts[0].ID != "new-attachment" {
		t.Fatalf("at-TTL snapshot = %+v, want v2/new attachment bundle", afterTTL.entry.plans)
	}
	if got := store.loads.Load(); got != 2 {
		t.Fatalf("snapshot loads after TTL = %d, want 2 total", got)
	}
	if got := versions.reads.Load(); got != 6 {
		t.Fatalf("version-key GET count = %d, want 6 (2 initial, 1 pre-TTL, 1 cache probe + 2 refresh probes at TTL)", got)
	}
}

func TestPolicyRuntime_SnapshotWithoutVersionReaderLeavesVersionUnknown(t *testing.T) {
	store := &snapshotHookStore{fakePolicyStore: newFakePolicyStore()}
	store.add(testOrg, adminstore.PolicyPipeline{ID: "unknown-token", OrgID: testOrg, Name: "unknown-token", Enabled: true, CurrentVersion: 1},
		map[int]string{1: denyWordYAML("unknown-token", "marker")}, []adminstore.PolicyAttachment{chatAttachment(1)})
	rt := newTestRuntime(t, store, nil, PolicyModeEnforce)
	outcome := rt.refreshWithOutcome(context.Background(), testOrg, nil, rt.now())
	if outcome.loadErr != nil || outcome.entry == nil {
		t.Fatalf("refresh outcome = %+v, want coherent snapshot with unknown version", outcome)
	}
	if outcome.entry.haveVer {
		t.Fatalf("version marked known without a version reader: %+v", outcome.entry)
	}
}

// secondAttemptCancelStore forces snapshot churn on the first refresh attempt
// (a committed activation lands between the version probes) and a canceled
// context on the second, exercising the bounded-retry cancellation boundary
// without sleeps or timing guesses.
type secondAttemptCancelStore struct {
	*fakePolicyStore
	loads         atomic.Int64
	versions      *fakeOrgPolicyVersions
	secondStarted chan struct{}
}

func (s *secondAttemptCancelStore) LoadPolicySnapshot(ctx context.Context, orgID string) (adminstore.PolicyPipelineSnapshot, error) {
	if s.loads.Add(1) == 2 {
		if s.secondStarted != nil {
			s.secondStarted <- struct{}{}
		}
		<-ctx.Done()
		return adminstore.PolicyPipelineSnapshot{}, ctx.Err()
	}
	snapshot, err := s.fakePolicyStore.LoadPolicySnapshot(ctx, orgID)
	if err == nil && s.loads.Load() == 1 {
		s.versions.bump(orgID)
	}
	return snapshot, err
}

// TestPolicyRuntime_ExhaustedSnapshotChurnKeepsColdEmptyAndWarmLastGood covers
// the retry-exhaustion boundary in both cache states: a cold org must stay
// empty (a churn failure never installs an entry) and a warm org must keep its
// exact last-good entry. Both states are bounded to exactly two store loads.
func TestPolicyRuntime_ExhaustedSnapshotChurnKeepsColdEmptyAndWarmLastGood(t *testing.T) {
	base := newFakePolicyStore()
	base.add(testOrg, adminstore.PolicyPipeline{ID: "churn", OrgID: testOrg, Name: "churn", Enabled: true, CurrentVersion: 1},
		map[int]string{1: denyWordYAML("churn", "v1")}, []adminstore.PolicyAttachment{chatAttachment(1)})
	versions := &fakeOrgPolicyVersions{versions: map[string]int64{testOrg: 1}}
	store := &snapshotHookStore{fakePolicyStore: base}
	store.after = func(int64) { versions.bump(testOrg) }
	rt := newTestRuntime(t, store, versions, PolicyModeEnforce)

	// Cold: both attempts race a concurrent activation; nothing may install.
	cold := rt.refreshWithOutcome(context.Background(), testOrg, nil, rt.now())
	if !errors.Is(cold.loadErr, errPolicySnapshotChurn) || cold.entry != nil || cold.stale {
		t.Fatalf("cold exhausted-churn outcome = %+v, want churn error with no entry and stale=false", cold)
	}
	if got := store.loads.Load(); got != 2 {
		t.Fatalf("cold snapshot loads = %d, want bounded maximum 2", got)
	}
	rt.mu.Lock()
	installed := rt.orgs[testOrg]
	rt.mu.Unlock()
	if installed != nil {
		t.Fatalf("cold churn installed cache entry %+v, want none", installed)
	}

	// Warm: the same exhaustion keeps the exact last-good entry in force.
	prior := &orgPolicyEntry{plans: []policyPlan{{policyID: "last-good", version: 9}}, loadedAt: rt.now(), version: 1, haveVer: true}
	rt.mu.Lock()
	rt.orgs[testOrg] = prior
	rt.mu.Unlock()
	warm := rt.refreshWithOutcome(context.Background(), testOrg, prior, rt.now())
	if !errors.Is(warm.loadErr, errPolicySnapshotChurn) || warm.entry != prior || !warm.stale {
		t.Fatalf("warm exhausted-churn outcome = %+v, want churn error with the exact last-good entry", warm)
	}
	if got := store.loads.Load(); got != 4 {
		t.Fatalf("warm snapshot loads = %d, want 4 total (2 cold + 2 warm)", got)
	}
	rt.mu.Lock()
	installed = rt.orgs[testOrg]
	rt.mu.Unlock()
	if installed != prior || len(installed.plans) != 1 || installed.plans[0].policyID != "last-good" {
		t.Fatal("warm churn replaced or rebuilt the last-good cache entry")
	}
}

// TestPolicyRuntime_SecondAttemptCancellationKeepsExactLastGoodAndRecovers
// proves that a context cancellation on the bounded retry's second attempt
// fails without touching the warm cache, then a clean refresh recovers with a
// fresh loadedAt and the current version token.
func TestPolicyRuntime_SecondAttemptCancellationKeepsExactLastGoodAndRecovers(t *testing.T) {
	base := newFakePolicyStore()
	base.add(testOrg, adminstore.PolicyPipeline{ID: "cancel", OrgID: testOrg, Name: "cancel", Enabled: true, CurrentVersion: 1},
		map[int]string{1: denyWordYAML("cancel", "marker")}, []adminstore.PolicyAttachment{chatAttachment(1)})
	versions := &fakeOrgPolicyVersions{versions: map[string]int64{testOrg: 1}}
	store := &secondAttemptCancelStore{fakePolicyStore: base, versions: versions, secondStarted: make(chan struct{}, 1)}
	rt := newTestRuntime(t, store, versions, PolicyModeEnforce)
	loadedAt := time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)
	prior := &orgPolicyEntry{plans: []policyPlan{{policyID: "last-good", version: 9}}, loadedAt: loadedAt, version: 1, haveVer: true}
	rt.mu.Lock()
	rt.orgs[testOrg] = prior
	rt.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-store.secondStarted
		cancel()
	}()
	canceled := rt.refreshWithOutcome(ctx, testOrg, prior, rt.now())
	if !errors.Is(canceled.loadErr, context.Canceled) {
		t.Fatalf("canceled second attempt outcome = %+v, want wrapped context.Canceled", canceled)
	}
	if canceled.entry != prior || !canceled.stale {
		t.Fatalf("canceled refresh outcome = %+v, want the exact last-good entry marked stale", canceled)
	}
	if got := store.loads.Load(); got != 2 {
		t.Fatalf("snapshot loads before recovery = %d, want exactly one churn attempt plus one canceled attempt", got)
	}
	rt.mu.Lock()
	installed := rt.orgs[testOrg]
	rt.mu.Unlock()
	if installed != prior || !installed.loadedAt.Equal(loadedAt) {
		t.Fatalf("cancellation corrupted the cache entry %+v, want the untouched last-good with loadedAt %v", installed, loadedAt)
	}

	recoveredAt := loadedAt.Add(5 * time.Second)
	recovered := rt.refreshWithOutcome(context.Background(), testOrg, prior, recoveredAt)
	if recovered.loadErr != nil || recovered.entry == nil || recovered.stale {
		t.Fatalf("recovery outcome = %+v, want a fresh successful entry", recovered)
	}
	if got := store.loads.Load(); got != 3 {
		t.Fatalf("snapshot loads after recovery = %d, want 3 total", got)
	}
	fresh := recovered.entry
	if fresh == prior || !fresh.loadedAt.Equal(recoveredAt) {
		t.Fatalf("recovered entry = %+v, want a rebuilt entry with loadedAt %v", fresh, recoveredAt)
	}
	token, _ := versions.GetPolicyVersion(context.Background(), testOrg)
	if !fresh.haveVer || fresh.version != token {
		t.Fatalf("recovered version token = (%d, %v), want the current token (%d, true)", fresh.version, fresh.haveVer, token)
	}
	if len(fresh.plans) != 1 || fresh.plans[0].policyID != "cancel" || fresh.plans[0].version != 1 {
		t.Fatalf("recovered plans = %+v, want the single compiled v1 plan", fresh.plans)
	}
	rt.mu.Lock()
	installed = rt.orgs[testOrg]
	rt.mu.Unlock()
	if installed != fresh {
		t.Fatal("recovery did not replace the cache entry")
	}
}

func TestPolicyRuntime_RepeatedSnapshotChurnKeepsLastGood(t *testing.T) {
	base := newFakePolicyStore()
	base.add(testOrg, adminstore.PolicyPipeline{ID: "churn", OrgID: testOrg, Name: "churn", Enabled: true, CurrentVersion: 1},
		map[int]string{1: denyWordYAML("churn", "v1"), 2: denyWordYAML("churn", "v2")}, []adminstore.PolicyAttachment{chatAttachment(1)})
	versions := &fakePolicyVersions{v: 1}
	store := &snapshotHookStore{fakePolicyStore: base}
	store.after = func(int64) { versions.bump() }
	rt := newTestRuntime(t, store, versions, PolicyModeEnforce)
	prior := &orgPolicyEntry{plans: []policyPlan{{policyID: "last-good", version: 9}}, loadedAt: rt.now(), version: 1, haveVer: true}
	rt.mu.Lock()
	rt.orgs[testOrg] = prior
	rt.mu.Unlock()
	outcome := rt.refreshWithOutcome(context.Background(), testOrg, prior, rt.now())
	if !errors.Is(outcome.loadErr, errPolicySnapshotChurn) || outcome.entry != prior || !outcome.stale {
		t.Fatalf("repeated-churn outcome = %+v, want last-good plus churn error", outcome)
	}
	if got := store.loads.Load(); got != 2 {
		t.Fatalf("snapshot loads = %d, want bounded maximum 2", got)
	}
	rt.mu.Lock()
	installed := rt.orgs[testOrg]
	rt.mu.Unlock()
	if installed != prior {
		t.Fatal("repeated churn replaced last-good cache entry")
	}
}

// denyAllYAML is a minimal one-step deny policy used by the regression
// anchors; marker names keep the candidates distinguishable.
func denyAllYAML(name, marker string) string {
	return denyWordYAML(name, marker)
}

// TestPolicyRuntime_InstalledEntryIsImmutableAcrossActivationAndTTLRefresh
// pins the version order: an entry captured before an activation keeps its
// pinned compiled plans for in-flight use, while a past-TTL refresh installs
// a NEW entry for later requests — no in-place mutation, no shared state.
func TestPolicyRuntime_InstalledEntryIsImmutableAcrossActivationAndTTLRefresh(t *testing.T) {
	base := newFakePolicyStore()
	base.add(testOrg, adminstore.PolicyPipeline{ID: "order", OrgID: testOrg, Name: "order", Enabled: true, CurrentVersion: 1},
		map[int]string{1: denyAllYAML("order", "old-marker"), 2: denyAllYAML("order", "new-marker")}, []adminstore.PolicyAttachment{chatAttachment(1)})
	versions := &fakeOrgPolicyVersions{versions: map[string]int64{testOrg: 1}}
	rt := newTestRuntime(t, base, versions, PolicyModeEnforce)
	now := time.Date(2026, 10, 11, 8, 0, 0, 0, time.UTC)
	rt.now = func() time.Time { return now }

	first := rt.entryWithOutcome(context.Background(), testOrg)
	if first.loadErr != nil || first.entry == nil {
		t.Fatalf("initial entry outcome = %+v, want a coherent v1 entry", first)
	}
	entry1 := first.entry
	denyUnder := func(outcome policyEntryOutcome, marker string) bool {
		ctx := withPolicyEntryOutcome(context.Background(), rt, testOrg, outcome)
		_, _, denied := rt.evaluate(ctx, testOrg, policyQuery{endpoint: "chat", hook: pipeline.HookPreUpstream, model: "m"},
			&pipeline.Payload{Kind: pipeline.KindRequest, Endpoint: "chat", Body: []byte(marker)})
		return denied
	}
	if !denyUnder(first, "old-marker") {
		t.Fatal("entry1 must deny its own pinned marker")
	}

	// Before any activation the healthy probe keeps the captured entry in
	// force regardless of TTL (equal token, no reload).
	now = now.Add(policyCacheTTL - time.Nanosecond)
	pre := rt.entryWithOutcome(context.Background(), testOrg)
	if pre.entry != entry1 || !denyUnder(pre, "old-marker") || denyUnder(pre, "new-marker") {
		t.Fatalf("pre-activation refresh = %+v, want the unchanged v1 entry still governing", pre.entry)
	}

	// An activation lands after the capture: DB and version key move to v2.
	// A version bump invalidates immediately — the next call refreshes.
	base.mu.Lock()
	base.policies[testOrg][0].CurrentVersion = 2
	base.mu.Unlock()
	versions.bump(testOrg)
	now = now.Add(time.Nanosecond)
	second := rt.entryWithOutcome(context.Background(), testOrg)
	if second.loadErr != nil || second.entry == nil || second.entry == entry1 {
		t.Fatalf("post-TTL refresh = %+v, want a new coherent v2 entry", second)
	}
	if !denyUnder(second, "new-marker") || denyUnder(second, "old-marker") {
		t.Fatal("entry2 must govern the committed v2 revision only")
	}
	if !denyUnder(first, "old-marker") || denyUnder(first, "new-marker") {
		t.Fatal("captured entry1 was mutated by the refresh; in-flight requests must keep their pinned snapshot")
	}
	rt.mu.Lock()
	installed := rt.orgs[testOrg]
	rt.mu.Unlock()
	if installed != second.entry {
		t.Fatal("cache must hold the newest coherent entry")
	}
}

// TestPolicyRuntime_InvalidCandidateNeverReplacesLastGood proves that an
// invalid snapshot (an active-version reference the snapshot cannot resolve)
// fails the whole candidate: the last-good entry stays installed and keeps
// governing requests until a valid refresh succeeds.
func TestPolicyRuntime_InvalidCandidateNeverReplacesLastGood(t *testing.T) {
	base := newFakePolicyStore()
	base.add(testOrg, adminstore.PolicyPipeline{ID: "guard", OrgID: testOrg, Name: "guard", Enabled: true, CurrentVersion: 1},
		map[int]string{1: denyAllYAML("guard", "good-marker")}, []adminstore.PolicyAttachment{chatAttachment(1)})
	versions := &fakeOrgPolicyVersions{versions: map[string]int64{testOrg: 1}}
	rt := newTestRuntime(t, base, versions, PolicyModeEnforce)
	now := time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)
	rt.now = func() time.Time { return now }

	good := rt.entryWithOutcome(context.Background(), testOrg)
	if good.loadErr != nil || good.entry == nil {
		t.Fatalf("initial entry outcome = %+v, want a valid v1 entry", good)
	}

	// The next candidate is broken: CurrentVersion points at a version the
	// snapshot does not carry (the unresolvable-active-reference case).
	base.mu.Lock()
	base.policies[testOrg][0].CurrentVersion = 3
	base.mu.Unlock()
	now = now.Add(policyCacheTTL + time.Nanosecond)
	broken := rt.entryWithOutcome(context.Background(), testOrg)
	var configErr *policyConfigError
	if !errors.As(broken.loadErr, &configErr) || broken.entry != good.entry || !broken.stale {
		t.Fatalf("invalid-candidate outcome = (err=%v entry=%v stale=%v), want config error with the last-good entry", broken.loadErr, broken.entry, broken.stale)
	}
	rt.mu.Lock()
	installed := rt.orgs[testOrg]
	rt.mu.Unlock()
	if installed != good.entry {
		t.Fatal("invalid candidate replaced the last-good cache entry")
	}
	ctx := withPolicyEntryOutcome(context.Background(), rt, testOrg, broken)
	_, _, denied := rt.evaluate(ctx, testOrg, policyQuery{endpoint: "chat", hook: pipeline.HookPreUpstream, model: "m"},
		&pipeline.Payload{Kind: pipeline.KindRequest, Endpoint: "chat", Body: []byte("good-marker")})
	if !denied {
		t.Fatal("the stale last-good entry must keep enforcing while no valid candidate exists")
	}

	// A later valid revision recovers normally.
	base.mu.Lock()
	base.policies[testOrg][0].CurrentVersion = 2
	base.versions[testOrg]["guard"][2] = denyAllYAML("guard", "recovered-marker")
	base.mu.Unlock()
	versions.bump(testOrg)
	now = now.Add(policyCacheTTL + time.Nanosecond)
	recovered := rt.entryWithOutcome(context.Background(), testOrg)
	if recovered.loadErr != nil || recovered.entry == nil || recovered.entry == good.entry {
		t.Fatalf("recovery outcome = %+v, want a fresh valid entry", recovered)
	}
}

// TestPolicyRuntime_StoredAttachmentMatchingScopesEndpointModelAndKeyLabel
// proves the attachment selector keeps the stored semantics: policy runs on
// the hooks it declares, the endpoints its attachments name, the model
// pattern they carry, and the key-label scope they set — never wider.
func TestPolicyRuntime_StoredAttachmentMatchingScopesEndpointModelAndKeyLabel(t *testing.T) {
	base := newFakePolicyStore()
	base.add(testOrg,
		adminstore.PolicyPipeline{ID: "chat-any", OrgID: testOrg, Name: "chat-any", Enabled: true, CurrentVersion: 1},
		map[int]string{1: denyAllYAML("chat-any", "chat-marker")},
		[]adminstore.PolicyAttachment{{ID: "a-chat", PolicyID: "chat-any", OrgID: testOrg, ModelPattern: "*", Endpoint: "chat", Priority: 5}})
	base.add(testOrg,
		adminstore.PolicyPipeline{ID: "msg-team", OrgID: testOrg, Name: "msg-team", Enabled: true, CurrentVersion: 1},
		map[int]string{1: denyAllYAML("msg-team", "msg-marker")},
		[]adminstore.PolicyAttachment{{ID: "a-msg", PolicyID: "msg-team", OrgID: testOrg, ModelPattern: "team-*", Endpoint: "messages", Priority: 6, KeyLabel: "team-x"}})
	versions := &fakeOrgPolicyVersions{versions: map[string]int64{testOrg: 1}}
	rt := newTestRuntime(t, base, versions, PolicyModeEnforce)
	entry := rt.entry(context.Background(), testOrg)
	if entry == nil || len(entry.plans) != 2 {
		t.Fatalf("entry = %+v, want both stored plans loaded", entry)
	}

	queries := []struct {
		name string
		q    policyQuery
		want string // policyID that must match; "" = none
	}{
		{"chat any model", policyQuery{endpoint: "chat", hook: pipeline.HookPreUpstream, model: "gpt-9"}, "chat-any"},
		{"messages team model team key", policyQuery{endpoint: "messages", hook: pipeline.HookPreUpstream, model: "team-alpha", keyLabels: []string{"team-x"}}, "msg-team"},
		{"messages team model other key", policyQuery{endpoint: "messages", hook: pipeline.HookPreUpstream, model: "team-alpha", keyLabels: []string{"other"}}, ""},
		{"messages other model team key", policyQuery{endpoint: "messages", hook: pipeline.HookPreUpstream, model: "other", keyLabels: []string{"team-x"}}, ""},
		{"chat post hook not declared", policyQuery{endpoint: "chat", hook: pipeline.HookPostUpstream, model: "gpt-9"}, ""},
	}
	for _, tc := range queries {
		plans := rt.plansFor(entry, tc.q)
		if tc.want == "" {
			if len(plans) != 0 {
				t.Errorf("%s: plans = %+v, want none", tc.name, plans)
			}
			continue
		}
		if len(plans) != 1 || plans[0].policyID != tc.want {
			t.Errorf("%s: plans = %+v, want exactly %s", tc.name, plans, tc.want)
		}
	}

	// Wire-level: the two positive selectors deny through their own compiled
	// plan; the missing-key-label request is untouched.
	outcome := policyEntryOutcome{entry: entry}
	runEval := func(q policyQuery, marker string) ([]policyDecision, bool) {
		ctx := withPolicyEntryOutcome(context.Background(), rt, testOrg, outcome)
		decisions, _, denied := rt.evaluate(ctx, testOrg, q, &pipeline.Payload{Kind: pipeline.KindRequest, Endpoint: q.endpoint, Body: []byte(marker)})
		return decisions, denied
	}
	chatDecisions, chatDenied := runEval(queries[0].q, "chat-marker")
	if !chatDenied || len(chatDecisions) != 1 || chatDecisions[0].PolicyID != "chat-any" {
		t.Fatalf("chat selector = (%+v %v), want a chat-any deny", chatDecisions, chatDenied)
	}
	msgDecisions, msgDenied := runEval(queries[1].q, "msg-marker")
	if !msgDenied || len(msgDecisions) != 1 || msgDecisions[0].PolicyID != "msg-team" {
		t.Fatalf("messages selector = (%+v %v), want a msg-team deny", msgDecisions, msgDenied)
	}
	if d, denied := runEval(queries[2].q, "msg-marker"); denied || len(d) != 0 {
		t.Fatalf("wrong-key request = (%+v %v), want untouched", d, denied)
	}
}

// TestPolicyRuntime_NoCrossOrgCacheLeak proves the per-org cache never serves
// one org's plans to another: an org with no policies gets an empty entry and
// untouched requests while org A's deny keeps working.
func TestPolicyRuntime_NoCrossOrgCacheLeak(t *testing.T) {
	const orgB = "org-2"
	base := newFakePolicyStore()
	base.add(testOrg, adminstore.PolicyPipeline{ID: "a-only", OrgID: testOrg, Name: "a-only", Enabled: true, CurrentVersion: 1},
		map[int]string{1: denyAllYAML("a-only", "a-marker")}, []adminstore.PolicyAttachment{chatAttachment(1)})
	versions := &fakeOrgPolicyVersions{versions: map[string]int64{testOrg: 1, orgB: 1}}
	rt := newTestRuntime(t, base, versions, PolicyModeEnforce)

	orgA := rt.entry(context.Background(), testOrg)
	if orgA == nil || len(orgA.plans) != 1 {
		t.Fatalf("org A entry = %+v, want its single plan", orgA)
	}
	orgBEntry := rt.entry(context.Background(), orgB)
	if orgBEntry == nil || len(orgBEntry.plans) != 0 {
		t.Fatalf("org B entry = %+v, want an empty plan set of its own", orgBEntry)
	}
	if orgBEntry == orgA {
		t.Fatal("distinct orgs must never share a cache entry")
	}

	// A deniable payload stays untouched under org B but denies under org A.
	payload := func() *pipeline.Payload {
		return &pipeline.Payload{Kind: pipeline.KindRequest, Endpoint: "chat", Body: []byte("a-marker")}
	}
	q := policyQuery{endpoint: "chat", hook: pipeline.HookPreUpstream, model: "m"}
	ctxA := withPolicyEntryOutcome(context.Background(), rt, testOrg, policyEntryOutcome{entry: orgA})
	decisionsA, _, deniedA := rt.evaluate(ctxA, testOrg, q, payload())
	if !deniedA || len(decisionsA) != 1 {
		t.Fatalf("org A evaluate = (%+v %v), want its own deny", decisionsA, deniedA)
	}
	ctxB := withPolicyEntryOutcome(context.Background(), rt, orgB, policyEntryOutcome{entry: orgBEntry})
	decisionsB, _, deniedB := rt.evaluate(ctxB, orgB, q, payload())
	if deniedB || len(decisionsB) != 0 {
		t.Fatalf("org B evaluate = (%+v %v), want no decisions and no carry-over", decisionsB, deniedB)
	}

	// A store-level activation for org A never appears in org B's entry.
	base.mu.Lock()
	base.policies[testOrg][0].CurrentVersion = 2
	base.versions[testOrg]["a-only"][2] = denyAllYAML("a-only", "a2-marker")
	base.mu.Unlock()
	versions.bump(testOrg)
	now := time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC)
	rt.now = func() time.Time { return now }
	_ = now.Add(policyCacheTTL + time.Nanosecond)
	orgA2 := rt.entryWithOutcome(context.Background(), testOrg)
	if orgA2.loadErr != nil || orgA2.entry == nil || orgA2.entry == orgA {
		t.Fatalf("org A refresh = %+v, want the activated revision", orgA2)
	}
	if got := rt.entry(context.Background(), orgB); got != orgBEntry || len(got.plans) != 0 {
		t.Fatalf("org B entry after org A activation = %+v, want the same empty entry", got)
	}
}
