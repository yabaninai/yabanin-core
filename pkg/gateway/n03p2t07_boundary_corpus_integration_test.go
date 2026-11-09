//go:build integration

package cli

// N03-P02-T07 boundary corpus: regression pins for the edges of
// "Enforcement на exact semantic replay" that the packet's earlier legs do
// not cover. The card acceptance ("Warm cache после ужесточения policy не
// отдаёт запрещённый ответ") and its negative ("Cache чужой org или старой
// policy не даёт bypass") are pinned end-to-end by T01/T06 on real plumbing;
// this corpus walks the BOUNDARIES of those guarantees:
//
//	loosen direction      — disabling a policy through the real control plane
//	                        is a regime change too: entries from every earlier
//	                        regime degrade, none resurrect (the real-control-
//	                        plane analog of T06's scripted rollback binding);
//	hook scope vs regime  — a stream-stage-only tighten changes the org's
//	                        whole cache identity, not just the tightened hook:
//	                        warm json entries degrade as well (identity is
//	                        org-regime-wide; hook scope governs enforcement
//	                        only — T02 pinned the enforcement side);
//	version-key loss      — deleting the org's Redis version key (the (0,nil)
//	                        missing-key contract) must not roll enforcement
//	                        back to a pre-tighten snapshot: the deny reloads
//	                        from the store and the system self-heals;
//	privacy-off boundary  — the production disable sequence (settings row +
//	                        InvalidateOrgAll flush) stops serving the org's
//	                        OWN warm entry, an org born off neither reads nor
//	                        writes, and NEITHER ticks the enforcement-off
//	                        counter (privacy-off is not enforcement-off — two
//	                        different "off" concepts the observability must
//	                        not conflate); the neighbor org is untouched;
//	enforcement-off × streams — a nil-runtime off window gates the DETACHED
//	                        stream writes too (T06 pinned the json path), and
//	                        a live stream may relay what post_upstream would
//	                        deny, but its re-warmed entry can never REPLAY
//	                        past the restored control (live relay is not a
//	                        replay license);
//	cache-mode isolation  — an exact-mode org is never served through the
//	                        semantic layer even when its own pgvector row
//	                        would match (mode boundary; the semantic-mode
//	                        control proves the stand would serve semantic).
//
// Environment parity with T06: migrated Postgres + Redis containers, the
// real adminstore with the real Redis policy version bumper, the real
// PolicyRuntime, the production auth middleware, and the real cache service
// with the production regime-resolver wiring. The upstream model stand is
// synthetic (benign prompts get clean content, everything else marker
// content); only disposable Docker stands are touched and the active
// OpenCode stand is never contacted.

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/cache"
)

// n03p2t07AbsentToken is a deny word that matches no upstream answer: the
// hook-scoped tighten must change the org's cache identity through its mere
// existence (compile + version bump), without any enforcement firing — that
// keeps the test's assertions on the identity boundary alone.
const n03p2t07AbsentToken = "n03t07-absent-token-314"

// n03p2t07NewOrg creates a synthetic org with an explicit cache mode (exact
// for the replay-path pins, semantic for the mode-boundary control).
func n03p2t07NewOrg(t *testing.T, env *n03p2t06ITEnv, suffix, cacheMode string) n03p2t06Org {
	t.Helper()
	org := n03p2t06NewOrg(t, env, suffix)
	_, err := env.pg.Exec(context.Background(),
		`UPDATE organizations SET cache_mode = $2 WHERE id::text = $1`, org.id, cacheMode)
	require.NoError(t, err, "set org cache mode to %s", cacheMode)
	return org
}

// n03p2t07AttachPolicy runs the real control-plane mutation (create +
// publish + attach + enable) for one org and returns the pipeline id so a
// later leg can disable or tighten it again. The version bump is asserted so
// a later degradation cannot be attributed to a TTL fallback.
func n03p2t07AttachPolicy(t *testing.T, env *n03p2t06ITEnv, org n03p2t06Org, name, yaml string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	before, err := env.versions.GetPolicyVersion(ctx, org.id)
	require.NoError(t, err, "read policy version before attach")
	pipeline, version, err := env.store.CreatePolicy(ctx, org.id, name, yaml, "n03p2t07-test-sha", "n03p2t07-suite")
	require.NoError(t, err, "create policy %s", name)
	_, err = env.store.SetActivePolicyVersion(ctx, org.id, pipeline.ID, version.Version)
	require.NoError(t, err, "publish draft version as active")
	_, err = env.store.SetPolicyAttachments(ctx, org.id, pipeline.ID,
		[]adminstore.PolicyAttachment{chatAttachment(10)})
	require.NoError(t, err, "attach policy to chat")
	_, err = env.store.UpdatePolicy(ctx, org.id, pipeline.ID, true)
	require.NoError(t, err, "enable policy")
	after, err := env.versions.GetPolicyVersion(ctx, org.id)
	require.NoError(t, err, "read policy version after attach")
	assert.Greater(t, after, before, "the real bumper must publish the version key on attach")
	return pipeline.ID
}

// n03p2t07DisablePolicy flips an existing policy to disabled through the
// real store — the production "loosen" mutation — and asserts the bump.
func n03p2t07DisablePolicy(t *testing.T, env *n03p2t06ITEnv, org n03p2t06Org, pipelineID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	before, err := env.versions.GetPolicyVersion(ctx, org.id)
	require.NoError(t, err, "read policy version before disable")
	_, err = env.store.UpdatePolicy(ctx, org.id, pipelineID, false)
	require.NoError(t, err, "disable policy (the real loosen mutation)")
	after, err := env.versions.GetPolicyVersion(ctx, org.id)
	require.NoError(t, err, "read policy version after disable")
	assert.Greater(t, after, before, "the real bumper must publish the version key on disable")
}

// n03p2t07DelVersionKey deletes the org's policy version key from the real
// Redis — the production shape of key expiry or a flushed cache, which the
// version store reads as version 0 (not an error).
func n03p2t07DelVersionKey(t *testing.T, env *n03p2t06ITEnv, org n03p2t06Org) {
	t.Helper()
	deleted, err := env.rdb.Del(context.Background(), adminstore.PolicyVersionKeyPrefix+org.id).Result()
	require.NoError(t, err, "delete the org policy version key")
	assert.Equal(t, int64(1), deleted, "the version key must exist before the deletion")
}

// n03p2t07WaitCounterDelta polls the enforcement-off skipped counter until it
// advanced by at least want since before — the detached stream writes land
// asynchronously, so the gated write ticks arrive after the response.
func n03p2t07WaitCounterDelta(t *testing.T, before, want float64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if testutil.ToFloat64(cache.CacheEnforcementOffSkippedTotal)-before >= want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("enforcement-off counter did not advance by %.0f within 10s (delta %.0f)",
		want, testutil.ToFloat64(cache.CacheEnforcementOffSkippedTotal)-before)
}

// TestN03P2T07_Boundary_LoosenDisable_NoResurrectionOnRealControlPlane pins
// the loosen direction on the REAL control plane: disabling the deny policy
// is a control-plane mutation with a real version bump, so it is a regime
// change like any tighten. The pre-tighten warm entry (stored under the
// no-policy regime) must NOT resurrect when the policy disappears — the
// store version inside the fingerprint digest makes the loosened regime a
// new one — and the tighten-era entry degrades too; both prompts refetch and
// re-warm under the loosened regime. T06 proved the binding contract with a
// scripted resolver (the control plane cannot return to a previous exact
// fingerprint); this pin walks the production loosen op itself.
func TestN03P2T07_Boundary_LoosenDisable_NoResurrectionOnRealControlPlane(t *testing.T) {
	env := n03p2t06ITSetup(t)
	orgA := n03p2t07NewOrg(t, env, "loosen", "exact")
	events := captureEvents(t)
	q1 := n03p2t06Chat("n03t07 loosen marker please")
	q2 := n03p2t06Chat("a benign loosen question")

	// Pre-tighten regime: warm and replay the marker answer.
	warm := n03p2t06Post(t, env, orgA, q1)
	require.Equal(t, http.StatusOK, warm.status, warm.body)
	assert.Contains(t, warm.body, n03p2t06Leak)
	require.Equal(t, int64(1), env.upstream.calls.Load())
	hit := n03p2t06Post(t, env, orgA, q1)
	require.Equal(t, http.StatusOK, hit.status, hit.body)
	assert.Equal(t, "EXACT", hit.header.Get("X-Cache"))
	require.Equal(t, int64(1), env.upstream.calls.Load())

	// Tighten: the pre-tighten entry degrades to a live denial.
	pipelineID := n03p2t07AttachPolicy(t, env, orgA, "n03p2t07-deny-leak",
		r011PostUpstreamYAML(r011DenyWordStep(n03p2t06Leak)))
	denied := n03p2t06Post(t, env, orgA, q1)
	require.Equal(t, http.StatusBadRequest, denied.status, denied.body)
	assert.Contains(t, denied.body, "content_policy_violation")
	assert.NotContains(t, denied.body, n03p2t06Leak)
	require.Equal(t, int64(2), env.upstream.calls.Load(), "the tighten degraded the warm entry to a refetched denial")

	// Warm a clean entry UNDER the tightened regime.
	fresh := n03p2t06Post(t, env, orgA, q2)
	require.Equal(t, http.StatusOK, fresh.status, fresh.body)
	require.Equal(t, int64(3), env.upstream.calls.Load())
	tightHit := n03p2t06Post(t, env, orgA, q2)
	require.Equal(t, http.StatusOK, tightHit.status, tightHit.body)
	assert.Equal(t, "EXACT", tightHit.header.Get("X-Cache"))
	require.Equal(t, int64(3), env.upstream.calls.Load())

	// Loosen: disable the policy through the real store (real bump).
	n03p2t07DisablePolicy(t, env, orgA, pipelineID)

	// The tighten-era entry degrades: fresh clean answer serves and re-warms.
	l1 := n03p2t06Post(t, env, orgA, q2)
	require.Equal(t, http.StatusOK, l1.status, l1.body)
	assert.Empty(t, l1.header.Get("X-Cache"), "the tighten-era entry must not serve under the loosened regime")
	assert.Contains(t, l1.body, "perfectly clean")
	require.Equal(t, int64(4), env.upstream.calls.Load(), "the loosen forced a real refetch, not a stale serve")
	l2 := n03p2t06Post(t, env, orgA, q2)
	require.Equal(t, http.StatusOK, l2.status, l2.body)
	assert.Equal(t, "EXACT", l2.header.Get("X-Cache"), "re-warmed under the loosened regime")
	require.Equal(t, int64(4), env.upstream.calls.Load())

	// The PRE-tighten entry must not resurrect: the loosened regime is a new
	// fingerprint (store version moved), so the old no-policy entry degrades
	// to a miss and the fresh marker answer serves under the org's own
	// disabled control — admin intent, not a bypass.
	l3 := n03p2t06Post(t, env, orgA, q1)
	require.Equal(t, http.StatusOK, l3.status, l3.body)
	assert.Empty(t, l3.header.Get("X-Cache"),
		"the pre-tighten entry must not resurrect after the disable — a real refetch must happen")
	assert.Contains(t, l3.body, n03p2t06Leak,
		"the org disabled its own policy, so the fresh answer serves unfiltered")
	require.Equal(t, int64(5), env.upstream.calls.Load())
	l4 := n03p2t06Post(t, env, orgA, q1)
	require.Equal(t, http.StatusOK, l4.status, l4.body)
	assert.Equal(t, "EXACT", l4.header.Get("X-Cache"), "re-warmed under the loosened regime")
	require.Equal(t, int64(5), env.upstream.calls.Load())

	// Audit trail: exactly the tighten denial failed; all loosen legs completed.
	evs := r011ITWaitEvents(t, events, 9)
	failed, completed := 0, 0
	for _, ev := range evs {
		require.Equal(t, orgA.id, ev.OrgID)
		switch ev.EventType {
		case "request.failed":
			failed++
			assert.Equal(t, int64(http.StatusBadRequest), ev.StatusCode)
			assert.Contains(t, ev.Policy, `"verdict":"deny"`)
		case "request.completed":
			completed++
		}
	}
	assert.Equal(t, 1, failed, "only the tightened-regime denial may fail")
	assert.Equal(t, 8, completed, "warm, hit and all six loosen legs must complete")
}

// TestN03P2T07_Boundary_HookScopedTighten_OrgWideRegimeForCacheIdentity pins
// the granularity boundary between enforcement scope and cache identity: a
// stream-stage-only policy (stream_final, deny word that matches nothing)
// changes the org's compiled snapshot, so the WHOLE cache identity moves —
// warm json entries degrade to misses exactly like warm stream entries —
// while the json enforcement surface itself is untouched (no post_upstream
// hook exists, so the fresh answer serves verbatim). T02 pinned that a warm
// replay must pass the CURRENT stream hooks; this pin documents that the
// tighten is org-regime-wide, not hook-scoped: a reader expecting
// hook-scoped invalidation sees the intended coarse behavior here.
func TestN03P2T07_Boundary_HookScopedTighten_OrgWideRegimeForCacheIdentity(t *testing.T) {
	env := n03p2t06ITSetup(t)
	orgA := n03p2t07NewOrg(t, env, "hookscope", "exact")
	events := captureEvents(t)
	q1 := n03p2t06Chat("n03t07 hookscope marker please")
	s1 := n03p2t06ChatStream("n03t07 hookscope marker please")

	// Warm both shapes: json and its own stream-shaped entry.
	warm := n03p2t06Post(t, env, orgA, q1)
	require.Equal(t, http.StatusOK, warm.status, warm.body)
	require.Equal(t, int64(1), env.upstream.calls.Load())
	hit := n03p2t06Post(t, env, orgA, q1)
	require.Equal(t, http.StatusOK, hit.status, hit.body)
	assert.Equal(t, "EXACT", hit.header.Get("X-Cache"))
	require.Equal(t, int64(1), env.upstream.calls.Load())

	_, _, writeBase := env.cacheSvc.WriterStats()
	streamWarm := n03p2t06Post(t, env, orgA, s1)
	require.Equal(t, http.StatusOK, streamWarm.status, streamWarm.body)
	require.Equal(t, int64(2), env.upstream.calls.Load())
	n03p2t06WaitStreamWrite(t, env, writeBase)
	sse := n03p2t06Post(t, env, orgA, s1)
	require.Equal(t, http.StatusOK, sse.status, sse.body)
	assert.Equal(t, "EXACT", sse.header.Get("X-Cache"))
	assert.True(t, strings.HasSuffix(sse.body, "data: [DONE]\n\n"))
	require.Equal(t, int64(2), env.upstream.calls.Load())

	// Tighten with a stream-only policy whose deny word never matches: the
	// mutation is real (compiled plan + version bump) but no enforcement
	// ever fires, isolating the identity boundary.
	n03p2t07AttachPolicy(t, env, orgA, "n03p2t07-stream-only",
		n03p02StreamYAML("stream_final", r011DenyWordStep(n03p2t07AbsentToken)))

	// The warm json entry degrades even though post_upstream is untouched.
	j1 := n03p2t06Post(t, env, orgA, q1)
	require.Equal(t, http.StatusOK, j1.status, j1.body)
	assert.Empty(t, j1.header.Get("X-Cache"),
		"a stream-only tighten moves the org's whole cache identity — the json entry must degrade too")
	assert.Contains(t, j1.body, n03p2t06Leak,
		"with no post_upstream hook the fresh answer serves verbatim")
	require.Equal(t, int64(3), env.upstream.calls.Load())
	j2 := n03p2t06Post(t, env, orgA, q1)
	require.Equal(t, http.StatusOK, j2.status, j2.body)
	assert.Equal(t, "EXACT", j2.header.Get("X-Cache"), "re-warmed under the new regime")
	require.Equal(t, int64(3), env.upstream.calls.Load())

	// The warm stream entry degrades identically; the fresh relay passes the
	// (never-matching) stream hook. Stream writes are detached, so the
	// re-warm must land before the replay is attempted.
	_, _, rebase := env.cacheSvc.WriterStats()
	s1r := n03p2t06Post(t, env, orgA, s1)
	require.Equal(t, http.StatusOK, s1r.status, s1r.body)
	assert.Empty(t, s1r.header.Get("X-Cache"))
	assert.NotContains(t, s1r.body, "content_policy_violation",
		"the deny word never matches — no enforcement may fire on the fresh relay")
	assert.True(t, strings.HasSuffix(s1r.body, "data: [DONE]\n\n"))
	require.Equal(t, int64(4), env.upstream.calls.Load())
	n03p2t06WaitStreamWrite(t, env, rebase)
	s2 := n03p2t06Post(t, env, orgA, s1)
	require.Equal(t, http.StatusOK, s2.status, s2.body)
	assert.Equal(t, "EXACT", s2.header.Get("X-Cache"), "re-warmed under the new regime")
	require.Equal(t, int64(4), env.upstream.calls.Load())

	// Everything completes: the corpus pins identity movement, not denials.
	evs := r011ITWaitEvents(t, events, 8)
	for _, ev := range evs {
		require.Equal(t, orgA.id, ev.OrgID)
		assert.Equal(t, "request.completed", ev.EventType,
			"a never-matching tighten must not produce any denial")
	}
}

// TestN03P2T07_Boundary_VersionKeyLoss_SelfHealsNoRollbackBypass pins the
// stale-policy boundary at the version-key seam: the policystore contract
// reads a MISSING version key as version 0 (not an error — fresh org,
// expired key, flushed cache). Deleting the key after a tighten must not
// roll the runtime back to the pre-tighten snapshot: the probe sees 0 ≠ the
// cached version, the snapshot reloads from the store (the deny is still
// enabled there) and enforcement still denies. The fingerprint moves with
// the version, so tighten-era warm entries degrade once and the system
// self-heals by re-warming under the v=0 regime.
func TestN03P2T07_Boundary_VersionKeyLoss_SelfHealsNoRollbackBypass(t *testing.T) {
	env := n03p2t06ITSetup(t)
	orgA := n03p2t07NewOrg(t, env, "verloss", "exact")
	events := captureEvents(t)
	q1 := n03p2t06Chat("n03t07 verloss marker please")
	q2 := n03p2t06Chat("a benign verloss question")

	// Tight regime from the start: the deny is attached before any warming.
	n03p2t07AttachPolicy(t, env, orgA, "n03p2t07-deny-leak",
		r011PostUpstreamYAML(r011DenyWordStep(n03p2t06Leak)))

	// Clean prompt warms and replays under the tight regime.
	fresh := n03p2t06Post(t, env, orgA, q2)
	require.Equal(t, http.StatusOK, fresh.status, fresh.body)
	require.Equal(t, int64(1), env.upstream.calls.Load())
	tightHit := n03p2t06Post(t, env, orgA, q2)
	require.Equal(t, http.StatusOK, tightHit.status, tightHit.body)
	assert.Equal(t, "EXACT", tightHit.header.Get("X-Cache"))
	require.Equal(t, int64(1), env.upstream.calls.Load())

	// The marker prompt is denied live (miss → refetch → deny).
	d1 := n03p2t06Post(t, env, orgA, q1)
	require.Equal(t, http.StatusBadRequest, d1.status, d1.body)
	assert.Contains(t, d1.body, "content_policy_violation")
	assert.NotContains(t, d1.body, n03p2t06Leak)
	require.Equal(t, int64(2), env.upstream.calls.Load())

	// Lose the version key (real Redis DEL — key expiry / flush shape).
	n03p2t07DelVersionKey(t, env, orgA)

	// No rollback: the marker prompt is still denied — the snapshot reloaded
	// from the store, where the deny is still enabled.
	d2 := n03p2t06Post(t, env, orgA, q1)
	require.Equal(t, http.StatusBadRequest, d2.status, d2.body)
	assert.Contains(t, d2.body, "content_policy_violation")
	assert.NotContains(t, d2.body, n03p2t06Leak,
		"a lost version key must not roll enforcement back to the pre-tighten snapshot")
	require.Equal(t, int64(3), env.upstream.calls.Load(),
		"the denial still answers from the live control, not from any resurrected entry")

	// The fingerprint moved with the version (v→0), so the tighten-era entry
	// degrades once and re-warms under the v=0 regime — self-healing.
	k1 := n03p2t06Post(t, env, orgA, q2)
	require.Equal(t, http.StatusOK, k1.status, k1.body)
	assert.Empty(t, k1.header.Get("X-Cache"), "the v=<nano> entry must degrade after the key loss")
	assert.Contains(t, k1.body, "perfectly clean")
	require.Equal(t, int64(4), env.upstream.calls.Load())
	k2 := n03p2t06Post(t, env, orgA, q2)
	require.Equal(t, http.StatusOK, k2.status, k2.body)
	assert.Equal(t, "EXACT", k2.header.Get("X-Cache"), "self-healed: re-warmed under the v=0 regime")
	require.Equal(t, int64(4), env.upstream.calls.Load())

	// Audit trail: the two marker denials failed, everything else completed.
	evs := r011ITWaitEvents(t, events, 6)
	failed, completed := 0, 0
	for _, ev := range evs {
		require.Equal(t, orgA.id, ev.OrgID)
		switch ev.EventType {
		case "request.failed":
			failed++
			assert.Equal(t, int64(http.StatusBadRequest), ev.StatusCode)
			assert.Contains(t, ev.Policy, `"verdict":"deny"`)
		case "request.completed":
			completed++
		}
	}
	assert.Equal(t, 2, failed, "both marker denials (before and after the key loss) must be observable")
	assert.Equal(t, 4, completed)
}

// TestN03P2T07_Boundary_CacheModeOff_GatewayIsolationAndCounterDistinction
// pins the privacy-off boundary at the gateway on real plumbing, along the
// production mutation contract (UpdateOrgCacheSettings + InvalidateOrgAll —
// services/admin/handlers/cache_handlers.go):
//   - the control-plane disable sequence kills the org's own warm entries
//     immediately (the disable flush), so the next request misses and
//     refetches. Within the gateway's per-org policy-memo TTL (60s) a
//     refetched answer may be re-written — documented bounded staleness;
//     the flush is what makes existing entries die now;
//   - an org born off (its policy memo loads PrivacyDisabled on first
//     touch) gets no read and no write on the gateway path end-to-end;
//   - NEITHER axis ticks CacheEnforcementOffSkippedTotal: privacy-off
//     short-circuits before the regime gate (LookupWithResult/Write), and
//     the observability must not conflate the two "off" concepts;
//   - the neighbor org's warm entry is untouched throughout.
//
// (The cache-level no-read/no-write pin lives in
// pkg/cache/off_regression_test.go; this pin walks the consumer path
// end-to-end.)
func TestN03P2T07_Boundary_CacheModeOff_GatewayIsolationAndCounterDistinction(t *testing.T) {
	env := n03p2t06ITSetup(t)
	orgA := n03p2t07NewOrg(t, env, "offctl", "exact")
	orgFlip := n03p2t07NewOrg(t, env, "offflip", "exact")
	orgBornOff := n03p2t07NewOrg(t, env, "offborn", "off")
	events := captureEvents(t)
	q1 := n03p2t06Chat("n03t07 offmode marker please")

	// Both exact orgs warm their own entry for the same prompt.
	warmA := n03p2t06Post(t, env, orgA, q1)
	require.Equal(t, http.StatusOK, warmA.status, warmA.body)
	require.Equal(t, int64(1), env.upstream.calls.Load())
	hitA := n03p2t06Post(t, env, orgA, q1)
	require.Equal(t, http.StatusOK, hitA.status, hitA.body)
	assert.Equal(t, "EXACT", hitA.header.Get("X-Cache"))
	require.Equal(t, int64(1), env.upstream.calls.Load())

	warmFlip := n03p2t06Post(t, env, orgFlip, q1)
	require.Equal(t, http.StatusOK, warmFlip.status, warmFlip.body)
	require.Equal(t, int64(2), env.upstream.calls.Load(), "org isolation: each org warms its own entry")
	hitFlip := n03p2t06Post(t, env, orgFlip, q1)
	require.Equal(t, http.StatusOK, hitFlip.status, hitFlip.body)
	assert.Equal(t, "EXACT", hitFlip.header.Get("X-Cache"))
	require.Equal(t, int64(2), env.upstream.calls.Load())

	// The counter baseline is taken BEFORE any off-org traffic so the
	// off-window requests are measured cleanly.
	counterBefore := testutil.ToFloat64(cache.CacheEnforcementOffSkippedTotal)

	// The org turns its cache off through the production mutation sequence:
	// the settings row update plus the disable flush the admin handler runs.
	require.NoError(t, env.store.UpdateOrgCacheSettings(context.Background(), orgFlip.id, false, "off"),
		"flip orgFlip off through the production settings mutation")
	inv := cache.NewInvalidator(cache.NewRedisStore(env.rdb, 24*time.Hour), cache.NewStore(env.pg), env.rdb)
	require.NoError(t, inv.InvalidateOrgAll(context.Background(), orgFlip.id),
		"the disable flush removes the org's own warm entries")

	// The flipped org's own warm entry stops serving, and a real refetch
	// happens instead.
	o1 := n03p2t06Post(t, env, orgFlip, q1)
	require.Equal(t, http.StatusOK, o1.status, o1.body)
	assert.Empty(t, o1.header.Get("X-Cache"),
		"the disable flush must stop serving the org's own warm entry")
	require.Equal(t, int64(3), env.upstream.calls.Load(), "a real refetch happens instead")

	// The born-off org gets no read and no write: its memo loads
	// PrivacyDisabled on first touch, so every request is a full relay.
	b1 := n03p2t06Post(t, env, orgBornOff, q1)
	require.Equal(t, http.StatusOK, b1.status, b1.body)
	assert.Empty(t, b1.header.Get("X-Cache"), "a born-off org never reads")
	require.Equal(t, int64(4), env.upstream.calls.Load())
	b2 := n03p2t06Post(t, env, orgBornOff, q1)
	require.Equal(t, http.StatusOK, b2.status, b2.body)
	assert.Empty(t, b2.header.Get("X-Cache"))
	require.Equal(t, int64(5), env.upstream.calls.Load(),
		"a born-off org never writes — the repeat is another full relay")

	// Privacy-off is not enforcement-off: neither the flip window nor the
	// born-off traffic may tick the enforcement-off counter.
	offDelta := testutil.ToFloat64(cache.CacheEnforcementOffSkippedTotal) - counterBefore
	assert.InDelta(t, float64(0), offDelta, 0.001,
		"privacy-disabled traffic short-circuits before the regime gate — the enforcement-off counter must not tick")

	// The neighbor org is untouched by orgFlip's switch.
	hitA2 := n03p2t06Post(t, env, orgA, q1)
	require.Equal(t, http.StatusOK, hitA2.status, hitA2.body)
	assert.Equal(t, "EXACT", hitA2.header.Get("X-Cache"),
		"one org's privacy switch must not degrade another org's warm entry")
	require.Equal(t, int64(5), env.upstream.calls.Load())

	// All eight requests complete.
	evs := r011ITWaitEvents(t, events, 8)
	for _, ev := range evs {
		assert.Equal(t, "request.completed", ev.EventType)
	}
}

// TestN03P2T07_Boundary_EnforcementOffStreamWrites_NoStaleReplayAfterRestore
// pins the enforcement-off boundary on the streaming surface (T06 pinned the
// json path): during a nil-runtime off window — the production off-shape —
// live streams relay unfiltered (documented fail-open) and the DETACHED
// stream cache writes are regime-gated like every other operation, so no
// stream entry lands. After defense is restored: the governed warm entry
// from before the window still replays (the window neither evicted nor
// bypassed it), the off-window stream prompt misses and refetches, and the
// re-warmed stream entry — whose document carries marker content, because a
// live stream never passes post_upstream — is DENIED on its SSE replay: a
// live relay is not a replay license. The denial is deterministic (the
// same-regime entry stays warm and denies again without a refetch).
func TestN03P2T07_Boundary_EnforcementOffStreamWrites_NoStaleReplayAfterRestore(t *testing.T) {
	env := n03p2t06ITSetup(t)
	orgA := n03p2t07NewOrg(t, env, "offstream", "exact")
	events := captureEvents(t)
	q2 := n03p2t06Chat("a benign offstream question")
	s1 := n03p2t06ChatStream("n03t07 offstream marker please")

	// Tight regime from the start; warm a clean json entry under it.
	n03p2t07AttachPolicy(t, env, orgA, "n03p2t07-deny-leak",
		r011PostUpstreamYAML(r011DenyWordStep(n03p2t06Leak)))
	fresh := n03p2t06Post(t, env, orgA, q2)
	require.Equal(t, http.StatusOK, fresh.status, fresh.body)
	require.Equal(t, int64(1), env.upstream.calls.Load())
	tightHit := n03p2t06Post(t, env, orgA, q2)
	require.Equal(t, http.StatusOK, tightHit.status, tightHit.body)
	assert.Equal(t, "EXACT", tightHit.header.Get("X-Cache"))
	require.Equal(t, int64(1), env.upstream.calls.Load())

	// Enforcement-off window (production off-shape: the nil runtime).
	counterBefore := testutil.ToFloat64(cache.CacheEnforcementOffSkippedTotal)
	env.gw.policyRuntime = nil
	o1 := n03p2t06Post(t, env, orgA, s1)
	require.Equal(t, http.StatusOK, o1.status, o1.body)
	assert.Empty(t, o1.header.Get("X-Cache"), "enforcement-off gates the lookup — no served hit")
	assert.Contains(t, o1.body, n03p2t06Leak,
		"mode off disables the control itself (documented fail-open), so the live stream relays unfiltered")
	require.Equal(t, int64(2), env.upstream.calls.Load())
	o2 := n03p2t06Post(t, env, orgA, s1)
	require.Equal(t, http.StatusOK, o2.status, o2.body)
	assert.Empty(t, o2.header.Get("X-Cache"))
	require.Equal(t, int64(3), env.upstream.calls.Load(),
		"nothing may be cached while enforcement is off — the replay refetches")
	// Two gated requests tick the counter +2 each: one gated lookup plus one
	// gated DETACHED stream write per request. The writes land asynchronously.
	n03p2t07WaitCounterDelta(t, counterBefore, 4)
	env.gw.policyRuntime = env.enforceRT

	// Defense restored: the pre-window governed entry still replays — the
	// off window neither evicted it nor served around it.
	r0 := n03p2t06Post(t, env, orgA, q2)
	require.Equal(t, http.StatusOK, r0.status, r0.body)
	assert.Equal(t, "EXACT", r0.header.Get("X-Cache"),
		"the off window must not have evicted or bypassed the governed warm entry")
	require.Equal(t, int64(3), env.upstream.calls.Load())

	// The off-window stream prompt was never stored: a fresh live stream is
	// relayed (post_upstream does not run on live streams), and its entry
	// lands under the restored tight regime.
	_, _, writeBase := env.cacheSvc.WriterStats()
	r1 := n03p2t06Post(t, env, orgA, s1)
	require.Equal(t, http.StatusOK, r1.status, r1.body)
	assert.Empty(t, r1.header.Get("X-Cache"),
		"the off window stored nothing — the restored lookup misses and refetches")
	assert.Contains(t, r1.body, n03p2t06Leak)
	require.Equal(t, int64(4), env.upstream.calls.Load())
	n03p2t06WaitStreamWrite(t, env, writeBase)

	// The re-warmed entry replays past NO control: its document carries the
	// marker (live streams skip post_upstream), but a replay is governed —
	// the SSE replay is denied before any frame.
	r2 := n03p2t06Post(t, env, orgA, s1)
	require.Equal(t, http.StatusBadRequest, r2.status, r2.body)
	assert.Contains(t, r2.body, "content_policy_violation")
	assert.NotContains(t, r2.body, n03p2t06Leak,
		"a live relay is not a replay license — the re-warmed entry is denied on replay")
	assert.NotContains(t, r2.body, "data:", "denied content must not be framed as SSE")

	// The same-regime warm entry stays: the denial repeats deterministically
	// without a refetch.
	r3 := n03p2t06Post(t, env, orgA, s1)
	require.Equal(t, http.StatusBadRequest, r3.status, r3.body)
	assert.Contains(t, r3.body, "content_policy_violation")
	require.Equal(t, int64(4), env.upstream.calls.Load(),
		"the denial answers from the warm entry's governance — no refetch")

	// Audit trail: exactly the two SSE replay denials failed.
	evs := r011ITWaitEvents(t, events, 8)
	failed, completed := 0, 0
	for _, ev := range evs {
		require.Equal(t, orgA.id, ev.OrgID)
		switch ev.EventType {
		case "request.failed":
			failed++
			assert.Equal(t, int64(http.StatusBadRequest), ev.StatusCode)
			assert.Contains(t, ev.Policy, `"verdict":"deny"`)
		case "request.completed":
			completed++
		}
	}
	assert.Equal(t, 2, failed, "both SSE replay denials must be observable")
	assert.Equal(t, 6, completed)
}

// TestN03P2T07_Boundary_ExactModeOrg_NeverServedViaSemanticLayer pins the
// cache-mode isolation boundary on the lookup path: an exact-mode org with a
// warm entry must NOT be served a semantic match for a different prompt —
// even though its own pgvector row exists (every write feeds the semantic
// store regardless of mode) and the constant-embedding stand would match
// anything. The semantic-mode control org proves the stand really serves
// SEMANTIC hits when the org's mode allows, so the exact-org negative is not
// vacuous. (Mode=off's no-read/no-write is pinned separately above.)
func TestN03P2T07_Boundary_ExactModeOrg_NeverServedViaSemanticLayer(t *testing.T) {
	env := n03p2t06ITSetup(t)
	orgX := n03p2t07NewOrg(t, env, "exactmode", "exact")
	orgS := n03p2t07NewOrg(t, env, "semmode", "semantic")
	events := captureEvents(t)

	// The exact-mode org warms its entry; the write also lands in the
	// semantic store (mode only governs lookups, not where writes land).
	warmX := n03p2t06Post(t, env, orgX, n03p2t06Chat("n03t07 exactmode base prompt"))
	require.Equal(t, http.StatusOK, warmX.status, warmX.body)
	require.Equal(t, int64(1), env.upstream.calls.Load())
	hitX := n03p2t06Post(t, env, orgX, n03p2t06Chat("n03t07 exactmode base prompt"))
	require.Equal(t, http.StatusOK, hitX.status, hitX.body)
	assert.Equal(t, "EXACT", hitX.header.Get("X-Cache"))
	_, _, writeBase := env.cacheSvc.WriterStats()
	require.Equal(t, int64(1), env.upstream.calls.Load())

	// A different prompt would semantic-match the row — but the exact-mode
	// org must miss and refetch, never serve through the semantic layer.
	x3 := n03p2t06Post(t, env, orgX, n03p2t06Chat("n03t07 exactmode different prompt"))
	require.Equal(t, http.StatusOK, x3.status, x3.body)
	assert.Empty(t, x3.header.Get("X-Cache"),
		"an exact-mode org must never be served through the semantic layer")
	require.Equal(t, int64(2), env.upstream.calls.Load(), "the semantic match must degrade to a real refetch")

	// Control: the semantic-mode org warms its own entry and then IS served
	// a SEMANTIC hit for a different prompt — same stand, opposite verdict.
	warmS := n03p2t06Post(t, env, orgS, n03p2t06Chat("n03t07 semmode base prompt"))
	require.Equal(t, http.StatusOK, warmS.status, warmS.body)
	require.Equal(t, int64(3), env.upstream.calls.Load())
	n03p2t06WaitStreamWrite(t, env, writeBase)
	s3 := n03p2t06Post(t, env, orgS, n03p2t06Chat("n03t07 semmode different prompt"))
	require.Equal(t, http.StatusOK, s3.status, s3.body)
	assert.Equal(t, "SEMANTIC", s3.header.Get("X-Cache"),
		"the control proves the stand serves semantic hits when the org mode allows")
	require.Equal(t, int64(3), env.upstream.calls.Load())

	// All five requests complete.
	evs := r011ITWaitEvents(t, events, 5)
	for _, ev := range evs {
		assert.Equal(t, "request.completed", ev.EventType)
	}
}
