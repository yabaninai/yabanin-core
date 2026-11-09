package cli

// N08-P05-T09 [compatibility] — the credential pool over the OLD and the
// NEW configuration, walked through the real supported consumer (the
// serving chain of resolveUpstreamKey), with explicit rejection for the
// unsupported shapes:
//
//   - OLD wiring (the frozen W-BYOK-DB legacy posture): org credential
//     resolution is wired (probe + newest-first ResolveKey) while the pool
//     surface is absent (credPool == nil — the historical wiring shape).
//     Pinned: the org key authenticates, the event carries used_org_key
//     without a masked ref, a 401 writes NO quarantine feedback, and the
//     invalid key IS sent again (no rotation).
//   - NEW wiring: the same single-credential (old-shape) org authenticates
//     with the SAME plaintext under the pool (migration parity), the 401
//     feeds the quarantine, and the invalid key is NOT repeated (typed
//     fail-closed refusal).
//   - Unsupported downgrade: with every held credential quarantined, the
//     per-model upstream_api_key and the global key are NOT silently sent
//     to the org-registered endpoint (the W-PROV leak-hazard posture, I51's
//     reject-with-exact-reason) — while an org WITHOUT a held credential on
//     the same model shape keeps its correct per-model fall-through.
//
// The recovered-key-without-race acceptance rides the pinned T08 recovery
// corpora (credpool_recovery_test.go: staged lapse exit, late-feedback
// re-quarantine, reset arc) and is not re-pinned here. Companion surfaces:
// credpool_test.go (selector battery), credpool_byok_test.go (serve E2E),
// credpool_failure_test.go (fail-closed legs), credpool_boundary_test.go /
// credpool_regression_test.go (T07/T04). Deterministic; exercised under
// -race -shuffle.

import (
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/retry"
)

// legacyWiredGateway builds the OLD configuration: org credential resolution
// is enabled (the probe + the frozen newest-first ResolveKey surface over the
// same stub store) but the pool surface is absent — credPool == nil, the
// pre-pool wiring shape of gatewayWiring.
func legacyWiredGateway(t *testing.T, upstreamURL string, store *stubCredPoolStore, versions *stubOrgVersions) *gateway {
	t.Helper()
	gw := streamTestGateway(upstreamURL)
	gw.res = byokResolver(upstreamURL)
	gw.cfg.ZAICodingEnabled = true
	gw.cfg.ZAICodingBaseURL = upstreamURL
	gw.retryPolicy = retry.Policy{MaxAttempts: 1}
	gw.orgCreds = store
	gw.orgCredsVersions = versions
	gw.orgCredsProbe = newOrgCredsProbe(store, versions, orgCredsProbeTTL, testLogger())
	gw.credPool = nil
	return gw
}

// TestCredPoolCompat_OldWiringLegacyServeAndNewWiringParity: one org, ONE
// credential (the old configuration shape) — under the old wiring the legacy
// path serves it with no rotation feedback and repeats the invalid key;
// under the new wiring the same org authenticates with the same plaintext
// (migration parity) and the invalid key is quarantined, not repeated.
func TestCredPoolCompat_OldWiringLegacyServeAndNewWiringParity(t *testing.T) {
	up := newPoolUpstream(t, "", false)
	versions := &stubOrgVersions{versions: map[string]int64{}}
	singleCred := func() *stubCredPoolStore {
		return newStubCredPoolStore(stubPoolCred{
			id: "aaaaaaaa-1111-4111-8111-000000000001", last4: "0001",
			key: "sk-pool-key-00000001", enabled: true, version: 1,
		})
	}

	var mu sync.Mutex
	var events []*eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	})
	defer restore()
	// lastOKEvent returns the latest completion event (HTTP 200): failed
	// hops publish their own error events, which this matrix ignores.
	lastOKEvent := func() *eventpub.Event {
		mu.Lock()
		defer mu.Unlock()
		for i := len(events) - 1; i >= 0; i-- {
			if events[i].StatusCode == http.StatusOK {
				return events[i]
			}
		}
		return nil
	}

	// --- OLD wiring: probe + newest-first ResolveKey, no pool surface. ---
	oldStore := singleCred()
	gwOld := legacyWiredGateway(t, up.srv.URL, oldStore, versions)

	rec := byokChatRequest(gwOld, "org-a", "glm-5.3", "old-serve", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, []string{"sk-pool-key-00000001"}, up.keysFor("old-serve"),
		"old wiring: the org credential authenticates the attempt")
	ev := lastOKEvent()
	require.NotNil(t, ev)
	assert.True(t, ev.UsedOrgKey)
	assert.Empty(t, ev.OrgCredentialRef, "the legacy path carries no masked credential ref")
	raw, err := json.Marshal(ev)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "org_credential_ref", "an empty ref stays off the wire")

	// A 401 under the old wiring: no quarantine write, and the SAME invalid
	// key is sent again on the next request — the legacy posture has no
	// rotation feedback (this is what the new configuration changes).
	up.setReject("sk-pool-key-00000001")
	rec = byokChatRequest(gwOld, "org-a", "glm-5.3", "old-repeat", false)
	assert.NotEqual(t, http.StatusOK, rec.Code, "the rejected key fails its own hop")
	assert.Empty(t, oldStore.quarantineLog(), "the old wiring has no quarantine feedback surface")
	rec = byokChatRequest(gwOld, "org-a", "glm-5.3", "old-repeat2", false)
	assert.NotEqual(t, http.StatusOK, rec.Code)
	assert.Equal(t, []string{"sk-pool-key-00000001"}, up.keysFor("old-repeat2"),
		"old wiring: the invalid key is repeated (newest-first, no rotation)")

	// --- NEW wiring: the same old-shape org through the pool. ---
	up.setReject("")
	newStore := singleCred()
	gwNew := credPoolGateway(t, up.srv.URL, newStore, versions)

	rec = byokChatRequest(gwNew, "org-a", "glm-5.3", "new-serve", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, []string{"sk-pool-key-00000001"}, up.keysFor("new-serve"),
		"migration parity: the same single-credential org authenticates with the same key under the pool")
	ev = lastOKEvent()
	require.NotNil(t, ev)
	assert.True(t, ev.UsedOrgKey)
	assert.Equal(t, "aaaaaaaa:0001", ev.OrgCredentialRef, "the pool wiring adds the masked ref")

	up.setReject("sk-pool-key-00000001")
	rec = byokChatRequest(gwNew, "org-a", "glm-5.3", "new-quarantine", false)
	assert.NotEqual(t, http.StatusOK, rec.Code)
	require.Len(t, newStore.quarantineLog(), 1, "the new wiring feeds the quarantine")
	rec = byokChatRequest(gwNew, "org-a", "glm-5.3", "new-norepeat", false)
	assert.GreaterOrEqual(t, rec.Code, 500, "the held-but-quarantined credential refuses, not a routing miss")
	assert.Empty(t, up.keysFor("new-norepeat"),
		"new wiring: the invalid key is NOT repeated — fail-closed, no dial at all")
}

// TestCredPoolCompat_AllQuarantinedRejectsPerModelDowngrade: the explicit
// rejection for the unsupported downgrade. With every held credential
// quarantined, the attempt fails closed — the per-model upstream_api_key of
// the model row and the global default are never sent to the org-registered
// endpoint — while an org that holds NO credential keeps its per-model
// fall-through (the rejection is scoped to held-but-quarantined, not an
// over-broad fail-close).
func TestCredPoolCompat_AllQuarantinedRejectsPerModelDowngrade(t *testing.T) {
	up := newPoolUpstream(t, "", false)
	store := newStubCredPoolStore(poolCreds3()...)
	versions := &stubOrgVersions{versions: map[string]int64{}}
	gw := credPoolGateway(t, up.srv.URL, store, versions)

	// Model rows that carry their OWN per-model key for both orgs.
	perModel := func() resolver.ModelInfo {
		mi := byokOrgModel(up.srv.URL)
		mi.UpstreamAPIKey = "sk-per-model-key"
		return mi
	}
	gw.res = &byokModelResolver{
		global:    map[string]resolver.ModelInfo{"smart": {ModelName: "smart", Tier: "smart", Enabled: true}},
		orgModels: map[string]resolver.ModelInfo{"org-a|glm-5.3": perModel(), "org-b|glm-5.3": perModel()},
	}

	// org-b holds NO credential: the negative miss falls through to the
	// per-model key (correct posture — nothing is held).
	rec := byokChatRequest(gw, "org-b", "glm-5.3", "b-permodel", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, []string{"sk-per-model-key"}, up.keysFor("b-permodel"),
		"no held credential → the per-model key is the correct fallback")

	// org-a: drive all three held credentials into quarantine with 401s.
	up.setReject("sk-pool-key-00000001")
	assert.NotEqual(t, http.StatusOK, byokChatRequest(gw, "org-a", "glm-5.3", "a-q1", false).Code)
	up.setReject("sk-pool-key-00000002")
	assert.NotEqual(t, http.StatusOK, byokChatRequest(gw, "org-a", "glm-5.3", "a-q2", false).Code)
	up.setReject("sk-pool-key-00000003")
	assert.NotEqual(t, http.StatusOK, byokChatRequest(gw, "org-a", "glm-5.3", "a-q3", false).Code)
	require.Len(t, store.quarantineLog(), 3, "all held credentials quarantined")

	// The unsupported downgrade is refused with the exact pool refusal: no
	// per-model key, no global key, no dial at all.
	dialsBefore := up.dials()
	rec = byokChatRequest(gw, "org-a", "glm-5.3", "a-refused", false)
	assert.GreaterOrEqual(t, rec.Code, 500, "held-but-quarantined fails closed, not a downgrade")
	assert.Empty(t, up.keysFor("a-refused"), "the per-model key is never sent")
	assert.Equal(t, dialsBefore, up.dials(), "the upstream is not dialed at all")
	assert.NotContains(t, rec.Body.String(), "sk-per-model-key")
	assert.NotContains(t, rec.Body.String(), "test-key")
	assert.NotContains(t, rec.Body.String(), "sk-pool-key-", "no key material in the refusal envelope")
}
