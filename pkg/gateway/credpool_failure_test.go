package cli

// end-to-end failure legs: every boundary of the multi-credential
// pool ON THE REAL REQUEST PATH — all credentials quarantined fails closed
// per path (chat JSON and SSE stream) with NO global-key fall-through, the
// pool store outage fails closed the same way, a mid-flight
// quarantine+rotation never breaks the in-flight attempt (per-request pin),
// and a 429 with a Retry-After header still quarantines day-granular
// (D-3: until the next UTC midnight; Retry-After is deliberately not
// parsed — pinned here as the documented behavior).

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCredPoolFailureE2E_AllQuarantinedFailsClosedChatPath: every pool key
// is rejected with 401 → every credential lands in quarantine → the next
// request FAILS (5xx) and the upstream is never dialed: no global-key
// fall-through on an endpoint whose org credentials are all quarantined.
// Rotating one credential back (Update + new key) restores service.
func TestCredPoolFailureE2E_AllQuarantinedFailsClosedChatPath(t *testing.T) {
	up := newPoolUpstream(t, "sk-pool-key-00000001", false)
	store := newStubCredPoolStore(poolCreds3()...)
	gw := credPoolGateway(t, up.srv.URL, store, &stubOrgVersions{versions: map[string]int64{}})

	// Phase 1: key 1 rejected (401) — its request fails, key 1 quarantined.
	rec := byokChatRequest(gw, "org-a", "glm-5.3", "phase1", false)
	assert.NotEqual(t, http.StatusOK, rec.Code)
	require.Len(t, store.quarantineLog(), 1)

	// Phase 2: keys 2 and 3 rejected too — every held credential ends up
	// quarantined.
	up.setReject("sk-pool-key-00000002")
	rec = byokChatRequest(gw, "org-a", "glm-5.3", "phase2", false)
	assert.NotEqual(t, http.StatusOK, rec.Code, "the second key's request fails its own hop")
	up.setReject("sk-pool-key-00000003")
	rec = byokChatRequest(gw, "org-a", "glm-5.3", "phase2b", false)
	assert.NotEqual(t, http.StatusOK, rec.Code)
	require.Len(t, store.quarantineLog(), 3, "all three credentials quarantined")

	// Phase 3: the next requests must fail CLOSED — no dial at all, in
	// particular no dial with the global "test-key".
	dialsBefore := up.dials()
	for i := 0; i < 3; i++ {
		rec := byokChatRequest(gw, "org-a", "glm-5.3", "phase3", false)
		assert.GreaterOrEqual(t, rec.Code, 500, "all-quarantined must surface a server error, not a silent fallback")
		assert.NotContains(t, rec.Body.String(), "sk-pool-key-", "no key material in the refusal envelope")
		assert.NotContains(t, rec.Body.String(), "test-key")
	}
	assert.Equal(t, dialsBefore, up.dials(), "fail-closed means the upstream sees NO request — no global-key fall-through")

	// Phase 4: rotating the first credential (Update + newPlaintextKey,
	// key_version++) lifts its quarantine; service resumes with the
	// rotated key.
	store.rotate("aaaaaaaa-1111-4111-8111-000000000001", "sk-pool-key-ROTATED-0011")
	gw.credPool.invalidate("org-a", zaiCodingProvider, up.srv.URL)
	up.setReject("")
	rec = byokChatRequest(gw, "org-a", "glm-5.3", "phase4", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, []string{"sk-pool-key-ROTATED-0011"}, up.keysFor("phase4"),
		"the rotated credential is the only eligible one and serves again")
}

// TestCredPoolFailureE2E_AllQuarantinedFailsClosedStreamPath: the same
// all-quarantined boundary on the SSE dial path — an in-stream error frame,
// and the upstream is never dialed again once every key is quarantined.
func TestCredPoolFailureE2E_AllQuarantinedFailsClosedStreamPath(t *testing.T) {
	up := newPoolUpstream(t, "sk-pool-key-00000001", true)
	store := newStubCredPoolStore(poolCreds3()...)
	gw := credPoolGateway(t, up.srv.URL, store, &stubOrgVersions{versions: map[string]int64{}})

	rec := byokChatRequest(gw, "org-a", "glm-5.3", "s-phase1", true)
	assert.Contains(t, rec.Body.String(), "permission_denied_error")
	require.Len(t, store.quarantineLog(), 1)

	up.setReject("sk-pool-key-00000002")
	rec = byokChatRequest(gw, "org-a", "glm-5.3", "s-phase2", true)
	assert.Contains(t, rec.Body.String(), "permission_denied_error")
	up.setReject("sk-pool-key-00000003")
	rec = byokChatRequest(gw, "org-a", "glm-5.3", "s-phase2b", true)
	assert.Contains(t, rec.Body.String(), "permission_denied_error")
	require.Len(t, store.quarantineLog(), 3)

	dialsBefore := up.dials()
	rec = byokChatRequest(gw, "org-a", "glm-5.3", "s-phase3", true)
	assert.NotContains(t, rec.Body.String(), `"content":"hi"`, "no completion content on the fail-closed stream")
	assert.NotContains(t, rec.Body.String(), "sk-pool-key-")
	assert.Equal(t, dialsBefore, up.dials(), "the stream path fails closed without dialing (no global-key hop)")
}

// TestCredPoolFailureE2E_StoreErrorFailsClosed: a pool store outage on the
// request path is an infrastructure failure — fail-closed, exactly like the
// all-quarantined verdict: the request errors and the upstream sees NO
// request (never the global key).
func TestCredPoolFailureE2E_StoreErrorFailsClosed(t *testing.T) {
	up := newPoolUpstream(t, "", false)
	store := newStubCredPoolStore(poolCreds3()...)
	gw := credPoolGateway(t, up.srv.URL, store, &stubOrgVersions{versions: map[string]int64{}})

	// Prime a healthy path first, then take the store down.
	rec := byokChatRequest(gw, "org-a", "glm-5.3", "healthy", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	store.mu.Lock()
	store.listErr = errors.New("credential store unavailable")
	store.mu.Unlock()
	gw.credPool.invalidate("org-a", zaiCodingProvider, up.srv.URL)

	dialsBefore := up.dials()
	rec = byokChatRequest(gw, "org-a", "glm-5.3", "outage", false)
	assert.GreaterOrEqual(t, rec.Code, 500, "a store outage must fail the request")
	assert.NotContains(t, rec.Body.String(), "sk-pool-key-")
	assert.Equal(t, dialsBefore, up.dials(), "the store outage must not leak a global-key dial to the org endpoint")
}

// TestCredPoolFailureE2E_InFlightRotationPinSurvives: while a request is IN
// FLIGHT (the upstream handler is running), its credential is quarantined
// AND rotated underneath. The in-flight attempt keeps its already-resolved
// plaintext and completes 200; only NEW attempts move to the rotated key /
// the sibling. The card's negative scenario — "вывод из ротации рвёт
// активные запросы" — must NOT reproduce.
func TestCredPoolFailureE2E_InFlightRotationPinSurvives(t *testing.T) {
	up := newPoolUpstream(t, "", false)
	store := newStubCredPoolStore(poolCreds3()...)
	gw := credPoolGateway(t, up.srv.URL, store, &stubOrgVersions{versions: map[string]int64{}})

	k1 := "aaaaaaaa-1111-4111-8111-000000000001"
	mutated := false
	// Mid-flight mutation: when the handler sees the first hop's key, the
	// credential is quarantined AND rotated (what a concurrent 401 + admin
	// Update would leave) before the response is written.
	up.mu.Lock()
	up.onDial = func(key string) {
		if key != "sk-pool-key-00000001" || mutated {
			return
		}
		mutated = true
		until := time.Now().UTC().Add(time.Hour)
		store.mu.Lock()
		store.quarantine[k1] = stubQuarantine{version: 1, until: until}
		store.quarantineCalls = append(store.quarantineCalls, stubQuarantineCall{credID: k1, version: 1, until: until})
		store.mu.Unlock()
		store.rotate(k1, "sk-pool-key-ROTATED-0011")
	}
	up.mu.Unlock()

	rec := byokChatRequest(gw, "org-a", "glm-5.3", "inflight", false)
	require.Equal(t, http.StatusOK, rec.Code, "the in-flight attempt must survive the mid-flight quarantine+rotation: активные доживают")
	assert.Equal(t, []string{"sk-pool-key-00000001"}, up.keysFor("inflight"),
		"the in-flight request completed with its pinned plaintext")

	// New attempts must not authenticate with the OLD k1 key; the rotated
	// key and the siblings carry the traffic.
	up.mu.Lock()
	up.onDial = nil
	up.mu.Unlock()
	gw.credPool.invalidate("org-a", zaiCodingProvider, up.srv.URL)
	seenRotated := false
	for i := 0; i < 6; i++ {
		marker := "after-rotation"
		rec := byokChatRequest(gw, "org-a", "glm-5.3", marker, false)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		keys := up.keysFor(marker)
		require.NotEmpty(t, keys)
		for _, k := range keys {
			assert.NotEqual(t, "sk-pool-key-00000001", k, "new attempts never reuse the rotated-out key")
		}
		if keys[0] == "sk-pool-key-ROTATED-0011" {
			seenRotated = true
		}
	}
	assert.True(t, seenRotated, "the rotated credential returns to rotation with its new key")
}

// TestCredPoolFailureE2E_429RetryAfterDayGranular: the upstream rejects a
// key with 429 AND a Retry-After: 60 header. Ratified D-3 is day-granular:
// the quarantine deadline is the NEXT UTC MIDNIGHT, not now+60s — the
// header is deliberately not parsed (documented limitation), and traffic
// continues on the siblings.
func TestCredPoolFailureE2E_429RetryAfterDayGranular(t *testing.T) {
	up := newPoolUpstream(t, "sk-pool-key-00000001", false)
	up.rejectStatus = http.StatusTooManyRequests
	up.retryAfter = "60"
	store := newStubCredPoolStore(poolCreds3()...)
	gw := credPoolGateway(t, up.srv.URL, store, &stubOrgVersions{versions: map[string]int64{}})

	rec := byokChatRequest(gw, "org-a", "glm-5.3", "rl-marker", false)
	assert.NotEqual(t, http.StatusOK, rec.Code, "the throttled hop fails its own request")

	calls := store.quarantineLog()
	require.Len(t, calls, 1, "429 must quarantine the credential (per-key cooldown)")
	until := calls[0].until
	h, m, s := until.UTC().Clock()
	assert.Zero(t, h)
	assert.Zero(t, m)
	assert.Zero(t, s, "the deadline is exactly a UTC midnight (day-granular D-3), not Retry-After seconds: got %s", until)
	assert.Positive(t, time.Until(until), "the quarantine is live")

	// Traffic continues on the siblings; the throttled key stays out.
	for i := 0; i < 6; i++ {
		marker := "rl-after"
		rec := byokChatRequest(gw, "org-a", "glm-5.3", marker, false)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		for _, k := range up.keysFor(marker) {
			assert.NotEqual(t, "sk-pool-key-00000001", k, "the 429-quarantined key must not serve new requests")
		}
	}
}
