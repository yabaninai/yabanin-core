package cli

// Fair distribution across keys (D-2), quarantine-on-401 with sibling
// takeover (D-3), masked credential attribution on the analytics event
// (D-4), and the no-secrets-on-the-wire invariant.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/retry"
)

// poolUpstream answers 401 for one rejected key and 200 otherwise,
// recording every Authorization it saw per request marker.
type poolUpstream struct {
	mu     sync.Mutex
	auth   map[string][]string
	reject string
	sse    bool
	srv    *httptest.Server

	// rejectStatus is the rejection code for the rejected key (401 by
	// default; uses 429 with a Retry-After header)
	rejectStatus int
	retryAfter   string
	// onDial runs inside the handler BEFORE the response is decided — the
	// mid-flight mutation hook of the in-flight boundary tests.
	onDial func(key string)
}

func newPoolUpstream(t *testing.T, rejectKey string, sse bool) *poolUpstream {
	t.Helper()
	u := &poolUpstream{auth: map[string][]string{}, reject: rejectKey, sse: sse, rejectStatus: http.StatusUnauthorized}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		var body struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		marker := ""
		if len(body.Messages) > 0 {
			marker = body.Messages[0].Content
		}
		u.mu.Lock()
		u.auth[marker] = append(u.auth[marker], key)
		hook := u.onDial
		rejected := key == u.reject
		u.mu.Unlock()

		if hook != nil {
			hook(key)
		}
		if rejected {
			w.Header().Set("Content-Type", "application/json")
			if u.retryAfter != "" {
				w.Header().Set("Retry-After", u.retryAfter)
			}
			w.WriteHeader(u.rejectStatus)
			_, _ = w.Write([]byte(`{"error":{"message":"rejected key"}}`))
			return
		}
		if sse {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cmpl","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *poolUpstream) keysFor(marker string) []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.auth[marker]...)
}

// dials is the total number of upstream hits (all markers).
func (u *poolUpstream) dials() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	n := 0
	for _, keys := range u.auth {
		n += len(keys)
	}
	return n
}

// then also the second).
func (u *poolUpstream) setReject(key string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.reject = key
}

// ResolveKey (frozen surface, newest-first) lets the stub double as the
// gateway's OrgKeyResolver so the wiring shape matches production.
func (s *stubCredPoolStore) ResolveKey(_ context.Context, orgID, provider, baseURL string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for i := len(s.creds) - 1; i >= 0; i-- {
		c := s.creds[i]
		if s.eligibleLocked(c, now) {
			return c.key, true, nil
		}
	}
	return "", false, nil
}

// credPoolGateway wires a gateway whose org-credential resolution runs
// exercised by the adminstore integration tests; here the structural
// surface is the contract).
func credPoolGateway(t *testing.T, upstreamURL string, store *stubCredPoolStore, versions *stubOrgVersions) *gateway {
	t.Helper()
	gw := streamTestGateway(upstreamURL)
	gw.res = byokResolver(upstreamURL)
	gw.cfg.ZAICodingEnabled = true
	gw.cfg.ZAICodingBaseURL = upstreamURL
	gw.retryPolicy = retry.Policy{MaxAttempts: 1}
	gw.orgCreds = store
	gw.orgCredsVersions = versions
	gw.credPool = newOrgCredsPool(store, versions, orgCredsPoolTTL, testLogger())
	return gw
}

// poolCreds3 is the standard three-credential fixture of one endpoint.
// Distinct id prefixes so masked refs are distinguishable in assertions.
func poolCreds3() []stubPoolCred {
	return []stubPoolCred{
		{id: "aaaaaaaa-1111-4111-8111-000000000001", last4: "0001", key: "sk-pool-key-00000001", enabled: true, version: 1},
		{id: "bbbbbbbb-2222-4222-8222-000000000002", last4: "0002", key: "sk-pool-key-00000002", enabled: true, version: 1},
		{id: "cccccccc-3333-4333-8333-000000000003", last4: "0003", key: "sk-pool-key-00000003", enabled: true, version: 1},
	}
}

// TestCredPoolE2E_FairDistribution: 30 requests over 3 eligible keys
// authenticate 10/10/10 (measurable and fair — the card's acceptance; no
// key monopolizes the traffic) and every event attributes its credential.
func TestCredPoolE2E_FairDistribution(t *testing.T) {
	up := newPoolUpstream(t, "", false)
	store := newStubCredPoolStore(poolCreds3()...)
	gw := credPoolGateway(t, up.srv.URL, store, &stubOrgVersions{versions: map[string]int64{}})

	var mu sync.Mutex
	events := []*eventpub.Event{}
	restore := observeEvent(func(e *eventpub.Event) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	})
	defer restore()

	refs := map[string]int{}
	for i := 0; i < 30; i++ {
		rec := byokChatRequest(gw, "org-a", "glm-5.3", "fair-marker", false)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		keys := up.keysFor("fair-marker")
		require.Len(t, keys, 1, "one provider attempt per request")
		refs[keys[0]]++
		up.mu.Lock()
		delete(up.auth, "fair-marker")
		up.mu.Unlock()
	}
	assert.Equal(t, map[string]int{
		"sk-pool-key-00000001": 10,
		"sk-pool-key-00000002": 10,
		"sk-pool-key-00000003": 10,
	}, refs, "round-robin must split 30 requests exactly 10/10/10")

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, events, 30)
	refCount := map[string]int{}
	for _, ev := range events {
		assert.True(t, ev.UsedOrgKey)
		assert.Regexp(t, `^[0-9a-f]{8}:000[123]$`, ev.OrgCredentialRef, "masked ref shape: id8:last4")
		refCount[ev.OrgCredentialRef]++
	}
	assert.Len(t, refCount, 3)
	for _, n := range refCount {
		assert.Equal(t, 10, n, "attribution must mirror the key distribution")
	}
}

// TestCredPoolE2E_QuarantineOn401AndSiblingTakeover: the upstream rejects
// key 1 with 401 → that request fails (its own hop), the credential is
// quarantined until the end of the UTC day, and every later request is
// served by the siblings. The rejected key never authenticates again.
func TestCredPoolE2E_QuarantineOn401AndSiblingTakeover(t *testing.T) {
	up := newPoolUpstream(t, "sk-pool-key-00000001", false)
	store := newStubCredPoolStore(poolCreds3()...)
	versions := &stubOrgVersions{versions: map[string]int64{}}
	gw := credPoolGateway(t, up.srv.URL, store, versions)

	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) { ev = e })
	defer restore()

	// First request draws key 1 (round-robin cursor starts at the oldest).
	rec := byokChatRequest(gw, "org-a", "glm-5.3", "q401-first", false)
	assert.NotEqual(t, http.StatusOK, rec.Code, "the 401 hop fails its own request")
	assert.Equal(t, []string{"sk-pool-key-00000001"}, up.keysFor("q401-first"))
	assert.NotContains(t, rec.Body.String(), "sk-pool-key-00000001", "the key must never leak to the client")

	// The quarantine hit the store with the version-scoped row.
	calls := store.quarantineLog()
	require.Len(t, calls, 1)
	assert.Equal(t, "aaaaaaaa-1111-4111-8111-000000000001", calls[0].credID)
	assert.Positive(t, versions.versions["org-a"], "cross-instance invalidation bump")

	// Every later request is served by a sibling and attributed to it.
	for i := 0; i < 6; i++ {
		ev = nil
		marker := "q401-after"
		rec := byokChatRequest(gw, "org-a", "glm-5.3", marker, false)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		keys := up.keysFor(marker)
		require.NotEmpty(t, keys)
		for _, k := range keys {
			assert.NotEqual(t, "sk-pool-key-00000001", k, "a quarantined credential must not authenticate new requests")
		}
		require.NotNil(t, ev)
		assert.True(t, ev.UsedOrgKey)
		assert.NotContains(t, ev.OrgCredentialRef, "aaaaaaaa", "the quarantined credential must not be attributed")
		up.mu.Lock()
		delete(up.auth, marker)
		up.mu.Unlock()
	}
}

// TestCredPoolE2E_StreamPathAttributionAndQuarantine: the SSE dialAttempt
// hop runs the same pool discipline — key pinned per attempt, 401 feeds the
// quarantine, the retried request streams over a sibling key, and the
// winning event carries the sibling's masked ref.
func TestCredPoolE2E_StreamPathAttributionAndQuarantine(t *testing.T) {
	up := newPoolUpstream(t, "sk-pool-key-00000001", true)
	store := newStubCredPoolStore(poolCreds3()...)
	gw := credPoolGateway(t, up.srv.URL, store, &stubOrgVersions{versions: map[string]int64{}})

	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) { ev = e })
	defer restore()

	rec := byokChatRequest(gw, "org-a", "glm-5.3", "stream-q401", true)
	// SSE headers flush before the upstream dial, so the failure rides an
	// in-stream error frame (not an HTTP status): the request yields an
	// error event, never a completion.
	assert.Contains(t, rec.Body.String(), "permission_denied_error", "the rejected-key stream must surface the upstream failure")
	assert.NotContains(t, rec.Body.String(), "sk-pool-key-", "no key material in the client-visible frame")
	assert.Equal(t, []string{"sk-pool-key-00000001"}, up.keysFor("stream-q401"))
	require.Len(t, store.quarantineLog(), 1, "the stream hop must feed the pool feedback too")

	ev = nil
	rec = byokChatRequest(gw, "org-a", "glm-5.3", "stream-ok", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	keys := up.keysFor("stream-ok")
	require.NotEmpty(t, keys)
	assert.NotEqual(t, "sk-pool-key-00000001", keys[0])
	require.NotNil(t, ev)
	assert.True(t, ev.UsedOrgKey)
	assert.Regexp(t, `^[0-9a-f]{8}:000[23]$`, ev.OrgCredentialRef)
}

// TestCredPoolE2E_NoCredentialFallsThrough: with the pool wired but no
// credential for the org, the request uses the global key and the event
// carries no credential ref (empty stays off the wire).
func TestCredPoolE2E_NoCredentialFallsThrough(t *testing.T) {
	up := newPoolUpstream(t, "", false)
	store := newStubCredPoolStore(poolCreds3()...)
	gw := credPoolGateway(t, up.srv.URL, store, &stubOrgVersions{versions: map[string]int64{}})

	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) { ev = e })
	defer restore()

	rec := byokChatRequest(gw, "org-b", "glm-5.3", "no-cred-marker", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, []string{"test-key"}, up.keysFor("no-cred-marker"), "no org credential → global key")
	require.NotNil(t, ev)
	assert.False(t, ev.UsedOrgKey)
	assert.Empty(t, ev.OrgCredentialRef)

	raw, err := json.Marshal(ev)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "org_credential_ref", "an empty ref must stay off the wire")
}

// TestCredPoolE2E_NoSecretsOnTheWire: the full event document never carries
// key material — only the masked credential ref.
func TestCredPoolE2E_NoSecretsOnTheWire(t *testing.T) {
	up := newPoolUpstream(t, "", false)
	store := newStubCredPoolStore(poolCreds3()...)
	gw := credPoolGateway(t, up.srv.URL, store, &stubOrgVersions{versions: map[string]int64{}})

	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) { ev = e })
	defer restore()

	rec := byokChatRequest(gw, "org-a", "glm-5.3", "secrets-marker", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotNil(t, ev)

	raw, err := json.Marshal(ev)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "sk-pool-key-00000001")
	assert.NotContains(t, string(raw), "sk-pool-key-00000002")
	assert.NotContains(t, string(raw), "sk-pool-key-00000003")
	assert.Contains(t, string(raw), `"org_credential_ref":"`, "the masked ref rides the event")
	assert.Regexp(t, `^(aaaaaaaa|bbbbbbbb|cccccccc):000[123]$`, ev.OrgCredentialRef)
	assert.NotContains(t, rec.Body.String(), "sk-pool-key-", "no key leaks to the client either")
}

// TestCredPoolE2E_JointUserScenario is the packet's joint user scenario
// (N08-P05-T06): ONE continuous organization journey over the chat path that
// chains every delivered behavior — fair round-robin serve with masked
// attribution, the invalid key's 401 quarantine, the throttled key's 429
// quarantine, sibling takeover, typed fail-closed when all keys are out,
// org isolation (a second org is untouched), and the operator reset that
// returns the recovered key to rotation. This is the MOCK environment:
// in-memory stub store, httptest upstream, synthetic keys, live clock. The
// REAL leg (real Postgres store, RLS, version rows) is the integration-tag
// build in credpool_integration_test.go and is explicitly NOT exercised
// here.
func TestCredPoolE2E_JointUserScenario(t *testing.T) {
	up := newPoolUpstream(t, "", false)
	store := newStubCredPoolStore(poolCreds3()...)
	versions := &stubOrgVersions{versions: map[string]int64{}}
	gw := credPoolGateway(t, up.srv.URL, store, versions)

	var mu sync.Mutex
	var events []*eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	})
	defer restore()

	// Phase 1 — fair serve: the three keys rotate in order with masked
	// attribution, one provider attempt per request.
	for i, marker := range []string{"joint-fair-1", "joint-fair-2", "joint-fair-3"} {
		rec := byokChatRequest(gw, "org-a", "glm-5.3", marker, false)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, []string{fmt.Sprintf("sk-pool-key-0000000%d", i+1)}, up.keysFor(marker), "pick %d: round-robin order", i+1)
		assert.NotContains(t, rec.Body.String(), "sk-pool-key-")
		up.mu.Lock()
		delete(up.auth, marker)
		up.mu.Unlock()
	}
	mu.Lock()
	require.Len(t, events, 3)
	fairRefs := map[string]bool{}
	for i, ev := range events {
		assert.True(t, ev.UsedOrgKey, "event %d", i)
		assert.Regexp(t, `^[0-9a-f]{8}:000[123]$`, ev.OrgCredentialRef, "event %d", i)
		fairRefs[ev.OrgCredentialRef] = true
	}
	assert.Len(t, fairRefs, 3, "each served key attributed once")
	mu.Unlock()

	// Phase 2 — the invalid key: its 401 fails its own request, hits the
	// version-scoped store quarantine until the end of the UTC day, and
	// bumps the org version for cross-instance invalidation.
	up.setReject("sk-pool-key-00000001")
	rec := byokChatRequest(gw, "org-a", "glm-5.3", "joint-bad-key1", false)
	assert.NotEqual(t, http.StatusOK, rec.Code, "the 401 hop fails its own request")
	assert.Equal(t, []string{"sk-pool-key-00000001"}, up.keysFor("joint-bad-key1"), "exactly one attempt: the invalid key is never retried in-request")
	assert.NotContains(t, rec.Body.String(), "sk-pool-key-")
	calls := store.quarantineLog()
	require.Len(t, calls, 1)
	assert.Equal(t, "aaaaaaaa-1111-4111-8111-000000000001", calls[0].credID)
	assert.Equal(t, 1, calls[0].version, "the quarantine row is scoped to the key version")
	assert.Zero(t, calls[0].until.Nanosecond()%(int(time.Second)), "until is the end-of-UTC-day deadline")
	assert.Positive(t, versions.versions["org-a"], "org version bump")
	verAfter401 := versions.versions["org-a"]

	// Phase 3 — the throttled key: 429 quarantines the sibling the same way
	// (the Retry-After hint is deliberately not parsed — packet policy).
	up.mu.Lock()
	up.rejectStatus = http.StatusTooManyRequests
	up.retryAfter = "3600"
	up.mu.Unlock()
	up.setReject("sk-pool-key-00000002")
	rec = byokChatRequest(gw, "org-a", "glm-5.3", "joint-bad-key2", false)
	assert.NotEqual(t, http.StatusOK, rec.Code)
	assert.Equal(t, []string{"sk-pool-key-00000002"}, up.keysFor("joint-bad-key2"))
	assert.NotContains(t, rec.Body.String(), "sk-pool-key-")
	calls = store.quarantineLog()
	require.Len(t, calls, 2)
	assert.Equal(t, "bbbbbbbb-2222-4222-8222-000000000002", calls[1].credID)
	assert.Equal(t, 1, calls[1].version)
	assert.Greater(t, versions.versions["org-a"], verAfter401)
	up.mu.Lock()
	up.rejectStatus = http.StatusUnauthorized
	up.retryAfter = ""
	up.mu.Unlock()

	// Phase 4 — sibling takeover: the third key serves alone and is the only
	// attributed credential from here.
	for _, marker := range []string{"joint-solo-1", "joint-solo-2"} {
		rec := byokChatRequest(gw, "org-a", "glm-5.3", marker, false)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, []string{"sk-pool-key-00000003"}, up.keysFor(marker), "only the surviving sibling dials")
		up.mu.Lock()
		delete(up.auth, marker)
		up.mu.Unlock()
	}

	// Phase 5 — the third key falls too: 401 quarantines it.
	up.setReject("sk-pool-key-00000003")
	rec = byokChatRequest(gw, "org-a", "glm-5.3", "joint-bad-key3", false)
	assert.NotEqual(t, http.StatusOK, rec.Code)
	assert.Equal(t, []string{"sk-pool-key-00000003"}, up.keysFor("joint-bad-key3"))
	calls = store.quarantineLog()
	require.Len(t, calls, 3)
	assert.Equal(t, "cccccccc-3333-4333-8333-000000000003", calls[2].credID)

	// Phase 6 — fail-closed: with every org credential out, org-a requests
	// fail without a single upstream dial and without falling through to the
	// global key.
	dialsBefore := up.dials()
	for _, marker := range []string{"joint-closed-1", "joint-closed-2"} {
		rec := byokChatRequest(gw, "org-a", "glm-5.3", marker, false)
		assert.GreaterOrEqual(t, rec.Code, 500, "all keys quarantined must fail closed")
		assert.NotContains(t, rec.Body.String(), "sk-pool-key-")
		assert.NotContains(t, rec.Body.String(), "test-key", "the org must not fall through to the global key")
	}
	assert.Equal(t, dialsBefore, up.dials(), "fail-closed must not dial the upstream at all")

	// Phase 7 — org isolation: org-b (no credentials) keeps working on the
	// global key while org-a is fail-closed; org-a stays closed.
	rec = byokChatRequest(gw, "org-b", "glm-5.3", "joint-orgb", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, []string{"test-key"}, up.keysFor("joint-orgb"), "org-b rides the global key")
	mu.Lock()
	require.NotEmpty(t, events)
	last := events[len(events)-1]
	assert.False(t, last.UsedOrgKey)
	assert.Empty(t, last.OrgCredentialRef)
	mu.Unlock()
	rec = byokChatRequest(gw, "org-a", "glm-5.3", "joint-closed-3", false)
	assert.GreaterOrEqual(t, rec.Code, 500, "org-a's exhaustion is untouched by org-b's traffic")
	assert.Equal(t, dialsBefore+1, up.dials(), "exactly the org-b global-key dial happened")

	// Phase 8 — operator reset returns the recovered key: rotate key 1 in
	// the store (new plaintext, key_version++) and reset it on the pool; the
	// past-dated quarantine row lands on the CURRENT version and the next
	// request is served by the recovered (rotated) key.
	store.rotate("aaaaaaaa-1111-4111-8111-000000000001", "sk-pool-key-ROTATED-0011")
	require.NoError(t, gw.credPool.ResetOrgCredential(context.Background(), "org-a", zaiCodingProvider, up.srv.URL, "aaaaaaaa-1111-4111-8111-000000000001"))
	calls = store.quarantineLog()
	require.Len(t, calls, 4)
	assert.Equal(t, "aaaaaaaa-1111-4111-8111-000000000001", calls[3].credID)
	assert.Equal(t, 2, calls[3].version, "the reset row is scoped to the rotated version")
	assert.True(t, calls[3].until.Before(time.Now()), "the reset writes a past-dated deadline")
	up.setReject("")
	rec = byokChatRequest(gw, "org-a", "glm-5.3", "joint-recovered", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, []string{"sk-pool-key-ROTATED-0011"}, up.keysFor("joint-recovered"), "the recovered key continues serving")
	mu.Lock()
	require.NotEmpty(t, events)
	last = events[len(events)-1]
	assert.True(t, last.UsedOrgKey)
	assert.Equal(t, "aaaaaaaa:0001", last.OrgCredentialRef, "the recovered credential is attributed again, mask stable across rotation")
	mu.Unlock()

	// Phase 9 — whole-journey hygiene: no key material anywhere in the
	// marshaled events of the entire scenario.
	mu.Lock()
	defer mu.Unlock()
	for i, ev := range events {
		raw, err := json.Marshal(ev)
		require.NoError(t, err, "event %d", i)
		assert.NotContains(t, string(raw), "sk-pool-key-", "event %d", i)
	}
}
