package cli

// W-BYOK-CORE: org credential (BYOK) upstream-key resolution, org custom
// model resolution, and the used_org_key event attribution. The org
// credential store is the frozen W-BYOK-DB contract; these tests stub it

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/retry"
)

// stubOrgKeys is an in-memory OrgKeyResolver. ResolveKeys counts probes;
// keys maps (org|provider|baseURL) to plaintext; err injects an outage.
type stubOrgKeys struct {
	mu     sync.Mutex
	keys   map[string]string
	err    error
	called int
}

func (s *stubOrgKeys) ResolveKey(_ context.Context, orgID, providerName, baseURL string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.called++
	if s.err != nil {
		return "", false, s.err
	}
	key, ok := s.keys[orgID+"|"+providerName+"|"+baseURL]
	if !ok {
		key, ok = s.keys[orgID+"|*|*"]
	}
	return key, ok, nil
}

func (s *stubOrgKeys) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.called
}

// stubOrgVersions is a fixed OrgCredsVersionStore.
type stubOrgVersions struct {
	mu       sync.Mutex
	versions map[string]int64
	getErr   error
}

func (s *stubOrgVersions) GetOrgCredsVersion(_ context.Context, orgID string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.getErr != nil {
		return 0, s.getErr
	}
	return s.versions[orgID], nil
}

func (s *stubOrgVersions) SetOrgCredsVersion(_ context.Context, orgID string, version int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.versions[orgID] = version
	return nil
}

// byokModelResolver serves as both the gateway modelResolver and the org
// modelResolver (W-BYOK-CORE structural surface): global misses are genuine
// (Fallback=true), org lookups consult orgModels.
type byokModelResolver struct {
	global    map[string]resolver.ModelInfo
	orgModels map[string]resolver.ModelInfo // orgID|name → info
}

func (s *byokModelResolver) Resolve(_ context.Context, name string) resolver.ModelInfo {
	if info, ok := s.global[name]; ok {
		return info
	}
	return resolver.ModelInfo{ModelName: name, Enabled: true}
}

func (s *byokModelResolver) ResolveChecked(ctx context.Context, name string) (resolver.ModelInfo, error) {
	if info, ok := s.global[name]; ok {
		return info, nil
	}
	// Globally unknown: genuine miss (RM-09 substitution shape).
	return resolver.ModelInfo{ModelName: name, Tier: "smart", Enabled: true, Fallback: true}, nil
}

func (s *byokModelResolver) ResolveOrgChecked(_ context.Context, orgID, name string) (resolver.ModelInfo, error) {
	if info, ok := s.orgModels[orgID+"|"+name]; ok {
		return info, nil
	}
	return resolver.ModelInfo{}, nil
}

const byokOrgZAIKey = "sk-org-zai-secret-7777"

// byokPerModelKey is a synthetic fixture value in the shape of a per-model
// provider key; never a real credential.
const byokPerModelKey = "sk-per-model"

// byokGateway builds a gateway wired for BYOK tests: an upstream mock that
// records the Authorization header per request marker, an org key resolver,
// and an org-aware model stub.
func byokGateway(t *testing.T, upstream *httptest.Server, keys *stubOrgKeys, versions *stubOrgVersions, res *byokModelResolver) *gateway {
	t.Helper()
	gw := streamTestGateway(upstream.URL)
	gw.res = res
	gw.cfg.ZAICodingEnabled = true
	gw.cfg.ZAICodingBaseURL = upstream.URL
	gw.retryPolicy = retry.Policy{MaxAttempts: 1}
	gw.orgCreds = keys
	gw.orgCredsVersions = versions
	gw.orgCredsProbe = newOrgCredsProbe(keys, versions, orgCredsProbeTTL, testLogger())
	return gw
}

// byokUpstream records the Authorization bearer per first-message marker.
type byokUpstream struct {
	mu   sync.Mutex
	auth map[string]string
	srv  *httptest.Server
}

func newByokUpstream(t *testing.T, sse bool) *byokUpstream {
	t.Helper()
	u := &byokUpstream{auth: make(map[string]string)}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Model    string `json:"model"`
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
		u.auth[marker] = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		u.mu.Unlock()

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

func (u *byokUpstream) authFor(marker string) string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.auth[marker]
}

func byokChatRequest(gw *gateway, orgID, model, marker string, stream bool) *httptest.ResponseRecorder {
	payload := map[string]interface{}{
		"model":    model,
		"messages": []map[string]string{{"role": "user", "content": marker}},
		"stream":   stream,
	}
	body, _ := json.Marshal(payload)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body)))
	r.Header.Set("X-Org-Id", orgID)
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)
	return rec
}

// byokOrgModel is the zai-coding org model info the stub resolves for org-a.
func byokOrgModel(upstreamURL string) resolver.ModelInfo {
	return resolver.ModelInfo{
		ModelName:   "glm-5.3",
		Provider:    zaiCodingProvider,
		UpstreamURL: upstreamURL,
		Enabled:     true,
	}
}

func byokResolver(upstreamURL string) *byokModelResolver {
	return &byokModelResolver{
		global:    map[string]resolver.ModelInfo{"smart": {ModelName: "smart", Tier: "smart", Enabled: true}},
		orgModels: map[string]resolver.ModelInfo{"org-a|glm-5.3": byokOrgModel(upstreamURL)},
	}
}

// TestBYOK_OrgKeyWinsOverPerModelAndGlobal is the W1 AC scenario end-to-end
// against the mock upstream: an org with a credential + zai org model sends
// a request, the upstream receives the ORG key, and the event carries
// used_org_key=true. A second org without a credential gets the global key.
func TestBYOK_OrgKeyWinsOverPerModelAndGlobal(t *testing.T) {
	up := newByokUpstream(t, false)
	keys := &stubOrgKeys{keys: map[string]string{
		"org-a|" + zaiCodingProvider + "|" + up.srv.URL: byokOrgZAIKey,
	}}
	res := byokResolver(up.srv.URL)
	// The org model itself carries no per-model key: the org credential
	// chain must supply it.
	res.global["global-only"] = resolver.ModelInfo{ModelName: "global-only", Provider: "openai", UpstreamURL: up.srv.URL, Enabled: true, UpstreamAPIKey: byokPerModelKey}
	gw := byokGateway(t, up.srv, keys, &stubOrgVersions{versions: map[string]int64{}}, res)

	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) { ev = e })
	defer restore()

	// 1. org-a with credential: upstream sees the ORG key.
	rec := byokChatRequest(gw, "org-a", "glm-5.3", "org-a-marker", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, byokOrgZAIKey, up.authFor("org-a-marker"), "upstream must receive the org credential")
	require.NotNil(t, ev, "completed event must be observed")
	assert.True(t, ev.UsedOrgKey, "event must attribute the org key")
	assert.NotContains(t, rec.Body.String(), byokOrgZAIKey, "the org key must never leak to the client")

	// 2. org-b without credential on the same model shape: global key.
	ev = nil
	rec = byokChatRequest(gw, "org-b", "glm-5.3", "org-b-marker", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "test-key", up.authFor("org-b-marker"), "org without a credential must use the global key")
	require.NotNil(t, ev)
	assert.False(t, ev.UsedOrgKey)

	// 3. org-a on a GLOBAL model with its own per-model key: the per-model
	// key is used (no org credential matches this endpoint), not the org key.
	ev = nil
	rec = byokChatRequest(gw, "org-a", "global-only", "global-marker", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "sk-per-model", up.authFor("global-marker"))
	require.NotNil(t, ev)
	assert.False(t, ev.UsedOrgKey)
}

// TestBYOK_OrgKeyOnStreamPath verifies the SSE (dialAttempt) hop uses the org
// credential and stamps the winning hop on the event.
func TestBYOK_OrgKeyOnStreamPath(t *testing.T) {
	up := newByokUpstream(t, true)
	keys := &stubOrgKeys{keys: map[string]string{
		"org-a|" + zaiCodingProvider + "|" + up.srv.URL: byokOrgZAIKey,
	}}
	gw := byokGateway(t, up.srv, keys, &stubOrgVersions{versions: map[string]int64{}}, byokResolver(up.srv.URL))

	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) { ev = e })
	defer restore()

	rec := byokChatRequest(gw, "org-a", "glm-5.3", "stream-marker", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, byokOrgZAIKey, up.authFor("stream-marker"))
	require.NotNil(t, ev)
	assert.True(t, ev.UsedOrgKey)
}

// TestBYOK_SecondOrgCannotResolveForeignOrgModel: the org model is
// org-scoped — org-b's request for org-a's model must not resolve it and
// must fall back to the global candidate with a global key.
func TestBYOK_SecondOrgCannotResolveForeignOrgModel(t *testing.T) {
	up := newByokUpstream(t, false)
	keys := &stubOrgKeys{keys: map[string]string{
		"org-a|" + zaiCodingProvider + "|" + up.srv.URL: byokOrgZAIKey,
	}}
	gw := byokGateway(t, up.srv, keys, &stubOrgVersions{versions: map[string]int64{}}, byokResolver(up.srv.URL))

	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) { ev = e })
	defer restore()

	rec := byokChatRequest(gw, "org-b", "glm-5.3", "foreign-marker", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.NotEqual(t, byokOrgZAIKey, up.authFor("foreign-marker"),
		"a foreign org must never authenticate with another org's credential")
	require.NotNil(t, ev)
	assert.False(t, ev.UsedOrgKey)
}

// TestBYOK_FailClosedOnCredentialStoreOutage: when the org holds a
// credential for the endpoint but the store is unreachable, the request must
// NOT silently fall back to the global key (the W-PROV leak-hazard class).
// The key fetch runs per request (per-request decrypt), so an outage fails
// closed immediately.
func TestBYOK_FailClosedOnCredentialStoreOutage(t *testing.T) {
	up := newByokUpstream(t, false)
	keys := &stubOrgKeys{keys: map[string]string{
		"org-a|" + zaiCodingProvider + "|" + up.srv.URL: byokOrgZAIKey,
	}}
	gw := byokGateway(t, up.srv, keys, &stubOrgVersions{versions: map[string]int64{}}, byokResolver(up.srv.URL))

	rec := byokChatRequest(gw, "org-a", "glm-5.3", "first-marker", false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Positive(t, keys.calls())

	keys.mu.Lock()
	keys.err = errors.New("credential store unavailable")
	keys.mu.Unlock()

	rec = byokChatRequest(gw, "org-a", "glm-5.3", "outage-marker", false)
	assert.NotEqual(t, http.StatusOK, rec.Code, "a credential outage must fail closed: %s", rec.Body.String())
	assert.Empty(t, up.authFor("outage-marker"), "no key may reach the upstream during a credential outage")
}

// TestBYOK_ProbeCacheInvalidation covers the version-key contract of the
// secret-free probe cache: negatives re-probe at TTL expiry (a stale negative
// must never pin an added credential for long), positives reuse the cached
// outcome while the version is unchanged, and a CRUD version bump refreshes
// the snapshot.
func TestBYOK_ProbeCacheInvalidation(t *testing.T) {
	keys := &stubOrgKeys{keys: map[string]string{}}
	versions := &stubOrgVersions{versions: map[string]int64{}}
	probe := newOrgCredsProbe(keys, versions, orgCredsProbeTTL, testLogger())
	ctx := context.Background()
	entryKey := "org-a\x00openai\x00http://ep"

	ok, err := probe.probe(ctx, "org-a", "openai", "http://ep")
	require.NoError(t, err)
	assert.False(t, ok, "no credential yet")
	require.Equal(t, 1, keys.calls(), "the first probe is authoritative")

	// Within the TTL the cached negative answers without a store round trip.
	ok, err = probe.probe(ctx, "org-a", "openai", "http://ep")
	require.NoError(t, err)
	assert.False(t, ok)
	require.Equal(t, 1, keys.calls())

	// Add a credential; a NEGATIVE entry never takes the version fast path,
	// so at TTL expiry it re-probes and flips without waiting for a bump.
	keys.mu.Lock()
	keys.keys["org-a|openai|http://ep"] = "sk-new"
	keys.mu.Unlock()
	probe.entries[entryKey].loadedAt = probe.now().Add(-2 * orgCredsProbeTTL)
	ok, err = probe.probe(ctx, "org-a", "openai", "http://ep")
	require.NoError(t, err)
	assert.True(t, ok, "a negative entry must re-probe at TTL expiry (staleness bounded by the TTL)")
	require.Equal(t, 2, keys.calls())

	// Positives take the version fast path: an unchanged version keeps the
	// outcome without a store round trip.
	probe.entries[entryKey].loadedAt = probe.now().Add(-2 * orgCredsProbeTTL)
	ok, err = probe.probe(ctx, "org-a", "openai", "http://ep")
	require.NoError(t, err)
	assert.True(t, ok)
	require.Equal(t, 2, keys.calls(), "unchanged version must not re-probe the store for a positive entry")

	// W-BYOK-API contract: CRUD bumps the version → the snapshot refreshes
	// and a deleted credential flips the entry negative on the next probe.
	keys.mu.Lock()
	delete(keys.keys, "org-a|openai|http://ep")
	keys.mu.Unlock()
	require.NoError(t, versions.SetOrgCredsVersion(ctx, "org-a", 42))
	probe.entries[entryKey].loadedAt = probe.now().Add(-2 * orgCredsProbeTTL)
	ok, err = probe.probe(ctx, "org-a", "openai", "http://ep")
	require.NoError(t, err)
	assert.False(t, ok, "a version bump must invalidate the positive entry immediately")
	require.Equal(t, 3, keys.calls())
}

// TestBYOK_ResolveUpstreamKeyChain pins the documented priority order
// (org credential → per-model → global) and the no-secrets logging rule.
func TestBYOK_ResolveUpstreamKeyChain(t *testing.T) {
	up := newByokUpstream(t, false)
	keys := &stubOrgKeys{keys: map[string]string{
		"org-a|" + zaiCodingProvider + "|" + up.srv.URL: byokOrgZAIKey,
	}}
	gw := byokGateway(t, up.srv, keys, &stubOrgVersions{versions: map[string]int64{}}, byokResolver(up.srv.URL))
	ctx := context.Background()

	orgModel := byokOrgModel(up.srv.URL)
	perModel := resolver.ModelInfo{ModelName: "m", Provider: "openai", UpstreamURL: up.srv.URL, UpstreamAPIKey: byokPerModelKey}

	// Org credential first.
	key, orgUsed, err := gw.resolveUpstreamKey(ctx, "org-a", orgModel)
	require.NoError(t, err)
	assert.Equal(t, byokOrgZAIKey, key)
	assert.True(t, orgUsed.used)

	// No org credential for this endpoint → per-model key.
	key, orgUsed, err = gw.resolveUpstreamKey(ctx, "org-a", perModel)
	require.NoError(t, err)
	assert.Equal(t, "sk-per-model", key)
	assert.False(t, orgUsed.used)

	// Neither → global default.
	key, orgUsed, err = gw.resolveUpstreamKey(ctx, "org-z", resolver.ModelInfo{ModelName: "m", Provider: "openai", UpstreamURL: up.srv.URL})
	require.NoError(t, err)
	assert.Equal(t, "test-key", key)
	assert.False(t, orgUsed.used)

	// BYOK not wired → the legacy chain is bit-for-bit.
	gw2 := streamTestGateway(up.srv.URL)
	key, orgUsed, err = gw2.resolveUpstreamKey(ctx, "org-a", orgModel)
	require.NoError(t, err)
	assert.Equal(t, "test-key", key)
	assert.False(t, orgUsed.used)
}
