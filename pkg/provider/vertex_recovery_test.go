package provider

// N08-P03-T08 recovery corpus (packet N08-P03 — «Повтор и восстановление»):
// interruption/retry/resume and recovery WITHOUT duplicate work and WITHOUT
// losses, over the packet surfaces. The ADC legs continue aspect 3 of the
// boundary corpus (vertex_regression_test.go) on the recovery paths the
// earlier corpora pinned only sequentially or only on the happy path:
//
//   - cooldown lapse → CONCURRENT re-admission (T07 pinned the sequential
//     lapse): N callers arriving at a lapsed park produce exactly ONE
//     recovery exchange and all receive the fresh token;
//   - transient non-429 outage (HTTP 500): the failing exchange is
//     singleflight-deduplicated (no retry storm), parks NO cooldown (only a
//     429 may park — immediate retry stays permitted), caches nothing, and
//     a healed endpoint admits exactly one recovery exchange;
//
// The stream/leg and the remaining ADC legs join in later commits; see the
// work record for the full duplication map against T03–T07.
//
// Determinism: exact counters and token identities; delays only widen the
// singleflight window (the established 80ms pattern) and every assertion
// runs after wg.Wait, so nothing depends on the schedule.

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVertexRecovery_CooldownLapseConcurrentRecovery pins the concurrent
// half of the cooldown-lapse recovery (TestVertexRegression_CooldownLapseReAdmitsBinding
// pins the sequential one): N callers arriving at a binding whose cooldown
// has just lapsed produce exactly ONE recovery exchange; the winner clears
// the stale entry, every caller — winner and waiters alike — receives the
// fresh token, and no cooldown residue remains.
func TestVertexRecovery_CooldownLapseConcurrentRecovery(t *testing.T) {
	tokenSrv := newVertexTokenRecorder(t)
	tokenSrv.status.Store(http.StatusTooManyRequests) // no Retry-After → base cooldown
	keyPath, _, _ := writeVertexSAKeyFile(t, tokenSrv.srv.URL)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", keyPath)
	adc := plainVertexADC(tokenSrv.srv)
	creds := VertexCredentials{Project: "api-proj-0001", Location: "us-central1"}

	_, err := adc.token(creds)
	require.ErrorContains(t, err, "rate-limited")
	require.Equal(t, int64(1), tokenSrv.hits.Load())

	// Force the single cooldown entry into the past (adc.mu seam, same as
	// the sequential lapse test) — the binding is re-admitted but has no
	// cached token, so the next wave must exchange exactly once.
	adc.mu.Lock()
	require.Len(t, adc.cooldowns, 1, "the park wrote exactly one entry")
	for key := range adc.cooldowns {
		adc.cooldowns[key] = time.Now().Add(-time.Second)
	}
	adc.mu.Unlock()

	tokenSrv.status.Store(0)
	tokenSrv.bodyToken.Store("VT-2")
	tokenSrv.delay.Store(80) // widen the singleflight window

	const n = 8
	results := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = adc.token(creds)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "caller %d", i)
		assert.Equal(t, "VT-2", results[i], "caller %d must receive the recovery token", i)
	}
	require.Equal(t, int64(2), tokenSrv.hits.Load(),
		"park + exactly ONE concurrent recovery exchange — no duplicate work at the lapse")
	adc.mu.Lock()
	cooldowns := len(adc.cooldowns)
	tokens := len(adc.tokens)
	adc.mu.Unlock()
	assert.Zero(t, cooldowns, "the recovery exchange cleared the stale cooldown")
	assert.Equal(t, 1, tokens, "exactly the fresh token is cached — no stale duplicate entry")
}

// TestVertexRecovery_TransientOutageConcurrentRetry pins the retry contract
// for a transient NON-429 token-endpoint outage (TestVertexADC429Cooldown
// pins the 429 variant): the failing exchange is singleflight-deduplicated
// (N concurrent callers → exactly ONE failing HTTP exchange, no retry
// storm), the failure parks NO cooldown (only a rate limit may park —
// immediate retry stays permitted) and caches nothing; once the endpoint
// heals, exactly ONE recovery exchange serves every caller.
func TestVertexRecovery_TransientOutageConcurrentRetry(t *testing.T) {
	tokenSrv := newVertexTokenRecorder(t)
	tokenSrv.status.Store(http.StatusInternalServerError)
	tokenSrv.delay.Store(80)
	keyPath, _, _ := writeVertexSAKeyFile(t, tokenSrv.srv.URL)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", keyPath)
	adc := plainVertexADC(tokenSrv.srv)
	creds := VertexCredentials{Project: "api-proj-0001", Location: "us-central1"}

	// Outage phase: one shared failing exchange, every caller refused.
	const n = 8
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = adc.token(creds)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		require.ErrorContains(t, err, "token exchange HTTP 500", "caller %d", i)
	}
	require.Equal(t, int64(1), tokenSrv.hits.Load(),
		"concurrent callers share ONE failing exchange — no retry storm")

	adc.mu.Lock()
	cooldowns, tokens := len(adc.cooldowns), len(adc.tokens)
	adc.mu.Unlock()
	assert.Zero(t, cooldowns, "a non-429 failure must NOT park the binding behind a cooldown")
	assert.Zero(t, tokens, "a failed exchange must cache nothing")

	// Heal: exactly one recovery exchange serves the whole concurrent wave.
	tokenSrv.status.Store(0)
	tokenSrv.bodyToken.Store("VT-OK")
	results := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = adc.token(creds)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		require.NoError(t, err, "caller %d", i)
		assert.Equal(t, "VT-OK", results[i], "caller %d must receive the recovery token", i)
	}
	require.Equal(t, int64(2), tokenSrv.hits.Load(),
		"outage + heal = exactly two exchanges total, one per phase")
	adc.mu.Lock()
	cooldowns, tokens = len(adc.cooldowns), len(adc.tokens)
	adc.mu.Unlock()
	assert.Zero(t, cooldowns)
	assert.Equal(t, 1, tokens, "the cache holds exactly the recovered token — no residue")
}

// vertexCachedTokens snapshots the set of cached access tokens (identity-
// free: assertions key on token VALUES, not the binding-key string format).
func vertexCachedTokens(t *testing.T, adc *vertexADC) map[string]bool {
	t.Helper()
	adc.mu.Lock()
	defer adc.mu.Unlock()
	out := make(map[string]bool, len(adc.tokens))
	for _, tok := range adc.tokens {
		out[tok.accessToken] = true
	}
	return out
}

// TestVertexRecovery_OutageSiblingUnharmed pins loss-free recovery across
// bindings: a transient outage of binding B's exchange must leave sibling
// binding A's healthy cached token untouched (the non-429 twin of the T05
// 429 isolation), and B's recovery mints its own token without disturbing
// or re-exchanging A.
func TestVertexRecovery_OutageSiblingUnharmed(t *testing.T) {
	tokenSrv := newVertexTokenRecorder(t)
	keyPath, _, _ := writeVertexSAKeyFile(t, tokenSrv.srv.URL)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", keyPath)
	adc := plainVertexADC(tokenSrv.srv)
	credsA := VertexCredentials{Project: "api-proj-0001", Location: "us-central1"}
	credsB := VertexCredentials{Project: "api-proj-0002", Location: "us-central1"}

	tokenSrv.bodyToken.Store("VT-A")
	tokA, err := adc.token(credsA)
	require.NoError(t, err)
	require.Equal(t, "VT-A", tokA)
	require.Equal(t, int64(1), tokenSrv.hits.Load())

	// B's cold exchange runs into a 500 outage: refused, nothing written.
	tokenSrv.status.Store(http.StatusInternalServerError)
	_, err = adc.token(credsB)
	require.ErrorContains(t, err, "token exchange HTTP 500")
	require.Equal(t, int64(2), tokenSrv.hits.Load())
	adc.mu.Lock()
	cooldowns := len(adc.cooldowns)
	adc.mu.Unlock()
	assert.Zero(t, cooldowns, "the outage parks nothing (only a 429 may)")
	assert.Equal(t, map[string]bool{"VT-A": true}, vertexCachedTokens(t, adc),
		"the outage must not evict or alter the sibling's healthy token")

	// Heal: B recovers with its OWN token; the cache holds both bindings.
	tokenSrv.status.Store(0)
	tokenSrv.bodyToken.Store("VT-B")
	tokB, err := adc.token(credsB)
	require.NoError(t, err)
	require.Equal(t, "VT-B", tokB)
	require.Equal(t, int64(3), tokenSrv.hits.Load())
	assert.Equal(t, map[string]bool{"VT-A": true, "VT-B": true}, vertexCachedTokens(t, adc),
		"both bindings keep exactly their own token — no duplicates, no losses")

	// A rides its cache untouched by B's outage-and-recovery episode.
	tokA, err = adc.token(credsA)
	require.NoError(t, err)
	assert.Equal(t, "VT-A", tokA, "the sibling keeps its pre-outage token")
	require.Equal(t, int64(3), tokenSrv.hits.Load(),
		"A was never re-exchanged: the outage cost zero sibling work")
}

// TestVertexRecovery_ResolutionOutageThenConcurrentMount pins the chain-
// resolution recovery race (TestVertexADCResolutionFailure_NotPinned pins
// it sequentially): while the configured credential is missing, N
// concurrent callers all fail closed with ZERO network work and no fall
// through to a weaker source (packet negative); once the credential
// appears, the SAME adapter recovers with exactly one walk+exchange for
// the whole concurrent wave; afterwards the pinned source and cached token
// survive the credential file's disappearance without a re-walk.
func TestVertexRecovery_ResolutionOutageThenConcurrentMount(t *testing.T) {
	tokenSrv := newVertexTokenRecorder(t)
	keyPath := filepath.Join(t.TempDir(), "late-key.json")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", keyPath)

	userSrv := newVertexTokenRecorder(t)

	adc := plainVertexADC(tokenSrv.srv)
	adc.oauthTokenURL = userSrv.srv.URL // must NEVER be consulted (no fallback)
	creds := VertexCredentials{Project: "api-proj-0001", Location: "us-central1"}

	// Resolution outage: every concurrent caller fails closed.
	const n = 8
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = adc.token(creds)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		require.ErrorContains(t, err, "GOOGLE_APPLICATION_CREDENTIALS is set but unusable", "caller %d", i)
	}
	require.Zero(t, tokenSrv.hits.Load(), "a resolution outage reaches no token endpoint")
	require.Zero(t, userSrv.hits.Load(), "a failed walk must not fall through to the weaker source")
	adc.mu.Lock()
	pinned := adc.pinned
	adc.mu.Unlock()
	assert.False(t, pinned, "a failed walk is never pinned")

	// The credential appears (volume mount): one walk+exchange serves all.
	writeVertexSAKeyFileAt(t, keyPath, tokenSrv.srv.URL)
	tokenSrv.delay.Store(80)
	results := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = adc.token(creds)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		require.NoError(t, err, "caller %d", i)
		assert.Equal(t, "VT-1", results[i], "caller %d must receive the mounted credential's token", i)
	}
	require.Equal(t, int64(1), tokenSrv.hits.Load(),
		"the whole recovery wave shares ONE walk+exchange")
	require.Zero(t, userSrv.hits.Load(), "recovery must not fall back either")
	adc.mu.Lock()
	pinned = adc.pinned
	adc.mu.Unlock()
	assert.True(t, pinned, "the successful recovery pins the source")

	// The credential volume disappears again: the pinned source and cached
	// token ride on — no re-walk, no lost binding.
	require.NoError(t, os.Remove(keyPath))
	tok, err := adc.token(creds)
	require.NoError(t, err)
	assert.Equal(t, "VT-1", tok, "cache serves across the credential's disappearance")
	assert.Equal(t, int64(1), tokenSrv.hits.Load(), "no re-exchange after recovery")
	require.Zero(t, userSrv.hits.Load(), "and still no fallback")
}

// TestVertexRecovery_StreamInterruptedThenCleanResume pins result recovery
// on the stream surface, end-to-end through the joint rig: a session
// interrupted mid-flight (in-band upstream error after flushed content —
// the 2d12f19 refusal shape pinned by TestVertexRegression_StreamInBandErrorWins)
// is followed by a CLEAN resumed session on the same adapter: the complete
// transcript with no frames of the broken session (no duplicates), no
// missing content, exactly one [DONE], the resumed session's own usage
// re-parsed by the billing path, and no duplicate token exchange — the
// resume rides the cached ADC token.
func TestVertexRecovery_StreamInterruptedThenCleanResume(t *testing.T) {
	const sseBroken = "data: " + `{"candidates":[{"content":{"role":"model","parts":[{"text":"частично "}]}}]}` + "\n\n" +
		"data: " + `{"error":{"code":403,"message":"request denied","status":"PERMISSION_DENIED"}}` + "\n\n"
	const sseFull = "data: " + `{"candidates":[{"content":{"role":"model","parts":[{"text":"восстановлен"}]}}]}` + "\n\n" +
		"data: " + `{"candidates":[{"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":7,"candidatesTokenCount":2,"totalTokenCount":9}}` + "\n\n"
	rig := newVertexJointRig(t, "", sseBroken)
	body := `{"model":"gemini-2.0-flash","messages":[{"role":"user","content":"hi"}]}`

	// Session 1: interrupted mid-stream — partial content is on the wire,
	// the error surfaces, the stream never completes.
	raw, _, err := rig.streamTurn(t, body, rig.credsA)
	require.ErrorContains(t, err, "vertex stream error (status PERMISSION_DENIED)")
	assert.Contains(t, raw, "частично", "already-flushed content stays on the wire")
	assert.NotContains(t, raw, "[DONE]", "an interrupted session never completes cleanly")
	hits, minted := rig.tokenSrv.snapshot()
	require.Equal(t, 1, hits)
	require.Equal(t, 1, minted)

	// Session 2: the resume — complete, clean, self-contained.
	rig.upstream.setReplies("", sseFull)
	var usage Usage
	raw, usage, err = rig.streamTurn(t, body, rig.credsA)
	require.NoError(t, err)

	assert.NotContains(t, raw, "частично", "no residue of the interrupted session")
	assert.Equal(t, 1, strings.Count(raw, "[DONE]"), "exactly one completion marker")
	chunks := parseVertexStreamFrames(t, raw)
	require.Len(t, chunks, 4, "role + content + finish + usage-only, got:\n%s", raw)
	assert.Equal(t, map[string]any{"role": "assistant"}, vertexChoice(t, chunks[0])["delta"])
	assert.Equal(t, map[string]any{"content": "восстановлен"}, vertexChoice(t, chunks[1])["delta"],
		"the resumed session's content is complete, nothing lost")
	assert.Equal(t, "stop", vertexChoice(t, chunks[2])["finish_reason"])
	wantUsage := Usage{PromptTokens: 7, CompletionTokens: 2, TotalTokens: 9, Source: UsageSourceProvider}
	assert.Equal(t, wantUsage, usage, "the resumed session reports its OWN usage only")
	usageChunk, err := json.Marshal(chunks[3])
	require.NoError(t, err)
	assert.Equal(t, wantUsage, (*Vertex)(nil).ParseUsage(usageChunk), "billing path re-parses the resumed usage")

	// The resume rode the SAME cached token: no duplicate exchange, and
	// each session authenticated its own upstream request with it.
	reqs := rig.upstream.snapshot()
	require.Len(t, reqs, 2)
	assert.Equal(t, "Bearer JT-1", reqs[0].auth)
	assert.Equal(t, "Bearer JT-1", reqs[1].auth, "the resume reuses the cached token")
	hits, minted = rig.tokenSrv.snapshot()
	assert.Equal(t, 1, hits, "no duplicate token exchange across the interruption boundary")
	assert.Equal(t, 1, minted)
}
