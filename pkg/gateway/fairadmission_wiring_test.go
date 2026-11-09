package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/batchstore"
	"github.com/reireirei/yabanin/pkg/retry"
	"github.com/reireirei/yabanin/pkg/router"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RATELIMIT-FALLBACK P3: the N09-P02 FairAdmission surface is wired into the
// gateway's single admission site — OFF by default (bit-for-bit legacy
// path), and when enabled it bounds per-replica in-flight concurrency with
// per-tenant isolation, bounded queueing, and shed backpressure (429 +
// Retry-After in the same seconds form as every other gateway hint). The
// ticket is anchored to the request context, so no handler changes and no
// slot can leak past ServeHTTP return.

const n07rlOKCompletion = `{"id":"chatcmpl-rl","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`

// n07rlPostChatBG posts a chat request with a background context (for
// in-flight goroutines whose lifetime the test joins explicitly).
func n07rlPostChatBG(t *testing.T, gw *gateway, body string, headers map[string][]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	gw.routes(r)
	r.ServeHTTP(rec, req)
	return rec
}

// n07rlServeGateway mounts the gateway routes on a real HTTP server. The
// release-dependent pins must run against real server lifecycle: net/http
// cancels the request context when ServeHTTP returns, which is exactly the
// production signal the ticket release is anchored to. (Recorder-based
// requests carry a never-canceling context and cannot exercise it.)
func n07rlServeGateway(t *testing.T, gw *gateway) *httptest.Server {
	t.Helper()
	r := chi.NewRouter()
	gw.routes(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

// n07rlPostReal posts a chat request to a real mounted server and returns
// status, Retry-After, body and error. It contains no assertions on
// purpose: testifylint's go-require forbids require.* in a helper that is
// also invoked from test goroutines (FailNow must stay on the test
// goroutine). Callers assert on the returned error at their join points.
// deadline bounds the wait so a wiring defect fails the test instead of
// hanging it.
func n07rlPostReal(t *testing.T, srv *httptest.Server, body string, headers map[string][]string, deadline time.Duration) (int, string, string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/v1/chat/completions", strings.NewReader(body))
	if err != nil {
		return 0, "", "", err
	}
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, "", "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, resp.Header.Get("Retry-After"), "", err
	}
	return resp.StatusCode, resp.Header.Get("Retry-After"), string(raw), nil
}

func TestFairAdmission_OffByDefaultPinsLegacyPath(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(n07rlOKCompletion))
	}))
	defer up.Close()

	gw := n03p6t06ChatGateway(t, up.URL)
	require.Nil(t, gw.fair, "off by default: no admission object may be constructed")

	rec := n07rlPostChatBG(t, gw, n03p6t06OpenAIPlainBody, nil)
	require.Equal(t, http.StatusOK, rec.Code,
		"the legacy path must serve the request untouched when the gate is off")
}

// TestFairAdmission_ShedsSameTenant_DifferentTenantStillAdmitted pins the
// isolation bound: one tenant holding its per-tenant slots is shed while
// another tenant keeps headroom under the global capacity — and the released
// slot becomes available again for the next same-tenant request.
func TestFairAdmission_ShedsSameTenant_DifferentTenantStillAdmitted(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	var upstreamHits atomic.Int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if upstreamHits.Add(1) == 1 {
			close(started) // the first request reached the upstream
		}
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(n07rlOKCompletion))
	}))
	defer up.Close()

	gw := n03p6t06ChatGateway(t, up.URL)
	gw.retryPolicy = retry.Policy{MaxAttempts: 1}
	gw.fair = router.NewFairAdmission(router.FairAdmissionConfig{
		Capacity:       2,
		MaxPerTenant:   1,
		QueueLimit:     0, // shed immediately, no waiting
		ShedRetryAfter: time.Second,
		ShedJitter:     0, // deterministic hint: exactly 1s → header "1"
	})
	gwSrv := n07rlServeGateway(t, gw)

	type res struct {
		code       int
		retryAfter string
		body       string
		err        error
	}
	res1 := make(chan res, 1)
	go func() {
		code, ra, body, err := n07rlPostReal(t, gwSrv, n03p6t06OpenAIPlainBody, nil, 5*time.Second)
		res1 <- res{code, ra, body, err}
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("first request never reached the upstream")
	}

	// Same tenant at its per-tenant bound: shed immediately (no queue).
	code, ra, body, err := n07rlPostReal(t, gwSrv, n03p6t06OpenAIPlainBody, nil, 5*time.Second)
	require.NoError(t, err)
	require.Equal(t, http.StatusTooManyRequests, code,
		"same tenant at its per-tenant bound must shed immediately (no queue)")
	assert.Equal(t, "1", ra, "hint 1s with zero jitter surfaces as the seconds form '1'")
	secs, err := strconv.Atoi(ra)
	require.NoError(t, err, "SDK clients parse the plain seconds form")
	assert.Equal(t, 1, secs)
	assert.Contains(t, body, "rate_limit_exceeded")
	assert.Contains(t, body, "tenant_limit")

	// Different tenant: keeps headroom under the global capacity. Its dial
	// blocks on the fixture until release, so observe it in the background.
	res3 := make(chan res, 1)
	go func() {
		c, _, b, e := n07rlPostReal(t, gwSrv, n03p6t06OpenAIPlainBody,
			map[string][]string{"X-Yabanin-Workload": {"other-tenant"}}, 5*time.Second)
		res3 <- res{c, "", b, e}
	}()
	waitFor(t, 5*time.Second, func() bool { return upstreamHits.Load() == 2 },
		"the other tenant's request was never admitted to the upstream")
	close(release)

	var r1, r3 res
	select {
	case r1 = <-res1:
	case <-time.After(5 * time.Second):
		t.Fatal("first request never completed after release")
	}
	select {
	case r3 = <-res3:
	case <-time.After(5 * time.Second):
		t.Fatal("other tenant's request never completed after release")
	}
	require.NoError(t, r1.err)
	require.NoError(t, r3.err)
	assert.Equal(t, http.StatusOK, r1.code)
	assert.Equal(t, http.StatusOK, r3.code,
		"a different tenant must keep headroom under the global capacity")
	assert.Equal(t, int64(2), upstreamHits.Load(),
		"exactly two dials: the shed request must never reach the upstream")

	// Leak pin: after both requests returned, ServeHTTP return must have
	// released their tickets — the same tenant is admitted again.
	code, _, _, err = n07rlPostReal(t, gwSrv, n03p6t06OpenAIPlainBody, nil, 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, code,
		"the slot must be free after ServeHTTP returned: no ticket may leak")
}

// waitFor polls cond until it holds or the deadline passes (a bounded
// substitute for observing cross-goroutine readiness without sleeps).
func waitFor(t *testing.T, d time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal(msg)
}

// TestFairAdmission_QueuesThenGrants pins bounded queueing: when queueing is
// enabled a saturated tenant's next request waits and is granted once a slot
// frees — instead of being shed. Runs on a real server so the release anchor
// (request-context cancellation on ServeHTTP return) fires like production.
func TestFairAdmission_QueuesThenGrants(t *testing.T) {
	firstDone := make(chan struct{})
	started := make(chan struct{})
	var upstreamHits atomic.Int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if upstreamHits.Add(1) == 1 {
			close(started)
		}
		// Hold the first dial briefly even after firstDone closes, so the
		// second request (launched right after close) deterministically
		// enqueues while capacity 1 is still held, then gets granted.
		time.Sleep(100 * time.Millisecond)
		<-firstDone
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(n07rlOKCompletion))
	}))
	defer up.Close()

	gw := n03p6t06ChatGateway(t, up.URL)
	gw.retryPolicy = retry.Policy{MaxAttempts: 1}
	gw.fair = router.NewFairAdmission(router.FairAdmissionConfig{
		Capacity:       1,
		MaxPerTenant:   0, // no isolation: capacity is the only bound
		QueueLimit:     4,
		WaitTimeout:    2 * time.Second,
		ShedRetryAfter: time.Second,
		ShedJitter:     0,
	})
	gwSrv := n07rlServeGateway(t, gw)

	type res struct {
		code       int
		retryAfter string
		err        error
	}
	res1 := make(chan res, 1)
	go func() {
		c, ra, _, e := n07rlPostReal(t, gwSrv, n03p6t06OpenAIPlainBody, nil, 5*time.Second)
		res1 <- res{c, ra, e}
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("first request never reached the upstream")
	}

	res2 := make(chan res, 1)
	go func() {
		c, ra, _, e := n07rlPostReal(t, gwSrv, n03p6t06OpenAIPlainBody, nil, 5*time.Second)
		res2 <- res{c, ra, e}
	}()

	close(firstDone)
	select {
	case r1 := <-res1:
		require.NoError(t, r1.err)
		assert.Equal(t, http.StatusOK, r1.code)
	case <-time.After(5 * time.Second):
		t.Fatal("first request never completed")
	}
	select {
	case r2 := <-res2:
		require.NoError(t, r2.err)
		assert.Equal(t, http.StatusOK, r2.code,
			"the queued request must be granted once the slot frees, not shed")
		assert.Empty(t, r2.retryAfter)
	case <-time.After(5 * time.Second):
		t.Fatal("queued request was never granted")
	}
	assert.Equal(t, int64(2), upstreamHits.Load())
}

// TestFairAdmission_ReleaseFreesSlotSequentially pins the leak-free ticket
// anchor: with capacity 1 and no queue, back-to-back requests must each be
// admitted — a slot held past ServeHTTP return would 429 the next request.
func TestFairAdmission_ReleaseFreesSlotSequentially(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(n07rlOKCompletion))
	}))
	defer up.Close()

	gw := n03p6t06ChatGateway(t, up.URL)
	gw.retryPolicy = retry.Policy{MaxAttempts: 1}
	gw.fair = router.NewFairAdmission(router.FairAdmissionConfig{
		Capacity:       1,
		QueueLimit:     0,
		ShedRetryAfter: time.Second,
		ShedJitter:     0,
	})
	gwSrv := n07rlServeGateway(t, gw)

	for i := 0; i < 3; i++ {
		code, _, _, err := n07rlPostReal(t, gwSrv, n03p6t06OpenAIPlainBody, nil, 5*time.Second)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code, "request %d: the slot must be free after the previous request returned", i+1)
	}
}

// TestFairAdmission_BatchLineReleasesSlotPerLine is the batch-path mirror of
// TestFairAdmission_ReleaseFreesSlotSequentially and pins the F1 fix
// (RATELIMIT-FALLBACK lane review 2026-11-02): the executor synthesizes each
// line's request over its long-lived context, so the line must end both of
// its release anchors — the per-line context cancel in batchLineRunner
// (AfterFunc backstop) and chatCompletions' synchronous ticket Release on
// return. The sync anchor is mandatory: context.AfterFunc fires in its own
// goroutine, which cannot order the release before the next line's Admit in
// the tight executor loop. Capacity 1 with no queue: three back-to-back
// lines (N > Capacity) must all be admitted, and an interactive request
// after the batch keeps headroom. Before the fix, line 1 held its slot
// forever and line 2 shed with 429.
func TestFairAdmission_BatchLineReleasesSlotPerLine(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(n07rlOKCompletion))
	}))
	defer up.Close()

	gw := n03p6t06ChatGateway(t, up.URL)
	gw.fair = router.NewFairAdmission(router.FairAdmissionConfig{
		Capacity:       1,
		QueueLimit:     0,
		ShedRetryAfter: time.Second,
		ShedJitter:     0,
	})

	b := &batchstore.Batch{ID: "batch_f1", OrgID: "org-batch", APIKeyID: "key-batch"}
	for i := 1; i <= 3; i++ {
		ln := batchstore.Line{
			BatchID:     b.ID,
			LineNo:      i,
			CustomID:    fmt.Sprintf("c%d", i),
			RequestID:   fmt.Sprintf("req_batch_f1_%d", i),
			RequestBody: []byte(n03p6t06OpenAIPlainBody),
		}
		// The executor's context never cancels (long-lived server ctx) —
		// exactly the production shape the release anchor must survive.
		res := gw.batchLineRunner(context.Background(), b, ln)
		require.Equal(t, http.StatusOK, res.Status,
			"line %d: the previous line's slot must be free after its LineResult returned: %s", i, string(res.Body))
	}

	// After the batch, every slot is released again: interactive traffic
	// must be admitted, not shed at an exhausted capacity.
	rec := n07rlPostChatBG(t, gw, n03p6t06OpenAIPlainBody, nil)
	require.Equal(t, http.StatusOK, rec.Code,
		"post-batch requests must be admitted: no batch line may leak a slot: %s", rec.Body.String())
}

// TestFairAdmission_DeadContextNoWrite pins the cancel discipline: a request
// whose context is already dead is refused WITHOUT writing a response —
// response ownership belongs to whoever canceled (client disconnect /
// timeout middleware).
func TestFairAdmission_DeadContextNoWrite(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(n07rlOKCompletion))
	}))
	defer up.Close()

	gw := n03p6t06ChatGateway(t, up.URL)
	gw.fair = router.NewFairAdmission(router.FairAdmissionConfig{
		Capacity:       4,
		QueueLimit:     0,
		ShedRetryAfter: time.Second,
		ShedJitter:     0,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // dead on arrival
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/chat/completions", strings.NewReader(n03p6t06OpenAIPlainBody))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	out, ok := gw.admissionCore(rec, req, testLogger(), admissionCoreInput{
		Model:           "gpt-4o",
		Body:            []byte(n03p6t06OpenAIPlainBody),
		SkipSpendChecks: true,
	})

	assert.False(t, ok, "a dead-context request must not be admitted")
	assert.Equal(t, admissionCore{}, out)
	assert.Equal(t, http.StatusOK, rec.Code, "nothing may be written: the recorder's implicit 200 stays untouched")
	assert.Empty(t, rec.Body.String(), "no bytes may be flushed on the cancel path")
}

// TestFairAdmission_ShedHelpers pins the shed render helpers: whole-second
// ceil with the 60s client-facing ceiling, and the message shape that
// mirrors the key rate limit wording.
func TestFairAdmission_ShedHelpers(t *testing.T) {
	for _, tc := range []struct {
		name string
		hint time.Duration
		want int
	}{
		{"zero hint omitted", 0, 0},
		{"negative hint omitted", -time.Second, 0},
		{"exact second", time.Second, 1},
		{"upward jitter ceil", 1200 * time.Millisecond, 2},
		{"above ceiling clamps", 90 * time.Second, 60},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, fairShedRetryAfterSeconds(tc.hint))
		})
	}

	assert.Contains(t, fairShedMessage(1, router.ShedCapacity), "retry in 1s")
	assert.Contains(t, fairShedMessage(1, router.ShedTenantLimit), "tenant_limit")
	assert.NotContains(t, fairShedMessage(0, router.ShedQueueFull), "retry in",
		"no hint configured: the message must not fabricate a wait time")
}
