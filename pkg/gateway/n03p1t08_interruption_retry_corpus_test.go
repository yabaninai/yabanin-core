package cli

// N03P1T08: interruption / retry / resume corpus — the packet's negative
// scenario families at the stream entry path, pinned end-to-end through the
// real pipelines. The "no duplicates, no losses" law is asserted on the
// exact observables each family exposes:
//
//   - INT-01 client TCP disconnect mid-stream: the analytics capture keeps
//     every byte the upstream flushed (sseTee integrity), exactly one
//     request.failed is published, the termination taxonomy says
//     client_cancel, the prefix usage is estimated once, and the upstream
//     handler goroutine exits (no leak).
//   - INT-02 transport failure after [DONE]: the wire still ends at the
//     first [DONE] (clientSawDone guard), while the ledger honestly records
//     the drain failure with upstream_error and the provider usage billed
//     once. (T06 pinned the wire shape; the taxonomy/capture side is new.)
//   - RTY-01 connection-phase retry success: a 503-then-200 pair yields the
//     second attempt's stream byte-exactly once, RetryTotal counts the
//     retry, usage is billed once, and both attempts dial with the same
//     ensureStreamUsage body.
//   - RTY-02 retry exhaustion falls to the provider fallback: the client
//     sees only the winning hop, usage is billed once from the winning hop,
//     the event attributes AttemptCount to the chain.
//   - RTY-03 mid-stream break then a fresh client-driven retry: the failed
//     attempt bills its estimated prefix once, the retried request serves a
//     self-contained stream — no fragment of the broken attempt leaks into
//     the resumed one and no double billing.
//   - RSM-01 reconnect replay through the stream cache: the second request
//     replays every fragment exactly once with a single [DONE] and never
//     touches the upstream.
//   - ISO-01 cancel isolation: cancelling one of two concurrent clients
//     fails only its own stream; the survivor completes byte-exactly with
//     its own untouched upstream request.
//
// Existing coverage cited instead of duplicated: wire shapes of cancel /
// cancel-after-[DONE] / idle-watchdog (T04 stream_cancel_close_test.go),
// mixed-flow wire + ledger one-event-per-request + late-error hijack wire
// (T06 n03p1t06_joint_scenario_test.go), static boundaries (T07 corpus),
// JSON-path retry/fallback transport semantics (golden unknown-outcome),
// idle-timeout drain golden (TestGoldenEvent_ChatSSE_IdleTimeout_DrainFailed).
//
// Stable IDs: N03P1T08-INT-*, N03P1T08-RTY-*, N03P1T08-RSM-01, N03P1T08-ISO-01.

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/budget"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/retry"
	fallbackrouter "github.com/reireirei/yabanin/pkg/router"

	apierrs "github.com/reireirei/yabanin/pkg/apierrors"
	apierrors "github.com/reireirei/yabanin/pkg/errors"
)

const (
	n03p1t08Model = "gpt-4o"
	n03p1t08Org   = "org-t08"
)

// n03p1t08ChatBody is the streaming chat request every corpus test sends.
func n03p1t08ChatBody() string {
	return `{"model":"` + n03p1t08Model + `","stream":true,"messages":[{"role":"user","content":"t08"}]}`
}

// n03p1t08Frames is the deterministic upstream stream: role frame, two
// content fragments, a usage-carrying finish frame, and [DONE]. Provider
// usage: 11 prompt / 7 completion tokens.
func n03p1t08Frames() []string {
	const (
		head  = `data: {"id":"cmpl-t08","object":"chat.completion.chunk","created":1,"model":"` + n03p1t08Model + `","choices":[{"index":0,"delta":`
		tailM = `,"finish_reason":null}]}` + "\n\n"
	)
	return []string{
		head + `{"role":"assistant","content":""}` + tailM,
		head + `{"content":"alpha "}` + tailM,
		head + `{"content":"beta"}` + tailM,
		`data: {"id":"cmpl-t08","object":"chat.completion.chunk","created":1,"model":"` + n03p1t08Model +
			`","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}}` + "\n\n",
		"data: [DONE]\n\n",
	}
}

// n03p1t08FullStream joins the whole fixture.
func n03p1t08FullStream() string { return strings.Join(n03p1t08Frames(), "") }

// n03p1t08IdleSuffix is the exact client-visible tail the idle-watchdog
// drain failure writes (stream.go: the idle abort is reported distinctly
// from the generic "stream interrupted" frame), one [DONE] included.
func n03p1t08IdleSuffix() string {
	return string(apierrs.SSEErrorFrame(&apierrs.E{Type: apierrors.ErrorCodeAPI,
		Message: "upstream stream idle timeout"})) + "data: [DONE]\n\n"
}

// n03p1t08Gate returns the off-mode reservation gate whose only live duty in
// these tests is stamping Reservations + Termination on published events
// (attach requires a non-nil rsv; off mode skips admission entirely).
func n03p1t08Gate() *reservationGate {
	return &reservationGate{
		plan: &budget.Plan{Mode: budget.ModeOff},
		rsv: &budget.Reservation{OrgID: n03p1t08Org, Scopes: []budget.ScopeReserve{
			{Scope: budget.ScopeWallet, Key: n03p1t08Org, Bound: 1_000_000},
		}},
	}
}

// n03p1t08Front mounts the gateway on a real TCP listener whose single chat
// route stamps the reservation gate onto the request context and calls
// serveStream directly (the T06 rig pattern — full serveStream behavior,
// real sockets for the disconnect tests).
func n03p1t08Front(t *testing.T, gw *gateway, gate *reservationGate, reqID string) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read failed", http.StatusBadRequest)
			return
		}
		info := resolver.ModelInfo{ModelName: n03p1t08Model, Provider: "openai", Enabled: true}
		ctx := r.Context()
		if gate != nil {
			ctx = withReservationGate(ctx, gate)
		}
		gw.serveStream(w, ctx, info, body, false,
			"t08-sess", n03p1t08Org, "", "t08-task", reqID, testLogger(),
			routingDecision{}, "", 0, "", "", "", false)
	})
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	front, err := newGatewayHTTPServer(ln.Addr().String(), mux)
	require.NoError(t, err)
	go func() { _ = front.Serve(ln) }()
	t.Cleanup(func() { _ = front.Close() })
	return "http://" + ln.Addr().String()
}

// n03p1t08DisconnectingClient returns a client whose Body.Close() really
// tears the TCP connection down (no keep-alive reuse — the server must
// observe a disconnect, not a pooled idle connection).
func n03p1t08DisconnectingClient() *http.Client {
	return &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
}

// n03p1t08Post reads a streaming response: readAll drains to EOF (the
// interruption suffix included), readN consumes exactly n prefix bytes and
// then slams the connection shut.
type n03p1t08Resp struct {
	status int
	body   []byte
	err    error
}

func n03p1t08Post(ctx context.Context, client *http.Client, url, body string) <-chan n03p1t08Resp {
	out := make(chan n03p1t08Resp, 1)
	go func() {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url+"/v1/chat/completions",
			strings.NewReader(body))
		if err != nil {
			out <- n03p1t08Resp{err: err}
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			out <- n03p1t08Resp{err: err}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		out <- n03p1t08Resp{status: resp.StatusCode, body: b, err: err}
	}()
	return out
}

func n03p1t08PostDisconnect(client *http.Client, url, body string, n int) error {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		url+"/v1/chat/completions", strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_, err = io.CopyN(io.Discard, resp.Body, int64(n))
	if err != nil {
		_ = resp.Body.Close()
		return err
	}
	return resp.Body.Close() // real TCP disconnect (DisableKeepAlives)
}

// n03p1t08AwaitEvents waits for n published events and returns them.
func n03p1t08AwaitEvents(t *testing.T, cap *goldenCapture, n int) []*eventpub.Event {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		evs := cap.all()
		if len(evs) >= n {
			return evs
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d events, have %d", n, len(evs))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// n03p1t08Quiesce lets late events (if any) surface before a count pin.
func n03p1t08Quiesce(t *testing.T) {
	t.Helper()
	time.Sleep(150 * time.Millisecond)
}

// --- INT-01: client TCP disconnect mid-stream ---------------------------------

// TestN03P1T08_ClientDisconnect_CaptureIntegrity: a real TCP disconnect in
// the middle of the stream must not lose a single upstream byte from the
// analytics capture, must publish exactly one request.failed with the
// client_cancel taxonomy, must bill the prefix estimate once, and must let
// the upstream handler exit.
func TestN03P1T08_ClientDisconnect_CaptureIntegrity(t *testing.T) {
	frames := n03p1t08Frames()
	prefix := frames[0] + frames[1]
	upstreamExited := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, prefix)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-r.Context().Done() // aborts when the gateway cancels its upstream request
		close(upstreamExited)
	}))
	defer up.Close()

	gw := streamTestGateway(up.URL)
	gw.streamIdleTimeout = 5 * time.Second // the client abort must win, not silence
	gate := n03p1t08Gate()
	front := n03p1t08Front(t, gw, gate, "t08-req-int01")
	cap := captureAll(t)

	require.NoError(t, n03p1t08PostDisconnect(n03p1t08DisconnectingClient(), front,
		n03p1t08ChatBody(), len(prefix)))

	n03p1t08AwaitEvents(t, cap, 1) // block until the request's events land
	n03p1t08Quiesce(t)
	evs := cap.all()
	require.Len(t, evs, 1, "a disconnect publishes exactly one ledger event")
	ev := evs[0]
	assert.Equal(t, "request.failed", ev.EventType)
	assert.Equal(t, "client_cancel", ev.Termination,
		"the disconnect must be attributed to the client, not the upstream")
	assert.Equal(t, prefix, ev.UpstreamResponse,
		"the capture keeps every byte the upstream flushed before the abort — no loss")
	assert.Equal(t, 0, ev.RetryCount, "mid-stream failure never retries")
	assert.Equal(t, int64(200), ev.StatusCode)
	assert.Equal(t, n03p1t08Model, ev.ModelUsed)
	assert.Equal(t, "estimated", ev.UsageSource, "no usage chunk arrived — prefix is estimated")
	assert.Positive(t, ev.TokensIn, "the prefix prompt is billed, not silently dropped")
	assert.True(t, strings.HasPrefix(ev.Error, "stream drain failed: "), "got %q", ev.Error)

	select {
	case <-upstreamExited:
	case <-time.After(5 * time.Second):
		t.Fatal("the upstream handler goroutine did not exit after the disconnect")
	}
}

// --- INT-02: transport failure after [DONE] -----------------------------------

// TestN03P1T08_UpstreamDiesAfterDone_NoSecondTerminal: the upstream sends a
// complete stream (usage chunk and [DONE] included) and then the connection
// dies without the terminal chunked-encoding zero block. The client still
// receives a stream that ends at the first [DONE] — no drain-failure frame
// appended — while the ledger records the honest drain failure with
// upstream_error and the provider usage billed exactly once.
func TestN03P1T08_UpstreamDiesAfterDone_NoSecondTerminal(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, rw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		payload := n03p1t08FullStream()
		// Raw chunked framing: the complete payload — [DONE] included — in
		// one body chunk, then the connection dies WITHOUT the terminal
		// 0-chunk (ErrUnexpectedEOF on the drain, not a clean end).
		_, _ = fmt.Fprintf(rw, "HTTP/1.1 200 OK\r\n"+
			"Content-Type: text/event-stream\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"Connection: close\r\n"+
			"\r\n%x\r\n%s\r\n", len(payload), payload)
		_ = rw.Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(500 * time.Millisecond):
		}
	}))
	defer up.Close()

	gw := streamTestGateway(up.URL)
	gw.streamIdleTimeout = 5 * time.Second
	gate := n03p1t08Gate()
	front := n03p1t08Front(t, gw, gate, "t08-req-int02")
	cap := captureAll(t)

	res := <-n03p1t08Post(context.Background(), n03p1t08DisconnectingClient(), front, n03p1t08ChatBody())
	require.NoError(t, res.err)
	require.Equal(t, 200, res.status)

	body := string(res.body)
	assert.Equal(t, 1, strings.Count(body, "data: [DONE]"),
		"exactly one [DONE] reaches the client")
	assert.True(t, strings.HasSuffix(body, "data: [DONE]\n\n"),
		"the wire ends at the first [DONE] — no drain-failure appendage: %q", body)
	assert.NotContains(t, body, "stream interrupted")

	n03p1t08AwaitEvents(t, cap, 1) // block until the request's events land
	n03p1t08Quiesce(t)
	evs := cap.all()
	require.Len(t, evs, 1)
	ev := evs[0]
	assert.Equal(t, "request.failed", ev.EventType,
		"the transport failure is recorded even though the client saw a complete stream")
	assert.Equal(t, "upstream_error", ev.Termination)
	assert.True(t, strings.HasPrefix(ev.Error, "stream drain failed: "), "got %q", ev.Error)
	assert.Equal(t, n03p1t08FullStream(), ev.UpstreamResponse,
		"the capture keeps the complete upstream bytes — no loss, no truncation")
	assert.Equal(t, "provider", ev.UsageSource, "the usage chunk arrived and is honored")
	assert.Equal(t, int64(11), ev.TokensIn)
	assert.Equal(t, int64(7), ev.TokensOut, "usage is billed once, not duplicated per frame")
	assert.Equal(t, 0, ev.RetryCount)
}

// --- RTY-01: connection-phase retry success -----------------------------------

// TestN03P1T08_ConnectionRetry_SecondAttemptByteExact: attempt 1 fails with
// a transient 503 before any streaming byte; attempt 2 serves the full
// stream. The client receives attempt 2's stream exactly once, usage is
// billed once, the retry is counted on the event and on RetryTotal, and
// both attempts dial with the same include_usage body.
func TestN03P1T08_ConnectionRetry_SecondAttemptByteExact(t *testing.T) {
	var (
		mu     sync.Mutex
		bodies []string
		hits   atomic.Int32
	)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		if hits.Add(1) == 1 {
			http.Error(w, "transient", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, n03p1t08FullStream())
	}))
	defer up.Close()

	gw := streamTestGateway(up.URL)
	gw.retryPolicy = retry.Policy{MaxAttempts: 2, BaseDelay: time.Nanosecond, MaxDelay: time.Nanosecond}
	gw.streamUsageProviders = map[string]bool{"openai": true} // RM-03: inject stream_options.include_usage on this provider
	gw.res = stubModelResolver{
		n03p1t08Model: {ModelName: n03p1t08Model, Provider: "openai", UpstreamURL: up.URL, Enabled: true},
	}
	cap := captureAll(t)
	retryBefore := testutil.ToFloat64(metrics.RetryTotal.WithLabelValues("1", "200"))

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(n03p1t08ChatBody()))
	r.Header.Set("Content-Type", "application/json")
	goldenIdentity(r)
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, int32(2), hits.Load(), "exactly two upstream connection attempts")

	body := rec.Body.String()
	assert.Equal(t, n03p1t08FullStream(), body,
		"the client receives attempt 2's stream byte-exactly once")
	assert.Equal(t, 1, strings.Count(body, "alpha "))
	assert.Equal(t, 1, strings.Count(body, "beta"))
	assert.Equal(t, 1, strings.Count(body, "data: [DONE]"))

	mu.Lock()
	require.Len(t, bodies, 2)
	b1, b2 := bodies[0], bodies[1]
	mu.Unlock()
	assert.Equal(t, b1, b2, "ensureStreamUsage is computed once per hop, outside the retry closure")
	assert.Contains(t, b1, `"include_usage":true`, "both attempts request the usage chunk")

	n03p1t08AwaitEvents(t, cap, 1) // block until the request's events land
	n03p1t08Quiesce(t)
	evs := cap.all()
	require.Len(t, evs, 1, "retrying the connection phase must not double-publish")
	ev := evs[0]
	assert.Equal(t, "request.completed", ev.EventType)
	assert.Equal(t, 1, ev.RetryCount, "the event reports exactly the one retry")
	assert.Equal(t, 1, ev.AttemptCount)
	assert.Equal(t, "provider", ev.UsageSource)
	assert.Equal(t, int64(11), ev.TokensIn, "usage billed once — the failed attempt carries none")
	assert.Equal(t, int64(7), ev.TokensOut)
	assert.Equal(t, n03p1t08FullStream(), ev.UpstreamResponse)

	assert.InDelta(t, retryBefore+1,
		testutil.ToFloat64(metrics.RetryTotal.WithLabelValues("1", "200")), 1e-9,
		"RetryTotal{attempt=1,status=200} counts the single retry — the label carries the hop's FINAL dial status")
}

// --- RTY-02: retry exhaustion falls to the provider fallback ------------------

// TestN03P1T08_RetryExhausted_FallbackServesOnce: the primary 503s through
// its whole retry budget, the fallback hop serves the stream. The client
// sees only the winning hop's bytes; usage is billed once from the winning
// hop and the event attributes the full chain (AttemptCount across hops).
func TestN03P1T08_RetryExhausted_FallbackServesOnce(t *testing.T) {
	var primaryHits, fallbackHits atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		primaryHits.Add(1)
		http.Error(w, "transient", http.StatusServiceUnavailable)
	}))
	defer primary.Close()
	fallbackUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		fallbackHits.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, n03p1t08FullStream())
	}))
	defer fallbackUp.Close()

	gw := streamTestGateway(primary.URL)
	gw.retryPolicy = retry.Policy{MaxAttempts: 2, BaseDelay: time.Nanosecond, MaxDelay: time.Nanosecond}
	gw.res = stubModelResolver{
		n03p1t08Model: {ModelName: n03p1t08Model, Provider: "openai", UpstreamURL: primary.URL,
			Enabled: true, FailoverModels: []string{"fallback"}},
		"fallback": {ModelName: "fallback", Provider: "openai", UpstreamURL: fallbackUp.URL, Enabled: true},
	}
	// The chain resolver lives on the FallbackExecutor itself (buildChain):
	// without it hop 2 is a name-only ModelInfo and never dials the
	// fallback endpoint.
	gw.fallback = fallbackrouter.NewFallbackExecutor(gw.res, 3, nil)
	cap := captureAll(t)

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/chat/completions", strings.NewReader(n03p1t08ChatBody()))
	r.Header.Set("Content-Type", "application/json")
	goldenIdentity(r)
	rec := httptest.NewRecorder()
	gw.chatCompletions(rec, r)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, int32(2), primaryHits.Load(),
		"the primary is dialed through its in-hop retry budget (503 retried once)")
	assert.Equal(t, int32(1), fallbackHits.Load(), "the fallback serves exactly once")

	body := rec.Body.String()
	assert.Equal(t, n03p1t08FullStream(), body,
		"only the winning hop's stream reaches the client — no primary bytes, no duplication")

	n03p1t08AwaitEvents(t, cap, 1) // block until the request's events land
	n03p1t08Quiesce(t)
	evs := cap.all()
	require.Len(t, evs, 1, "the chain publishes exactly one ledger event")
	ev := evs[0]
	assert.Equal(t, "request.completed", ev.EventType)
	assert.Equal(t, "fallback", ev.ModelUsed, "the event attributes the winning hop")
	assert.Equal(t, 2, ev.AttemptCount, "two chain outcomes: primary exhausted, fallback won")
	assert.Equal(t, 1, ev.RetryCount, "exactly the primary's single in-hop dial retry")
	assert.Equal(t, "provider", ev.UsageSource)
	assert.Equal(t, int64(11), ev.TokensIn, "usage billed once, from the winning hop only")
	assert.Equal(t, int64(7), ev.TokensOut)
}

// --- RTY-03: mid-stream break, then a fresh client-driven retry ---------------

// TestN03P1T08_MidStreamBreak_FreshRetrySelfContained: attempt 1 breaks in
// the middle of the stream (idle watchdog aborts the silent upstream). The
// ledger bills its estimated prefix once. The client's retry is a NEW
// request that serves the full stream self-contained — no fragment of the
// broken attempt leaks into it, and the two attempts are billed separately.
func TestN03P1T08_MidStreamBreak_FreshRetrySelfContained(t *testing.T) {
	frames := n03p1t08Frames()
	prefix := frames[0] + frames[1]
	var hits atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		if hits.Add(1) == 1 {
			_, _ = io.WriteString(w, prefix)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			<-r.Context().Done() // silent until the watchdog aborts
			return
		}
		_, _ = io.WriteString(w, n03p1t08FullStream())
	}))
	defer up.Close()

	gw := streamTestGateway(up.URL)
	gw.streamIdleTimeout = 120 * time.Millisecond
	cap := captureAll(t)
	post := func() *httptest.ResponseRecorder {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
			"/v1/chat/completions", strings.NewReader(n03p1t08ChatBody()))
		r.Header.Set("Content-Type", "application/json")
		goldenIdentity(r)
		// The termination taxonomy (§5.3 Finalize) is stamped by the
		// reservation gate's attach; stamp the off-mode gate directly.
		r = r.WithContext(withReservationGate(r.Context(), n03p1t08Gate()))
		rec := httptest.NewRecorder()
		gw.chatCompletions(rec, r)
		return rec
	}

	rec1 := post()
	require.Equal(t, http.StatusOK, rec1.Code, rec1.Body.String())
	assert.Equal(t, prefix+n03p1t08IdleSuffix(), rec1.Body.String(),
		"attempt 1's wire carries its prefix plus the idle error frame and nothing fabricated")
	assert.Equal(t, 1, strings.Count(rec1.Body.String(), "data: [DONE]"),
		"the broken attempt still terminates its own wire exactly once")

	rec2 := post()
	require.Equal(t, http.StatusOK, rec2.Code, rec2.Body.String())
	assert.Equal(t, n03p1t08FullStream(), rec2.Body.String(),
		"the resumed request is self-contained — each fragment exactly once")
	assert.Equal(t, 1, strings.Count(rec2.Body.String(), "alpha "))
	assert.Equal(t, 1, strings.Count(rec2.Body.String(), "data: [DONE]"))
	assert.Equal(t, int32(2), hits.Load())

	n03p1t08AwaitEvents(t, cap, 2) // block until both requests' events land
	n03p1t08Quiesce(t)
	evs := cap.all()
	require.Len(t, evs, 2, "two requests, two events — never merged, never duplicated")
	failed, completed := evs[0], evs[1]
	assert.Equal(t, "request.failed", failed.EventType)
	assert.Equal(t, "idle_timeout", failed.Termination)
	assert.Equal(t, "estimated", failed.UsageSource)
	assert.Equal(t, prefix, failed.UpstreamResponse, "attempt 1's capture is its own prefix")

	assert.Equal(t, "request.completed", completed.EventType)
	assert.Equal(t, "provider", completed.UsageSource)
	assert.Equal(t, int64(11), completed.TokensIn, "each attempt is billed exactly once, separately")
	assert.Equal(t, int64(7), completed.TokensOut)
	assert.Equal(t, n03p1t08FullStream(), completed.UpstreamResponse,
		"attempt 2's capture is complete and self-contained")
}

// --- RSM-01: reconnect replay through the stream cache ------------------------

// TestN03P1T08_ReconnectReplay_EachFragmentOnce: the first request streams
// and warms the exact cache; a retrying client with the identical body is
// served from the cache without touching the upstream — every fragment
// replayed exactly once, a single [DONE], and the ledger attributes the
// hit without billing upstream usage again.
func TestN03P1T08_ReconnectReplay_EachFragmentOnce(t *testing.T) {
	var hits atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		hits.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, n03p1t08FullStream())
	}))
	defer up.Close()

	gw := goldenChatGateway(t, up.URL)
	gw.cfg.CacheStreamEnabled = true
	c := newRT05Cache()
	gw.cache = c
	cap := captureAll(t)
	post := func() *httptest.ResponseRecorder {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
			"/v1/chat/completions", strings.NewReader(n03p1t08ChatBody()))
		r.Header.Set("Content-Type", "application/json")
		goldenIdentity(r)
		rec := httptest.NewRecorder()
		gw.chatCompletions(rec, r)
		return rec
	}

	rec1 := post()
	require.Equal(t, http.StatusOK, rec1.Code, rec1.Body.String())
	assert.Equal(t, n03p1t08FullStream(), rec1.Body.String())
	deadline := time.Now().Add(5 * time.Second)
	for {
		c.mu.Lock()
		writes := c.writes
		c.mu.Unlock()
		if writes >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the async stream-cache writer never persisted the completion")
		}
		time.Sleep(10 * time.Millisecond)
	}

	rec2 := post()
	require.Equal(t, http.StatusOK, rec2.Code, rec2.Body.String())
	assert.Equal(t, "EXACT", rec2.Header().Get("X-Cache"), "the retry is served from the exact cache")
	body := rec2.Body.String()
	assert.Equal(t, 1, strings.Count(body, "alpha "), "each fragment replays exactly once")
	assert.Equal(t, 1, strings.Count(body, "beta"))
	assert.Equal(t, 1, strings.Count(body, "data: [DONE]"), "exactly one terminal")
	assert.Equal(t, int32(1), hits.Load(), "the replay never touches the upstream")

	n03p1t08AwaitEvents(t, cap, 2) // block until both requests' events land
	n03p1t08Quiesce(t)
	evs := cap.all()
	require.Len(t, evs, 2)
	completed, replay := evs[0], evs[1]
	assert.Equal(t, "request.completed", completed.EventType)
	assert.Equal(t, "provider", completed.UsageSource,
		"the first (upstream) attempt is billed from its usage chunk")
	assert.Equal(t, int64(11), completed.TokensIn)
	assert.Equal(t, int64(7), completed.TokensOut)
	assert.Equal(t, "request.completed", replay.EventType)
	assert.Equal(t, "exact", replay.CacheHitType)
	assert.Equal(t, "cache_hit", replay.CostStatus)
	assert.Empty(t, replay.UpstreamResponse, "a cache replay carries no upstream capture")
	assert.Equal(t, "none", replay.UsageSource,
		"the replay bills no upstream usage — the hit is priced counterfactually instead")
	assert.Positive(t, replay.CounterfactualCostUSD,
		"the counterfactual prices the cached completion as if it had gone upstream")
}

// --- ISO-01: cancel isolation between concurrent clients ----------------------

// TestN03P1T08_CancelIsolation_SurvivorByteExact: two concurrent clients
// share the upstream server but never a stream. Cancelling client A mid
// stream fails only A's ledger entry; client B's upstream request is not
// cancelled and B completes byte-exactly with provider usage billed once.
func TestN03P1T08_CancelIsolation_SurvivorByteExact(t *testing.T) {
	frames := n03p1t08Frames()
	prefix := frames[0] + frames[1]
	rest := frames[2] + frames[3] + frames[4]

	releaseB := make(chan struct{})
	var (
		mu      sync.Mutex
		ctxErrs = map[int]error{}
		seq     atomic.Int32
	)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, prefix)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		id := int(seq.Add(1)) // A connects first, B second
		var err error
		if id == 1 {
			<-r.Context().Done() // A: dies with its client
			err = r.Context().Err()
		} else {
			select {
			case <-releaseB: // B: kept alive, then completes
				_, err2 := io.WriteString(w, rest)
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				err = err2
			case <-r.Context().Done():
				err = r.Context().Err()
			}
		}
		mu.Lock()
		ctxErrs[id] = err
		mu.Unlock()
	}))
	defer up.Close()

	gw := streamTestGateway(up.URL)
	gw.streamIdleTimeout = 5 * time.Second
	gate := n03p1t08Gate()
	front := n03p1t08Front(t, gw, gate, "t08-req-iso01")
	cap := captureAll(t)
	client := n03p1t08DisconnectingClient()

	// A connects and consumes only the prefix, then disconnects.
	require.NoError(t, n03p1t08PostDisconnect(client, front, n03p1t08ChatBody(), len(prefix)))
	n03p1t08AwaitEvents(t, cap, 1) // block until A's failure lands on the ledger

	// B streams to EOF; releasing its upstream hop lets the survivor finish
	// (B's handler parks on releaseB once its prefix is flushed).
	resCh := n03p1t08Post(context.Background(), client, front, n03p1t08ChatBody())
	close(releaseB)
	resB := <-resCh
	require.NoError(t, resB.err)
	require.Equal(t, 200, resB.status)
	n03p1t08AwaitEvents(t, cap, 2) // block until both events land
	n03p1t08Quiesce(t)
	evs := cap.all()
	require.Len(t, evs, 2, "one ledger entry per request — the cancel must not merge or duplicate")

	var evA, evB *eventpub.Event
	for _, ev := range evs {
		switch ev.Termination {
		case "client_cancel":
			evA = ev
		case "completed":
			evB = ev
		}
	}
	require.NotNil(t, evA, "A's failure must carry the client_cancel taxonomy: %+v", evs)
	require.NotNil(t, evB, "B must complete: %+v", evs)
	assert.Equal(t, "request.failed", evA.EventType)
	assert.Equal(t, prefix, evA.UpstreamResponse, "A's capture keeps its prefix — no loss")
	assert.Equal(t, "request.completed", evB.EventType)
	assert.Equal(t, n03p1t08FullStream(), evB.UpstreamResponse, "B's capture is complete")
	assert.Equal(t, "provider", evB.UsageSource)
	assert.Equal(t, int64(11), evB.TokensIn, "B is billed once for its own usage only")
	assert.Equal(t, int64(7), evB.TokensOut)
	assert.Equal(t, n03p1t08FullStream(), string(resB.body),
		"B's wire is byte-exact despite A's concurrent disconnect")
	assert.Equal(t, 1, strings.Count(string(resB.body), "data: [DONE]"))

	mu.Lock()
	defer mu.Unlock()
	require.ErrorIs(t, ctxErrs[1], context.Canceled,
		"A's upstream request was cancelled with its client")
	assert.NoError(t, ctxErrs[2],
		"B's upstream request outlived A's cancel untouched")
}
