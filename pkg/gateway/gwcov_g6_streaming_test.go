package cli

// G6 coverage recovery: independent fault-injection and behavioral tests for
// the zero-coverage blocks in realtime_endpoint.go, stream.go,
// messages_native.go, responses_native.go and upstream.go. Each test targets
// the production refusal/fault branch named in its comment; no production
// file is modified. All helpers carry the g6 prefix; every upstream is an
// httptest loopback server (no network egress).

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/apiformat"
	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/evalgate"
	routehint "github.com/reireirei/yabanin/pkg/gateway/internal/routehint"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/upstream"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

var (
	errG6Read  = errors.New("g6: upstream read failed")
	errG6Facts = errors.New("g6: terminal facts store down")
	errG6Admit = errors.New("g6: invocation admit down")
)

type g6ErrReader struct{}

func (g6ErrReader) Read(p []byte) (int, error) { return 0, errG6Read }

// g6NoFlushWriter is an http.ResponseWriter without Flush: serveStream must
// refuse the stream before dialing upstream (stream.go 547).
type g6NoFlushWriter struct {
	header http.Header
	body   strings.Builder
	code   int
}

func (w *g6NoFlushWriter) Header() http.Header         { return w.header }
func (w *g6NoFlushWriter) Write(p []byte) (int, error) { return w.body.Write(p) }
func (w *g6NoFlushWriter) WriteHeader(code int)        { w.code = code }

// g6ShortWriter under-reports every non-empty write so writeSSEBytes hits its
// io.ErrShortWrite guard (stream.go 2110).
type g6ShortWriter struct{}

func (g6ShortWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return len(p) - 1, nil
}

// g6DiscardWriter accepts and flushes everything (realtime relay sink).
type g6DiscardWriter struct{ flushed int }

func (w *g6DiscardWriter) Header() http.Header         { return http.Header{} }
func (w *g6DiscardWriter) WriteHeader(int)             {}
func (w *g6DiscardWriter) Write(p []byte) (int, error) { return len(p), nil }
func (w *g6DiscardWriter) Flush()                      { w.flushed++ }

// g6FailFlushWriter combines failWritesWriter with a Flush method.
type g6FailFlushWriter struct{ failWritesWriter }

func (g6FailFlushWriter) Flush() {}

// g6RepeatReader streams its chunk until `remaining` bytes were emitted.
type g6RepeatReader struct {
	chunk     []byte
	remaining int64
}

func (r *g6RepeatReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	n := 0
	for n < len(p) && r.remaining > 0 {
		c := copy(p[n:], r.chunk)
		if c == 0 {
			break
		}
		n += c
		r.remaining -= int64(c)
	}
	return n, nil
}

// g6SetFileSizeLimit caps writes through the filesystem so the terminal
// hold's spill writes fail with EFBIG (realtime 752/757). Restored on cleanup.
func g6SetFileSizeLimit(t *testing.T, soft int64) {
	t.Helper()
	var old syscall.Rlimit
	require.NoError(t, syscall.Getrlimit(syscall.RLIMIT_FSIZE, &old))
	require.NoError(t, syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{
		Cur: uint64(soft), Max: old.Max,
	}))
	t.Cleanup(func() { _ = syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old) })
}

// g6AdmittedFactsErrCtx admits an invocation on gw's store, then arms a
// terminal-facts fault: finishers run their ferr branches (the provider work
// already happened) while admission stays clean.
func g6AdmittedFactsErrCtx(t *testing.T, gw *gateway) context.Context {
	t.Helper()
	id := newInvocationIdentity(testOrg, "g6-req", "g6-sess", "7", "9", "m1")
	require.NoError(t, id.beginPaidDispatch(t.Context(), gw.invocations, invocationKindStream))
	gw.invocations.(*fakeInvocationStore).factsErr = errG6Facts
	return withInvocationIdentity(context.Background(), id)
}

// g6ServeStream mirrors streamPolicyPostAsync (resolver, info, gate, arg
// list) but takes the caller's context so tests can carry an invocation
// identity. Synchronous: waits for serveStream to return.
func g6ServeStream(t *testing.T, gw *gateway, body string, ctx context.Context) *syncRecorder {
	t.Helper()
	gw.res = stubModelResolver{
		"m1": {ModelName: "m1", Provider: "openai", UpstreamURL: gw.cfg.Provider, Enabled: true},
	}
	info := rt06TestResolve(gw, "m1")
	r := httptest.NewRequestWithContext(ctx, http.MethodPost,
		"/v1/chat/completions", strings.NewReader(body))
	gateCtx := withReservationGate(r.Context(), &reservationGate{
		plan: &budget.Plan{Mode: budget.ModeOff},
		// Fully-populated wallet tuple: the terminal projection validates
		// reservation tuples (allowance id, period) before the store seam.
		rsv: &budget.Reservation{OrgID: testOrg, Scopes: []budget.ScopeReserve{
			{Scope: budget.ScopeWallet, Key: testOrg, Period: "", AllowanceID: 1, Bound: 1_000_000},
		}},
	})
	rec := newSyncRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		gw.serveStream(rec, gateCtx, info, []byte(body), false, "sess", testOrg, "", "task", "req",
			testLogger(), routingDecision{From: "m1"}, "", 0, "", "", "", false)
	}()
	<-done
	return rec
}

// g6PostResponsesWithHint posts /v1/responses with a route hint in the
// context (responses_native 62: foreign hint refuses with 400).
func g6PostResponsesWithHint(t *testing.T, gw *gateway, body, hint string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(routehint.WithHint(t.Context(), hint),
		http.MethodPost, "/v1/responses", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	gw.routes(r)
	r.ServeHTTP(rec, req)
	return rec
}

func g6ResponsesAttachment(endpoint string) adminstore.PolicyAttachment {
	return adminstore.PolicyAttachment{KeyLabel: "", ModelPattern: "*", Endpoint: endpoint, Priority: 10}
}

// g6NativeResponsesGateway wires the native /v1/responses route exactly like
// the existing native tests: provider allowlist + the default "m" resolver.
func g6NativeResponsesGateway(t *testing.T, upstreamURL string) *gateway {
	t.Helper()
	gw := responsesTestGateway(t, upstreamURL)
	gw.cfg.ResponsesNativeProviders = []string{"openai"}
	return gw
}

// g6FactsStore returns gw's invocation store cast for fault assertions.
func g6FactsStore(gw *gateway) *fakeInvocationStore { return gw.invocations.(*fakeInvocationStore) }

// ---------------------------------------------------------------------------
// upstream.go
// ---------------------------------------------------------------------------

// TestGWCovG6_CallUpstreamSingle_GuardRefusals covers upstream.go 489/494/499:
// empty model, unconfigured upstream and an uninitialisable pool client each
// refuse before any dispatch.
func TestGWCovG6_CallUpstreamSingle_GuardRefusals(t *testing.T) {
	gw := streamTestGateway("http://127.0.0.1:1")
	body := []byte(`{"messages":[{"role":"user","content":"hi"}]}`)
	ctx := t.Context()

	t.Run("empty model", func(t *testing.T) {
		_, err := gw.callUpstreamSingle(ctx, resolver.ModelInfo{}, body)
		require.ErrorContains(t, err, "empty premium model")
	})

	t.Run("no upstream configured", func(t *testing.T) {
		_, err := gw.callUpstreamSingle(ctx, resolver.ModelInfo{ModelName: "g6m"}, body)
		require.ErrorContains(t, err, "no upstream configured for model g6m")
	})

	t.Run("client construction refused", func(t *testing.T) {
		gw.pool = upstream.NewPool(upstream.Options{})
		_, err := gw.callUpstreamSingle(ctx,
			resolver.ModelInfo{ModelName: "g6m", UpstreamURL: "ftp://example.invalid"}, body)
		require.ErrorContains(t, err, "resolve upstream client for model g6m")
	})
}

// ---------------------------------------------------------------------------
// stream.go
// ---------------------------------------------------------------------------

// TestGWCovG6_StreamAdmit_NonFlusherRefusedBeforeUpstream covers stream.go
// 547-552: a non-flushing client gets 501 + the streaming refusal envelope
// and no upstream dial happens.
func TestGWCovG6_StreamAdmit_NonFlusherRefusedBeforeUpstream(t *testing.T) {
	gw := streamTestGateway("http://127.0.0.1:1")
	w := &g6NoFlushWriter{header: make(http.Header)}
	r := &streamRun{gw: gw, w: w, ctx: t.Context(), l: testLogger(),
		body: []byte(`{"model":"m1","messages":[{"role":"user","content":"hi"}]}`)}
	flusher, ok := r.admit(resolver.ModelInfo{ModelName: "m1", Provider: "openai", Enabled: true})
	require.False(t, ok)
	require.Nil(t, flusher)
	require.Equal(t, http.StatusNotImplemented, w.code)
	require.Contains(t, w.body.String(), "streaming not supported")
}

// TestGWCovG6_StreamConnect_UnknownOutcomeRefusal covers stream.go 658-665:
// the upstream accepts the request then dies without a response; the client
// is told the outcome is unknown and that no retry happened.
func TestGWCovG6_StreamConnect_UnknownOutcomeRefusal(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		panic(http.ErrAbortHandler)
	}))
	t.Cleanup(up.Close)
	gw := streamTestGateway(up.URL)
	rec := g6ServeStream(t, gw, `{"model":"m1","messages":[{"role":"user","content":"hi"}]}`, t.Context())
	require.Contains(t, rec.body(), "upstream outcome unknown; request was not retried")

	t.Run("no upstream status defaults to 502", func(t *testing.T) {
		// Direct finalize call: an unknown-outcome failure that carries no
		// upstream status at all renders 502, never an invalid zero status.
		gw := streamTestGateway("http://127.0.0.1:1")
		w := httptest.NewRecorder()
		r := &streamRun{
			gw: gw, w: w, ctx: t.Context(), l: testLogger(),
			gate: &reservationGate{
				plan: &budget.Plan{Mode: budget.ModeOff},
				rsv: &budget.Reservation{OrgID: testOrg, Scopes: []budget.ScopeReserve{
					{Scope: budget.ScopeWallet, Key: testOrg, Period: "", AllowanceID: 1, Bound: 1_000_000},
				}},
			},
			lastErr:  unknownOutcomeError(errG6Read),
			lastCode: 0,
		}
		r.finishConnectFailure()
		require.Equal(t, http.StatusBadGateway, w.Code)
		require.Contains(t, w.Body.String(), "upstream outcome unknown; request was not retried")
	})
}

// TestGWCovG6_StreamConnect_ExhaustionFactsFailure covers stream.go 742-744:
// after connect exhaustion the terminal facts commit fails and is logged
// without changing the client answer.
func TestGWCovG6_StreamConnect_ExhaustionFactsFailure(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("g6-upstream-down"))
	}))
	t.Cleanup(up.Close)
	gw := streamTestGateway(up.URL)
	ctx := g6AdmittedFactsErrCtx(t, gw)
	rec := g6ServeStream(t, gw, `{"model":"m1","messages":[{"role":"user","content":"hi"}]}`, ctx)
	require.Equal(t, 1, g6FactsStore(gw).factsCalls)
	require.NotEmpty(t, rec.body())
}

// TestGWCovG6_SSEPassthroughTail_CompleteSingleLF covers stream.go 941: a
// torn tail whose last byte was a bare LF is closed with exactly one LF.
func TestGWCovG6_SSEPassthroughTail_CompleteSingleLF(t *testing.T) {
	rec := httptest.NewRecorder()
	tail := &ssePassthroughTail{w: rec, total: 5, run: 1}
	tail.complete()
	require.Equal(t, "\n", rec.Body.String())
}

// TestGWCovG6_StreamPolicyDenied_FactsFailureDropsTerminator covers
// stream.go 1110-1114: on a terminal-facts failure the policy-denied
// finisher drops the held [DONE] terminator — the client never sees a clean
// end after a denied stream whose accounting could not commit.
func TestGWCovG6_StreamPolicyDenied_FactsFailureDropsTerminator(t *testing.T) {
	up := newStreamPolicyUpstream(t, 0, streamChunkFrame("g6c", "g6 says g6denyword"))
	gw := withUpstream(streamPolicyGateway(t, PolicyModeEnforce, streamDenyPrefixYAML("g6denyword")), up.srv.URL)
	ctx := g6AdmittedFactsErrCtx(t, gw)
	rec := g6ServeStream(t, gw,
		`{"model":"m1","messages":[{"role":"user","content":"please say g6denyword"}]}`, ctx)
	require.Equal(t, 1, g6FactsStore(gw).factsCalls)
	require.NotContains(t, rec.body(), "[DONE]")
	require.NotContains(t, rec.body(), "g6denyword")
}

// TestGWCovG6_StreamDrainFailure_FactsFailure covers stream.go 1548-1550: a
// mid-stream upstream abort after partial delivery notifies the client, and
// the failed facts commit is logged rather than retried.
func TestGWCovG6_StreamDrainFailure_FactsFailure(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		_, _ = w.Write([]byte("data: " + streamChunkFrame("g6c", "par") + "\n\n"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		panic(http.ErrAbortHandler)
	}))
	t.Cleanup(up.Close)
	gw := streamTestGateway(up.URL)
	ctx := g6AdmittedFactsErrCtx(t, gw)
	rec := g6ServeStream(t, gw, `{"model":"m1","messages":[{"role":"user","content":"hi"}]}`, ctx)
	require.Equal(t, 1, g6FactsStore(gw).factsCalls)
	require.Contains(t, rec.body(), "stream interrupted")
}

// TestGWCovG6_RecordStreamEvalgateSkip_CheapResponseUnavailable covers
// stream.go 1681-1682: a cheap-response gate that cannot sample takes its
// skip branch and records nothing.
func TestGWCovG6_RecordStreamEvalgateSkip_CheapResponseUnavailable(t *testing.T) {
	gw := responsesTestGateway(t, "http://127.0.0.1:1")
	// Non-nil judge/verdict store plus an org id reach the sampling gate;
	// a non-"medium" class then takes the 1681 skip return.
	gw.judge = evalgate.NewJudge("http://127.0.0.1:1", nil)
	gw.evalStore = newFakeVerdictStore()
	r := &streamRun{gw: gw, orgID: testOrg, classifierClass: "low", l: testLogger()}
	require.NotPanics(t, func() { r.recordStreamEvalgateSkip() })
}

// TestGWCovG6_SuccessEvent_MissingDonePartialEnvelope covers stream.go
// 1733-1734: history captured a terminal-delivered stream without its [DONE]
// frame; the event's processed response is marked partial with the missing
// terminator note while keeping the visible text.
func TestGWCovG6_SuccessEvent_MissingDonePartialEnvelope(t *testing.T) {
	// Fresh watch: the stream's [DONE] frame never passed through it, so
	// neither clientTerminalDelivered nor doneHoldPending can be true.
	dw := newSSETerminalWatch(httptest.NewRecorder())
	require.False(t, dw.sawDone())

	cap0 := newResponseHistoryCapture(httptest.NewRecorder())
	_, werr := cap0.Write([]byte("data: " + streamChunkFrame("g6c", "hi") + "\n\n"))
	require.NoError(t, werr)

	gw := responsesTestGateway(t, "http://127.0.0.1:1")
	r := &streamRun{
		gw: gw, ctx: t.Context(), l: testLogger(),
		reqID: "g6-req", sessionID: "g6-sess", orgID: testOrg,
		dec:       routingDecision{From: "m1"},
		finalInfo: resolver.ModelInfo{ModelName: "g6m", Provider: "openai"},
		history:   cap0,
		sseTee:    &boundedBuffer{},
		doneWatch: dw,
	}
	base := r.successEvent(provider.Anthropic{}.ParseUsage([]byte(`{"input_tokens":3,"output_tokens":1}`)), provider.ExtendedUsage{}, 0, 0, false)
	require.Contains(t, base.ProcessedResponse, "partial")
	require.Contains(t, base.ProcessedResponse, "missing_done_frame")
	require.Contains(t, base.ProcessedResponse, "hi")
}

// TestGWCovG6_SSETerminalWatch_NilSafety covers stream.go 2004-2005 and
// 2032-2033: the watch methods are nil-receiver safe.
func TestGWCovG6_SSETerminalWatch_NilSafety(t *testing.T) {
	var sw *sseTerminalWatch
	require.NotPanics(t, func() {
		sw.releaseDoneHold()
		sw.failDoneHold()
	})
	require.False(t, sw.doneHoldPending())
}

// TestGWCovG6_SSETerminalWatch_ArmedWriteFailures covers stream.go 2079-2080
// (an ordinary held line whose client write fails) and 2098-2099 (the
// captured [DONE] prefix flush fails while the next line arrives mid-prefix).
func TestGWCovG6_SSETerminalWatch_ArmedWriteFailures(t *testing.T) {
	sw := newSSETerminalWatch(&failWritesWriter{})
	sw.armDoneHold()
	_, err := sw.Write([]byte("data: {\"x\":1}\n\n"))
	require.ErrorIs(t, err, errClientGoneWrite)

	sw2 := newSSETerminalWatch(&failWritesWriter{})
	sw2.armDoneHold()
	_, err = sw2.Write([]byte("data: [DO"))
	require.NoError(t, err) // captured as the held prefix, nothing written yet
	_, err = sw2.Write([]byte("zz\n"))
	require.ErrorIs(t, err, errClientGoneWrite)
}

// TestGWCovG6_WriteSSEBytes_ShortWrite covers stream.go 2110-2111: an
// under-reporting writer surfaces io.ErrShortWrite.
func TestGWCovG6_WriteSSEBytes_ShortWrite(t *testing.T) {
	n, err := writeSSEBytes(g6ShortWriter{}, []byte("g6-bytes"))
	require.ErrorIs(t, err, io.ErrShortWrite)
	require.Equal(t, len("g6-bytes")-1, n)
}

// ---------------------------------------------------------------------------
// responses_native.go
// ---------------------------------------------------------------------------

const g6ResponsesSuccess = `{"id":"resp_g6","object":"response","status":"completed",` +
	`"usage":{"input_tokens":5,"output_tokens":2},` +
	`"output":[{"type":"message","content":[{"type":"output_text","text":"hello"}]}]}`

// TestGWCovG6_Responses_EntryGuardRefusals covers responses_native.go
// 42-44 (no pool), 62-63 (foreign route hint), 68-69 (history outage) and
// 72-73 (uninitialisable upstream client).
func TestGWCovG6_Responses_EntryGuardRefusals(t *testing.T) {
	body := `{"model":"m","input":"hi"}`

	t.Run("no upstream pool", func(t *testing.T) {
		gw := g6NativeResponsesGateway(t, "http://127.0.0.1:1")
		gw.pool = nil
		rec := postResponses(t, gw, body)
		require.Equal(t, http.StatusBadGateway, rec.Code)
		require.Contains(t, rec.Body.String(), "upstream is not configured")
	})

	t.Run("foreign route hint refused", func(t *testing.T) {
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(g6ResponsesSuccess))
		}))
		t.Cleanup(up.Close)
		gw := g6NativeResponsesGateway(t, up.URL)
		rec := g6PostResponsesWithHint(t, gw, body, "meta")
		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.NotEmpty(t, rec.Body.String())
	})

	t.Run("history outage denies", func(t *testing.T) {
		gw := g6NativeResponsesGateway(t, "http://127.0.0.1:1")
		gw.admission = historyOnlyController(t,
			stubHistoryProbe{state: budget.HistoryStateWriteUnavailable}, budget.HistoryModeReject)
		rec := postResponses(t, gw, body)
		require.Equal(t, http.StatusServiceUnavailable, rec.Code)
		require.Contains(t, rec.Body.String(), "history_unavailable")
	})

	t.Run("uninitialisable upstream client", func(t *testing.T) {
		gw := g6NativeResponsesGateway(t, "http://127.0.0.1:1")
		gw.res = stubModelResolver{"m": {
			ModelName: "m", Provider: "openai", UpstreamURL: "ftp://example.invalid", Enabled: true,
		}}
		rec := postResponses(t, gw, body)
		require.Equal(t, http.StatusBadGateway, rec.Code)
		require.Contains(t, rec.Body.String(), "failed to initialise upstream client")
	})
}

// TestGWCovG6_Responses_PolicyDenied_Enforce covers responses_native.go
// 115-127: a post-upstream deny answers 400 without leaking the trigger
// word, both with a healthy facts store and with a facts failure (120-122).
func TestGWCovG6_Responses_PolicyDenied_Enforce(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"resp_g6","object":"response","status":"completed",` +
			`"usage":{"input_tokens":5,"output_tokens":2},` +
			`"output":[{"type":"message","content":[{"type":"output_text","text":"g6leaked secret"}]}]}`))
	}))
	t.Cleanup(up.Close)

	newGateway := func(t *testing.T) *gateway {
		gw := g6NativeResponsesGateway(t, up.URL)
		store := newFakePolicyStore()
		store.add("org-test", adminstore.PolicyPipeline{
			ID: "g6-pol", OrgID: "org-test", Name: "g6-responses-deny",
			Enabled: true, CurrentVersion: 1,
		}, map[int]string{1: n03p6t09PostDenyYAML("g6-native-deny", "g6leaked")},
			[]adminstore.PolicyAttachment{g6ResponsesAttachment("responses")})
		gw.policyRuntime = newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeEnforce)
		return gw
	}

	t.Run("clean denial hides the trigger", func(t *testing.T) {
		gw := newGateway(t)
		rec := postResponses(t, gw, `{"model":"m","input":"hi"}`)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.NotContains(t, rec.Body.String(), "g6leaked")
	})

	t.Run("facts failure still denies", func(t *testing.T) {
		gw := newGateway(t)
		gw.invocations = &fakeInvocationStore{factsErr: errG6Facts}
		rec := postResponses(t, gw, `{"model":"m","input":"hi"}`)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Equal(t, 1, g6FactsStore(gw).factsCalls)
	})

	t.Run("policy pass-through keeps the body", func(t *testing.T) {
		// The pipeline runs post-upstream without a denial: the masked
		// body replaces the buffered one and the 200 forward proceeds.
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"resp_g6","object":"response","status":"completed",` +
				`"usage":{"input_tokens":5,"output_tokens":2},` +
				`"output":[{"type":"message","content":[{"type":"output_text","text":"clean hello"}]}]}`))
		}))
		t.Cleanup(up.Close)
		gw := g6NativeResponsesGateway(t, up.URL)
		store := newFakePolicyStore()
		store.add("org-test", adminstore.PolicyPipeline{
			ID: "g6-pol-clean", OrgID: "org-test", Name: "g6-responses-clean",
			Enabled: true, CurrentVersion: 1,
		}, map[int]string{1: n03p6t09PostDenyYAML("g6-native-clean", "g6absentword")},
			[]adminstore.PolicyAttachment{g6ResponsesAttachment("responses")})
		gw.policyRuntime = newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeEnforce)
		rec := postResponses(t, gw, `{"model":"m","input":"hi"}`)
		require.Equal(t, http.StatusOK, rec.Code)
		require.Contains(t, rec.Body.String(), "clean hello")
	})
}

// TestGWCovG6_Responses_Success_FactsFailure covers responses_native.go
// 133-135: the provider served the response but the durable usage record
// could not commit; the client gets the 500 accounting envelope, never the
// response body.
func TestGWCovG6_Responses_Success_FactsFailure(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(g6ResponsesSuccess))
	}))
	t.Cleanup(up.Close)
	gw := g6NativeResponsesGateway(t, up.URL)
	gw.invocations = &fakeInvocationStore{factsErr: errG6Facts}
	rec := postResponses(t, gw, `{"model":"m","input":"hi"}`)
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	require.Contains(t, rec.Body.String(), "accounting_commit_failed")
	require.NotContains(t, rec.Body.String(), "hello")
	require.Equal(t, 1, g6FactsStore(gw).factsCalls)
}

// TestGWCovG6_Responses_DefaultContentType covers responses_native.go
// 141-142: an upstream error answer without a Content-Type gets the JSON
// default.
func TestGWCovG6_Responses_DefaultContentType(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// An explicitly empty (but present) Content-Type suppresses the
		// Go server's sniffed default, so the gateway's own default applies.
		w.Header().Set("Content-Type", "")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(g6ResponsesSuccess))
	}))
	t.Cleanup(up.Close)
	gw := g6NativeResponsesGateway(t, up.URL)
	rec := postResponses(t, gw, `{"model":"m","input":"hi"}`)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))
}

// TestGWCovG6_Responses_ForwardError_FactsFailure covers responses_native.go
// 153-154: an upstream error status is forwarded with its body while the
// facts failure is only logged.
func TestGWCovG6_Responses_ForwardError_FactsFailure(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"message":"g6-resp-boom"}}`))
	}))
	t.Cleanup(up.Close)
	gw := g6NativeResponsesGateway(t, up.URL)
	gw.invocations = &fakeInvocationStore{factsErr: errG6Facts}
	rec := postResponses(t, gw, `{"model":"m","input":"hi"}`)
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	require.Contains(t, rec.Body.String(), "g6-resp-boom")
	require.Equal(t, 1, g6FactsStore(gw).factsCalls)
}

// TestGWCovG6_Responses_StreamDrainFailure_FactsFailure covers
// responses_native.go 259-260: a stream that dies mid-relay gets the drain
// failure answer and the failed facts commit is logged.
func TestGWCovG6_Responses_StreamDrainFailure_FactsFailure(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		_, _ = w.Write([]byte("data: {\"type\":\"response.created\"}\n\n"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		panic(http.ErrAbortHandler)
	}))
	t.Cleanup(up.Close)
	gw := g6NativeResponsesGateway(t, up.URL)
	gw.invocations = &fakeInvocationStore{factsErr: errG6Facts}
	rec := postResponses(t, gw, `{"model":"m","input":"hi","stream":true}`)
	require.Equal(t, 1, g6FactsStore(gw).factsCalls)
	require.Contains(t, rec.Body.String(), "data:")
}

// TestGWCovG6_WriteResponsesStreamFailedCode_ClientGone covers
// responses_native.go 309-310 and 312-313: marshaling the fixed frame cannot
// fail, and a client-write failure of response.failed is swallowed.
func TestGWCovG6_WriteResponsesStreamFailedCode_ClientGone(t *testing.T) {
	require.NotPanics(t, func() {
		writeResponsesStreamFailedCode(httptest.NewRecorder(), "g6code", "g6msg")
		writeResponsesStreamFailedCode(&failWritesWriter{}, "g6code", "g6msg")
	})
}

// TestGWCovG6_ResponsesRelay_DirectUnits covers responses_native.go 391-392
// (empty frame no-op), 421-422 (comment passthrough), 452-453 (line-limit
// abort), 461-462 (client-write failure returned) and 472-473 (flushParser
// terminal/usage).
func TestGWCovG6_ResponsesRelay_DirectUnits(t *testing.T) {
	t.Run("empty frame is a no-op", func(t *testing.T) {
		rl := newResponsesStreamRelay(httptest.NewRecorder())
		rl.writeFrame(nil)
	})

	t.Run("comment passes through", func(t *testing.T) {
		rec := httptest.NewRecorder()
		_, _, err := relayResponsesSSE(rec, strings.NewReader(": ping\n\n"))
		require.NoError(t, err)
		require.Contains(t, rec.Body.String(), ": ping")
	})

	t.Run("oversized line aborts", func(t *testing.T) {
		huge := "data: " + strings.Repeat("a", 9<<20) + "\n\n"
		_, _, err := relayResponsesSSE(httptest.NewRecorder(), strings.NewReader(huge))
		require.ErrorIs(t, err, apiformat.ErrSSELineLimit)
	})

	t.Run("client write failure surfaces", func(t *testing.T) {
		_, _, err := relayResponsesSSE(&failWritesWriter{},
			&oneShotBytesReader{data: "event: response.created\ndata: {}\n", err: errG6Read})
		require.ErrorIs(t, err, errClientGoneWrite)
	})

	t.Run("flushParser settles terminal and usage", func(t *testing.T) {
		rl := newResponsesStreamRelay(httptest.NewRecorder())
		rl.parser.Feed([]byte("event: response.completed\n" +
			"data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":7,\"output_tokens\":3}}}\r"))
		rl.flushParser()
		require.Equal(t, "response.completed", rl.terminal)
		require.Equal(t, int64(7), rl.usage.PromptTokens)
	})
}

// ---------------------------------------------------------------------------
// messages_native.go
// ---------------------------------------------------------------------------

// TestGWCovG6_Messages_EntryGuardRefusals covers messages_native.go 43-45
// (no pool), 63-64 (history outage) and 67-68 (uninitialisable upstream
// client).
func TestGWCovG6_Messages_EntryGuardRefusals(t *testing.T) {
	body := `{"model":"claude-3-5-sonnet","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`

	t.Run("no upstream pool", func(t *testing.T) {
		gw := nativeMessagesGateway(t, "http://127.0.0.1:1")
		gw.pool = nil
		rec := postMessages(t, gw, body)
		require.Equal(t, http.StatusBadGateway, rec.Code)
		require.Contains(t, rec.Body.String(), "upstream is not configured")
	})

	t.Run("history outage denies", func(t *testing.T) {
		gw := nativeMessagesGateway(t, "http://127.0.0.1:1")
		gw.admission = historyOnlyController(t,
			stubHistoryProbe{state: budget.HistoryStateWriteUnavailable}, budget.HistoryModeReject)
		rec := postMessages(t, gw, body)
		require.Equal(t, http.StatusServiceUnavailable, rec.Code)
		require.Contains(t, rec.Body.String(), "history_unavailable")
	})

	t.Run("uninitialisable upstream client", func(t *testing.T) {
		gw := nativeMessagesGateway(t, "http://127.0.0.1:1")
		gw.res = stubModelResolver{"claude-3-5-sonnet": {
			ModelName: "claude-upstream", Provider: "anthropic",
			UpstreamURL: "ftp://example.invalid", Enabled: true,
		}}
		rec := postMessages(t, gw, body)
		require.Equal(t, http.StatusBadGateway, rec.Code)
		require.Contains(t, rec.Body.String(), "failed to initialise upstream client")
	})
}

// TestGWCovG6_Messages_PolicyDenied_Enforce covers messages_native.go
// 116-124: post-upstream denial answers 400 without the trigger word, with
// and without a facts failure.
func TestGWCovG6_Messages_PolicyDenied_Enforce(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_g6","type":"message","role":"assistant","model":"claude-upstream",` +
			`"usage":{"input_tokens":5,"output_tokens":2},` +
			`"content":[{"type":"text","text":"g6leaked secret"}]}`))
	}))
	t.Cleanup(up.Close)

	newGateway := func(t *testing.T) *gateway {
		gw := nativeMessagesGateway(t, up.URL)
		store := newFakePolicyStore()
		store.add("org-test", adminstore.PolicyPipeline{
			ID: "g6-pol", OrgID: "org-test", Name: "g6-messages-deny",
			Enabled: true, CurrentVersion: 1,
		}, map[int]string{1: n03p6t09PostDenyYAML("g6-native-deny", "g6leaked")},
			[]adminstore.PolicyAttachment{g6ResponsesAttachment("messages")})
		gw.policyRuntime = newTestRuntime(t, store, &fakePolicyVersions{}, PolicyModeEnforce)
		return gw
	}
	body := `{"model":"claude-3-5-sonnet","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`

	t.Run("clean denial hides the trigger", func(t *testing.T) {
		gw := newGateway(t)
		rec := postMessages(t, gw, body)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.NotContains(t, rec.Body.String(), "g6leaked")
	})

	t.Run("facts failure still denies", func(t *testing.T) {
		gw := newGateway(t)
		gw.invocations = &fakeInvocationStore{factsErr: errG6Facts}
		rec := postMessages(t, gw, body)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Equal(t, 1, g6FactsStore(gw).factsCalls)
	})
}

// TestGWCovG6_AnthStreamRelay_DirectUnits covers messages_native.go 462-463
// (empty frame), 467-468 (write failure latches), 560-563 (settle flushes
// the pending message_start for usage) and 639-640 (bad usage JSON is
// dropped, source none).
func TestGWCovG6_AnthStreamRelay_DirectUnits(t *testing.T) {
	t.Run("empty frame is a no-op", func(t *testing.T) {
		rl := newAnthStreamRelay(httptest.NewRecorder())
		rl.writeFrame([]byte{})
	})

	t.Run("write failure latches", func(t *testing.T) {
		rl := newAnthStreamRelay(&failWritesWriter{})
		rl.writeFrame([]byte("data: {}\n\n"))
		require.ErrorIs(t, rl.werr, errClientGoneWrite)
	})

	t.Run("settle flushes pending usage event", func(t *testing.T) {
		rl := newAnthStreamRelay(httptest.NewRecorder())
		rl.parser.Feed([]byte("data: {\"type\":\"message_start\",\"message\":{" +
			"\"usage\":{\"input_tokens\":7,\"output_tokens\":0}}}\n"))
		usage, err := rl.settle(&ssePassthroughTail{w: httptest.NewRecorder()})
		require.NoError(t, err)
		require.Equal(t, int64(7), usage.PromptTokens)
	})

	t.Run("bad usage json yields no source", func(t *testing.T) {
		var u anthStreamUsage
		u.note(apiformat.SSEEvent{Event: "message_start", Data: "{bad json"})
		require.Equal(t, provider.UsageSourceNone, u.usage().Source)
	})
}

// TestGWCovG6_Messages_JSONErrorForward_FactsFailure covers
// messages_native.go 696-697 (facts failure logged) and 702-703 (missing
// upstream Content-Type defaults to application/json).
func TestGWCovG6_Messages_JSONErrorForward_FactsFailure(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Explicitly empty (but present) Content-Type suppresses the Go
		// server's sniffed default so the gateway's fallback applies.
		w.Header().Set("Content-Type", "")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"api_error","message":"g6-boom-body"}}`))
	}))
	t.Cleanup(up.Close)
	gw := nativeMessagesGateway(t, up.URL)
	gw.invocations = &fakeInvocationStore{factsErr: errG6Facts}
	rec := postMessages(t, gw,
		`{"model":"claude-3-5-sonnet","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`)
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	require.Contains(t, rec.Body.String(), "g6-boom-body")
	require.Equal(t, 1, g6FactsStore(gw).factsCalls)
}

// TestGWCovG6_Messages_StreamAccountingFailure_ClientGone covers
// messages_native.go 789-790: the accounting-failure event write to a gone
// client returns early without panicking.
func TestGWCovG6_Messages_StreamAccountingFailure_ClientGone(t *testing.T) {
	require.NotPanics(t, func() {
		writeAnthropicStreamAccountingFailure(httptest.NewRecorder())
		writeAnthropicStreamAccountingFailure(&failWritesWriter{})
	})
}

// ---------------------------------------------------------------------------
// realtime_endpoint.go
// ---------------------------------------------------------------------------

// TestGWCovG6_RealtimeParse_BodyRefusals covers realtime_endpoint.go 58-59
// (cancelled context: silent abort) and 64-65 (unreadable body: 400).
func TestGWCovG6_RealtimeParse_BodyRefusals(t *testing.T) {
	t.Run("cancelled context stays silent", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/realtime", g6ErrReader{})
		rec := httptest.NewRecorder()
		_, _, ok := parseRealtimeRequest(rec, r)
		require.False(t, ok)
		require.Equal(t, http.StatusOK, rec.Code) // nothing written
	})

	t.Run("read failure answers 400", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/v1/realtime", g6ErrReader{})
		rec := httptest.NewRecorder()
		_, _, ok := parseRealtimeRequest(rec, r)
		require.False(t, ok)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Contains(t, rec.Body.String(), "request body too large or malformed")
	})
}

// TestGWCovG6_Realtime_PaidPipelineRefusals covers realtime_endpoint.go
// 120-121 (history outage 503), 125-126 (uninitialisable upstream client)
// and 137-138 (admission failure 503).
func TestGWCovG6_Realtime_PaidPipelineRefusals(t *testing.T) {
	body := `{"model":"m"}`

	t.Run("history outage denies", func(t *testing.T) {
		gw := r105TestGateway(t, realtimeTestModel("http://127.0.0.1:1"))
		gw.admission = historyOnlyController(t,
			stubHistoryProbe{state: budget.HistoryStateWriteUnavailable}, budget.HistoryModeReject)
		rec := postR105(t, gw, "/v1/realtime", body, nil)
		require.Equal(t, http.StatusServiceUnavailable, rec.Code)
		require.Contains(t, rec.Body.String(), "history_unavailable")
	})

	t.Run("uninitialisable upstream client", func(t *testing.T) {
		gw := r105TestGateway(t, realtimeTestModel("ftp://example.invalid"))
		rec := postR105(t, gw, "/v1/realtime", body, nil)
		require.Equal(t, http.StatusBadGateway, rec.Code)
		require.Contains(t, rec.Body.String(), "failed to initialise upstream client")
	})

	t.Run("admission failure denies fail-closed", func(t *testing.T) {
		gw := r105TestGateway(t, realtimeTestModel("http://127.0.0.1:1"))
		gw.invocations = &fakeInvocationStore{admitErr: errG6Admit}
		rec := postR105(t, gw, "/v1/realtime", body, nil)
		require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	})
}

// TestGWCovG6_Realtime_DialFailure covers realtime_endpoint.go 204-209: a
// configured but unreachable upstream refuses with 502 before any stream.
func TestGWCovG6_Realtime_DialFailure(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := up.URL
	up.Close()
	gw := r105TestGateway(t, realtimeTestModel(url))
	rec := postR105(t, gw, "/v1/realtime", `{"model":"m"}`, nil)
	require.Equal(t, http.StatusBadGateway, rec.Code)
	require.Contains(t, rec.Body.String(), "upstream request failed")
}

// TestGWCovG6_Realtime_DrainError_FactsFailure covers realtime_endpoint.go
// 328-329: an SSE session that dies mid-stream notifies the client and the
// failed facts commit is logged.
func TestGWCovG6_Realtime_DrainError_FactsFailure(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		_, _ = w.Write([]byte("data: {\"type\":\"session.created\"}\n\n"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		panic(http.ErrAbortHandler)
	}))
	t.Cleanup(up.Close)
	gw := r105TestGateway(t, realtimeTestModel(up.URL))
	gw.invocations = &fakeInvocationStore{factsErr: errG6Facts}
	rec := postR105(t, gw, "/v1/realtime", `{"model":"m"}`, nil)
	require.Equal(t, 1, g6FactsStore(gw).factsCalls)
	require.Contains(t, rec.Body.String(), "interrupted")
}

// TestGWCovG6_RealtimeFinish_UnarmedFactsFailure covers realtime_endpoint.go
// 364-365: the facts commit failed on an unarmed hold (no suffix was ever
// deferred); the failure is logged and the client answer is untouched.
func TestGWCovG6_RealtimeFinish_UnarmedFactsFailure(t *testing.T) {
	gw := r105TestGateway(t, realtimeTestModel("http://127.0.0.1:1"))
	st := &fakeInvocationStore{factsErr: errG6Facts}
	gw.invocations = st
	id := newInvocationIdentity("org-test", "g6r", "g6s", "7", "9", "m")
	require.NoError(t, id.beginPaidDispatch(t.Context(), &fakeInvocationStore{}, invocationKindStream))
	s := realtimeSettle{
		rctx: withInvocationIdentity(t.Context(), id),
		w:    httptest.NewRecorder(),
		l:    testLogger(),
		admitted: admitted{
			OrgID: "org-test", RequestID: "g6r",
			Info: resolver.ModelInfo{ModelName: "m", Provider: "openai"},
		},
		usage: provider.Anthropic{}.ParseUsage([]byte(`{"input_tokens":3,"output_tokens":1}`)),
		tee:   &boundedBuffer{},
		resp:  &http.Response{StatusCode: http.StatusOK, Header: make(http.Header)},
	}
	require.NotPanics(t, func() { gw.finishRealtimeSession(s, &realtimeTerminalHold{write: func([]byte) {}}) })
	require.Equal(t, 1, st.factsCalls)
	require.Empty(t, s.w.(*httptest.ResponseRecorder).Body.String())
}

// TestGWCovG6_RealtimeFinish_ReplayFailure covers realtime_endpoint.go
// 381-382 (and 780-782): the facts committed but the deferred suffix's spill
// file could not be replayed; the failure surfaces on the hold for the
// endpoint's loud log.
func TestGWCovG6_RealtimeFinish_ReplayFailure(t *testing.T) {
	tf, err := os.CreateTemp(t.TempDir(), "g6-hold-*")
	require.NoError(t, err)
	require.NoError(t, tf.Close())
	gw := r105TestGateway(t, realtimeTestModel("http://127.0.0.1:1"))
	hold := &realtimeTerminalHold{
		write: func([]byte) {}, armed: true, suffixing: true,
		ram: []byte{}, spill: tf,
	}
	s := realtimeSettle{
		rctx:  t.Context(), // no identity: facts finish cleanly
		w:     httptest.NewRecorder(),
		l:     testLogger(),
		usage: provider.Anthropic{}.ParseUsage([]byte(`{"input_tokens":3,"output_tokens":1}`)),
		tee:   &boundedBuffer{},
		resp:  &http.Response{StatusCode: http.StatusOK, Header: make(http.Header)},
	}
	gw.finishRealtimeSession(s, hold)
	require.Error(t, hold.replayErr)
}

// TestGWCovG6_RealtimeRelay_Aborts covers realtime_endpoint.go 439-440
// (relay size cap), 443-445 + 581 + 602 (line-limit abort) and 459-460 +
// 497-499 (client-write failure settles as cancel).
func TestGWCovG6_RealtimeRelay_Aborts(t *testing.T) {
	gw := r105TestGateway(t, realtimeTestModel("http://127.0.0.1:1"))
	noopCancel := func() {}

	t.Run("relay size cap", func(t *testing.T) {
		w := &g6DiscardWriter{}
		_, _, _, _, err := gw.realtimeRelay(t.Context(), w, w,
			&g6RepeatReader{chunk: []byte(": g6\n\n"), remaining: realtimeStreamLimit + 1<<20}, noopCancel)
		var tooLarge errRealtimeStreamTooLarge
		require.True(t, errors.As(err, &tooLarge), "got %v", err)
	})

	t.Run("line limit abort", func(t *testing.T) {
		w := &g6DiscardWriter{}
		huge := "data: " + strings.Repeat("a", 9<<20) + "\n"
		_, _, _, _, err := gw.realtimeRelay(t.Context(), w, w, strings.NewReader(huge), noopCancel)
		var lineLarge errRealtimeLineTooLarge
		require.True(t, errors.As(err, &lineLarge), "got %v", err)
	})

	t.Run("client write failure settles as cancel", func(t *testing.T) {
		fw := &g6FailFlushWriter{}
		_, _, term, _, err := gw.realtimeRelay(t.Context(), fw, fw,
			strings.NewReader("data: {\"type\":\"session.created\"}\n\n"), noopCancel)
		require.ErrorIs(t, err, errClientGoneWrite)
		require.Equal(t, budget.TerminationClientCancel, term)
	})

	t.Run("mid-relay spool failure aborts", func(t *testing.T) {
		// The suffix spool cannot be created once the deferred suffix
		// outgrows RAM (TMPDIR is broken), so the first over-limit frame
		// after a completed response.done aborts the relay as hold I/O.
		t.Setenv("TMPDIR", "/nonexistent-g6-tmp")
		gw := r105TestGateway(t, realtimeTestModel("http://127.0.0.1:1"))
		rctx := g6AdmittedFactsErrCtx(t, gw)
		done := "event: response.done\ndata: {\"type\":\"response.done\",\"response\":{\"status\":\"completed\"}}\n\n"
		huge := "data: " + strings.Repeat("a", realtimeTerminalHoldLimit+4096) + "\n\n"
		rec := httptest.NewRecorder()
		_, _, term, _, err := gw.realtimeRelay(rctx, rec, rec,
			strings.NewReader(done+huge), noopCancel)
		var holdIO errRealtimeHoldIO
		require.True(t, errors.As(err, &holdIO), "got %v", err)
		require.Equal(t, budget.TerminationUpstreamErr, term)
	})
}

// TestGWCovG6_RealtimeSink_SettleEndBranches covers realtime_endpoint.go
// 534-535 + 632-633 (salvage into a broken spool aborts as upstream error),
// 537-538 (recorded write failure settles as cancel) and 624-625 (comment
// line into a broken spool).
func TestGWCovG6_RealtimeSink_SettleEndBranches(t *testing.T) {
	closedSpill := func(t *testing.T) *os.File {
		tf, err := os.CreateTemp(t.TempDir(), "g6-hold-*")
		require.NoError(t, err)
		require.NoError(t, tf.Close())
		return tf
	}

	t.Run("salvage with broken spool aborts", func(t *testing.T) {
		s := newRealtimeRelaySink(httptest.NewRecorder(), httptest.NewRecorder())
		s.hold.armed, s.hold.suffixing = true, true
		s.hold.spill = closedSpill(t)
		_, overflow := s.frames.Add([]byte("data: {}"), apiformat.SSEStreamLineLimit)
		require.False(t, overflow)
		term, err := s.settleEnd(t.Context(), nil, io.EOF)
		var holdIO errRealtimeHoldIO
		require.True(t, errors.As(err, &holdIO), "got %v", err)
		require.Equal(t, budget.TerminationUpstreamErr, term)
	})

	t.Run("recorded write failure settles as cancel", func(t *testing.T) {
		fw := &g6FailFlushWriter{}
		s := newRealtimeRelaySink(fw, fw)
		s.lines.Feed([]byte("data: g6partial")) // trailing partial suppresses salvage
		s.write([]byte("x"))                    // latches werr
		term, err := s.settleEnd(t.Context(), nil, io.EOF)
		require.ErrorIs(t, err, errClientGoneWrite)
		require.Equal(t, budget.TerminationClientCancel, term)
	})

	t.Run("comment into broken spool fails", func(t *testing.T) {
		s := newRealtimeRelaySink(httptest.NewRecorder(), httptest.NewRecorder())
		s.hold.armed, s.hold.suffixing = true, true
		s.hold.spill = closedSpill(t)
		// The trailing lone CR is what settleTail's Flush resolves into a
		// complete comment line, routing it into the broken spool.
		s.lines.Feed([]byte(": keep\r"))
		err := s.settleTail()
		var holdIO errRealtimeHoldIO
		require.True(t, errors.As(err, &holdIO), "got %v", err)
	})

	t.Run("feedChunk routes hold failure", func(t *testing.T) {
		s := newRealtimeRelaySink(httptest.NewRecorder(), httptest.NewRecorder())
		s.hold.armed, s.hold.suffixing = true, true
		s.hold.spill = closedSpill(t)
		err := s.feedChunk([]byte(": keep\n"))
		var holdIO errRealtimeHoldIO
		require.True(t, errors.As(err, &holdIO), "got %v", err)
	})

	t.Run("oversize line aborts processLine", func(t *testing.T) {
		s := newRealtimeRelaySink(httptest.NewRecorder(), httptest.NewRecorder())
		line := []byte("data: " + strings.Repeat("a", apiformat.SSEStreamLineLimit+1024))
		err := s.processLine(line)
		var lineLarge errRealtimeLineTooLarge
		require.True(t, errors.As(err, &lineLarge), "got %v", err)
	})
}

// TestGWCovG6_RealtimeHold_SpoolBranches covers realtime_endpoint.go 741-744
// (spill write error vs success), 749-750 (no spill creatable), 752-755 and
// 757-760 (EFBIG on ram/unit writes), 774-775 + 810-811 (nil-receiver
// safety), 780-782 (seek failure on replay) and 796-798 (read failure on
// replay).
func TestGWCovG6_RealtimeHold_SpoolBranches(t *testing.T) {
	noopWrite := func([]byte) {}

	t.Run("closed spill fails, open spill admits", func(t *testing.T) {
		tf, err := os.CreateTemp(t.TempDir(), "g6-hold-*")
		require.NoError(t, err)
		t.Cleanup(func() { _ = tf.Close() })

		h := &realtimeTerminalHold{write: noopWrite, armed: true, suffixing: true, spill: tf}
		require.NoError(t, h.admit([]byte("x")))

		require.NoError(t, tf.Close())
		var holdIO errRealtimeHoldIO
		require.True(t, errors.As(h.admit([]byte("y")), &holdIO))
	})

	t.Run("no spill creatable", func(t *testing.T) {
		t.Setenv("TMPDIR", "/nonexistent-g6-dir")
		h := &realtimeTerminalHold{write: noopWrite, armed: true, suffixing: true}
		h.ram = make([]byte, 64)
		err := h.admit(make([]byte, realtimeTerminalHoldLimit+16))
		var holdIO errRealtimeHoldIO
		require.True(t, errors.As(err, &holdIO))
	})

	t.Run("efbig on ram write", func(t *testing.T) {
		g6SetFileSizeLimit(t, 512*1024)
		h := &realtimeTerminalHold{write: noopWrite, armed: true, suffixing: true}
		h.ram = make([]byte, 800*1024)
		err := h.admit(make([]byte, 300*1024)) // ram+unit > 1 MiB triggers spilling
		var holdIO errRealtimeHoldIO
		require.True(t, errors.As(err, &holdIO))
	})

	t.Run("efbig on unit write", func(t *testing.T) {
		g6SetFileSizeLimit(t, 900*1024)
		h := &realtimeTerminalHold{write: noopWrite, armed: true, suffixing: true}
		h.ram = make([]byte, 600*1024)
		err := h.admit(make([]byte, 600*1024))
		var holdIO errRealtimeHoldIO
		require.True(t, errors.As(err, &holdIO))
	})

	t.Run("nil receiver safety", func(t *testing.T) {
		var h *realtimeTerminalHold
		require.NotPanics(t, func() {
			h.release()
			h.drop()
		})
	})

	t.Run("seek failure on replay", func(t *testing.T) {
		tf, err := os.CreateTemp(t.TempDir(), "g6-hold-*")
		require.NoError(t, err)
		require.NoError(t, tf.Close())
		h := &realtimeTerminalHold{write: noopWrite, spill: tf}
		h.release()
		require.Error(t, h.replayErr)
	})

	t.Run("read failure on replay", func(t *testing.T) {
		dir, err := os.Open(t.TempDir()) // a directory fd: Seek ok, Read fails EISDIR
		require.NoError(t, err)
		t.Cleanup(func() { _ = dir.Close() })
		h := &realtimeTerminalHold{write: noopWrite, spill: dir}
		h.release()
		require.Error(t, h.replayErr)
	})
}

// TestGWCovG6_RealtimeCompletedResponseDone_BadShapes covers
// realtime_endpoint.go 855-856: undecodable data and a nil response object
// are not successful terminals.
func TestGWCovG6_RealtimeCompletedResponseDone_BadShapes(t *testing.T) {
	require.False(t, realtimeCompletedResponseDone([]byte("event: response.done\ndata: {not json}\n\n")))
	require.False(t, realtimeCompletedResponseDone([]byte("event: response.done\ndata: {}\n\n")))
	require.False(t, realtimeCompletedResponseDone([]byte("event: response.output_text\ndata: {\"response\":{\"status\":\"completed\"}}\n\n")))
}

// ---------------------------------------------------------------------------
// Error-carrier contracts bound by the critical-go name binding: the binding
// resolves interface-level Error() calls to every same-named production
// method, so each carrier's exact semantic output is pinned here through the
// plain error interface (contract text from each carrier's doc comment).
// ---------------------------------------------------------------------------

// TestGWCovG6_RealtimeErrorCarrierMessages pins the realtime relay's
// terminal error carriers: a line/frame past the buffering limit, and the
// terminal hold spool failing with its wrapped cause preserved.
func TestGWCovG6_RealtimeErrorCarrierMessages(t *testing.T) {
	var lineErr error = errRealtimeLineTooLarge{}
	if got, want := lineErr.Error(), "upstream realtime SSE line or frame exceeds the buffering limit"; got != want {
		t.Errorf("errRealtimeLineTooLarge via error interface = %q, want %q", got, want)
	}

	cause := errors.New("g6: spill file creation refused")
	var holdErr error = errRealtimeHoldIO{err: cause}
	if got, want := holdErr.Error(), "realtime terminal hold spool failed: g6: spill file creation refused"; got != want {
		t.Errorf("errRealtimeHoldIO via error interface = %q, want %q", got, want)
	}
	if unwrapped := errors.Unwrap(holdErr); !errors.Is(unwrapped, cause) {
		t.Errorf("errRealtimeHoldIO unwrap = %v, want the spool cause %v", unwrapped, cause)
	}
}

// TestGWCovG6_TokenEndpointErrorNoStatusNoCause pins the degenerate arm of
// the transient token-endpoint carrier: neither an HTTP status nor a cause
// recorded, the contract line stays a plain transient-unreachable statement
// and Unwrap reports no cause.
func TestGWCovG6_TokenEndpointErrorNoStatusNoCause(t *testing.T) {
	var carrier error = &tokenEndpointError{}
	if got, want := carrier.Error(), "oauth token endpoint unreachable (transient)"; got != want {
		t.Errorf("tokenEndpointError no-status/no-cause via error interface = %q, want %q", got, want)
	}
	if unwrapped := errors.Unwrap(carrier); unwrapped != nil {
		t.Errorf("tokenEndpointError no-cause unwrap = %v, want nil", unwrapped)
	}
}
