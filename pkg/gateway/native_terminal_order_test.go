package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nativeTerminalOrderStore scripts the durable seam and observes the
// client body at the exact commit point: the before hook runs while
// RecordTerminalFacts is in flight.
type nativeTerminalOrderStore struct {
	fakeInvocationStore
	before func()
}

func (s *nativeTerminalOrderStore) RecordTerminalFacts(ctx context.Context, rec terminalFactsRecord) error {
	s.before()
	return s.fakeInvocationStore.RecordTerminalFacts(ctx, rec)
}

type nativeTerminalOrderCase struct {
	family, path, body, prefix, terminal string
	upstream                             func(w io.Writer)
}

// TestNativeTerminalOrder pins the Preview2 central binding on the real
// native stream handlers: the client must never see the stream's success
// terminal before the durable terminal-facts commit succeeds, a failed
// commit replaces it with the accounting failure terminal, and exactly
// one provider invocation serves the request. Both protocols carry
// their genuine pre-terminal traffic — a message_delta carrying
// stop_reason and usage for /v1/messages, a response.output_text.delta
// for /v1/responses — so nonterminal frames are proven to flush through
// the seam while the terminal waits.
func TestNativeTerminalOrder(t *testing.T) {
	for _, tc := range []nativeTerminalOrderCase{
		{
			family: "messages", path: "/v1/messages",
			body:   `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"hi"}],"stream":true}`,
			prefix: "message_delta", terminal: "message_stop",
			upstream: func(w io.Writer) {
				// Genuine Anthropic closing traffic: usage and stop_reason
				// ride the nonterminal message_delta; message_stop is bare.
				_, _ = io.WriteString(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":13}}}\n\n")
				_, _ = io.WriteString(w, "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":5,\"cache_read_input_tokens\":4}}\n\n")
				_, _ = io.WriteString(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
			},
		},
		{
			family: "responses", path: "/v1/responses",
			body:   `{"model":"m","input":"hi","stream":true}`,
			prefix: "response.output_text.delta", terminal: "response.completed",
			upstream: func(w io.Writer) {
				_, _ = io.WriteString(w, "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"usage\":{\"input_tokens\":13}}}\n\n")
				_, _ = io.WriteString(w, "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\n")
				_, _ = io.WriteString(w, "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":13,\"output_tokens\":5}}}\n\n")
			},
		},
	} {
		for _, fail := range []bool{false, true} {
			mode := "committed"
			if fail {
				mode = "facts_failure"
			}
			t.Run(tc.family+"/"+mode, func(t *testing.T) {
				runNativeTerminalOrderCase(t, tc, fail)
			})
		}
	}
}

func runNativeTerminalOrderCase(t *testing.T, tc nativeTerminalOrderCase, fail bool) {
	t.Helper()
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		tc.upstream(w)
	}))
	defer upstream.Close()

	rec := httptest.NewRecorder()
	commitChecks := 0
	store := &nativeTerminalOrderStore{before: func() {
		commitChecks++
		assert.Contains(t, rec.Body.String(), "event: "+tc.prefix)
		assert.NotContains(t, rec.Body.String(), "event: "+tc.terminal,
			"success terminal reached the client before the durable facts commit")
	}}
	if fail {
		store.factsErr = errors.New("permanent accounting storage failure")
	}

	req := httptest.NewRequestWithContext(t.Context(), "POST", tc.path, strings.NewReader(tc.body))
	goldenIdentity(req)
	invokeNativeTerminalOrderHandler(t, tc, upstream.URL, store, rec, req)
	assertNativeTerminalOrderResult(t, tc, fail, calls.Load(), commitChecks, rec.Body.String())
}

func invokeNativeTerminalOrderHandler(t *testing.T, tc nativeTerminalOrderCase, upstreamURL string, store *nativeTerminalOrderStore, rec *httptest.ResponseRecorder, req *http.Request) {
	t.Helper()
	if tc.family == "messages" {
		gw := nativeMessagesGateway(t, upstreamURL)
		gw.invocations = store
		gw.messagesNative(rec, req, []byte(tc.body), "claude-3-5-sonnet")
		return
	}
	gw := responsesTestGateway(t, upstreamURL)
	gw.invocations = store
	gw.responsesNative(rec, req, []byte(tc.body))
}

func assertNativeTerminalOrderResult(t *testing.T, tc nativeTerminalOrderCase, fail bool, calls int32, commitChecks int, result string) {
	t.Helper()
	require.EqualValues(t, 1, calls, "single provider invocation")
	require.Equal(t, 1, commitChecks)
	assert.Contains(t, result, "event: "+tc.prefix, "nonterminal traffic survives every end")
	if fail {
		assert.Contains(t, result, "accounting_commit_failed")
		assert.Contains(t, result, "NOT safe to retry")
		assert.NotContains(t, result, "event: "+tc.terminal)
		return
	}
	assert.Equal(t, 1, strings.Count(result, "event: "+tc.terminal), "exactly one success terminal")
	assert.NotContains(t, result, "accounting_commit_failed")
}

// TestNativeTerminalOrderUsageAndTrailer pins usage transparency past
// the seam on the committed end: the message_delta's stop_reason and
// usage remain client-visible, the prompt-cache trailer rides the
// response, and the released terminal closes the body exactly once.
func TestNativeTerminalOrderUsageAndTrailer(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":13}}}\n\n")
		_, _ = fmt.Fprintf(w, "event: message_delta\ndata: %s\n\n", `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":5,"cache_read_input_tokens":4}}`)
		_, _ = io.WriteString(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	}))
	defer upstream.Close()

	rec := httptest.NewRecorder()
	body := `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"hi"}],"stream":true}`
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/v1/messages", strings.NewReader(body))
	goldenIdentity(req)
	gw := nativeMessagesGateway(t, upstream.URL)
	gw.invocations = &fakeInvocationStore{}
	gw.messagesNative(rec, req, []byte(body), "claude-3-5-sonnet")

	result := rec.Body.String()
	assert.Contains(t, result, "stop_reason")
	assert.Contains(t, result, `"output_tokens":5`)
	assert.Equal(t, 1, strings.Count(result, "event: message_stop"))
	assert.NotContains(t, result, "accounting_commit_failed")
	assert.Equal(t, "hit", rec.Header().Get(http.TrailerPrefix+PromptCacheHeader), "prompt-cache trailer preserved past the seam")
}

// TestNativeTerminalOrderFailureTerminalNoDouble pins the
// exactly-one-terminal rule when the stream already ended in-protocol:
// a delivered upstream failure terminal is the single client terminal
// (even when the facts commit also fails, no accounting frame stacks a
// second one), and after a delivered success terminal the drain stops —
// trailing duplicate or failure frames are never re-dispatched.
func TestNativeTerminalOrderFailureTerminalNoDouble(t *testing.T) {
	for _, tc := range []struct {
		name, family, success, failure, frames string
		factsErr                               error
		wantFacts                              int
	}{
		{
			name: "failure terminal first, commit ok", family: "messages", success: "message_stop", failure: "error",
			frames:    "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"api_error\",\"message\":\"upstream failed\"}}\n\n",
			wantFacts: 1,
		},
		{
			name: "failure terminal first, commit fails", family: "messages", success: "message_stop", failure: "error",
			frames:    "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"api_error\",\"message\":\"upstream failed\"}}\n\n",
			factsErr:  errors.New("permanent accounting storage failure"),
			wantFacts: 0,
		},
		{
			name: "post-terminal frames dropped", family: "messages", success: "message_stop", failure: "error",
			frames: "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":5}}\n\n" +
				"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n" +
				"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n" +
				"event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"api_error\",\"message\":\"late upstream failure\"}}\n\n",
			wantFacts: 1,
		},
		{
			name: "failure terminal first, commit ok", family: "responses", success: "response.completed", failure: "response.failed",
			frames:    "event: response.failed\ndata: {\"type\":\"response.failed\",\"response\":{\"error\":{\"code\":\"server_error\"}}}\n\n",
			wantFacts: 1,
		},
		{
			name: "failure terminal first, commit fails", family: "responses", success: "response.completed", failure: "response.failed",
			frames:    "event: response.failed\ndata: {\"type\":\"response.failed\",\"response\":{\"error\":{\"code\":\"server_error\"}}}\n\n",
			factsErr:  errors.New("permanent accounting storage failure"),
			wantFacts: 0,
		},
		{
			name: "post-terminal frames dropped", family: "responses", success: "response.completed", failure: "response.failed",
			frames: "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\n" +
				"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":13,\"output_tokens\":5}}}\n\n" +
				"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":13,\"output_tokens\":5}}}\n\n" +
				"event: response.failed\ndata: {\"type\":\"response.failed\",\"response\":{\"error\":{\"code\":\"server_error\"}}}\n\n",
			wantFacts: 1,
		},
	} {
		t.Run(tc.family+"/"+tc.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, tc.frames)
			}))
			defer upstream.Close()

			rec := httptest.NewRecorder()
			store := &fakeInvocationStore{factsErr: tc.factsErr}
			body := `{"model":"m","input":"hi","stream":true}`
			path := "/v1/responses"
			model := ""
			if tc.family == "messages" {
				body = `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"hi"}],"stream":true}`
				path = "/v1/messages"
				model = "claude-3-5-sonnet"
			}
			req := httptest.NewRequestWithContext(t.Context(), "POST", path, strings.NewReader(body))
			goldenIdentity(req)
			if tc.family == "messages" {
				gw := nativeMessagesGateway(t, upstream.URL)
				gw.invocations = store
				gw.messagesNative(rec, req, []byte(body), model)
			} else {
				gw := responsesTestGateway(t, upstream.URL)
				gw.invocations = store
				gw.responsesNative(rec, req, []byte(body))
			}

			result := rec.Body.String()
			successCount := strings.Count(result, "event: "+tc.success)
			failureCount := strings.Count(result, "event: "+tc.failure)
			if tc.name == "post-terminal frames dropped" {
				assert.Equal(t, 1, successCount, "the delivered success terminal is the client's single terminal")
				assert.Equal(t, 0, failureCount, "a trailing failure frame after the authoritative terminal is never re-dispatched")
			} else {
				assert.Equal(t, 1, failureCount, "the in-protocol failure terminal stands")
				assert.Equal(t, 0, successCount, "no success terminal exists on a failed stream")
			}
			assert.NotContains(t, result, "accounting_commit_failed", "no accounting frame stacks a second terminal on the ended stream")
			require.Len(t, store.facts, tc.wantFacts)
		})
	}
}

// TestNativeTerminalOrderHeartbeat pins the heartbeat path on the real
// handler: a keepalive the provider flushes must reach the client
// immediately, not wait for the next frame, with nothing accumulating
// at the seam.
func TestNativeTerminalOrderHeartbeat(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, ": control heartbeat\n")
		w.(http.Flusher).Flush()
		// Hold the stream until the client actually received the flushed
		// keepalive (the recorder's Flush hook below signals it).
		<-release
		_, _ = io.WriteString(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	}))
	defer upstream.Close()

	rec := &heartbeatRecorder{ResponseRecorder: httptest.NewRecorder(), seen: release}
	body := `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"hi"}],"stream":true}`
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/v1/messages", strings.NewReader(body))
	goldenIdentity(req)
	gw := nativeMessagesGateway(t, upstream.URL)
	gw.invocations = &fakeInvocationStore{}
	gw.messagesNative(rec, req, []byte(body), "claude-3-5-sonnet")

	result := rec.Body.String()
	assert.Contains(t, result, ": control heartbeat")
	assert.Equal(t, 1, strings.Count(result, "event: message_stop"))
}

// heartbeatRecorder signals when the flushed heartbeat became
// client-visible.
type heartbeatRecorder struct {
	*httptest.ResponseRecorder
	seen chan struct{}
}

func (r *heartbeatRecorder) Flush() {
	r.ResponseRecorder.Flush()
	if strings.Contains(r.Body.String(), ": control heartbeat") {
		select {
		case <-r.seen:
		default:
			close(r.seen)
		}
	}
}

// TestNativeTerminalOrderOpenAfterTerminal maintains the r3 control: a
// provider that flushes the authoritative final event and then keeps
// the connection open waiting for consumer completion must not delay
// the client's terminal or the durable facts commit on physical EOF —
// the drain settles at the delivered terminal, the facts record once,
// and the client's released terminal unblocks the provider promptly.
func TestNativeTerminalOrderOpenAfterTerminal(t *testing.T) {
	for _, tc := range []struct {
		family, terminal, body, model string
	}{
		{
			family: "messages", terminal: "message_stop", model: "claude-3-5-sonnet",
			body: `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"hi"}],"stream":true}`,
		},
		{
			family: "responses", terminal: "response.completed", model: "m",
			body: `{"model":"m","input":"hi","stream":true}`,
		},
	} {
		t.Run(tc.family, func(t *testing.T) {
			rec := &finalEventRecorder{ResponseRecorder: httptest.NewRecorder(), marker: "event: " + tc.terminal, seen: make(chan struct{})}
			serverDone := make(chan struct{})
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(serverDone)
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = fmt.Fprintf(w, "event: %s\ndata: {\"type\":\"%s\"}\n\n", tc.terminal, tc.terminal)
				w.(http.Flusher).Flush()
				// Hold the connection open past the final event: only the
				// client's delivered terminal (or the aborted request) may
				// unblock this — never a timeout.
				select {
				case <-rec.seen:
				case <-r.Context().Done():
				case <-time.After(2 * time.Second):
					t.Error("client and accounting waited for provider EOF despite an authoritative flushed protocol terminal")
				}
			}))
			defer upstream.Close()

			store := &fakeInvocationStore{}
			req := httptest.NewRequestWithContext(t.Context(), "POST", "/v1/"+tc.family, strings.NewReader(tc.body))
			goldenIdentity(req)
			if tc.family == "messages" {
				gw := nativeMessagesGateway(t, upstream.URL)
				gw.invocations = store
				gw.messagesNative(rec, req, []byte(tc.body), tc.model)
			} else {
				gw := responsesTestGateway(t, upstream.URL)
				gw.invocations = store
				gw.responsesNative(rec, req, []byte(tc.body))
			}
			<-serverDone
			require.Len(t, store.facts, 1)
			require.Contains(t, rec.Body.String(), rec.marker)
			require.Equal(t, 1, strings.Count(rec.Body.String(), "event: "+tc.terminal))
		})
	}
}

// finalEventRecorder signals when the released terminal became
// client-visible.
type finalEventRecorder struct {
	*httptest.ResponseRecorder
	marker string
	seen   chan struct{}
	once   sync.Once
}

func (r *finalEventRecorder) Flush() {
	r.ResponseRecorder.Flush()
	if strings.Contains(r.Body.String(), r.marker) {
		r.once.Do(func() { close(r.seen) })
	}
}

// TestNativeTerminalHoldUnits covers the seam directly: terminator
// dialects (LF, CRLF, lone CR) classify within their own Write via the
// shared parser's Feed+Flush, split-data and event-field names resolve
// identically, and unarmed streams pass through untouched.
func TestNativeTerminalHoldUnits(t *testing.T) {
	newHold := func(rec http.ResponseWriter) *nativeTerminalHold {
		return &nativeTerminalHold{ResponseWriter: rec, name: nativeEventName, success: anthNativeSuccessTerminals, failure: anthNativeFailureTerminals, armed: true}
	}
	stopFrames := map[string][]byte{
		"lf":   []byte("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"),
		"crlf": []byte("event: message_stop\r\ndata: {\"type\":\"message_stop\"}\r\n\r\n"),
		"cr":   []byte("event: message_stop\rdata: {\"type\":\"message_stop\"}\r\r"),
	}
	t.Run("heartbeats bypass without accumulating", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h := newHold(rec)
		const n = 1000
		for i := 0; i < n; i++ {
			_, err := h.Write([]byte(": control heartbeat\n"))
			require.NoError(t, err)
		}
		require.Equal(t, strings.Repeat(": control heartbeat\n", n), rec.Body.String())
		require.Nil(t, h.held, "comment-only writes must never buffer")
	})
	for _, dialect := range []string{"lf", "crlf", "cr"} {
		t.Run(dialect+" terminal holds then releases", func(t *testing.T) {
			rec := httptest.NewRecorder()
			h := newHold(rec)
			_, err := h.Write([]byte("event: ping\ndata: {\"type\":\"ping\"}\n\n"))
			require.NoError(t, err)
			_, err = h.Write(stopFrames[dialect])
			require.NoError(t, err)
			require.NotNil(t, h.held, "a complete record must classify in its own Write")
			require.NotContains(t, rec.Body.String(), "message_stop")
			h.release()
			assert.Contains(t, rec.Body.String(), "event: message_stop")
		})
	}
	t.Run("split data-only terminal holds by decoded type", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h := newHold(rec)
		_, err := h.Write([]byte("data: {\ndata: \"type\":\"message_stop\"}\n\n"))
		require.NoError(t, err)
		require.NotNil(t, h.held)
		require.NotContains(t, rec.Body.String(), "message_stop")
		h.release()
		assert.Contains(t, rec.Body.String(), "message_stop")
	})
	t.Run("failure terminal drops a buffered success", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h := newHold(rec)
		_, err := h.Write(stopFrames["lf"])
		require.NoError(t, err)
		_, err = h.Write([]byte("event: error\ndata: {\"type\":\"error\"}\n\n"))
		require.NoError(t, err)
		require.Nil(t, h.held)
		require.True(t, h.failureSeen())
		h.release()
		assert.NotContains(t, rec.Body.String(), "message_stop", "the buffered success must not follow the failure terminal")
		assert.Contains(t, rec.Body.String(), "event: error")
	})
	t.Run("unarmed passes through", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h := newHold(rec)
		h.armed = false
		_, err := h.Write(stopFrames["lf"])
		require.NoError(t, err)
		h.release()
		h.fail()
		assert.Contains(t, rec.Body.String(), "message_stop")
	})
}
