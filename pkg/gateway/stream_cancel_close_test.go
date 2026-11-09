package cli

// N03-P01-T04: the cancel-path writer contract — "закрыть writer ровно один
// раз при cancel", proven on the wire. These tests pin the end-to-end
// behaviour that makes the existing code exactly-once safe without a product
// change:
//
//   - the upstream response body is closed by exactly one owner (the single
//     `defer r.streamResp.Body.Close()` in serveStream; Client.Stream closes
//     non-200 bodies itself, so no second closer exists), and the drain that
//     owns it stops at client cancel;
//   - a mid-stream client cancel yields a VALID stream: complete chunk
//     frames only, one error frame, exactly one `data: [DONE]`;
//   - a cancel that lands after the [DONE] terminator must not append a
//     second terminal event (the cancel-flavour complement of the idle-
//     flavour TestServeStream_LateErrorAfterDoneEmitsNoSecondTerminal);
//   - a stream split into sub-frame pieces upstream still reaches the client
//     as complete frames whose prefix matches the original byte stream;
//   - the tool gate, when a late drain failure arrives while it holds
//     frames, releases the held frames exactly once on [DONE] — the error
//     frame joins the release order, no duplicate terminator;
//   - the idle watchdog's Stop disarms the timer so a finished drain can
//     never cause a late cancel (Fired stays false).
//
// No production code changed for this card: the tests are the deliverable.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apierrs "github.com/reireirei/yabanin/pkg/apierrors"
	apiformat "github.com/reireirei/yabanin/pkg/apiformat"
	apierrors "github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/resolver"
)

// interruptedSuffix is the exact client-visible tail finishDrainFailure
// writes for a non-idle drain failure: the structured SSE error frame built
// from the same helper the production path uses, followed by the single
// [DONE] terminator.
func interruptedSuffix() string {
	return string(apierrs.SSEErrorFrame(&apierrs.E{Type: apierrors.ErrorCodeAPI, Message: "stream interrupted"})) +
		"data: [DONE]\n\n"
}

// chunkFrame renders one deterministic chat.completion.chunk SSE frame.
func chunkFrame(id, content string) string {
	return fmt.Sprintf("data: {\"id\":%q,\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":%q}}]}\n\n", id, content)
}

// assertSingleTerminal holds the shared wire contract of every cancel test:
// exactly one [DONE], exactly the finisher's error frame, a well-formed
// terminator tail, and a body pkg/apiformat.ValidateChatStream accepts.
func assertSingleTerminal(t *testing.T, body string, wantError bool) {
	t.Helper()

	tail := body
	if len(tail) > 200 {
		tail = tail[len(tail)-200:]
	}
	require.Equal(t, 1, strings.Count(body, "[DONE]"),
		"exactly one [DONE] terminator expected, got body:\n%s", body)
	if wantError {
		require.True(t, strings.HasSuffix(body, interruptedSuffix()),
			"stream must end with the interrupted error frame + [DONE], got tail:\n%q", tail)
		require.Equal(t, 1, strings.Count(body, "stream interrupted"),
			"exactly one error frame expected")
	} else {
		require.True(t, strings.HasSuffix(body, "data: [DONE]\n\n"),
			"stream must end with the bare [DONE] terminator, got tail:\n%q", tail)
		require.NotContains(t, body, "stream interrupted",
			"no error frame expected on this path")
	}
	require.NoError(t, apiformat.ValidateChatStream(strings.Split(body, "\n")),
		"the delivered body must be a valid chat stream")
}

// serveCancelledStream runs serveStream against the given upstream with a
// client context cancelled after d, and returns the recorder.
func serveCancelledStream(t *testing.T, upstreamURL string, cancelAfter time.Duration) *httptest.ResponseRecorder {
	t.Helper()

	gw := streamTestGateway(upstreamURL)
	info := resolver.ModelInfo{ModelName: "gpt-4", Provider: "", Enabled: true}
	rec := httptest.NewRecorder()
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(cancelAfter, cancel)
	defer cancel()

	gw.serveStream(rec, ctx, info, streamBody(t, "gpt-4", "hi"), false,
		"sess", "org", "", "task", "req", testLogger(), routingDecision{},
		"", 0, "", "", "", false)
	return rec
}

// TestServeStream_ClientCancelMidStreamSingleTerminal: the client hangs up
// mid-stream. The drain stops at the cancel, the finisher appends exactly
// one error frame + one [DONE], and everything delivered before the cut is
// a sequence of complete chunk frames — no torn frames, no double terminal.
func TestServeStream_ClientCancelMidStreamSingleTerminal(t *testing.T) {
	const maxChunks = 400 // safety cap (~10s); the cancel ends the test first
	var srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for i := 0; i < maxChunks; i++ {
			_, _ = fmt.Fprint(w, chunkFrame("1", fmt.Sprintf("chunk-%d", i)))
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(25 * time.Millisecond):
			}
		}
	}))
	defer srv.Close()

	rec := serveCancelledStream(t, srv.URL, 120*time.Millisecond)

	body := rec.Body.String()
	assertSingleTerminal(t, body, true)

	// Everything before the terminal tail must be the concatenation of the
	// first k deterministic chunks — a byte-exact frame boundary, never a
	// torn frame.
	suffix := interruptedSuffix()
	require.True(t, strings.HasSuffix(body, suffix))
	prefix := strings.TrimSuffix(body, suffix)
	require.NotEmpty(t, prefix, "at least one chunk must have been relayed before the cancel")

	found := false
	for k := 1; k <= maxChunks; k++ {
		var want strings.Builder
		for i := 0; i < k; i++ {
			want.WriteString(chunkFrame("1", fmt.Sprintf("chunk-%d", i)))
		}
		if want.String() == prefix {
			found = true
			break
		}
	}
	require.True(t, found, "delivered prefix is not a whole number of complete chunks:\n%q", prefix)
}

// TestServeStream_ClientCancelAfterDoneNoSecondTerminal: the upstream
// finishes its stream ([DONE] delivered) and keeps the connection open; the
// client cancels during that silence. The drain error that follows arrives
// after clientSawDone, so the gateway must stay silent — no error frame, no
// second [DONE]. (Cancel-flavour complement of the idle-flavour
// TestServeStream_LateErrorAfterDoneEmitsNoSecondTerminal.)
func TestServeStream_ClientCancelAfterDoneNoSecondTerminal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, chunkFrame("1", "a"))
		w.(http.Flusher).Flush()
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
		w.(http.Flusher).Flush()
		// Hold the connection until the gateway disconnects (or a generous
		// real-time cap; the test's cancel at 150ms wins long before).
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer srv.Close()

	rec := serveCancelledStream(t, srv.URL, 150*time.Millisecond)

	want := chunkFrame("1", "a") + "data: [DONE]\n\n"
	require.Equal(t, want, rec.Body.String(),
		"the body must be byte-identical to what the upstream sent — nothing may follow the [DONE]")
	assertSingleTerminal(t, rec.Body.String(), false)
}

// TestServeStream_CancelUnderSplitChunksValidPrefix: the upstream splits its
// frames into sub-frame pieces (the harness's own streamBody-style handlers
// always write whole frames; real proxies don't). The line-buffered relay
// must still deliver only complete frames, and the bytes received before the
// cancel must be a byte-prefix of the original stream (the card's acceptance
// "клиенты читают валидный поток при любом разбиении чанков", under cancel).
func TestServeStream_CancelUnderSplitChunksValidPrefix(t *testing.T) {
	var full strings.Builder
	for i := 0; i < 30; i++ {
		full.WriteString(chunkFrame("1", fmt.Sprintf("piece-%02d", i)))
	}
	full.WriteString("data: [DONE]\n\n")
	fullStream := full.String()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		// ~40-byte pieces, 5ms apart: the first complete frame assembles at
		// ~15ms, the test cancels at 120ms (several frames relayed), and the
		// full stream takes ~415ms — the cancel lands safely mid-stream even
		// when the harness machine stretches the pacing.
		for i := 0; i < len(fullStream); i += 40 {
			end := i + 40
			if end > len(fullStream) {
				end = len(fullStream)
			}
			if _, err := w.Write([]byte(fullStream[i:end])); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
	}))
	defer srv.Close()

	rec := serveCancelledStream(t, srv.URL, 120*time.Millisecond)

	body := rec.Body.String()
	assertSingleTerminal(t, body, true)

	suffix := interruptedSuffix()
	require.True(t, strings.HasSuffix(body, suffix))
	prefix := strings.TrimSuffix(body, suffix)
	require.NotEmpty(t, prefix, "at least one piece must have been relayed before the cancel")
	require.True(t, strings.HasPrefix(fullStream, prefix),
		"delivered bytes must be a byte-prefix of the original stream")
	require.True(t, strings.HasSuffix(prefix, "\n\n"),
		"the relay is line-buffered: only complete frames may reach the client")
	require.Less(t, len(prefix), len(fullStream),
		"the cancel must have landed mid-stream for this test to prove anything")
}

// TestSSEToolGate_LateErrorWhileHoldingReleasesOnceOnDone: a drain failure
// (writeSSEError) arriving while the tool gate HOLDS a tool-call's frames
// must not deliver anything out of order or duplicate the terminator. The
// error frame is held like any other; the [DONE] write releases held frames,
// then the error frame, then exactly one [DONE] — a valid stream, writer
// flushed exactly once.
func TestSSEToolGate_LateErrorWhileHoldingReleasesOnceOnDone(t *testing.T) {
	rec := httptest.NewRecorder()
	gate := newSSEToolGateWriter(context.Background(), rec, nil, "org", "*", true)

	// A name-bearing first fragment of a tool call engages the hold (the
	// gate waits for the call's argument chunks before deciding).
	nameFrame := "data: {\"id\":\"1\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"\"}}]}}]}\n\n"
	_, err := gate.Write([]byte(nameFrame))
	require.NoError(t, err)
	assert.True(t, gate.holding, "a name-bearing tool-call fragment must engage the hold")
	assert.Empty(t, rec.Body.String(), "nothing may reach the client while the gate holds")

	// A late drain failure lands mid-hold: the error frame joins the held
	// queue instead of cutting the held call apart.
	errFrame := apierrs.SSEErrorFrame(&apierrs.E{Type: apierrors.ErrorCodeAPI, Message: "stream interrupted"})
	_, err = gate.Write(errFrame)
	require.NoError(t, err)
	assert.True(t, gate.holding, "a non-terminal frame must not release the hold")
	assert.Empty(t, rec.Body.String())

	// The terminal [DONE] flushes held frames (order preserved), then the
	// error frame, then the terminator — exactly once.
	_, err = gate.Write([]byte("data: [DONE]\n\n"))
	require.NoError(t, err)

	want := nameFrame + string(errFrame) + "data: [DONE]\n\n"
	require.Equal(t, want, rec.Body.String(),
		"release must emit held frames, the error frame, then a single [DONE] — byte-exact")
	assert.False(t, gate.holding, "the hold must be cleared by the release")
	assert.Empty(t, gate.heldFrames, "no frame may be left in the hold")
	assert.Zero(t, gate.DeniedCount(), "no policy denial is involved here")

	assertSingleTerminal(t, rec.Body.String(), true)

	// Post-release passthrough: later writes go straight through.
	after := chunkFrame("1", "tail")
	_, err = gate.Write([]byte(after))
	require.NoError(t, err)
	assert.False(t, gate.holding)
	require.True(t, strings.HasSuffix(rec.Body.String(), after))
}

// TestIdleWatchdogStopDisarmsBeforeFire: drain() defers streamIdle.Stop()
// exactly once; the disarmed timer must never fire afterwards — a finished
// drain cannot cause a late streamCtx cancel (which would race the finisher
// and could misclassify the termination). Pins the Stop contract the
// exactly-once close argument relies on.
func TestIdleWatchdogStopDisarmsBeforeFire(t *testing.T) {
	var onIdle atomic.Int32
	ir := newIdleReader(strings.NewReader("hello"), 30*time.Millisecond, func() {
		onIdle.Add(1)
	})

	buf := make([]byte, 5)
	n, err := ir.Read(buf) // delivers bytes and pushes the deadline back
	require.NoError(t, err)
	require.Equal(t, 5, n)

	ir.Stop()                          // the drain-ended disarm
	time.Sleep(120 * time.Millisecond) // comfortably past the 30ms window

	assert.False(t, ir.Fired(), "a stopped watchdog must never fire")
	assert.Equal(t, int32(0), onIdle.Load(), "onIdle must not run after Stop")
}
