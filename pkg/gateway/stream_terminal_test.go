package cli

// N03-P01-T02: the SSE terminal contract — exactly one terminal event per
// stream. A late drain failure after the client already received the [DONE]
// terminator must not emit a second terminal event (an error frame plus a
// duplicate [DONE] after [DONE] is an invalid stream per
// pkg/apiformat.ValidateChatStream); a mid-stream failure before any [DONE]
// still yields the error frame followed by a single [DONE].

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apiformat "github.com/reireirei/yabanin/pkg/apiformat"
	"github.com/reireirei/yabanin/pkg/resolver"
)

// terminalStubWriter is an http.ResponseWriter without Flusher, for the
// nil-flusher branch of the terminal watch.
type terminalStubWriter struct{ header http.Header }

func (w *terminalStubWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}

func (w *terminalStubWriter) Write(p []byte) (int, error) { return len(p), nil }
func (w *terminalStubWriter) WriteHeader(int)             {}

func TestSSETerminalWatch_DetectsTerminatorShapes(t *testing.T) {
	const chunk = "data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"a\"}}]}\n\n"
	cases := []struct {
		name   string
		writes [][]byte
		want   bool
	}{
		{"bare line (openai passthrough)", [][]byte{[]byte(chunk), []byte("data: [DONE]")}, true},
		{"whole frame (anthropic/policy writers)", [][]byte{[]byte(chunk), []byte("data: [DONE]\n\n")}, true},
		{"frame split across writes", [][]byte{[]byte("data: [DONE]"), []byte("\n\n")}, true},
		// N03-P01 review: ValidateChatStream (pkg/apiformat) accepts the
		// no-space form (`data:` prefix, payload after trimming at most one
		// space), so a no-space terminator must mark the delivery too — the
		// openai passthrough relays upstream bytes verbatim.
		{"no-space bare line", [][]byte{[]byte(chunk), []byte("data:[DONE]")}, true},
		{"no-space whole frame", [][]byte{[]byte(chunk), []byte("data:[DONE]\n\n")}, true},
		{"no-space frame split across writes", [][]byte{[]byte("data:[DONE]"), []byte("\n\n")}, true},
		{"no-space frame with trailing CR", [][]byte{[]byte(chunk), []byte("data:[DONE]\r\n\r\n")}, true},
		{"mention inside a content delta", [][]byte{[]byte("data: {\"choices\":[{\"delta\":{\"content\":\"say data: [DONE] to stop\"}}]}\n\n")}, false},
		{"no-space mention inside a content delta", [][]byte{[]byte("data: {\"choices\":[{\"delta\":{\"content\":\"say data:[DONE] to stop\"}}]}\n\n")}, false},
		{"two-space terminator is not a valid shape", [][]byte{[]byte(chunk), []byte("data:  [DONE]\n\n")}, false},
		{"no terminator", [][]byte{[]byte(chunk)}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			watch := newSSETerminalWatch(rec)
			var want strings.Builder
			for _, p := range tc.writes {
				n, err := watch.Write(p)
				require.NoError(t, err)
				require.Equal(t, len(p), n)
				want.Write(p)
			}
			assert.Equal(t, tc.want, watch.sawDone())
			assert.Equal(t, want.String(), rec.Body.String(),
				"the watch must relay bytes unchanged")
		})
	}
}

func TestSSETerminalWatch_FlushPassthrough(t *testing.T) {
	rec := httptest.NewRecorder()
	watch := newSSETerminalWatch(rec)
	require.NotPanics(t, func() { watch.Flush() }, "flusher passthrough must work")

	bare := newSSETerminalWatch(&terminalStubWriter{})
	require.NotPanics(t, func() { bare.Flush() }, "a writer without Flusher must not panic on Flush")
}

// TestServeStream_LateErrorAfterDoneEmitsNoSecondTerminal is the card's
// negative acceptance: "поздняя ошибка не выдаёт второй terminal event".
// The upstream delivers its [DONE] and only then stalls past the idle
// watchdog, so HandleStream returns a drain error AFTER the terminator
// reached the client. The gateway must not append an error frame or a
// second [DONE]: the client's stream ends at the first [DONE] and
// validates cleanly; the failure stays a log/accounting/event matter.
func TestServeStream_LateErrorAfterDoneEmitsNoSecondTerminal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, "data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"a\"}}]}\n\n")
		w.(http.Flusher).Flush()
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
		w.(http.Flusher).Flush()
		// Real-timeout stall: the drain error must arrive only after the
		// terminator was already relayed (same race discipline as the idle
		// test: the silent stretch comfortably outlasts the idle window).
		time.Sleep(400 * time.Millisecond)
	}))
	defer srv.Close()

	gw := streamTestGateway(srv.URL)
	gw.streamIdleTimeout = 80 * time.Millisecond

	info := resolver.ModelInfo{ModelName: "gpt-4", Provider: "", Enabled: true}
	rec := httptest.NewRecorder()
	gw.serveStream(rec, context.Background(), info,
		streamBody(t, "gpt-4", "hi"), false, "sess", "org", "", "task", "req",
		testLogger(), routingDecision{}, "", 0, "", "", "", false)

	body := rec.Body.String()
	assert.Contains(t, body, "\"content\":\"a\"", "the delivered prefix must reach the client")
	assert.Equal(t, 1, strings.Count(body, "data: [DONE]"),
		"exactly one [DONE] expected, got %q", body)
	assert.True(t, strings.HasSuffix(body, "data: [DONE]\n\n"),
		"the stream must end at the delivered [DONE], got %q", body)
	assert.NotContains(t, body, "\"error\"",
		"a late failure after [DONE] must not append an error frame")
	require.NoError(t, apiformat.ValidateChatStream(strings.Split(body, "\n")),
		"the client's stream must validate cleanly")
}

// TestServeStream_LateErrorAfterNoSpaceDoneEmitsNoSecondTerminal pins the
// N03-P01 review gap: ValidateChatStream accepts the no-space
// `data:[DONE]` terminator, and the openai passthrough relays upstream
// bytes verbatim — so a late failure after a NO-SPACE terminator must stay
// silent exactly like after the spaced one. Before the widened watch this
// produced an error frame + duplicate [DONE] after [DONE], a stream
// ValidateChatStream rejects ("duplicate [DONE]").
func TestServeStream_LateErrorAfterNoSpaceDoneEmitsNoSecondTerminal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, "data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"a\"}}]}\n\n")
		w.(http.Flusher).Flush()
		_, _ = fmt.Fprint(w, "data:[DONE]\n\n") // no space after the colon
		w.(http.Flusher).Flush()
		time.Sleep(400 * time.Millisecond) // late drain error after the terminator
	}))
	defer srv.Close()

	gw := streamTestGateway(srv.URL)
	gw.streamIdleTimeout = 80 * time.Millisecond

	info := resolver.ModelInfo{ModelName: "gpt-4", Provider: "", Enabled: true}
	rec := httptest.NewRecorder()
	gw.serveStream(rec, context.Background(), info,
		streamBody(t, "gpt-4", "hi"), false, "sess", "org", "", "task", "req",
		testLogger(), routingDecision{}, "", 0, "", "", "", false)

	body := rec.Body.String()
	assert.Contains(t, body, "\"content\":\"a\"", "the delivered prefix must reach the client")
	assert.Equal(t, 1, strings.Count(body, "[DONE]"),
		"exactly one terminator (the no-space one) expected, got %q", body)
	assert.True(t, strings.HasSuffix(body, "data:[DONE]\n\n"),
		"the stream must end at the delivered no-space [DONE], got %q", body)
	assert.NotContains(t, body, "\"error\"",
		"a late failure after the no-space [DONE] must not append an error frame")
	require.NoError(t, apiformat.ValidateChatStream(strings.Split(body, "\n")),
		"the client's stream must validate cleanly")
}

// TestServeStream_MidStreamErrorStillWritesSingleTerminal pins the unchanged
// contract: a failure BEFORE any [DONE] still notifies the client with the
// error frame followed by exactly one [DONE] (the guard must only suppress
// post-terminator writes).
func TestServeStream_MidStreamErrorStillWritesSingleTerminal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, "data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"a\"}}]}\n\n")
		w.(http.Flusher).Flush()
		time.Sleep(400 * time.Millisecond) // stall: no [DONE] ever arrives
	}))
	defer srv.Close()

	gw := streamTestGateway(srv.URL)
	gw.streamIdleTimeout = 80 * time.Millisecond

	info := resolver.ModelInfo{ModelName: "gpt-4", Provider: "", Enabled: true}
	rec := httptest.NewRecorder()
	gw.serveStream(rec, context.Background(), info,
		streamBody(t, "gpt-4", "hi"), false, "sess", "org", "", "task", "req",
		testLogger(), routingDecision{}, "", 0, "", "", "", false)

	body := rec.Body.String()
	assert.Contains(t, body, "upstream stream idle timeout",
		"a mid-stream failure must still be reported to the client")
	assert.Equal(t, 1, strings.Count(body, "data: [DONE]"),
		"exactly one [DONE] expected, got %q", body)
	assert.True(t, strings.HasSuffix(body, "data: [DONE]\n\n"), "got %q", body)
	require.NoError(t, apiformat.ValidateChatStream(strings.Split(body, "\n")))
}
