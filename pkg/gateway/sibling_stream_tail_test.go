package cli

// Sibling SSE tail-integrity reproduction (follow-up to the chat F2 fix in
// records/2026-11-21-p2-stream-fix-ci-44814334185.md, "Remaining limits" 2):
// the four passthrough relays that share the chat drain-failure canon —
// legacy /v1/completions, /v1/realtime, native /v1/messages and native
// /v1/responses — must never strand a half-written event on the client
// when the upstream breaks mid-flight:
//
//   - a complete line whose blank separator never arrived is closed
//     (byte-exact against the upstream stream) so the terminal frame
//     composes at an event boundary;
//   - a line cut before its terminator is withheld — a delimiter alone
//     cannot turn truncated JSON into a decodable event, and provider SDKs
//     that JSON-decode each data payload would fail there and never see
//     the terminal frame;
//   - every dispatched data payload decodes as JSON (the [DONE] sentinel
//     excepted), which is exactly what an event-by-event SDK consumer does.
//
// The oracle is deliberately independent of the product SSE stack (no
// apiformat): a test-local line/frame scanner plus expected frames
// enumerated from the fixture constants. Fixture-authored frames are
// pinned byte-exact; synthesized terminal frames are pinned by parsed
// content, never by re-running the producing code on the output.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/apiformat"
	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/config"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	upstreampkg "github.com/reireirei/yabanin/pkg/upstream"
)

// sseFrame is one parsed client event: its raw bytes (without the
// terminating blank line), the "event:" value and the "data:" payloads.
type sseFrame struct {
	raw   string
	event string
	data  []string
}

// sseClientFrames is the independent test oracle for the client byte
// stream: an SSE line scanner (LF, CRLF and CR terminators per the SSE
// grammar) grouping lines into frames at blank lines. Bytes after the last
// blank line that never reached a line terminator are reported as a torn
// tail. Lines that are neither event/data fields nor comments fail the
// parse — the fixtures are fully controlled.
func sseClientFrames(t *testing.T, raw string) (frames []sseFrame, torn string) {
	t.Helper()
	pos, frameStart, lastContentEnd := 0, 0, 0
	var cur sseFrame
	sawLine, hasField := false, false
	for pos < len(raw) {
		i := strings.IndexAny(raw[pos:], "\r\n")
		if i < 0 {
			// Unterminated trailing bytes: a partial line never dispatched
			// by the frame grammar.
			return frames, raw[frameStart:]
		}
		contentEnd := pos + i
		next := contentEnd + 1
		if raw[contentEnd] == '\r' && contentEnd+1 < len(raw) && raw[contentEnd+1] == '\n' {
			next = contentEnd + 2 // CRLF pair
		}
		line := raw[pos:contentEnd]
		pos = next
		if line == "" {
			if sawLine && hasField {
				cur.raw = raw[frameStart:lastContentEnd]
				frames = append(frames, cur)
				cur = sseFrame{}
				sawLine, hasField = false, false
			}
			frameStart = pos
			continue
		}
		sawLine = true
		lastContentEnd = contentEnd
		switch {
		case strings.HasPrefix(line, "event:"):
			if cur.event != "" {
				t.Fatalf("frame carries two event lines:\n%s", line)
			}
			cur.event = strings.TrimPrefix(strings.TrimPrefix(line, "event:"), " ")
			hasField = true
		case strings.HasPrefix(line, "data:"):
			cur.data = append(cur.data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
			hasField = true
		case strings.HasPrefix(line, ":"):
			// SSE comment line: rides no event, so a comment-only frame
			// is not an event (the keepalive passthrough contract).
		default:
			t.Fatalf("frame carries a non-SSE line %q", line)
		}
	}
	if sawLine {
		return frames, raw[frameStart:]
	}
	return frames, ""
}

// requireFramePrefix asserts the client stream is whole-framed and starts
// with exactly the expected fixture frames: no torn tail, every expected
// frame byte-equal (normalized line terminators preserved in raw). Returns
// all parsed frames so the tests can pin the synthesized terminal frames
// by content.
func requireFramePrefix(t *testing.T, name, raw string, want []string) []sseFrame {
	t.Helper()
	frames, torn := sseClientFrames(t, raw)
	if torn != "" {
		t.Fatalf("%s: stream ends in a torn tail %q\nstream:\n%s", name, torn, raw)
	}
	if len(frames) < len(want) {
		t.Fatalf("%s: got %d frames, want at least %d\nstream:\n%s", name, len(frames), len(want), raw)
	}
	for i, wf := range want {
		if frames[i].raw != wf {
			t.Fatalf("%s: frame %d mismatch\n got %q\nwant %q\nstream:\n%s", name, i, frames[i].raw, wf, raw)
		}
		if len(frames[i].data) == 0 {
			t.Fatalf("%s: frame %d has no data line:\n%s", name, i, frames[i].raw)
		}
	}
	return frames
}

// requireAllDataJSON is the SDK-consumer oracle: every dispatched event
// must decode as JSON — exactly what a provider SDK parsing the stream
// event-by-event does. SSE decodes one event by joining its data lines
// with LF, so the JOINED payload is validated, not each line separately
// (a multiline event split across data lines is one JSON document). The
// [DONE] terminator is the one legal sentinel.
func requireAllDataJSON(t *testing.T, name string, frames []sseFrame) {
	t.Helper()
	for i, f := range frames {
		if len(f.data) == 0 {
			continue // comment-only keepalive frames carry no event
		}
		joined := strings.Join(f.data, "\n")
		if joined == "[DONE]" {
			continue
		}
		if !json.Valid([]byte(joined)) {
			t.Fatalf("%s: frame %d data (data lines joined with LF) does not decode as JSON (an event-by-event SDK consumer would fail here): %q\nframe:\n%s", name, i, joined, f.raw)
		}
	}
}

// requireOpenAIErrorFrame pins the writeSSEError terminal frame by
// content: a data-only frame whose payload is an error envelope with the
// exact message produced by the drain-failure canon.
func requireOpenAIErrorFrame(t *testing.T, f sseFrame, message string) {
	t.Helper()
	if f.event != "" {
		t.Fatalf("error frame must be data-only, saw event %q:\n%s", f.event, f.raw)
	}
	if len(f.data) != 1 {
		t.Fatalf("error frame must carry one data line, saw %d:\n%s", len(f.data), f.raw)
	}
	var doc struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(f.data[0]), &doc); err != nil {
		t.Fatalf("error frame data is not valid JSON (%v):\n%s", err, f.raw)
	}
	if doc.Error.Message != message {
		t.Fatalf("error message %q, want %q:\n%s", doc.Error.Message, message, f.raw)
	}
	if doc.Error.Type == "" {
		t.Fatalf("error envelope without a type:\n%s", f.raw)
	}
}

// requireTerminalSequence checks the two-frame writeSSEError tail — the
// error frame then the [DONE] terminator — at the given index.
func requireTerminalSequence(t *testing.T, frames []sseFrame, errIdx int, message string) {
	t.Helper()
	requireOpenAIErrorFrame(t, frames[errIdx], message)
	done := frames[errIdx+1]
	if done.event != "" || len(done.data) != 1 || done.data[0] != "[DONE]" {
		t.Fatalf("frame after the error must be the bare [DONE] terminator, got event %q data %v", done.event, done.data)
	}
	if errIdx+2 != len(frames) {
		t.Fatalf("nothing may follow the [DONE] terminator: %d extra frames", len(frames)-errIdx-2)
	}
}

// ---- legacy /v1/completions ----

// TestCompletions_StreamBreakTornTailCompletesBeforeError: the upstream
// cuts after a data line and its LF but before the blank separator. The
// relayed dangling event must be closed (one LF — byte-exact against the
// upstream stream) so the drain-failure error frame and [DONE] arrive as
// whole events instead of gluing into the half-written chunk.
func TestCompletions_StreamBreakTornTailCompletesBeforeError(t *testing.T) {
	const whole = `data: {"id":"cmpl-torn","object":"text_completion.chunk","model":"m","choices":[{"index":0,"text":"he"}]}` + "\n\n"
	const dangling = `data: {"id":"cmpl-torn","object":"text_completion.chunk","model":"m","choices":[{"index":0,"text":"ll"}]}`

	upstreamSrv := breakServer(t, whole+dangling+"\n")
	defer upstreamSrv.Close()

	gw := &gateway{
		cfg:                  config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: upstreamSrv.URL},
		log:                  slog.Default(),
		auth:                 NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
		res:                  stubModelResolver{"m": {ModelName: "fim", Provider: "openai", UpstreamURL: upstreamSrv.URL, Enabled: true}},
		pool:                 upstreampkg.NewPool(upstreampkg.Options{}),
		streamUsageProviders: map[string]bool{"openai": true},
		streamIdleTimeout:    0,
	}

	rec := postCompletions(t, gw, `{"model":"m","prompt":"fn","stream":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	raw := rec.Body.String()
	frames := requireFramePrefix(t, "completions", raw, []string{
		strings.TrimSuffix(whole, "\n\n"),
		dangling,
	})
	if len(frames) != 4 {
		t.Fatalf("completions: got %d frames, want 4 (2 upstream + error + [DONE])\nstream:\n%s", len(frames), raw)
	}
	requireTerminalSequence(t, frames, 2, "stream drain failed")
	requireAllDataJSON(t, "completions", frames)
}

// TestCompletions_StreamBreakMidLineWithholdsPartialLine: the cut lands
// inside a data line. bufio.Scanner yields the trailing partial token on
// a read error, so the re-serializing relay would dispatch it
// delimiter-completed — truncated JSON an event-by-event SDK consumer
// fails on before ever seeing the terminal frame. The partial must be
// withheld instead.
func TestCompletions_StreamBreakMidLineWithholdsPartialLine(t *testing.T) {
	const whole = `data: {"id":"cmpl-torn","object":"text_completion.chunk","model":"m","choices":[{"index":0,"text":"he"}]}` + "\n\n"
	const partial = `data: {"id":"cmpl-torn","object":"text_completion.chunk","model":"m","choices":[{"index":0,"text":"ll"`

	upstreamSrv := breakServer(t, whole+partial)
	defer upstreamSrv.Close()

	gw := &gateway{
		cfg:                  config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: upstreamSrv.URL},
		log:                  slog.Default(),
		auth:                 NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
		res:                  stubModelResolver{"m": {ModelName: "fim", Provider: "openai", UpstreamURL: upstreamSrv.URL, Enabled: true}},
		pool:                 upstreampkg.NewPool(upstreampkg.Options{}),
		streamUsageProviders: map[string]bool{"openai": true},
		streamIdleTimeout:    0,
	}

	rec := postCompletions(t, gw, `{"model":"m","prompt":"fn","stream":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	raw := rec.Body.String()
	frames := requireFramePrefix(t, "completions mid-line", raw, []string{
		strings.TrimSuffix(whole, "\n\n"),
	})
	if len(frames) != 3 {
		t.Fatalf("completions mid-line: got %d frames, want 3 (1 upstream + error + [DONE]); the partial line must be withheld\nstream:\n%s", len(frames), raw)
	}
	if strings.Contains(raw, `"text":"ll"`) || strings.Contains(raw, partial) {
		t.Fatalf("completions mid-line: the unterminated partial line reached the client:\n%s", raw)
	}
	requireTerminalSequence(t, frames, 1, "stream drain failed")
	requireAllDataJSON(t, "completions mid-line", frames)
}

// ---- /v1/realtime ----

// TestRealtime_StreamBreakDanglingLineClosesBeforeError: the relay cuts
// after a complete event line pair and its LF but before the blank
// separator. The dangling event must be closed before writeSSEError.
func TestRealtime_StreamBreakDanglingLineClosesBeforeError(t *testing.T) {
	const whole = "event: session.created\n" +
		`data: {"type":"session.created","session":{"id":"sess_1","model":"gpt-4o-realtime-canon"}}` + "\n\n"
	const dangling = "event: response.done\n" +
		`data: {"type":"response.done","response":{"id":"resp_1","usage":{"input_tokens":9,"output_tokens":2}}}` + "\n"

	upstream := breakServer(t, whole+dangling)
	defer upstream.Close()

	gw := r105TestGateway(t, realtimeTestModel(upstream.URL))

	rec := postR105(t, gw, "/v1/realtime", `{"model":"m","session":{"voice":"alloy"},"input":"hello"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	raw := rec.Body.String()
	frames := requireFramePrefix(t, "realtime", raw, []string{
		strings.TrimSuffix(whole, "\n\n"),
		strings.TrimSuffix(dangling, "\n"),
	})
	if len(frames) != 4 {
		t.Fatalf("realtime: got %d frames, want 4 (2 upstream + error + [DONE])\nstream:\n%s", len(frames), raw)
	}
	requireTerminalSequence(t, frames, 2, "realtime stream interrupted")
	requireAllDataJSON(t, "realtime", frames)
}

// TestRealtime_StreamBreakMidLineWithholdsPartialLine: the cut lands
// inside a data line. The unterminated partial must never reach the
// client — a delimiter cannot make truncated JSON decodable, and an SDK
// consuming events would fail on it and never see the terminal frame. The
// terminal sequence still composes at an event boundary.
func TestRealtime_StreamBreakMidLineWithholdsPartialLine(t *testing.T) {
	const whole = "event: session.created\n" +
		`data: {"type":"session.created","session":{"id":"sess_1","model":"gpt-4o-realtime-canon"}}` + "\n\n"
	const partial = `data: {"type":"response.done","resp`

	upstream := breakServer(t, whole+partial)
	defer upstream.Close()

	gw := r105TestGateway(t, realtimeTestModel(upstream.URL))

	rec := postR105(t, gw, "/v1/realtime", `{"model":"m","session":{"voice":"alloy"},"input":"hello"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	raw := rec.Body.String()
	frames := requireFramePrefix(t, "realtime mid-line", raw, []string{
		strings.TrimSuffix(whole, "\n\n"),
	})
	if len(frames) != 3 {
		t.Fatalf("realtime mid-line: got %d frames, want 3 (1 upstream + error + [DONE]); the partial line must be withheld\nstream:\n%s", len(frames), raw)
	}
	if strings.Contains(raw, `"resp`+`onse.done"`) || strings.Contains(raw, partial) {
		t.Fatalf("realtime mid-line: the unterminated partial line reached the client:\n%s", raw)
	}
	requireTerminalSequence(t, frames, 1, "realtime stream interrupted")
	requireAllDataJSON(t, "realtime mid-line", frames)
}

// ---- native /v1/messages ----

// requireSynthesizedClose pins the messages-native synthesized terminal
// pair by content: content_block_stop for the open index, then the shared
// error event.
func requireSynthesizedClose(t *testing.T, name string, frames []sseFrame, stopIdx int) {
	t.Helper()
	stop := frames[stopIdx]
	if stop.event != "content_block_stop" {
		t.Fatalf("%s: frame %d must be the synthesized content_block_stop, saw event %q:\n%s", name, stopIdx, stop.event, stop.raw)
	}
	var stopDoc struct {
		Type  string `json:"type"`
		Index int    `json:"index"`
	}
	if err := json.Unmarshal([]byte(stop.data[0]), &stopDoc); err != nil {
		t.Fatalf("%s: synthesized stop frame data is not valid JSON (%v):\n%s", name, err, stop.raw)
	}
	if stopDoc.Type != "content_block_stop" || stopDoc.Index != 0 {
		t.Fatalf("%s: synthesized stop frame %+v:\n%s", name, stopDoc, stop.raw)
	}
	errFrame := frames[stopIdx+1]
	if errFrame.event != "error" {
		t.Fatalf("%s: frame %d must be the synthesized error event, saw %q:\n%s", name, stopIdx+1, errFrame.event, errFrame.raw)
	}
	var errDoc struct {
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(errFrame.data[0]), &errDoc); err != nil {
		t.Fatalf("%s: synthesized error frame data is not valid JSON (%v):\n%s", name, err, errFrame.raw)
	}
	if errDoc.Error.Message != "stream interrupted" || errDoc.Error.Type == "" {
		t.Fatalf("%s: synthesized error frame %+v:\n%s", name, errDoc, errFrame.raw)
	}
	if stopIdx+2 != len(frames) {
		t.Fatalf("%s: nothing may follow the synthesized error event: %d extra frames", name, len(frames)-stopIdx-2)
	}
}

const messagesNativeWhole = "event: message_start\n" +
	`data: {"type":"message_start","message":{"id":"msg_1","usage":{"input_tokens":5,"output_tokens":1}}}` + "\n\n" +
	"event: content_block_start\n" +
	`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}` + "\n\n"

var messagesNativeWholeFrames = []string{
	"event: message_start\n" + `data: {"type":"message_start","message":{"id":"msg_1","usage":{"input_tokens":5,"output_tokens":1}}}`,
	"event: content_block_start\n" + `data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
}

const messagesRequestBody = `{"model":"claude-3-5-sonnet","max_tokens":16,"stream":true,"messages":[{"role":"user","content":"hi"}]}`

// TestMessagesNative_StreamBreakTornTailSynthesisClosesFrame: the upstream
// cuts after a content_block_delta data line and its LF but before the
// blank separator. The dangling event must be closed before the
// synthesized content_block_stop / error frames glue into it.
func TestMessagesNative_StreamBreakTornTailSynthesisClosesFrame(t *testing.T) {
	const dangling = "event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"he"}}` + "\n"

	upstream := breakServer(t, messagesNativeWhole+dangling)
	defer upstream.Close()

	gw := nativeMessagesGateway(t, upstream.URL)

	rec := postMessages(t, gw, messagesRequestBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	raw := rec.Body.String()
	frames := requireFramePrefix(t, "messages native", raw, append(append([]string{}, messagesNativeWholeFrames...),
		strings.TrimSuffix(dangling, "\n"),
	))
	if len(frames) != 5 {
		t.Fatalf("messages native: got %d frames, want 5 (3 upstream + synthesized stop + error)\nstream:\n%s", len(frames), raw)
	}
	requireSynthesizedClose(t, "messages native", frames, 3)
	requireAllDataJSON(t, "messages native", frames)
}

// TestMessagesNative_StreamBreakMidLineWithholdsPartialLine: the cut lands
// inside the delta data line; the unterminated partial must be withheld
// (never dispatched, never JSON-decoded by a consumer) while the still-open
// block still gets its synthesized close.
func TestMessagesNative_StreamBreakMidLineWithholdsPartialLine(t *testing.T) {
	const partial = "event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_de`

	upstream := breakServer(t, messagesNativeWhole+partial)
	defer upstream.Close()

	gw := nativeMessagesGateway(t, upstream.URL)

	rec := postMessages(t, gw, messagesRequestBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	raw := rec.Body.String()
	frames := requireFramePrefix(t, "messages native mid-line", raw, messagesNativeWholeFrames)
	if len(frames) != 4 {
		t.Fatalf("messages native mid-line: got %d frames, want 4 (2 upstream + synthesized stop + error); the partial line must be withheld\nstream:\n%s", len(frames), raw)
	}
	if strings.Contains(raw, `text_de`+`lta"`) || strings.Contains(raw, partial) {
		t.Fatalf("messages native mid-line: the unterminated partial line reached the client:\n%s", raw)
	}
	requireSynthesizedClose(t, "messages native mid-line", frames, 2)
	requireAllDataJSON(t, "messages native mid-line", frames)
}

// TestMessagesNative_StreamBreakCRLNTornTailSynthesisClosesFrame: the same
// dangling-line cut on a CRLF-terminated upstream. CRLF is a valid SSE
// line terminator; closing the tail with one LF yields a legal blank line
// (mixed terminators dispatch per the grammar) and the synthesized frames
// still start at an event boundary.
func TestMessagesNative_StreamBreakCRLNTornTailSynthesisClosesFrame(t *testing.T) {
	whole := strings.ReplaceAll(messagesNativeWhole, "\n", "\r\n")
	const dangling = "event: content_block_delta\r\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"he"}}` + "\r\n"

	upstream := breakServer(t, whole+dangling)
	defer upstream.Close()

	gw := nativeMessagesGateway(t, upstream.URL)

	rec := postMessages(t, gw, messagesRequestBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	raw := rec.Body.String()
	frames := requireFramePrefix(t, "messages native CRLF", raw, []string{
		"event: message_start\r\n" + `data: {"type":"message_start","message":{"id":"msg_1","usage":{"input_tokens":5,"output_tokens":1}}}`,
		"event: content_block_start\r\n" + `data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
		"event: content_block_delta\r\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"he"}}`,
	})
	if len(frames) != 5 {
		t.Fatalf("messages native CRLF: got %d frames, want 5\nstream:\n%s", len(frames), raw)
	}
	requireSynthesizedClose(t, "messages native CRLF", frames, 3)
	requireAllDataJSON(t, "messages native CRLF", frames)
}

// TestMessagesNative_MultilineDataEventPassesThroughByteExact: a healthy
// upstream may split one JSON event across two data lines — SSE decodes
// the event by joining its data lines with LF — and the relay forwards
// frames byte-verbatim, so the joined payload must still decode. This is
// the positive control for the cut test below: multiline events are not
// mangled or split by the frame batching.
func TestMessagesNative_MultilineDataEventPassesThroughByteExact(t *testing.T) {
	const multilineDelta = "event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,` + "\n" +
		`data: "delta":{"type":"text_delta","text":"he"}}` + "\n\n"
	const wholeJSON = `{"type":"content_block_delta","index":0,` + "\n" +
		`"delta":{"type":"text_delta","text":"he"}}`
	const stop = "event: message_stop\n" + `data: {"type":"message_stop"}` + "\n\n"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, messagesNativeWhole+multilineDelta+stop)
	}))
	defer upstream.Close()

	gw := nativeMessagesGateway(t, upstream.URL)

	rec := postMessages(t, gw, messagesRequestBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	raw := rec.Body.String()
	frames := requireFramePrefix(t, "messages native multiline", raw, append(append([]string{}, messagesNativeWholeFrames...),
		strings.TrimSuffix(strings.TrimSuffix(multilineDelta, "\n"), "\n"),
	))
	if len(frames) != 4 {
		t.Fatalf("messages native multiline: got %d frames, want 4 (3 upstream + message_stop; a healthy complete stream synthesizes nothing)\nstream:\n%s", len(frames), raw)
	}
	delta := frames[2]
	if len(delta.data) != 2 || strings.Join(delta.data, "\n") != wholeJSON {
		t.Fatalf("messages native multiline: the two data lines must arrive verbatim and LF-join to the whole JSON document; got %q\nstream:\n%s", strings.Join(delta.data, "\n"), raw)
	}
	if frames[3].event != "message_stop" {
		t.Fatalf("messages native multiline: frame 3 must be message_stop, saw %q\nstream:\n%s", frames[3].event, raw)
	}
	requireAllDataJSON(t, "messages native multiline", frames)
}

// TestMessagesNative_MultilineDataCutDropsIncompleteEvent: the reviewer's
// independent RED (TestReviewMessagesMultilineCut, sse-multiline-review.log
// in the isolated core-preview2-stream-review worktree): the first data
// line of a multiline event is complete, the cut lands inside the second.
// The held frame's LF-joined payload is truncated JSON — undecodable — so
// the whole event is dropped (not dispatched separator-completed) and the
// synthesized close composes at an event boundary.
func TestMessagesNative_MultilineDataCutDropsIncompleteEvent(t *testing.T) {
	const cut = "event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,` + "\n" +
		`data: "delta":{"type":"text_de`

	upstream := breakServer(t, messagesNativeWhole+cut)
	defer upstream.Close()

	gw := nativeMessagesGateway(t, upstream.URL)

	rec := postMessages(t, gw, messagesRequestBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	raw := rec.Body.String()
	frames := requireFramePrefix(t, "messages native multiline cut", raw, messagesNativeWholeFrames)
	if len(frames) != 4 {
		t.Fatalf("messages native multiline cut: got %d frames, want 4 (2 upstream + synthesized stop + error); the truncated multiline event must be dropped\nstream:\n%s", len(frames), raw)
	}
	if strings.Contains(raw, `"delta"`) || strings.Contains(raw, `text_de`) {
		t.Fatalf("messages native multiline cut: any part of the cut multiline event reached the client:\n%s", raw)
	}
	requireSynthesizedClose(t, "messages native multiline cut", frames, 2)
	requireAllDataJSON(t, "messages native multiline cut", frames)
}

// ---- native /v1/responses ----

// requireResponsesFailedFrame pins the writeResponsesStreamFailed terminal
// frame by content: event name, response.failed type, failed status and
// the drain-failure message prefix.
func requireResponsesFailedFrame(t *testing.T, f sseFrame) {
	t.Helper()
	if f.event != "response.failed" {
		t.Fatalf("terminal frame must be response.failed, saw %q:\n%s", f.event, f.raw)
	}
	var doc struct {
		Type     string `json:"type"`
		Response struct {
			Status string `json:"status"`
			Error  struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		} `json:"response"`
	}
	if err := json.Unmarshal([]byte(f.data[0]), &doc); err != nil {
		t.Fatalf("failed frame data is not valid JSON (%v):\n%s", err, f.raw)
	}
	if doc.Type != "response.failed" || doc.Response.Status != "failed" {
		t.Fatalf("failed frame type/status %+v:\n%s", doc, f.raw)
	}
	if !strings.HasPrefix(doc.Response.Error.Message, "stream drain failed") {
		t.Fatalf("failed frame message %q must start with the drain-failure canon:\n%s", doc.Response.Error.Message, f.raw)
	}
}

// postResponsesNativeStream runs one streamed /v1/responses request
// against a real gateway server (the harness the native break tests use)
// and returns the full client byte stream.
func postResponsesNativeStream(t *testing.T, gw *gateway) string {
	t.Helper()
	router := chi.NewRouter()
	gw.routes(router)
	gwServer := httptest.NewServer(router)
	t.Cleanup(gwServer.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, gwServer.URL+"/v1/responses",
		strings.NewReader(`{"model":"m","input":"Hi","stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return string(raw)
}

// responsesNativeBreakGateway wires the native-responses break harness
// (strict auth, openai provider in the native list, stub model) and drains
// the finish-event observer so the relay fully settled before teardown.
func responsesNativeBreakGateway(t *testing.T, upstreamURL string) *gateway {
	t.Helper()
	gw := responsesTestGateway(t, upstreamURL)
	gw.cfg.ResponsesNativeProviders = []string{"openai"}
	gw.res = stubModelResolver{"m": {ModelName: "m", Provider: "openai", UpstreamURL: upstreamURL, Enabled: true}}
	evCh := make(chan *eventpub.Event, 4)
	restore := observeEvent(func(e *eventpub.Event) { evCh <- e })
	t.Cleanup(restore)
	t.Cleanup(func() {
		select {
		case <-evCh:
		case <-time.After(15 * time.Second):
		}
	})
	return gw
}

const responsesNativeWhole = "event: response.created\n" +
	`data: {"type":"response.created","response":{"id":"resp_1","usage":{"input_tokens":7,"output_tokens":0}}}` + "\n\n"

const responsesNativeWholeFrame = "event: response.created\n" +
	`data: {"type":"response.created","response":{"id":"resp_1","usage":{"input_tokens":7,"output_tokens":0}}}`

// TestResponsesNative_StreamBreakTornTailFailureFrameClosesFrame: the
// upstream cuts after a data-only delta line and its LF but before the
// blank separator; the dangling event must be closed before the
// response.failed frame composes.
func TestResponsesNative_StreamBreakTornTailFailureFrameClosesFrame(t *testing.T) {
	const dangling = `data: {"type":"response.output_text.delta","item_id":"msg_1","output_index":0,"content_index":0,"delta":"he"}` + "\n"

	upstream := breakServer(t, responsesNativeWhole+dangling)
	defer upstream.Close()

	raw := postResponsesNativeStream(t, responsesNativeBreakGateway(t, upstream.URL))
	frames := requireFramePrefix(t, "responses native", raw, []string{
		responsesNativeWholeFrame,
		strings.TrimSuffix(dangling, "\n"),
	})
	if len(frames) != 3 {
		t.Fatalf("responses native: got %d frames, want 3 (2 upstream + failed)\nstream:\n%s", len(frames), raw)
	}
	requireResponsesFailedFrame(t, frames[2])
	requireAllDataJSON(t, "responses native", frames)
}

// TestResponsesNative_StreamBreakMidLineWithholdsPartialLine: the cut
// lands inside the delta data line; the unterminated partial must be
// withheld and the response.failed frame composes at an event boundary.
func TestResponsesNative_StreamBreakMidLineWithholdsPartialLine(t *testing.T) {
	const partial = `data: {"type":"response.output_text.delta","item_id":"msg_1","output_index":0,"content_index":0,"delta":"h`

	upstream := breakServer(t, responsesNativeWhole+partial)
	defer upstream.Close()

	raw := postResponsesNativeStream(t, responsesNativeBreakGateway(t, upstream.URL))
	frames := requireFramePrefix(t, "responses native mid-line", raw, []string{
		responsesNativeWholeFrame,
	})
	if len(frames) != 2 {
		t.Fatalf("responses native mid-line: got %d frames, want 2 (1 upstream + failed); the partial line must be withheld\nstream:\n%s", len(frames), raw)
	}
	if strings.Contains(raw, partial) {
		t.Fatalf("responses native mid-line: the unterminated partial line reached the client:\n%s", raw)
	}
	requireResponsesFailedFrame(t, frames[1])
	requireAllDataJSON(t, "responses native mid-line", frames)
}

// ---- review round 2: boundary-aligned salvage, one terminal, keepalive,
// bounded frames (messages/realtime equivalents of the owner-verified
// responses controls) ----

// cleanEOEServer serves a fixture fully and returns normally: the client
// sees a clean end-of-stream, not a transport cut.
func cleanEOEServer(t *testing.T, fixture string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, fixture)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}))
}

// TestMessagesNative_PartialAfterValidFrameDropped: the frame's first data
// line is complete valid JSON (salvageable on its own) but the cut lands
// inside the SECOND data line. Observing the cut partial proves the event
// was still being written, so salvaging the valid prefix would fabricate a
// shorter event than the upstream sent — the whole frame is dropped and
// the synthesized close composes at an event boundary.
func TestMessagesNative_PartialAfterValidFrameDropped(t *testing.T) {
	const validThenCut = "event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"he"}}` + "\n" +
		`data: {"type":"con`

	upstream := breakServer(t, messagesNativeWhole+validThenCut)
	defer upstream.Close()

	gw := nativeMessagesGateway(t, upstream.URL)
	rec := postMessages(t, gw, messagesRequestBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	raw := rec.Body.String()
	frames := requireFramePrefix(t, "messages partial-rule", raw, messagesNativeWholeFrames)
	if len(frames) != 4 {
		t.Fatalf("messages partial-rule: got %d frames, want 4 (2 upstream + synthesized stop + error); a frame followed by a cut partial must not be salvaged\nstream:\n%s", len(frames), raw)
	}
	if strings.Contains(raw, `text":"he"`) {
		t.Fatalf("messages partial-rule: the salvageable-looking prefix of the cut event reached the client:\n%s", raw)
	}
	requireSynthesizedClose(t, "messages partial-rule", frames, 2)
	requireAllDataJSON(t, "messages partial-rule", frames)
}

// TestMessagesNative_CleanEOPTornTailClosesFrame: the upstream ENDS
// cleanly (no transport cut) after a data line and its LF but before the
// blank separator and any message_stop. EOF is not a drain failure: the
// boundary-aligned frame is dispatched, closed with its separator (the
// tracker's close), and the stream still synthesizes its close because no
// message_stop was seen.
func TestMessagesNative_CleanEOPTornTailClosesFrame(t *testing.T) {
	const dangling = "event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"he"}}` + "\n"

	upstream := cleanEOEServer(t, messagesNativeWhole+dangling)
	defer upstream.Close()

	gw := nativeMessagesGateway(t, upstream.URL)
	rec := postMessages(t, gw, messagesRequestBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	raw := rec.Body.String()
	frames := requireFramePrefix(t, "messages eof salvage", raw, append(append([]string{}, messagesNativeWholeFrames...),
		strings.TrimSuffix(dangling, "\n"),
	))
	if len(frames) != 5 {
		t.Fatalf("messages eof salvage: got %d frames, want 5 (3 upstream + synthesized stop + error)\nstream:\n%s", len(frames), raw)
	}
	requireSynthesizedClose(t, "messages eof salvage", frames, 3)
	requireAllDataJSON(t, "messages eof salvage", frames)
}

// TestMessagesNative_CRStreamHealthyPassthrough: a complete stream whose
// lines are CR-terminated (a legal SSE terminator) passes through framed
// identically — every event dispatches, message_stop is seen, nothing is
// synthesized, and the client bytes keep the upstream's CR terminators.
func TestMessagesNative_CRStreamHealthyPassthrough(t *testing.T) {
	wholeCR := strings.ReplaceAll(messagesNativeWhole, "\n", "\r")
	deltaCR := "event: content_block_delta\r" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"he"}}` + "\r\r"
	stopCR := "event: message_stop\r" + `data: {"type":"message_stop"}` + "\r\r"

	upstream := cleanEOEServer(t, wholeCR+deltaCR+stopCR)
	defer upstream.Close()

	gw := nativeMessagesGateway(t, upstream.URL)
	rec := postMessages(t, gw, messagesRequestBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	raw := rec.Body.String()
	frames := requireFramePrefix(t, "messages cr", raw, []string{
		"event: message_start\r" + `data: {"type":"message_start","message":{"id":"msg_1","usage":{"input_tokens":5,"output_tokens":1}}}`,
		"event: content_block_start\r" + `data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
		"event: content_block_delta\r" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"he"}}`,
		"event: message_stop\r" + `data: {"type":"message_stop"}`,
	})
	if len(frames) != 4 {
		t.Fatalf("messages cr: got %d frames, want 4; a healthy complete CR stream synthesizes nothing\nstream:\n%s", len(frames), raw)
	}
	if frames[3].event != "message_stop" {
		t.Fatalf("messages cr: frame 3 must be message_stop, saw %q\nstream:\n%s", frames[3].event, raw)
	}
	requireAllDataJSON(t, "messages cr", frames)
}

// TestMessagesNative_KeepaliveForwardedWhileUpstreamOpen: the keepalive
// comment must reach the client WHILE the upstream is still open —
// frame-batching comments would hold the heartbeat until the stream ends,
// defeating its purpose (downstream idle timeouts). The upstream blocks
// after its first ping; receiving the ping before the gate releases is the
// control.
func TestMessagesNative_KeepaliveForwardedWhileUpstreamOpen(t *testing.T) {
	gate := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, ": ping\n\n")
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		<-gate
		_, _ = io.WriteString(w, messagesNativeWhole+"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	}))
	defer upstream.Close()

	gw := nativeMessagesGateway(t, upstream.URL)
	router := chi.NewRouter()
	gw.routes(router)
	gwServer := httptest.NewServer(router)
	t.Cleanup(gwServer.Close)

	release := sync.OnceFunc(func() { close(gate) })
	t.Cleanup(release)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, gwServer.URL+"/v1/messages",
		strings.NewReader(messagesRequestBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	lines := make(chan string, 16)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()

	select {
	case first, ok := <-lines:
		if !ok || first != ": ping" {
			t.Fatalf("first client line must be the keepalive comment, got %q", first)
		}
		// Received while the upstream handler is still blocked on the
		// gate: the comment was forwarded immediately, not batched.
	case <-time.After(5 * time.Second):
		t.Fatal("keepalive comment was not forwarded while the upstream was open")
	}

	// Release the upstream; the healthy remainder streams and ends with
	// message_stop — nothing synthesized, comment rode through.
	release()
	var raw strings.Builder
	raw.WriteString(": ping\n\n")
	for line := range lines {
		raw.WriteString(line)
		raw.WriteString("\n")
	}
	stream, torn := sseClientFrames(t, raw.String())
	if torn != "" {
		t.Fatalf("messages keepalive: stream ends in a torn tail %q\nstream:\n%s", torn, raw.String())
	}
	if len(stream) != 3 {
		t.Fatalf("messages keepalive: got %d frames, want 3 (2 upstream + message_stop; the comment rides no event)\nstream:\n%s", len(stream), raw.String())
	}
	// The comment's presence on the wire is pinned by the first-line
	// check above; the frame scanner counts only event-bearing frames.
	want := append(append([]string{}, messagesNativeWholeFrames...),
		"event: message_stop\ndata: {\"type\":\"message_stop\"}")
	for i, wf := range want {
		if stream[i].raw != wf {
			t.Fatalf("messages keepalive: frame %d mismatch\n got %q\nwant %q\nstream:\n%s", i, stream[i].raw, wf, raw.String())
		}
	}
	requireAllDataJSON(t, "messages keepalive", stream)
}

// TestMessagesNative_OversizedFrameAbortsBounded: a frame whose buffered
// lines cross SSEStreamLineLimit (two in-limit data lines, one over-sized
// frame) aborts the drain instead of buffering unboundedly; nothing of
// the oversized frame reaches the client and the synthesized close ends
// the stream. Direct relay unit: the abort must fire at the in-memory
// bound, independent of transport truncation.
func TestMessagesNative_OversizedFrameAbortsBounded(t *testing.T) {
	big := strings.Repeat("x", 5<<20) // two of these cross the 8 MiB frame bound
	var buf bytes.Buffer

	usage, err := relayAnthropicSSE(&recorderWriter{w: &buf}, strings.NewReader(messagesNativeWhole+
		"data: "+big+"\n"+
		"data: "+big+"\n"))
	raw := buf.String()
	if err != nil {
		t.Fatalf("the oversized abort composes its own terminal; no relay error expected: %v", err)
	}
	if usage.PromptTokens != 5 || usage.CompletionTokens != 1 {
		t.Fatalf("usage of the frames dispatched before the oversized abort: %+v", usage)
	}
	frames := requireFramePrefix(t, "messages oversized", raw, messagesNativeWholeFrames)
	if len(frames) != 4 {
		t.Fatalf("messages oversized: got %d frames, want 4 (2 upstream + synthesized stop + error)\nstream:\n%s", len(frames), raw)
	}
	if len(raw) > 1<<20 {
		t.Fatalf("messages oversized: %d client bytes for an aborted oversized frame; held bytes must stay server-side", len(raw))
	}
	requireSynthesizedClose(t, "messages oversized", frames, 2)
	requireAllDataJSON(t, "messages oversized", frames)
}

// ---- /v1/realtime equivalents ----

const realtimeWhole = "event: session.created\n" +
	`data: {"type":"session.created","session":{"id":"sess_1","model":"gpt-4o-realtime-canon"}}` + "\n\n"

const realtimeWholeFrame = "event: session.created\n" +
	`data: {"type":"session.created","session":{"id":"sess_1","model":"gpt-4o-realtime-canon"}}`

const realtimeDone = "event: response.done\n" +
	`data: {"type":"response.done","response":{"id":"resp_1","usage":{"input_tokens":9,"output_tokens":2}}}` + "\n\n"

// TestRealtime_PartialAfterValidFrameDropped: the response.done event's
// first data line is complete valid JSON but the cut lands inside its
// second data line. The frame must not be salvaged — the client would
// receive a shorter event than the upstream sent — and the terminal
// sequence composes at an event boundary.
func TestRealtime_PartialAfterValidFrameDropped(t *testing.T) {
	const validThenCut = "event: response.done\n" +
		`data: {"type":"response.done","response":{"id":"resp_1","usage":{"input_tokens":9,"output_tokens":2}}}` + "\n" +
		`data: {"type":"con`

	upstream := breakServer(t, realtimeWhole+validThenCut)
	defer upstream.Close()

	gw := r105TestGateway(t, realtimeTestModel(upstream.URL))
	rec := postR105(t, gw, "/v1/realtime", `{"model":"m","session":{"voice":"alloy"},"input":"hello"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	raw := rec.Body.String()
	frames := requireFramePrefix(t, "realtime partial-rule", raw, []string{realtimeWholeFrame})
	if len(frames) != 3 {
		t.Fatalf("realtime partial-rule: got %d frames, want 3 (1 upstream + error + [DONE]); a frame followed by a cut partial must not be salvaged\nstream:\n%s", len(frames), raw)
	}
	if strings.Contains(raw, "response.done") {
		t.Fatalf("realtime partial-rule: the salvageable-looking prefix of the cut event reached the client:\n%s", raw)
	}
	requireTerminalSequence(t, frames, 1, "realtime stream interrupted")
	requireAllDataJSON(t, "realtime partial-rule", frames)
}

// TestRealtime_CleanEOFTornTailClosesAndCompletes: the session ENDS
// cleanly after a response.done data line and its LF but before the blank
// separator. EOF is not a drain failure: the frame is dispatched closed
// with its separator, its usage flows through the same parser (parity),
// and NO terminal sequence is synthesized — the stream simply ends.
func TestRealtime_CleanEOFTornTailClosesAndCompletes(t *testing.T) {
	dangling := strings.TrimSuffix(realtimeDone, "\n")

	upstream := cleanEOEServer(t, realtimeWhole+dangling)
	defer upstream.Close()

	gw := r105TestGateway(t, realtimeTestModel(upstream.URL))
	rec := postR105(t, gw, "/v1/realtime", `{"model":"m","session":{"voice":"alloy"},"input":"hello"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	raw := rec.Body.String()
	frames := requireFramePrefix(t, "realtime eof salvage", raw, []string{
		realtimeWholeFrame,
		strings.TrimSuffix(dangling, "\n"),
	})
	if len(frames) != 2 {
		t.Fatalf("realtime eof salvage: got %d frames, want 2 (created + closed done); clean EOF synthesizes no terminal sequence\nstream:\n%s", len(frames), raw)
	}
	if frames[1].event != "response.done" {
		t.Fatalf("realtime eof salvage: frame 1 must be response.done, saw %q\nstream:\n%s", frames[1].event, raw)
	}
	requireAllDataJSON(t, "realtime eof salvage", frames)
}

// TestRealtime_CRStreamHealthyPassthrough: a complete CR-terminated
// session relays framed identically — both events dispatch, nothing is
// synthesized, and the client bytes keep the upstream's CR terminators.
func TestRealtime_CRStreamHealthyPassthrough(t *testing.T) {
	fixture := strings.ReplaceAll(realtimeWhole+realtimeDone, "\n", "\r")

	upstream := cleanEOEServer(t, fixture)
	defer upstream.Close()

	gw := r105TestGateway(t, realtimeTestModel(upstream.URL))
	rec := postR105(t, gw, "/v1/realtime", `{"model":"m","session":{"voice":"alloy"},"input":"hello"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	raw := rec.Body.String()
	frames := requireFramePrefix(t, "realtime cr", raw, []string{
		"event: session.created\r" + `data: {"type":"session.created","session":{"id":"sess_1","model":"gpt-4o-realtime-canon"}}`,
		"event: response.done\r" + `data: {"type":"response.done","response":{"id":"resp_1","usage":{"input_tokens":9,"output_tokens":2}}}`,
	})
	if len(frames) != 2 {
		t.Fatalf("realtime cr: got %d frames, want 2; a healthy complete CR session synthesizes nothing\nstream:\n%s", len(frames), raw)
	}
	requireAllDataJSON(t, "realtime cr", frames)
}

// TestRealtime_OversizedLineAbortsBounded: one unterminated line past
// SSEStreamLineLimit aborts the drain (bounded memory) instead of
// buffering the multi-megabyte line; the held bytes never reach the
// client. Direct relay unit: the abort must fire at the in-memory bound,
// independent of transport truncation; the HTTP layer's terminal
// composition is covered by the cut fixtures above.
func TestRealtime_OversizedLineAbortsBounded(t *testing.T) {
	big := "data: " + strings.Repeat("x", 9<<20) // one line > the 8 MiB bound
	rec := httptest.NewRecorder()

	gw := &gateway{}
	usage, _, term, drainErr, _ := gw.realtimeRelay(context.Background(), rec, rec, strings.NewReader(realtimeWhole+big+"\n\nmore\n"), nil)
	raw := rec.Body.String()
	var tooLarge errRealtimeLineTooLarge
	if !errors.As(drainErr, &tooLarge) {
		t.Fatalf("the oversized line must abort as an upstream error, got %v", drainErr)
	}
	if term != budget.TerminationUpstreamErr {
		t.Fatalf("termination class %v, want TerminationUpstreamErr", term)
	}
	if usage.PromptTokens != 0 || usage.CompletionTokens != 0 {
		t.Fatalf("no usage-bearing event survived the oversized abort: %+v", usage)
	}
	frames := requireFramePrefix(t, "realtime oversized", raw, []string{realtimeWholeFrame})
	if len(frames) != 1 {
		t.Fatalf("realtime oversized: got %d frames, want 1 (the HTTP layer composes the terminal)\nstream:\n%s", len(frames), raw)
	}
	if len(raw) > 1<<20 {
		t.Fatalf("realtime oversized: %d client bytes for an aborted oversized line; held bytes must stay server-side", len(raw))
	}
}

// TestRealtime_KeepaliveCommentForwarded: the comment rides no event and
// must not be swallowed by the frame batching — on a mid-line cut after a
// ping, the ping has already been forwarded (the buffer holds only field
// lines).
func TestRealtime_KeepaliveCommentForwarded(t *testing.T) {
	const partial = `data: {"type":"response.done","resp`

	upstream := breakServer(t, realtimeWhole+": ping\n\n"+partial)
	defer upstream.Close()

	gw := r105TestGateway(t, realtimeTestModel(upstream.URL))
	rec := postR105(t, gw, "/v1/realtime", `{"model":"m","session":{"voice":"alloy"},"input":"hello"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	raw := rec.Body.String()
	if !strings.Contains(raw, ": ping") {
		t.Fatalf("realtime keepalive: the comment never reached the client (held in the frame buffer and dropped with the cut frame):\n%s", raw)
	}
	frames := requireFramePrefix(t, "realtime keepalive", raw, []string{realtimeWholeFrame})
	if len(frames) != 3 {
		t.Fatalf("realtime keepalive: got %d frames, want 3 (1 upstream + error + [DONE])\nstream:\n%s", len(frames), raw)
	}
	requireTerminalSequence(t, frames, 1, "realtime stream interrupted")
}

// ---- /v1/responses equivalents of the owner-verified six ----

// TestResponsesNative_CleanEOFTornTailClosesFrame: the upstream ENDS
// cleanly after a data line and its LF but before the blank separator.
// EOF is not a drain failure: the frame is dispatched closed with its
// separator and NO response.failed follows — the stream ends delivered.
func TestResponsesNative_CleanEOFTornTailClosesFrame(t *testing.T) {
	const dangling = `data: {"type":"response.output_text.delta","item_id":"msg_1","output_index":0,"content_index":0,"delta":"he"}` + "\n"

	upstream := cleanEOEServer(t, responsesNativeWhole+dangling)
	defer upstream.Close()

	raw := postResponsesNativeStream(t, responsesNativeBreakGateway(t, upstream.URL))
	frames := requireFramePrefix(t, "responses eof salvage", raw, []string{
		responsesNativeWholeFrame,
		strings.TrimSuffix(dangling, "\n"),
	})
	if len(frames) != 2 {
		t.Fatalf("responses eof salvage: got %d frames, want 2 (created + closed delta); clean EOF writes no failure frame\nstream:\n%s", len(frames), raw)
	}
	if strings.Contains(raw, "response.failed") {
		t.Fatalf("responses eof salvage: clean EOF must not produce a failure frame:\n%s", raw)
	}
	requireAllDataJSON(t, "responses eof salvage", frames)
}

// TestResponsesNative_DeliveredTerminalLateBreakNoSecondTerminal: the
// response.completed event is fully delivered, then the transport cuts.
// The stream is over on the wire — a late failure must not append a
// second, conflicting terminal (N03-P01 twin).
func TestResponsesNative_DeliveredTerminalLateBreakNoSecondTerminal(t *testing.T) {
	completed := "event: response.completed\n" +
		`data: {"type":"response.completed","response":{"id":"resp_1","usage":{"input_tokens":7,"output_tokens":3}}}` + "\n\n"

	upstream := breakServer(t, responsesNativeWhole+completed)
	defer upstream.Close()

	raw := postResponsesNativeStream(t, responsesNativeBreakGateway(t, upstream.URL))
	frames := requireFramePrefix(t, "responses late break", raw, []string{
		responsesNativeWholeFrame,
		strings.TrimSuffix(strings.TrimSuffix(completed, "\n"), "\n"),
	})
	if len(frames) != 2 {
		t.Fatalf("responses late break: got %d frames, want 2; nothing may follow the delivered terminal\nstream:\n%s", len(frames), raw)
	}
	if frames[1].event != "response.completed" {
		t.Fatalf("responses late break: frame 1 must be response.completed, saw %q\nstream:\n%s", frames[1].event, raw)
	}
	if strings.Contains(raw, "response.failed") {
		t.Fatalf("responses late break: a second terminal was written after the delivered response.completed:\n%s", raw)
	}
	requireAllDataJSON(t, "responses late break", frames)
}

// TestResponsesNative_TornSecondDataFieldNoSalvage: the event's first
// data line is complete valid JSON (salvageable on its own) but the cut
// lands inside the second data line. Observing the cut partial proves the
// event was still being written — salvaging the prefix would fabricate a
// shorter event than the upstream sent. The frame is dropped and
// response.failed composes at an event boundary.
func TestResponsesNative_TornSecondDataFieldNoSalvage(t *testing.T) {
	const validThenCut = `data: {"type":"response.output_text.delta","item_id":"msg_1","output_index":0,"content_index":0,"delta":"he"}` + "\n" +
		`data: 2`

	upstream := breakServer(t, responsesNativeWhole+validThenCut)
	defer upstream.Close()

	raw := postResponsesNativeStream(t, responsesNativeBreakGateway(t, upstream.URL))
	frames := requireFramePrefix(t, "responses torn-second-field", raw, []string{
		responsesNativeWholeFrame,
	})
	if len(frames) != 2 {
		t.Fatalf("responses torn-second-field: got %d frames, want 2 (1 upstream + failed); the frame before a cut partial must not be salvaged\nstream:\n%s", len(frames), raw)
	}
	if strings.Contains(raw, "output_text.delta") {
		t.Fatalf("responses torn-second-field: the salvageable-looking prefix of the cut event reached the client:\n%s", raw)
	}
	requireResponsesFailedFrame(t, frames[1])
	requireAllDataJSON(t, "responses torn-second-field", frames)
}

// TestResponsesNative_CRStreamBreakTornTailSalvage: a CR-terminated
// upstream cuts after the delta data line's CR but before the blank
// separator. The trailing CR resolves at the end into a complete line —
// a boundary-aligned end — so the frame is salvaged closed with its
// separator and the failure frame composes at an event boundary.
func TestResponsesNative_CRStreamBreakTornTailSalvage(t *testing.T) {
	wholeCR := strings.ReplaceAll(responsesNativeWhole, "\n", "\r")
	const danglingCR = `data: {"type":"response.output_text.delta","item_id":"msg_1","output_index":0,"content_index":0,"delta":"he"}` + "\r"

	upstream := breakServer(t, wholeCR+danglingCR)
	defer upstream.Close()

	raw := postResponsesNativeStream(t, responsesNativeBreakGateway(t, upstream.URL))
	frames := requireFramePrefix(t, "responses cr salvage", raw, []string{
		"event: response.created\r" + `data: {"type":"response.created","response":{"id":"resp_1","usage":{"input_tokens":7,"output_tokens":0}}}`,
		`data: {"type":"response.output_text.delta","item_id":"msg_1","output_index":0,"content_index":0,"delta":"he"}`,
	})
	if len(frames) != 3 {
		t.Fatalf("responses cr salvage: got %d frames, want 3 (created + closed delta + failed)\nstream:\n%s", len(frames), raw)
	}
	requireResponsesFailedFrame(t, frames[2])
	requireAllDataJSON(t, "responses cr salvage", frames)
}

// TestResponsesNative_OversizedFrameAbortsBounded: a frame whose buffered
// lines cross SSEStreamLineLimit aborts the drain (bounded memory);
// nothing of the oversized frame reaches the client and the caller's
// response.failed closes the stream. Direct relay unit: the abort must
// fire at the in-memory bound, independent of transport truncation.
func TestResponsesNative_OversizedFrameAbortsBounded(t *testing.T) {
	big := strings.Repeat("x", 5<<20)
	var buf bytes.Buffer

	usage, terminal, err := relayResponsesSSE(&recorderWriter{w: &buf}, strings.NewReader(responsesNativeWhole+
		"data: "+big+"\n"+
		"data: "+big+"\n"))
	raw := buf.String()
	if !errors.Is(err, apiformat.ErrSSELineLimit) {
		t.Fatalf("the oversized frame must abort as ErrSSELineLimit, got %v", err)
	}
	frames := requireFramePrefix(t, "responses oversized", raw, []string{responsesNativeWholeFrame})
	if len(frames) != 1 {
		t.Fatalf("responses oversized: got %d frames, want 1 (the caller composes response.failed)\nstream:\n%s", len(frames), raw)
	}
	if len(raw) > 1<<20 {
		t.Fatalf("responses oversized: %d client bytes for an aborted oversized frame; held bytes must stay server-side", len(raw))
	}
	if usage.PromptTokens != 7 || usage.CompletionTokens != 0 {
		t.Fatalf("usage of the frame dispatched before the oversized abort: %+v", usage)
	}
	if terminal != "" {
		t.Fatalf("no terminal event was delivered, got %q", terminal)
	}
}

// ---- direct relay units: usage parity, write-error drain behavior ----

// TestRelayResponsesSSE_CleanEOFSalvageClosesAndParsesUsage: at the relay
// boundary — clean EOF with a decodable frame missing just its separator
// — the frame is written CLOSED with a CRLF blank separator (an SSE
// client dispatches it instead of discarding it at stream end) and the
// same bytes feed the usage parser, so the settlement bills exactly
// what the client saw.
func TestRelayResponsesSSE_CleanEOFSalvageClosesAndParsesUsage(t *testing.T) {
	created := "event: response.created\n" +
		`data: {"type":"response.created","response":{"id":"resp_1","usage":{"input_tokens":7,"output_tokens":0}}}` + "\n\n"
	delta := `data: {"type":"response.output_text.delta","item_id":"msg_1","output_index":0,"content_index":0,"delta":"he"}` + "\n"

	var buf bytes.Buffer
	usage, terminal, err := relayResponsesSSE(&recorderWriter{w: &buf}, strings.NewReader(created+delta))
	if err != nil {
		t.Fatalf("clean EOF must not be a drain error: %v", err)
	}
	if terminal != "" {
		t.Fatalf("no terminal event was in the stream, got %q", terminal)
	}
	if got := buf.String(); got != created+delta+"\r\n" {
		t.Fatalf("salvaged frame not closed with its separator:\n got %q\nwant %q", got, created+delta+"\r\n")
	}
	if usage.PromptTokens != 7 || usage.CompletionTokens != 0 {
		t.Fatalf("usage parsed off the salvaged stream: %+v", usage)
	}
}

// errAfterReader serves data then fails: the transport cut fixture.
type errAfterReader struct {
	errorReads int
	data       string
	err        error
}

func (r *errAfterReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		r.errorReads++
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

// oneShotBytesReader delivers its entire payload in a single Read
// returned together with its error — the read shape a transport cut
// produces when the final buffered chunk and the failure arrive as one
// Read result.
type oneShotBytesReader struct {
	data string
	err  error
	done bool
}

func (r *oneShotBytesReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	n := copy(p, r.data)
	return n, r.err
}

// TestRelayResponsesSSE_TornMultilineTerminalWithByteCarryingError: the
// completed event's field lines are complete and decodable, but the
// upstream was still writing a following data line when the transport
// cut arrived IN THE SAME READ as the final bytes. The torn tail must
// surface with the error (identical finalization to a separate error
// read, LF and lone-CR terminator forms alike, and standard EOF with
// bytes), so the relay drops the mid-event frame instead of salvaging a
// shorter delivered response.completed terminal.
func TestRelayResponsesSSE_TornMultilineTerminalWithByteCarryingError(t *testing.T) {
	const completedFields = "event: response.completed\n" +
		`data: {"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":7,"output_tokens":3}}}` + "\n"
	cases := []struct {
		name    string
		body    io.Reader
		wantErr error
	}{
		{"lf torn tail with unexpected eof", &oneShotBytesReader{data: completedFields + "data: {", err: io.ErrUnexpectedEOF}, io.ErrUnexpectedEOF},
		{"lf torn tail split read", io.MultiReader(strings.NewReader(completedFields+"data: {"), &errAfterReader{err: io.ErrUnexpectedEOF}), io.ErrUnexpectedEOF},
		{"cr torn tail with unexpected eof", &oneShotBytesReader{data: strings.ReplaceAll(completedFields, "\n", "\r") + "data: {", err: io.ErrUnexpectedEOF}, io.ErrUnexpectedEOF},
		{"lf torn tail with eof", &oneShotBytesReader{data: completedFields + "data: {", err: io.EOF}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			usage, terminal, err := relayResponsesSSE(w, tc.body)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("EOF is a clean end, not a relay error: %v", err)
				}
			} else if !errors.Is(err, tc.wantErr) {
				t.Fatalf("read shape %T must surface its error, got %v", tc.body, err)
			}
			if got := w.Body.String(); strings.Contains(got, "response.completed") {
				t.Fatalf("read shape %T salvaged a torn multiline into a delivered terminal:\n%s", tc.body, got)
			}
			if usage.PromptTokens != 0 || usage.CompletionTokens != 0 {
				t.Fatalf("a torn terminal settles no usage: %+v", usage)
			}
			if terminal != "" {
				t.Fatalf("a torn terminal is not delivered, got %q", terminal)
			}
		})
	}
}

// TestRelayResponsesSSE_LateBreakAfterTerminalKeepsUsageAndOutput: the
// terminal event is fully relayed, then the transport cuts. The relay
// returns the terminal's usage (7/3 — parity with what the client saw),
// reports the delivered terminal name so the caller suppresses the
// second terminal, and writes nothing after the delivered terminal.
func TestRelayResponsesSSE_LateBreakAfterTerminalKeepsUsageAndOutput(t *testing.T) {
	created := "event: response.created\n" +
		`data: {"type":"response.created","response":{"id":"resp_1","usage":{"input_tokens":7,"output_tokens":0}}}` + "\n\n"
	completed := "event: response.completed\n" +
		`data: {"type":"response.completed","response":{"id":"resp_1","usage":{"input_tokens":7,"output_tokens":3}}}` + "\n\n"

	var buf bytes.Buffer
	// A subsequent read would encounter the transport cut. Settlement must
	// finish on the delivered terminal even if that read would hang.
	source := &errAfterReader{data: created + completed, err: errors.New("cut")}
	usage, terminal, err := relayResponsesSSE(&recorderWriter{w: &buf}, source)
	if err != nil || source.errorReads != 0 {
		t.Fatalf("relay read past the delivered terminal: reads=%d err=%v", source.errorReads, err)
	}
	if terminal != "response.completed" {
		t.Fatalf("the delivered response.completed must be reported, got %q", terminal)
	}
	if got := buf.String(); got != created+completed {
		t.Fatalf("relay wrote beyond the delivered terminal:\n got %q\nwant %q", got, created+completed)
	}
	if usage.PromptTokens != 7 || usage.CompletionTokens != 3 {
		t.Fatalf("usage must be the terminal's, got %+v", usage)
	}
}

// failWritesWriter rejects every write: the client-gone fixture.
type failWritesWriter struct {
	writes int
}

var errClientGoneWrite = errors.New("client gone (write failed)")

func (w *failWritesWriter) Header() http.Header         { return http.Header{} }
func (w *failWritesWriter) WriteHeader(int)             {}
func (w *failWritesWriter) Write(p []byte) (int, error) { w.writes++; return 0, errClientGoneWrite }

// TestRelayResponsesSSE_ClientWriteErrorStopsPullingKeepsUsage: when the
// first client write fails the relay stops writing AND stops pulling
// provider bytes — a streaming upstream on the live connection would keep
// doing paid work for a client that is gone. Frames already read still
// feed the usage parser (the tokens were consumed upstream and are
// authoritative), the write error surfaces, and the terminal is NOT
// marked delivered (the client never received it).
func TestRelayResponsesSSE_ClientWriteErrorStopsPullingKeepsUsage(t *testing.T) {
	created := "event: response.created\n" +
		`data: {"type":"response.created","response":{"id":"resp_1","usage":{"input_tokens":7,"output_tokens":0}}}` + "\n\n"
	completed := "event: response.completed\n" +
		`data: {"type":"response.completed","response":{"id":"resp_1","usage":{"input_tokens":7,"output_tokens":3}}}` + "\n\n"
	w := &failWritesWriter{}
	reads := &countingReader{r: strings.NewReader(created + completed)}

	usage, terminal, err := relayResponsesSSE(w, reads)
	if !errors.Is(err, errClientGoneWrite) {
		t.Fatalf("relay must surface the write error, got %v", err)
	}
	if w.writes != 1 {
		t.Fatalf("relay attempted %d writes; after the first failure writes must stop", w.writes)
	}
	if reads.reads > 1 {
		t.Fatalf("relay issued %d provider reads; after the failed write no further bytes may be pulled (the buffered remainder still settles usage)", reads.reads)
	}
	if terminal != "" {
		t.Fatalf("an event the client never received must not count as delivered, got %q", terminal)
	}
	if usage.PromptTokens != 7 || usage.CompletionTokens != 3 {
		t.Fatalf("usage read from upstream must survive the failed write, got %+v", usage)
	}
}

// countingReader counts Read calls: the stop-pulling units pin that no
// provider read happens after the client write failure.
type countingReader struct {
	r     io.Reader
	reads int
}

func (c *countingReader) Read(p []byte) (int, error) {
	c.reads++
	return c.r.Read(p)
}

// recorderWriter adapts an io.Writer to http.ResponseWriter for direct
// relay/tracker units.
type recorderWriter struct {
	w io.Writer
}

func (r *recorderWriter) Header() http.Header         { return http.Header{} }
func (r *recorderWriter) WriteHeader(int)             {}
func (r *recorderWriter) Write(p []byte) (int, error) { return r.w.Write(p) }

// ---- tail tracker unit ----

// TestSSEPassthroughTail_SplitTerminatorsAcrossWrites: terminator state
// derives from the cumulative stream, so a CRLF (or lone-CR) separator
// split across two writes is framed exactly like an unfragmented one —
// not torn, and complete() appends nothing; a genuinely dangling line
// (trailing CR or content) stays torn until complete() closes it.
func TestSSEPassthroughTail_SplitTerminatorsAcrossWrites(t *testing.T) {
	var buf bytes.Buffer
	tail := &ssePassthroughTail{w: &recorderWriter{w: &buf}}
	if _, err := tail.Write([]byte("data: x\r\n\r")); err != nil {
		t.Fatal(err)
	}
	if tail.torn() {
		t.Fatal("CRLF separator split across writes must not read as torn")
	}
	if _, err := tail.Write([]byte("\n")); err != nil {
		t.Fatal(err)
	}
	if tail.torn() {
		t.Fatal("resolved CRLF pair must complete the separator")
	}
	before := buf.Len()
	tail.complete()
	if buf.Len() != before {
		t.Fatalf("complete() appended %d bytes to an already-separated tail", buf.Len()-before)
	}

	var buf2 bytes.Buffer
	dangling := &ssePassthroughTail{w: &recorderWriter{w: &buf2}}
	if _, err := dangling.Write([]byte("data: x\r")); err != nil {
		t.Fatal(err)
	}
	if !dangling.torn() {
		t.Fatal("a line closed only by a hanging CR is torn (no separator yet)")
	}
	dangling.complete()
	if got := buf2.String(); got != "data: x\r\n\n" {
		t.Fatalf("hanging-CR tail must close with LF-pair + separator, got %q", got)
	}
	if dangling.torn() {
		t.Fatal("tail must read complete after complete()")
	}
}

// ---- terminal-type settlement (D1 reflects the delivered terminal) ----

// TestResponsesNative_UpstreamFailedEventCleanEOFFailedSettlement: the
// upstream ends its stream with response.failed and closes cleanly. The
// client receives exactly the upstream events — the failed terminal was
// delivered, so no second response.failed is synthesized — and the
// settlement event records request.failed with the upstream's usage.
func TestResponsesNative_UpstreamFailedEventCleanEOFFailedSettlement(t *testing.T) {
	upstream := cleanEOEServer(t, "event: response.created\n"+
		`data: {"type":"response.created","response":{"id":"resp_1","usage":{"input_tokens":7,"output_tokens":0}}}`+"\n\n"+
		"event: response.failed\n"+
		`data: {"type":"response.failed","response":{"id":"resp_1","status":"failed","usage":{"input_tokens":7,"output_tokens":3},"error":{"code":"","message":"overloaded"}}}`+"\n\n")
	defer upstream.Close()

	gw := responsesTestGateway(t, upstream.URL)
	gw.cfg.ResponsesNativeProviders = []string{"openai"}
	gw.res = stubModelResolver{"m": {ModelName: "m", Provider: "openai", UpstreamURL: upstream.URL, Enabled: true}}
	terminal := make(chan *eventpub.Event, 4)
	restore := observeEvent(func(ev *eventpub.Event) {
		if ev.EventType == "request.completed" || ev.EventType == "request.failed" {
			terminal <- ev
		}
	})
	t.Cleanup(restore)

	raw := postResponsesNativeStream(t, gw)
	frames := requireFramePrefix(t, "responses upstream failed", raw, []string{
		responsesNativeWholeFrame,
		"event: response.failed\n" + `data: {"type":"response.failed","response":{"id":"resp_1","status":"failed","usage":{"input_tokens":7,"output_tokens":3},"error":{"code":"","message":"overloaded"}}}`,
	})
	if len(frames) != 2 {
		t.Fatalf("responses upstream failed: got %d frames, want 2 (the delivered failed terminal IS the stream's end; a second terminal must not be synthesized)\nstream:\n%s", len(frames), raw)
	}
	select {
	case ev := <-terminal:
		if ev.EventType != "request.failed" || ev.TokensIn != 7 || ev.TokensOut != 3 {
			t.Fatalf("settlement must follow the delivered terminal: %s %d/%d, want request.failed 7/3", ev.EventType, ev.TokensIn, ev.TokensOut)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("settlement event missing")
	}
}

// TestResponsesNative_CompletedThenLateCutKeepsCompletion: the terminal
// response.completed is fully delivered, then the transport cuts. The
// delivered terminal is authoritative: no second client terminal is
// synthesized and the settlement stays request.completed — a late
// transport error cannot fail a response the client fully received.
func TestResponsesNative_CompletedThenLateCutKeepsCompletion(t *testing.T) {
	completed := "event: response.completed\n" +
		`data: {"type":"response.completed","response":{"id":"resp_1","usage":{"input_tokens":7,"output_tokens":3}}}` + "\n"
	// The appended LF completes the terminal's blank separator; the
	// breakServer cut then lands after the delivered terminal.
	upstream := breakServer(t, responsesNativeWhole+completed+"\n")
	defer upstream.Close()

	gw := responsesTestGateway(t, upstream.URL)
	gw.cfg.ResponsesNativeProviders = []string{"openai"}
	gw.res = stubModelResolver{"m": {ModelName: "m", Provider: "openai", UpstreamURL: upstream.URL, Enabled: true}}
	terminal := make(chan *eventpub.Event, 4)
	restore := observeEvent(func(ev *eventpub.Event) {
		if ev.EventType == "request.completed" || ev.EventType == "request.failed" {
			terminal <- ev
		}
	})
	t.Cleanup(restore)

	raw := postResponsesNativeStream(t, gw)
	frames := requireFramePrefix(t, "responses completed then cut", raw, []string{
		responsesNativeWholeFrame,
		"event: response.completed\n" + `data: {"type":"response.completed","response":{"id":"resp_1","usage":{"input_tokens":7,"output_tokens":3}}}`,
	})
	if len(frames) != 2 {
		t.Fatalf("responses completed then cut: got %d frames, want 2 (the delivered terminal IS the stream's end; a late cut must not add one)\nstream:\n%s", len(frames), raw)
	}
	select {
	case ev := <-terminal:
		if ev.EventType != "request.completed" || ev.TokensIn != 7 || ev.TokensOut != 3 {
			t.Fatalf("settlement must follow the delivered terminal: %s %d/%d, want request.completed 7/3", ev.EventType, ev.TokensIn, ev.TokensOut)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("settlement event missing")
	}
}

// TestMessagesNative_UpstreamErrorEventKeepsCompletionCanon: the upstream
// closes its stream with an Anthropic error event. The client receives
// the events verbatim — an explicit upstream error is never duplicated
// with a synthesized close — and per the messages D1 asymmetry canon
// (pinned by TestMessagesNative_MidStreamErrorEvent) the settlement
// stays request.completed with the delivered usage.
func TestMessagesNative_UpstreamErrorEventKeepsCompletionCanon(t *testing.T) {
	const upstreamError = "event: error\n" +
		`data: {"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}` + "\n\n"

	upstream := cleanEOEServer(t, messagesNativeWhole+upstreamError)
	defer upstream.Close()

	gw := nativeMessagesGateway(t, upstream.URL)
	terminal := make(chan *eventpub.Event, 4)
	restore := observeEvent(func(ev *eventpub.Event) {
		if ev.EventType == "request.completed" || ev.EventType == "request.failed" {
			terminal <- ev
		}
	})
	t.Cleanup(restore)

	rec := postMessages(t, gw, messagesRequestBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	raw := rec.Body.String()
	frames := requireFramePrefix(t, "messages upstream error", raw, append(append([]string{}, messagesNativeWholeFrames...),
		"event: error\n"+`data: {"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}`,
	))
	if len(frames) != 3 {
		t.Fatalf("messages upstream error: got %d frames, want 3 (2 upstream + the verbatim error terminal; the synthesized close is suppressed)\nstream:\n%s", len(frames), raw)
	}
	select {
	case ev := <-terminal:
		if ev.EventType != "request.completed" || ev.TokensIn != 5 || ev.TokensOut != 1 {
			t.Fatalf("settlement keeps the messages D1 canon: %s %d/%d, want request.completed 5/1", ev.EventType, ev.TokensIn, ev.TokensOut)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("settlement event missing")
	}
}
