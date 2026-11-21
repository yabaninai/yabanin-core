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
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
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
	sawLine := false
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
			if sawLine {
				cur.raw = raw[frameStart:lastContentEnd]
				frames = append(frames, cur)
				cur = sseFrame{}
				sawLine = false
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
		case strings.HasPrefix(line, "data:"):
			cur.data = append(cur.data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		case strings.HasPrefix(line, ":"):
			// SSE comment line — legal, fixtures do not use it.
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
