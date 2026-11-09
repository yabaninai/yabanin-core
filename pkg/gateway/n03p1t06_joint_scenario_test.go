package cli

// N03-P01-T06 — SSE contract and message boundaries: joint user scenario.
//
// A realistic multi-consumer flow through ONE gateway instance served by the
// production server factory: eight consumers stream concurrently while the
// fake provider splits the byte stream at every awkward offset a real
// network produces — inside multi-byte UTF-8 runes, inside the "\n\n" event
// boundary, inside a JSON data line (numbers, escapes, \uXXXX sequences),
// across interleaved SSE comment keepalives — plus two stall flavours and a
// late upstream death inside the live concurrent flow.
//
// Contract under test (owner answers I45/I51 as contract references):
//   - every consumer reconstructs EXACTLY the events the provider emitted
//     (byte-exact, valid UTF-8, no truncated and no glued event) regardless
//     of how the network chunked the bytes in either direction;
//   - a provider stall shorter than the idle watchdog is invisible on the
//     wire (slow-but-alive streams are never aborted);
//   - a provider stall past the watchdog produces ONE honest terminal: the
//     partial prefix, one error frame, one [DONE] — never a fabricated
//     continuation (I45: interrupted streams are described honestly);
//   - a late error after the [DONE] terminator must NOT emit a second
//     terminal frame: the wire ends at the first [DONE] even while the rest
//     of the joint flow is still streaming;
//   - the analytics ledger records exactly one event per request, completed
//     or failed, with the drain-failure detail carried on the event.
//
// Distinct from N03-P01-T05 (drain-level property + single-stream wire
// tests): this card pins the same contract across a concurrent, mixed
// provider, mixed pattern consumer flow end to end.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/require"

	apierrs "github.com/reireirei/yabanin/pkg/apierrors"
	apiformat "github.com/reireirei/yabanin/pkg/apiformat"
	apierrors "github.com/reireirei/yabanin/pkg/errors"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/resolver"
)

// Scenario tuning. The idle watchdog must sit far above the paced-delivery
// gaps (8 ms nominal, scheduler-stretch safe) and above the intentional
// mid-stream stall, yet below the test deadline: a genuine silence of 2 s
// aborts the stalled consumer while every healthy consumer finishes.
const (
	n03p1t06IdleTimeout  = 2 * time.Second
	n03p1t06Pace         = 8 * time.Millisecond
	n03p1t06StallSilence = 700 * time.Millisecond // below the watchdog: recover flavour
	n03p1t06LateDwell    = 250 * time.Millisecond // late-error hold before the transport dies
)

// Consumer identities double as the `model` field the rig dispatches on
// (the mux resolves them, the fake upstream serves the matching pattern).
const (
	n03p1t06MUTF8      = "t06-utf8"
	n03p1t06MBoundary  = "t06-boundary"
	n03p1t06MJSON      = "t06-jsonline"
	n03p1t06MKeepalive = "t06-keepalive"
	n03p1t06MAnthropic = "t06-anthropic"
	n03p1t06MStallOK   = "t06-stall-recover"
	n03p1t06MStallDead = "t06-stall-dead"
	n03p1t06MLateErr   = "t06-late-error"
)

// --- fixtures: each returns the exact bytes the upstream writes unsplit ------

func n03p1t06UTF8Fixture() string {
	var b strings.Builder
	for _, s := range []string{"Привет", " мир 🌍", " — 日本語のテキスト", " Δοκιμή 🚀🎉", " ascii tail"} {
		b.WriteString(chunkFrame("chatcmpl-t06-u", s))
	}
	b.WriteString("data: [DONE]\n\n")
	return b.String()
}

func n03p1t06BoundaryFixture() string {
	var b strings.Builder
	for _, s := range []string{"frame-one", "frame-two", "frame-three", "frame-four", "frame-five"} {
		b.WriteString(chunkFrame("chatcmpl-t06-b", s))
	}
	b.WriteString("data: [DONE]\n\n")
	return b.String()
}

// n03p1t06JSONLineFixture uses long data lines whose interiors are worth
// tearing apart: string escapes (\" and \n), a \uXXXX escape, digit runs and
// a trailing usage object — cuts land inside all of them.
func n03p1t06JSONLineFixture() string {
	const id = `"id":"chatcmpl-t06-j","object":"chat.completion.chunk","created":1767000123,"model":"t06-model"`
	return "data: {" + id + `,"choices":[{"index":0,"delta":{"role":"assistant","content":"call \"now\""},"finish_reason":null}]}` + "\n\n" +
		"data: {" + id + `,"choices":[{"index":0,"delta":{"content":"escaped \n newline + \u00e9tude"},"finish_reason":null}]}` + "\n\n" +
		"data: {" + id + `,"choices":[{"index":0,"delta":{"content":"числа 1234567890 tail"},"finish_reason":null}]}` + "\n\n" +
		"data: {" + id + `,"choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":42,"completion_tokens":17,"total_tokens":59}}` + "\n\n" +
		"data: [DONE]\n\n"
}

// n03p1t06KeepaliveFixture interleaves SSE comment keepalives (including a
// multi-byte one) between data frames: for the OpenAI passthrough the
// comments are part of what the provider emitted and must reach the
// consumer byte-exactly.
func n03p1t06KeepaliveFixture() string {
	return ": keepalive first\n\n" +
		chunkFrame("chatcmpl-t06-k", "alpha ") +
		": ping\n\n" +
		chunkFrame("chatcmpl-t06-k", "бета ") +
		": keepalive середина\n\n" +
		chunkFrame("chatcmpl-t06-k", "gamma ") +
		": ping\n\n" +
		chunkFrame("chatcmpl-t06-k", "delta") +
		"data: [DONE]\n\n"
}

// n03p1t06AnthropicFixture is the translating consumer's native stream:
// Anthropic events with multi-byte text and comment keepalives the
// translator must skip. The translated output is deterministic, so the
// consumer-side reconstruction is compared byte-exactly against the
// unsplit translation.
func n03p1t06AnthropicFixture() string {
	return ": stream keepalive\n\n" +
		"event: message_start\n" +
		"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_t06\",\"usage\":{\"input_tokens\":9}}}\n\n" +
		"event: content_block_delta\n" +
		"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Привет 🌍\"}}\n\n" +
		": keepalive\n\n" +
		"event: content_block_delta\n" +
		"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\" — anthropic 世界\"}}\n\n" +
		"event: message_delta\n" +
		"data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":7}}\n\n" +
		"event: message_stop\n" +
		"data: {\"type\":\"message_stop\"}\n\n"
}

func n03p1t06StallRecoverFixture() (pre, post string) {
	pre = chunkFrame("chatcmpl-t06-sr", "before-stall-один ") +
		chunkFrame("chatcmpl-t06-sr", "before-stall-two ")
	post = chunkFrame("chatcmpl-t06-sr", "after-stall-три ") +
		chunkFrame("chatcmpl-t06-sr", "done") +
		"data: [DONE]\n\n"
	return pre, post
}

// n03p1t06StallDeadFixture has no terminator: the provider never sends
// another byte after these frames.
func n03p1t06StallDeadFixture() string {
	return chunkFrame("chatcmpl-t06-sd", "partial-один ") +
		chunkFrame("chatcmpl-t06-sd", "partial-two ") +
		chunkFrame("chatcmpl-t06-sd", "partial-three ")
}

// n03p1t06LateErrorFixture is a COMPLETE stream (terminator included) that
// the upstream transport then abandons without the HTTP terminal chunk.
func n03p1t06LateErrorFixture() string {
	return chunkFrame("chatcmpl-t06-late", "fully delivered before the transport died ") +
		"data: [DONE]\n\n"
}

// n03p1t06IdleAbortSuffix is the exact client-visible tail of a watchdog
// abort: the structured error frame the finisher writes, then the single
// [DONE] terminator.
func n03p1t06IdleAbortSuffix() string {
	return string(apierrs.SSEErrorFrame(&apierrs.E{Type: apierrors.ErrorCodeAPI, Message: "upstream stream idle timeout"})) +
		"data: [DONE]\n\n"
}

// --- split compositions -------------------------------------------------------

// n03p1t06UTF8Cuts cuts one byte into every multi-byte rune so consecutive
// chunks tear the UTF-8 encoding apart mid-character.
func n03p1t06UTF8Cuts(s string) []int {
	var cuts []int
	for i := 0; i < len(s); {
		_, size := utf8.DecodeRuneInString(s[i:])
		if size > 1 && i+1 < len(s) {
			cuts = append(cuts, i+1)
		}
		i += size
	}
	return cuts
}

// n03p1t06BoundaryCuts cuts between the two LFs of every "\n\n" event
// boundary and right after every "data:" field name.
func n03p1t06BoundaryCuts(s string) []int {
	var cuts []int
	for i := 0; i < len(s); i++ {
		switch {
		case strings.HasPrefix(s[i:], "\n\n"):
			cuts = append(cuts, i+1)
		case strings.HasPrefix(s[i:], "data: "):
			cuts = append(cuts, i+5)
		}
	}
	return cuts
}

// n03p1t06JSONLineCuts cuts inside every data line's JSON payload (thirds of
// the line) and inside the \uXXXX escape when present.
func n03p1t06JSONLineCuts(s string) []int {
	var cuts []int
	for i := 0; i < len(s); {
		end := strings.IndexByte(s[i:], '\n')
		if end < 0 {
			break
		}
		line := s[i : i+end]
		if strings.HasPrefix(line, "data: {") && len(line) > 18 {
			cuts = append(cuts, i+6+len(line)/3, i+6+2*len(line)/3)
		}
		i += end + 1
	}
	if at := strings.Index(s, `\u00e9`); at >= 0 {
		cuts = append(cuts, at+2, at+4)
	}
	return cuts
}

// n03p1t06KeepaliveCuts combines boundary cuts with cuts inside the comment
// keepalive text itself.
func n03p1t06KeepaliveCuts(s string) []int {
	cuts := n03p1t06BoundaryCuts(s)
	for i := 0; i < len(s); {
		end := strings.IndexByte(s[i:], '\n')
		if end < 0 {
			break
		}
		line := s[i : i+end]
		if strings.HasPrefix(line, ": ") && len(line) > 3 {
			cuts = append(cuts, i+len(line)/2)
		}
		i += end + 1
	}
	return cuts
}

// --- fake upstream pattern writers --------------------------------------------

// n03p1t06WriteSplit delivers the fixture through the fake upstream in the
// given network-chunk composition, one flush per piece so every piece
// becomes its own HTTP chunk on the wire, paced so the flow is alive.
func n03p1t06WriteSplit(w http.ResponseWriter, fixture string, cuts []int) {
	flusher, _ := w.(http.Flusher)
	w.Header().Set("Content-Type", "text/event-stream")
	for _, piece := range cutPieces([]byte(fixture), cuts) {
		if _, err := w.Write(piece); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
		time.Sleep(n03p1t06Pace)
	}
}

func n03p1t06ServeAnthropic(w http.ResponseWriter) {
	fx := n03p1t06AnthropicFixture()
	n03p1t06WriteSplit(w, fx, append(n03p1t06UTF8Cuts(fx), n03p1t06BoundaryCuts(fx)...))
}

func n03p1t06ServeStallRecover(w http.ResponseWriter) {
	pre, post := n03p1t06StallRecoverFixture()
	n03p1t06WriteSplit(w, pre, nil)
	// The provider goes silent BELOW the idle watchdog, then resumes: the
	// watchdog re-arms on every delivered read, so this must never abort.
	time.Sleep(n03p1t06StallSilence)
	n03p1t06WriteSplit(w, post, nil)
}

func n03p1t06ServeStallDead(w http.ResponseWriter, r *http.Request) {
	n03p1t06WriteSplit(w, n03p1t06StallDeadFixture(), nil)
	// Stalled provider: not one more byte. The gateway's idle watchdog must
	// abort the relay; its cancellation reaches the upstream as request-ctx
	// cancellation and ends this handler. The timeout branch is a safety net
	// that must stay silent (any byte here would break the wire contract).
	select {
	case <-r.Context().Done():
	case <-time.After(30 * time.Second):
	}
}

func n03p1t06ServeLateError(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	payload := n03p1t06LateErrorFixture()
	// Raw chunked framing: the complete SSE payload — [DONE] included — in
	// one body chunk, then the connection dies WITHOUT the terminal 0-chunk.
	_, _ = fmt.Fprintf(rw, "HTTP/1.1 200 OK\r\n"+
		"Content-Type: text/event-stream\r\n"+
		"Transfer-Encoding: chunked\r\n"+
		"Connection: close\r\n"+
		"\r\n%x\r\n%s\r\n", len(payload), payload)
	_ = rw.Flush()
	// Hold the (now limbless) connection briefly so the failure lands while
	// the rest of the joint flow is still streaming.
	select {
	case <-r.Context().Done():
	case <-time.After(n03p1t06LateDwell):
	}
}

// --- shared wire rig -----------------------------------------------------------

// n03p1t06StartRig wires one gateway (production server factory, idle
// watchdog armed) to one fake provider upstream and returns the front URL
// plus a snapshot func over the analytics event ledger.
func n03p1t06StartRig(t *testing.T) (string, func() []*eventpub.Event) {
	t.Helper()

	var (
		mu     sync.Mutex
		events []*eventpub.Event
	)
	restore := observeEvent(func(e *eventpub.Event) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	})
	t.Cleanup(restore)

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/messages" { // the anthropic adapter's upstream path
			n03p1t06ServeAnthropic(w)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read failed", http.StatusBadRequest)
			return
		}
		var req struct {
			Model string `json:"model"`
		}
		_ = json.Unmarshal(body, &req)
		switch req.Model {
		case n03p1t06MUTF8:
			fx := n03p1t06UTF8Fixture()
			n03p1t06WriteSplit(w, fx, n03p1t06UTF8Cuts(fx))
		case n03p1t06MBoundary:
			fx := n03p1t06BoundaryFixture()
			n03p1t06WriteSplit(w, fx, n03p1t06BoundaryCuts(fx))
		case n03p1t06MJSON:
			fx := n03p1t06JSONLineFixture()
			n03p1t06WriteSplit(w, fx, n03p1t06JSONLineCuts(fx))
		case n03p1t06MKeepalive:
			fx := n03p1t06KeepaliveFixture()
			n03p1t06WriteSplit(w, fx, n03p1t06KeepaliveCuts(fx))
		case n03p1t06MStallOK:
			n03p1t06ServeStallRecover(w)
		case n03p1t06MStallDead:
			n03p1t06ServeStallDead(w, r)
		case n03p1t06MLateErr:
			n03p1t06ServeLateError(w, r)
		default:
			http.Error(w, "unknown t06 model", http.StatusNotFound)
		}
	}))
	t.Cleanup(up.Close)

	gw := streamTestGateway(up.URL)
	gw.streamIdleTimeout = n03p1t06IdleTimeout

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read failed", http.StatusBadRequest)
			return
		}
		var req struct {
			Model string `json:"model"`
		}
		_ = json.Unmarshal(body, &req)
		providerName := ""
		if req.Model == n03p1t06MAnthropic {
			providerName = "anthropic"
		}
		info := resolver.ModelInfo{ModelName: req.Model, Provider: providerName, Enabled: true}
		gw.serveStream(w, r.Context(), info, body, false,
			"t06-sess", "t06-org", "", "t06-task", "t06-req-"+req.Model, testLogger(),
			routingDecision{}, "", 0, "", "", "", false)
	})

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	front, err := newGatewayHTTPServer(ln.Addr().String(), mux)
	require.NoError(t, err)
	go func() { _ = front.Serve(ln) }()
	t.Cleanup(func() { _ = front.Close() })

	snapshot := func() []*eventpub.Event {
		mu.Lock()
		defer mu.Unlock()
		return append([]*eventpub.Event(nil), events...)
	}
	return "http://" + ln.Addr().String(), snapshot
}

// --- consumer side --------------------------------------------------------------

type n03p1t06Result struct {
	model  string
	status int
	body   []byte
	err    error
}

// n03p1t06Consume streams one request through the rig like a real client:
// POST, then read the body to EOF. Runs on its own goroutine — never calls
// require (FailNow belongs to the test goroutine); everything is reported
// through out. slow selects byte-at-a-time consumption (a constrained
// consumer pulling one byte per read against the live stream).
func n03p1t06Consume(ctx context.Context, client *http.Client, frontURL, model string, reqBody []byte, slow bool, out chan<- n03p1t06Result) {
	res := n03p1t06Result{model: model}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, frontURL+"/v1/chat/completions", bytes.NewReader(reqBody))
	if err != nil {
		res.err = err
		out <- res
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		res.err = err
		out <- res
		return
	}
	defer func() { _ = resp.Body.Close() }()
	res.status = resp.StatusCode
	var r io.Reader = resp.Body
	if slow {
		r = iotest.OneByteReader(resp.Body)
	}
	res.body, res.err = io.ReadAll(r)
	out <- res
}

// n03p1t06CheckFrames is the consumer-side message-boundary audit: the
// reassembled body must decompose into complete SSE frames — no empty
// (glued-separator) frame, no truncated or glued data payload, exactly one
// [DONE] and it must be the final frame.
func n03p1t06CheckFrames(t *testing.T, name, body string) {
	t.Helper()
	require.Truef(t, utf8.ValidString(body), "%s: reassembled stream must be valid UTF-8 — a mid-rune cut must never leak a torn byte", name)
	frames := strings.Split(body, "\n\n")
	require.GreaterOrEqualf(t, len(frames), 2, "%s: at least one framed event expected", name)
	require.Emptyf(t, frames[len(frames)-1], "%s: stream must end at a frame separator — no truncated tail", name)
	frames = frames[:len(frames)-1]
	doneAt := -1
	for i, frame := range frames {
		require.NotEmptyf(t, frame, "%s: frame %d is empty (glued separator)", name, i)
		for _, line := range strings.Split(frame, "\n") {
			switch {
			case strings.HasPrefix(line, ":"):
				// keepalive comment — part of the emitted stream, never a data event
			case strings.HasPrefix(line, "data:"):
				payload := strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " ")
				if payload == "[DONE]" {
					require.Equalf(t, -1, doneAt, "%s: second [DONE] at frame %d", name, i)
					doneAt = i
					continue
				}
				require.Truef(t, json.Valid([]byte(payload)),
					"%s: frame %d carries a truncated or glued data payload: %q", name, i, payload)
			default:
				require.Failf(t, "unexpected SSE line", "%s: frame %d carries line %q", name, i, line)
			}
		}
	}
	require.Equalf(t, len(frames)-1, doneAt, "%s: [DONE] must be the final frame", name)
}

// n03p1t06AssertReconstructed holds the full positive contract for one
// consumer: byte-exact reconstruction of the provider's bytes, complete
// frames, and a pkg/apiformat-valid stream.
func n03p1t06AssertReconstructed(t *testing.T, name string, gotBody []byte, want string) {
	t.Helper()
	n03p1t06CheckFrames(t, name, string(gotBody))
	require.Equalf(t, want, string(gotBody),
		"%s: the consumer must reconstruct exactly the bytes the provider emitted", name)
	require.NoErrorf(t, apiformat.ValidateChatStream(strings.Split(string(gotBody), "\n")),
		"%s: the reassembled stream must be a valid chat stream at any chunking", name)
}

// --- the joint scenario -----------------------------------------------------------

// TestN03P1T06_JointConcurrentStreamContract runs eight consumers against one
// gateway concurrently: three pure splitting patterns (multi-byte UTF-8,
// event boundary, JSON line interior), one keepalive-interleaved pattern
// consumed byte-at-a-time, one translated Anthropic stream, a stall-recover
// flavour, a stall-past-the-watchdog flavour, and a late upstream death
// inside the live flow. It pins: exact reconstruction for every consumer,
// terminal uniqueness on both failure flavours, and an analytics ledger of
// exactly one event per request.
func TestN03P1T06_JointConcurrentStreamContract(t *testing.T) {
	frontURL, eventsSnapshot := n03p1t06StartRig(t)

	// Expected reconstructions, computed once on the test goroutine.
	wantAnthropic, _ := drainSplit(t, []byte(n03p1t06AnthropicFixture()), "anthropic", n03p1t06MAnthropic, nil)
	stallPre, stallPost := n03p1t06StallRecoverFixture()
	type expect struct {
		model string
		want  string
	}
	positives := []expect{
		{n03p1t06MUTF8, n03p1t06UTF8Fixture()},
		{n03p1t06MBoundary, n03p1t06BoundaryFixture()},
		{n03p1t06MJSON, n03p1t06JSONLineFixture()},
		{n03p1t06MKeepalive, n03p1t06KeepaliveFixture()},
		{n03p1t06MAnthropic, wantAnthropic},
		{n03p1t06MStallOK, stallPre + stallPost},
	}
	wantStallDead := n03p1t06StallDeadFixture() + n03p1t06IdleAbortSuffix()
	wantLate := n03p1t06LateErrorFixture()

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}

	plans := []struct {
		model    string
		slowRead bool
	}{
		{n03p1t06MUTF8, false},
		{n03p1t06MBoundary, false},
		{n03p1t06MJSON, false},
		{n03p1t06MKeepalive, true},
		{n03p1t06MAnthropic, false},
		{n03p1t06MStallOK, false},
		{n03p1t06MStallDead, false},
		{n03p1t06MLateErr, false},
	}

	// Request bodies are built before the goroutines launch (streamBody uses
	// require, which must stay on the test goroutine).
	bodies := make(map[string][]byte, len(plans))
	for _, p := range plans {
		bodies[p.model] = streamBody(t, p.model, "joint scenario "+p.model)
	}

	out := make(chan n03p1t06Result, len(plans))
	var wg sync.WaitGroup
	for _, p := range plans {
		wg.Add(1)
		go func(model string, slow bool) {
			defer wg.Done()
			n03p1t06Consume(context.Background(), client, frontURL, model, bodies[model], slow, out)
		}(p.model, p.slowRead)
	}
	wg.Wait()
	close(out)

	got := make(map[string]n03p1t06Result, len(plans))
	for res := range out {
		require.NoErrorf(t, res.err, "%s: consumer stream read", res.model)
		got[res.model] = res
	}
	require.Len(t, got, len(plans), "every consumer must report a result")

	// Positive patterns: the consumer reconstructs exactly what the provider
	// emitted — byte for byte, valid frames, valid stream — including the
	// stall-recover consumer whose mid-stream silence must be invisible.
	for _, tc := range positives {
		res := got[tc.model]
		require.Equalf(t, http.StatusOK, res.status, "%s: stream status", tc.model)
		n03p1t06AssertReconstructed(t, tc.model, res.body, tc.want)
	}

	// Negative flavour 1: a stall past the watchdog aborts the stream
	// honestly — the partial prefix, exactly one error frame, exactly one
	// [DONE], nothing fabricated.
	res := got[n03p1t06MStallDead]
	require.Equal(t, http.StatusOK, res.status)
	n03p1t06AssertReconstructed(t, n03p1t06MStallDead, res.body, wantStallDead)

	// Negative flavour 2: a late error AFTER the completed stream must not
	// emit a second terminal — the wire ends exactly at the first [DONE].
	res = got[n03p1t06MLateErr]
	require.Equal(t, http.StatusOK, res.status)
	n03p1t06AssertReconstructed(t, n03p1t06MLateErr, res.body, wantLate)
	require.Equal(t, wantLate, string(res.body),
		"a late drain failure after [DONE] must add nothing to the wire")

	// Analytics ledger: exactly one event per request, completed for the six
	// healthy consumers, failed for the two failure flavours, with the real
	// cause on the failed events.
	var evs []*eventpub.Event
	require.Eventually(t, func() bool {
		evs = eventsSnapshot()
		return len(evs) == len(plans)
	}, 5*time.Second, 10*time.Millisecond, "each consumer must publish exactly one analytics event")

	wantType := map[string]string{}
	for _, tc := range positives {
		wantType[tc.model] = "request.completed"
	}
	wantType[n03p1t06MStallDead] = "request.failed"
	wantType[n03p1t06MLateErr] = "request.failed"

	counts := map[string]int{}
	for _, ev := range evs {
		counts[ev.RequestID]++
		model := strings.TrimPrefix(ev.RequestID, "t06-req-")
		require.Equalf(t, wantType[model], ev.EventType,
			"request %s: wrong event type", ev.RequestID)
		switch model {
		case n03p1t06MStallDead:
			require.Equal(t, "upstream stream idle timeout", ev.Error,
				"the watchdog abort must be reported honestly on the event")
		case n03p1t06MLateErr:
			require.Contains(t, ev.Error, "stream read failed",
				"the late transport death must carry the drain read failure, got %q", ev.Error)
		}
	}
	for _, p := range plans {
		require.Equalf(t, 1, counts["t06-req-"+p.model],
			"request %s: exactly one analytics event expected", "t06-req-"+p.model)
	}
}

// TestN03P1T06_SlowClientByteAtATimeReassembly pins the consumer direction
// of the chunking contract: a constrained client that pulls the live stream
// one byte at a time (iotest.OneByteReader) must still reconstruct exactly
// the keepalive-interleaved stream the provider emitted, with the gateway's
// line-granular flushes surviving the backpressure untouched.
func TestN03P1T06_SlowClientByteAtATimeReassembly(t *testing.T) {
	frontURL, eventsSnapshot := n03p1t06StartRig(t)

	out := make(chan n03p1t06Result, 1)
	reqBody := streamBody(t, n03p1t06MKeepalive, "slow consumer")
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	go n03p1t06Consume(context.Background(), client, frontURL, n03p1t06MKeepalive, reqBody, true, out)

	res := <-out
	require.NoError(t, res.err, "slow consumer stream read")
	require.Equal(t, http.StatusOK, res.status)
	n03p1t06AssertReconstructed(t, "slow-keepalive", res.body, n03p1t06KeepaliveFixture())

	require.Eventually(t, func() bool {
		return len(eventsSnapshot()) == 1
	}, 5*time.Second, 10*time.Millisecond, "exactly one completed event for the slow consumer")
	evs := eventsSnapshot()
	require.Equal(t, "request.completed", evs[0].EventType)
	require.Equal(t, "t06-req-"+n03p1t06MKeepalive, evs[0].RequestID)
}
