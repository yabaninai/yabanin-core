package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	apierrs "github.com/reireirei/yabanin/pkg/apierrors"
	"github.com/reireirei/yabanin/pkg/apiformat"
	"github.com/reireirei/yabanin/pkg/budget"
	apierrors "github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/logctx"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/upstream"
)

const messagesResponseLimit = 8 << 20

func (gw *gateway) messagesNative(w http.ResponseWriter, r *http.Request, body []byte, model string) {
	started := time.Now()
	l := logctx.From(r.Context(), gw.log)
	var probe struct {
		Stream bool `json:"stream"`
	}
	_ = json.Unmarshal(body, &probe)
	admitted, ok := gw.admit(w, r, admitInput{
		Endpoint: "messages.native",
		Model:    model,
		Body:     body,
		NoRemap:  true,
	})
	if !ok {
		return
	}
	if gw.pool == nil {
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "upstream is not configured")
		return
	}
	// OP-8: unified policy-pipeline run point (pre-upstream, before the
	// reservation and the forward). One call site for both branches of this
	// endpoint (streaming hooks arrive with OP-4); the decision record rides
	// rctx into the finisher's event.
	guarded, policyEvent, ok := gw.policyPreUpstream(w, r, "messages", admitted.Info.ModelName, admitted.Info.Provider, admitted.Body)
	if !ok {
		return
	}
	admitted.Body = guarded
	// hint foreign to the serving provider refuses here, before any
	// reservation (the native client pool serves "anthropic").
	if !gw.enforceSingularRouteHint(w, r, "anthropic") {
		return
	}
	// NEXT-18c (ADR-0001 §5.1): pre-check + reserve before the upstream
	// call (no cache branch on this pipeline). The gate rides the
	// request-derived context for the finishers below.
	rctx := withPolicyEvent(r.Context(), policyEvent)
	rctx = withInvocationIdentity(rctx, admitted.Invocation)
	gate, ok := gw.reservationPlan(w, r, "messages.native",
		gw.reservationRequest(rctx, admitted.OrgID, admitted.TeamID, admitted.AgentID, admitted.SessionKeyID,
			admitted.Info, admitted.Body, nil, false))
	if !ok {
		return
	}
	rctx = withReservationGate(rctx, gate)
	if !gate.reserve(rctx) {
		return
	}
	apiKey := admitted.Info.UpstreamAPIKey
	if apiKey == "" {
		apiKey = gw.getUpstreamAPIKey()
	}
	upstreamURL := gw.upstreamURL(admitted.Info)
	client, err := gw.pool.Get(upstreamURL, "anthropic")
	if err != nil {
		l.Warn("upstream client unavailable", "provider", "anthropic", "error", err.Error())
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "failed to initialise upstream client")
		return
	}
	upstreamBody := upstream.OverrideModelRaw(admitted.Body, admitted.Info.ModelName)
	extra := anthropicExtraHeaders(r)
	// Preview2 durable accounting: the confirmed start commits immediately
	// BEFORE the first paid provider dispatch — after every fallible local
	// setup step above (pool wiring, model remap, header prep), so a local
	// failure never strands a durable admission for a request that never
	// dispatched. One admission per request; the JSON and stream branches
	// below share it and the kind binds to the transport actually
	// dispatched. Fail closed: an unwritten start (write error, timeout or
	// lost ACK — outcome unknown) refuses the request with ZERO provider
	// arrivals under the history_unavailable envelope, and the escrow is
	// released.
	if err := gw.confirmPaidInvocation(rctx, invocationKindForChat(probe.Stream)); err != nil {
		gate.finalizeNoEvent(budget.TerminationPolicyDenied)
		l.Warn("refusing paid dispatch: durable start unwritten", "error", err)
		writeInvocationStartRefusal(w, err)
		return
	}
	if probe.Stream {
		// W-TIMEOUT: streams carry no whole-request deadline; the transport's
		// ResponseHeaderTimeout plus the idle watchdog below bound them.
		gw.messagesNativeStream(w, r, rctx, gate, admitted, client, upstreamBody, apiKey, upstreamURL, extra, started)
		return
	}
	gw.messagesNativeJSON(w, r, rctx, gate, admitted, client, upstreamBody, apiKey, upstreamURL, extra, started, l)
}

// messagesNativeJSON serves the non-streaming native /v1/messages request:
// one whole-request upstream roundtrip with timeout, usage and post-
// upstream policy applied to the buffered reply, durable settlement before
// the client sees a payable success, and the byte-identical forward.
func (gw *gateway) messagesNativeJSON(w http.ResponseWriter, r *http.Request, rctx context.Context, gate *reservationGate, admitted admitted, client *upstream.Client, upstreamBody []byte, apiKey, upstreamURL string, extra http.Header, started time.Time, l *slog.Logger) {
	timeout := admitted.Info.UpstreamTimeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(rctx, timeout)
	defer cancel()
	resp, err := client.Do(ctx, "/v1/messages", upstreamBody, apiKey, false, extra)
	if err != nil {
		closeUpstream(l, resp)
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "upstream request failed")
		return
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			l.Debug("close upstream body", "error", cerr)
		}
	}()
	limited, err := readNativeBufferedBody(resp, messagesResponseLimit)
	if err != nil {
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		writePaidBodyError(w, "failed to read upstream response")
		return
	}
	if resp.StatusCode != http.StatusOK {
		gw.forwardAnthropicError(w, rctx, admitted, resp, limited, upstreamURL, started)
		return
	}
	if len(limited) > messagesResponseLimit {
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		writePaidBodyError(w, "upstream response too large")
		return
	}
	usage := provider.Anthropic{}.ParseUsage(limited)
	// OP-8: post-upstream policy hook. Usage was parsed from the ORIGINAL
	// body (the tokens were consumed); a mask replaces what the client and
	// the finisher see; a deny answers 400 instead of the upstream body.
	if gw.policyRuntime != nil {
		masked, postEvent, denied := gw.policyPostUpstream(r, "messages", admitted.Info.ModelName, admitted.Info.Provider, limited)
		if postEvent != "" {
			rctx = withPolicyEvent(rctx, appendPolicyEvents(policyEventFrom(rctx), postEvent))
		}
		if denied {
			if ferr := gw.finishNativeMessages(w, rctx, admitted, usage, upstreamURL, http.StatusBadRequest, started, resp, "request.failed", "response blocked by organization policy"); ferr != nil {
				l.Error("terminal facts commit failed; event withheld from consumer", "error", ferr)
			}
			apierrors.WriteWithCode(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
				"response blocked by organization policy", policyDenyErrorCode)
			return
		}
		limited = masked
	}
	if ferr := gw.finishNativeMessages(w, rctx, admitted, usage, upstreamURL, http.StatusOK, started, resp, "request.completed", ""); ferr != nil {
		// Central binding: usage was dispatched but its durable record did
		// not commit — the client must not see the upstream body as a
		// payable success (never a re-dispatch; support reconciles).
		writeTerminalAccountingFailure(w)
		return
	}
	// N03-P06-T02: same provider-derived transparency the OpenAI-compat
	// JSON path reports (finalizeChatJSON); before WriteHeader below.
	setPromptCacheHeader(w, usage)
	copyAnthropicPassthrough(w.Header(), resp.Header)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(limited)
}

func (gw *gateway) messagesNativeStream(w http.ResponseWriter, r *http.Request, rctx context.Context, gate *reservationGate, admitted admitted, client *upstream.Client, upstreamBody []byte, apiKey, upstreamURL string, extra http.Header, started time.Time) {
	l := logctx.From(rctx, gw.log)
	streamCtx, cancelStream := context.WithCancel(rctx)
	defer cancelStream()
	resp, err := client.Do(streamCtx, "/v1/messages", upstreamBody, apiKey, true, extra)
	if err != nil {
		closeUpstream(l, resp)
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "upstream request failed")
		return
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			l.Debug("close upstream body", "error", cerr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		limited, readErr := io.ReadAll(io.LimitReader(resp.Body, messagesResponseLimit))
		if readErr != nil {
			gate.finalizeNoEvent(budget.TerminationUpstreamErr)
			apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "failed to read upstream response")
			return
		}
		gw.forwardAnthropicError(w, rctx, admitted, resp, limited, upstreamURL, started)
		return
	}
	copyAnthropicPassthrough(w.Header(), resp.Header)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	body := io.Reader(resp.Body)
	if gw.streamIdleTimeout > 0 {
		idle := newIdleReader(resp.Body, gw.streamIdleTimeout, cancelStream)
		defer idle.Stop()
		body = idle
	}
	// The success terminal is ordered after the terminal-facts commit
	// (Preview2 central binding): the relay writes through the terminal
	// hold, which forwards nonterminal frames immediately and buffers
	// message_stop at the seam until finishNativeMessages commits.
	hold := gw.armNativeTerminalHold(w, rctx, nativeEventName, anthNativeSuccessTerminals, anthNativeFailureTerminals)
	usage, _ := relayAnthropicSSE(hold, body)
	// N03-P06-T02: SSE headers are already committed; the provider
	// prompt-cache outcome rides the HTTP trailer (usage is final here).
	// The settlement keeps the D1 canon on every end: an explicit upstream
	// error event is the provider closing the stream in-protocol (billed
	// as produced output), while cuts and cancels complete per D1 — the
	// delivered-usage asymmetry is pinned by
	// TestMessagesNative_EventAsymmetry_CutStream.
	setPromptCacheTrailer(w, usage)
	if ferr := gw.finishNativeMessages(w, rctx, admitted, usage, upstreamURL, http.StatusOK, started, resp, "request.completed", ""); ferr != nil {
		// SSE 200 headers are already committed: the client keeps the
		// stream, and the terminal accounting failure closes it with the
		// protocol-shaped error event carrying accounting_commit_failed
		// (the chat stream canon: NOT safe to retry — support reconciles
		// the charge). The withheld event never reaches the consumer;
		// when the relay already delivered a terminal error frame the
		// stream ended client-side and the commit failure is log-only —
		// never a second terminal.
		l.Error("terminal facts commit failed after streamed dispatch", "error", ferr)
		hold.fail()
		if !hold.failureSeen() {
			writeAnthropicStreamAccountingFailure(w)
		}
		return
	}
	hold.release()
}

// Terminal event names for the native relays: the success terminal whose
// client delivery must follow the durable terminal-facts commit, and the
// failure terminals that end the stream in-protocol and must never be
// followed by a second terminal.
var (
	anthNativeSuccessTerminals = map[string]bool{"message_stop": true}
	anthNativeFailureTerminals = map[string]bool{"error": true}

	respNativeSuccessTerminals = map[string]bool{
		"response.completed":  true,
		"response.incomplete": true,
	}
	respNativeFailureTerminals = map[string]bool{"response.failed": true}
)

// anthNativeSuccessTerminals etc. classify through nativeEventName
// (shared with the responses relay): event field first, JSON type
// fallback — data-only terminals hold the same as event-field ones.

// nativeTerminalHold orders the client-visible success terminal of a
// native SSE relay after the durable terminal-facts commit (the native
// twin of the chat drain's doneWatch, stream.go sseTerminalWatch):
// records flush through while the first success terminal is buffered at
// this seam. release writes the held record once the facts are
// committed; fail drops it, letting the caller's accounting-failure
// frame close the stream as its single terminal. Failure terminals pass
// through unheld and set sawFailure — the caller then suppresses the
// accounting frame, and a success terminal buffered before that failure
// is dropped, so every end path leaves exactly one client terminal.
// Classification runs the records the relays dispatch through the
// shared apiformat.SSEParser (the relays' own wire semantics, including
// split data lines); records that complete no event — heartbeat
// comments, blank separators, frame partials — pass through at once, so
// heartbeats never wait on an event separator, nothing accumulates, and
// a released stream is byte-identical to an unheld relay.
type nativeTerminalHold struct {
	http.ResponseWriter
	name    func(apiformat.SSEEvent) string
	success map[string]bool
	failure map[string]bool
	flusher http.Flusher
	armed   bool

	held       []byte // buffered success terminal, pending the facts commit
	sawFailure bool   // a failure terminal was forwarded; stream ended client-side
}

// armNativeTerminalHold wraps the stream's writer when the success
// terminal must follow the facts commit: an admitted invocation with a
// live durable store (the chat drain's doneWatch arming rule). Streams
// outside that scope pass straight through and the hold methods are
// no-ops.
func (gw *gateway) armNativeTerminalHold(w http.ResponseWriter, ctx context.Context, name func(apiformat.SSEEvent) string, success, failure map[string]bool) *nativeTerminalHold {
	h := &nativeTerminalHold{ResponseWriter: w, name: name, success: success, failure: failure}
	if f, ok := w.(http.Flusher); ok {
		h.flusher = f
	}
	if id := invocationIdentityFrom(ctx); id != nil && id.Admitted() && gw.invocations != nil {
		h.armed = true
	}
	return h
}

// Write routes one relay dispatch. The relays emit bounded complete
// records per Write (frames whole via apiformat.SSEFrameBuffer, comment
// lines standalone), so a fresh parser's Feed+Flush resolves exactly
// the record p carried — including the lone-CR terminator dialect,
// whose trailing CR Feed alone would hold for the next chunk — without
// ever completing record N's classification on record N+1's bytes. A
// Write classifying to no event holds no terminal and passes through
// unchanged.
func (h *nativeTerminalHold) Write(p []byte) (int, error) {
	if !h.armed {
		return h.ResponseWriter.Write(p)
	}
	var classifier apiformat.SSEParser
	events := append(classifier.Feed(p), classifier.Flush()...)
	if len(events) == 0 {
		_, err := h.ResponseWriter.Write(p)
		return len(p), err
	}
	if err := h.dispatch(p, h.name(events[0])); err != nil {
		return 0, err
	}
	return len(p), nil
}

// dispatch routes one complete record by its event name: failure
// terminals pass through and end the stream in-protocol (a buffered
// success is dropped so it cannot follow the client's terminal), the
// first success terminal is held for the facts commit, later ones are
// dropped as post-terminal duplicates, and every other record passes
// through.
func (h *nativeTerminalHold) dispatch(p []byte, name string) error {
	switch {
	case h.failure[name]:
		h.sawFailure = true
		h.held = nil
		_, err := h.ResponseWriter.Write(p)
		return err
	case h.success[name] && h.held == nil && !h.sawFailure:
		h.held = append([]byte(nil), p...)
		return nil
	case h.success[name]:
		return nil
	}
	_, err := h.ResponseWriter.Write(p)
	return err
}

// Flush passes client flushes through; the held terminal stays at the
// seam until the facts commit releases it.
func (h *nativeTerminalHold) Flush() {
	if h.flusher != nil {
		h.flusher.Flush()
	}
}

// release writes the held success terminal after the terminal facts
// committed, then disarms the hold.
func (h *nativeTerminalHold) release() {
	if !h.armed {
		return
	}
	h.armed = false
	if h.held != nil {
		_, _ = h.ResponseWriter.Write(h.held)
		h.held = nil
	}
	if h.flusher != nil {
		h.flusher.Flush()
	}
}

// fail drops the held terminal after an uncommittable facts record; the
// caller's accounting-failure frame is then the stream's single
// terminal.
func (h *nativeTerminalHold) fail() {
	h.armed = false
	h.held = nil
}

// failureSeen reports whether a failure terminal was already forwarded:
// the client's stream ended in-protocol and no accounting frame may
// stack a second terminal on it.
func (h *nativeTerminalHold) failureSeen() bool { return h.sawFailure }

// relayAnthropicSSE forwards the upstream Anthropic SSE stream to the client
// byte-identically while accounting usage. It returns the provider usage
// parsed off the events read from upstream (authoritative even when the
// client disconnected mid-drain) and the first failed client write, if
// any: after it no further bytes are written and no further provider
// bytes are pulled — a streaming upstream on the live connection would
// keep doing paid work for a client that is gone — while frames already
// read still settle usage. Only complete upstream lines are forwarded: a
// line cut before its terminator is withheld — a delimiter cannot make
// truncated JSON decodable for event-by-event SDK consumers — so the
// client never receives a partial event; a boundary-aligned decodable
// frame missing just its separator is salvaged and closed with a CRLF
// blank separator, valid after an LF, CRLF or lone-CR last line alike.
// The relay also tracks stream lifecycle: when the upstream ends without
// a terminal event — transport cut, ErrAbortHandler, or the idle
// watchdog canceling the read — the still-open content blocks are
// closed (ascending index order) and one terminal error frame in the
// shared adapted shape is synthesized (N07-P02-T03, the native twin of
// the adapted writer's D2 closing in emitStreamErrorLocked).
// message_stop is never fabricated and an explicit upstream error event
// is never duplicated. A blob ending in a lone CR leaves its event
// pending in the parser until more bytes arrive or the final Flush; each
// dispatched record is finalized through Feed+Flush, so a complete
// record's event — including the lone-CR separator dialect — settles
// within its own dispatch instead of on the next chunk. The drain stops
// at the authoritative delivered terminal (message_stop, or an error
// event): everything after it is not part of the message, and the relay
// never waits on physical EOF to settle usage and lifecycle.
// anthBlockLifecycle tracks the client-visible lifecycle of a native
// /v1/messages stream: which content blocks the client saw open, and
// whether a terminal — message_stop, or an error event closing the stream
// in-protocol — was delivered. Tracking is delivered-only: an event the
// client never received never happened.
type anthBlockLifecycle struct {
	open     map[int]struct{}
	sawStop  bool
	sawError bool
}

// note applies one delivered event's lifecycle effect. Same name semantics
// as the terminal hold: the event field, else the data payload's type
// member — a data-only terminal ends the stream identically (no
// synthesized error after it, and no error synthesized twice).
func (lc *anthBlockLifecycle) note(ev apiformat.SSEEvent) {
	switch nativeEventName(ev) {
	case "content_block_start":
		var doc struct {
			Index *int `json:"index"`
		}
		// A start frame without an explicit index is a malformed block
		// declaration: tracking it would invent index 0 and synthesize a
		// content_block_stop for a block the upstream never declared.
		if json.Unmarshal([]byte(ev.Data), &doc) == nil && doc.Index != nil {
			lc.open[*doc.Index] = struct{}{}
		}
	case "content_block_stop":
		var doc struct {
			Index int `json:"index"`
		}
		if json.Unmarshal([]byte(ev.Data), &doc) == nil {
			delete(lc.open, doc.Index)
		}
	case "message_stop":
		lc.sawStop = true
	case "error":
		lc.sawError = true
	}
}

// terminal reports whether a delivered event ended the stream in-protocol:
// everything after it is not part of the message.
func (lc anthBlockLifecycle) terminal() bool {
	return lc.sawStop || lc.sawError
}

// anthStreamRelay carries one native /v1/messages drain's state (the
// streamRun canon): the client write path, the event parser, the usage and
// lifecycle observers, the frame accumulator, and the first client-write
// failure that stops further provider pulls.
type anthStreamRelay struct {
	w         http.ResponseWriter
	flusher   http.Flusher
	parser    apiformat.SSEParser
	acc       anthStreamUsage
	lifecycle anthBlockLifecycle
	frames    apiformat.SSEFrameBuffer
	werr      error // first client-write failure; writes stop and no further provider bytes are pulled (usage is read-based)
}

func newAnthStreamRelay(w http.ResponseWriter) *anthStreamRelay {
	rl := &anthStreamRelay{w: w, lifecycle: anthBlockLifecycle{open: map[int]struct{}{}}}
	if f, ok := w.(http.Flusher); ok {
		rl.flusher = f
	}
	return rl
}

// writeFrame delivers one complete upstream record — a comment line or a
// whole frame, separator included — to the client and settles its parsed
// usage and delivered lifecycle effects. Frames are dispatched whole: an
// event is only decodable once its blank separator has arrived, so lines
// of an unterminated frame are held back and only a decodable event
// missing just the separator is salvaged on a boundary-aligned end
// (apiformat.SSEFrameBuffer).
func (rl *anthStreamRelay) writeFrame(blob []byte) {
	if len(blob) == 0 {
		return
	}
	delivered := rl.werr == nil
	if delivered {
		if _, e := rl.w.Write(blob); e != nil {
			rl.werr, delivered = e, false
		} else if rl.flusher != nil {
			rl.flusher.Flush()
		}
	}
	// Usage is fed from what was read; lifecycle tracking only from
	// what the client actually received.
	for _, ev := range append(rl.parser.Feed(blob), rl.parser.Flush()...) {
		rl.acc.note(ev)
		if delivered {
			rl.lifecycle.note(ev)
		}
	}
}

// drain pumps the upstream line reader until the stream ends: a
// client-write failure (after the already-buffered paid bytes settle), an
// oversized line or frame, an upstream break, a clean EOF, or the
// authoritative delivered terminal.
func (rl *anthStreamRelay) drain(lr *apiformat.SSELineReader) {
	// After a client write fails, finish accounting for buffered bytes only.
	for rl.werr == nil || lr.Buffered() {
		line, err := lr.ReadLine()
		if errors.Is(err, apiformat.ErrSSELineLimit) {
			// Oversized upstream line: drop it and the held frame, stop
			// relaying. The synthesis below closes the client stream (no
			// stop was seen); the caller's deferred upstream body close
			// aborts the provider connection, so the tail is never
			// produced.
			slog.Debug("native relay dropped oversized upstream line", "limit_bytes", apiformat.SSEStreamLineLimit)
			break
		}
		if err != nil {
			// Upstream ended mid-line (transport cut, or EOF without the
			// terminator): the unterminated partial is withheld, and the
			// held frame is dispatched only when the end aligned to a
			// line boundary (no partial followed it — observing a cut
			// partial proves the event was still being written, so
			// salvaging a valid-JSON prefix of it would fabricate a
			// shorter event) AND it is a decodable event missing just
			// the separator — closed with its CRLF blank separator so
			// the parser emits it here, delivered or not. Otherwise it
			// is dropped so the synthesis below composes at an event
			// boundary.
			if len(line) == 0 && rl.frames.Salvageable() {
				rl.writeFrame(append(rl.frames.Take(), '\r', '\n'))
			}
			break
		}
		if apiformat.SSECommentLine(line) {
			// Keepalive comments ride no event: forward them immediately
			// instead of frame-batching them; the buffer holds only
			// field lines.
			rl.writeFrame(line)
			continue
		}
		blank, overflow := rl.frames.Add(line, apiformat.SSEStreamLineLimit)
		if overflow {
			slog.Debug("native relay dropped oversized upstream frame", "limit_bytes", apiformat.SSEStreamLineLimit)
			break
		}
		if blank {
			// Blank separator: the frame is complete — dispatch it whole,
			// verbatim, separator included.
			rl.writeFrame(append(rl.frames.Take(), line...))
			if rl.lifecycle.terminal() {
				// The provider declared the authoritative terminal
				// (message_stop ends the message; an error event closes
				// the stream in-protocol): settle the known usage and
				// stop pulling upstream bytes — a provider that holds
				// the connection open after the final event must not
				// delay the client's terminal or the facts commit on
				// physical EOF. Post-terminal bytes are not part of the
				// message, there is no re-dispatch, and the caller's
				// deferred body close aborts the connection.
				break
			}
		}
	}
}

// settle applies the drain's end: the parser's pending event (a blob
// ending in a lone CR leaves the separator pending until this flush,
// under the same delivered rule), the tail tracker's close of a torn last
// event, and — only when no terminal was delivered — the synthesized
// close of still-open content blocks.
func (rl *anthStreamRelay) settle(tail *ssePassthroughTail) (provider.Usage, error) {
	delivered := rl.werr == nil
	for _, ev := range rl.parser.Flush() {
		rl.acc.note(ev)
		if delivered {
			rl.lifecycle.note(ev)
		}
	}
	// Close a torn tail (dangling line or cut mid-line) before the
	// synthesized stop/error frames glue into it; no-op on whole-frame tails.
	tail.complete()
	if !rl.lifecycle.terminal() {
		closeOpenAnthropicBlocks(rl.w, rl.flusher, rl.lifecycle.open)
	}
	return rl.acc.usage(), rl.werr
}

func relayAnthropicSSE(w http.ResponseWriter, body io.Reader) (usage provider.Usage, err error) {
	// The relay writes through the tail tracker so a torn last event is
	// closed before the synthesized terminal frames compose (chat F2 canon).
	tail := &ssePassthroughTail{w: w}
	rl := newAnthStreamRelay(tail)
	rl.drain(apiformat.NewSSELineReader(bufio.NewReader(body), apiformat.SSEStreamLineLimit))
	return rl.settle(tail)
}

// closeOpenAnthropicBlocks terminates a truncated native stream: every
// still-open content block gets its content_block_stop (ascending), then one
// Anthropic error frame closes the stream. Best-effort by the same contract
// as writeSSEError: a client that already disconnected can make the
// underlying Write/Flush panic inside net/http, and the panic is contained
// so the caller's cleanup — budget accounting, analytics — always runs.
func closeOpenAnthropicBlocks(w http.ResponseWriter, flusher http.Flusher, open map[int]struct{}) {
	defer func() {
		if rec := recover(); rec != nil {
			slog.Debug("native stream close panicked (client gone)", "panic", rec)
		}
	}()
	indices := make([]int, 0, len(open))
	for idx := range open {
		indices = append(indices, idx)
	}
	sort.Ints(indices)
	for _, idx := range indices {
		doc, err := json.Marshal(struct {
			Type  string `json:"type"`
			Index int    `json:"index"`
		}{Type: "content_block_stop", Index: idx})
		if err != nil {
			continue
		}
		if werr := apiformat.WriteSSEEvent(w, "content_block_stop", doc); werr != nil {
			slog.Debug("native stream close write failed, client disconnected", "error", werr)
			return
		}
	}
	errDoc, _ := apierrs.Anthropic(http.StatusInternalServerError, &apierrs.E{Type: apierrs.TypeAPI, Message: "stream interrupted"})
	if werr := apiformat.WriteSSEEvent(w, "error", errDoc); werr != nil {
		slog.Debug("native stream error write failed, client disconnected", "error", werr)
	}
	if flusher != nil {
		flusher.Flush()
	}
}

type anthStreamUsage struct {
	input, output, cacheRead, cacheCreate int64
	seen                                  bool
}

func (u *anthStreamUsage) note(ev apiformat.SSEEvent) {
	name := nativeEventName(ev)
	if name != "message_start" && name != "message_delta" {
		return
	}
	var doc struct {
		Message struct {
			Usage *anthRawUsage `json:"usage"`
		} `json:"message"`
		Usage *anthRawUsage `json:"usage"`
	}
	if json.Unmarshal([]byte(ev.Data), &doc) != nil {
		return
	}
	raw := doc.Usage
	if raw == nil {
		raw = doc.Message.Usage
	}
	u.merge(raw)
}

func (u *anthStreamUsage) merge(raw *anthRawUsage) {
	if raw == nil {
		return
	}
	u.seen = true
	if raw.Input != nil {
		u.input = *raw.Input
	}
	if raw.Output != nil {
		u.output = *raw.Output
	}
	if raw.CacheRead != nil {
		u.cacheRead = *raw.CacheRead
	}
	if raw.CacheCreate != nil {
		u.cacheCreate = *raw.CacheCreate
	}
}

func (u anthStreamUsage) usage() provider.Usage {
	if !u.seen {
		return provider.Usage{Source: provider.UsageSourceNone}
	}
	raw, err := json.Marshal(map[string]any{
		"usage": map[string]int64{
			"input_tokens":                u.input,
			"output_tokens":               u.output,
			"cache_read_input_tokens":     u.cacheRead,
			"cache_creation_input_tokens": u.cacheCreate,
		},
	})
	if err != nil {
		return provider.Usage{Source: provider.UsageSourceNone}
	}
	return provider.Anthropic{}.ParseUsage(raw)
}

type anthRawUsage struct {
	Input       *int64 `json:"input_tokens"`
	Output      *int64 `json:"output_tokens"`
	CacheRead   *int64 `json:"cache_read_input_tokens"`
	CacheCreate *int64 `json:"cache_creation_input_tokens"`
}

func (gw *gateway) forwardAnthropicError(w http.ResponseWriter, ctx context.Context, admitted admitted, resp *http.Response, body []byte, upstreamURL string, started time.Time) {
	if ferr := gw.finishNativeMessages(w, ctx, admitted, provider.Usage{}, upstreamURL, resp.StatusCode, started, resp, "request.failed", "upstream request failed"); ferr != nil {
		// The client envelope is already the upstream failure; the
		// withheld event is logged loudly (finishRequestLogged canon).
		logctx.From(ctx, gw.log).Error("terminal facts commit failed; event withheld from consumer", "error", ferr)
	}
	copyAnthropicPassthrough(w.Header(), resp.Header)
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	} else {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}

// finishNativeMessages closes the native /v1/messages request. It returns
// the terminal-facts commit error so success call sites can convert the
// client reply (writeTerminalAccountingFailure / the Anthropic SSE
// accounting event); failure call sites log it (finishRequestLogged canon).
func (gw *gateway) finishNativeMessages(w http.ResponseWriter, ctx context.Context, admitted admitted, usage provider.Usage, upstreamURL string, status int, started time.Time, resp *http.Response, eventType, errText string) error {
	ext := provider.ComputeCost(usage, "anthropic", admitted.Info.ModelName)
	if eventType == "request.completed" {
		gw.accountUsage(ctx, w, usageRecord{
			orgID:      admitted.OrgID,
			taskID:     admitted.TaskID,
			sessionID:  admitted.SessionID,
			usage:      usage,
			costUSD:    ext.EstimatedCostUSD,
			priceKnown: ext.PriceKnown,
		})
	}
	term := budget.TerminationUpstreamErr
	if eventType == "request.completed" {
		term = completionTermination(ctx)
	}
	_, ferr := gw.finishRequest(ctx, requestFinish{
		base: eventBase{
			EventType:                  eventType,
			RequestID:                  admitted.RequestID,
			SessionID:                  admitted.SessionID,
			OrgID:                      admitted.OrgID,
			TeamID:                     admitted.TeamID,
			AgentID:                    admitted.AgentID,
			UserID:                     admitted.UserID,
			APIKeyID:                   admitted.APIKeyID,
			SessionKeyID:               admitted.SessionKeyID,
			TaskID:                     admitted.TaskID,
			ModelRequested:             admitted.RequestedModel,
			ModelUsed:                  admitted.Info.ModelName,
			UpstreamURL:                upstreamURL,
			StatusCode:                 int64(status),
			DurationMs:                 time.Since(started).Milliseconds(),
			TokensIn:                   usage.PromptTokens,
			TokensOut:                  usage.CompletionTokens,
			CacheReadTokens:            usage.CacheReadTokens,
			CacheCreationTokens:        usage.CacheCreationTokens,
			EstimatedCostUSD:           ext.EstimatedCostUSD,
			Endpoint:                   "messages",
			UsageSource:                usageSourceOrNone(usage.Source),
			CostStatus:                 costStatus(false, usage.Source, ext.PriceKnown),
			Method:                     http.MethodPost,
			Error:                      errText,
			InferenceRegion:            admitted.Info.Region,
			ModelOriginCountry:         admitted.Info.Provider,
			LogStorageRegion:           gw.cfg.Region,
			ProviderEntityJurisdiction: admitted.Info.Provider,
			Labels:                     labelsFrom(ctx),
			Policy:                     policyEventFrom(ctx), // OP-8: decision record (OP-9 contract)
		},
		info: admitted.Info,
		resp: resp,
		// NEXT-18c: settle the reservation and stamp tuples + termination
		// (§5.3 Finalize). No resale on this pipeline; the wallet actual
		// falls back to the base quote — the consumer's own rule.
		termination: term,
		eventNote:   true,
	}, nil)
	if ferr != nil {
		return ferr
	}
	return nil
}

// writeAnthropicStreamAccountingFailure closes a native /v1/messages
// stream whose terminal accounting could not be committed after the
// provider already served it: the Anthropic error-event shape mirroring
// closeOpenAnthropicBlocks, with the accounting_commit_failed code in the
// message (the fixed anthropic error.type vocabulary has no code slot)
// and the chat-stream canon's no-safe-retry language. Best-effort: the
// client may already be gone.
func writeAnthropicStreamAccountingFailure(w http.ResponseWriter) {
	payload, _ := apierrs.Anthropic(http.StatusInternalServerError, &apierrs.E{
		Type:    apierrs.TypeAPI,
		Message: accountingCommitFailedCode + ": stream completed but its durable usage record could not be committed; NOT safe to retry — support reconciles the charge",
	})
	if werr := apiformat.WriteSSEEvent(w, "error", payload); werr != nil {
		return
	}
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}

func anthropicExtraHeaders(r *http.Request) http.Header {
	extra := make(http.Header)
	version := r.Header.Get("anthropic-version")
	if version == "" {
		version = "2023-06-01"
	}
	extra.Set("anthropic-version", version)
	if beta := r.Header.Get("anthropic-beta"); beta != "" {
		extra.Set("anthropic-beta", beta)
	} else {
		extra.Set("anthropic-beta", "")
	}
	if ws := r.Header.Get("anthropic-workspace-id"); ws != "" {
		extra.Set("anthropic-workspace-id", ws)
	}
	return extra
}

func copyAnthropicPassthrough(dst, src http.Header) {
	for key, values := range src {
		lower := strings.ToLower(key)
		if lower == "retry-after" || lower == "x-should-retry" || lower == "request-id" || strings.HasPrefix(lower, "anthropic-ratelimit-unified-") {
			for _, value := range values {
				dst.Add(key, value)
			}
		}
	}
}
