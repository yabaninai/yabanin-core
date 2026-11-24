package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/reireirei/yabanin/pkg/apiformat"
	"github.com/reireirei/yabanin/pkg/budget"
	apierrors "github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/httpmw"
	"github.com/reireirei/yabanin/pkg/logctx"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// realtimeStreamLimit caps the total bytes relayed from one upstream realtime
// session to the client (contract subset matrix). Crossing it aborts the
// relay as an upstream error — the gateway never silently truncates an SSE
// stream mid-event.
const realtimeStreamLimit = 64 << 20

// realtimeDefaultTimeout bounds a realtime session when the registry entry
// carries no UpstreamTimeout (session semantics need more headroom than the
// 60s unary default; the idle watchdog catches a stalled stream earlier).
const realtimeDefaultTimeout = 5 * time.Minute

// SSE-only session-style proxy. The request body is passed through to the
// OpenAI-compat /v1/realtime upstream with stream semantics; the upstream
// event stream is relayed byte-honestly to the client. WebSocket transport
// is explicitly out (D4: SSE-only first release) and refused before
// admission. Usage accounting is actual (D3): the last usage-bearing event
// (top-level usage or response.usage) is billed; a client disconnect settles
// the consumed prefix with TerminationClientCancel — usage is never lost
// (G3 parity with the chat stream drain contract).
// realtimeRequest is the validated client shape of the realtime route.
type realtimeRequest struct {
	Model string `json:"model"`
}

// parseRealtimeRequest reads and validates the client request. Every
// refusal lands BEFORE admission, so a rejected request leaves no durable
// trace; a client that walked away mid-body gets no envelope at all (N3,
// audio parity — the response target is gone, and writing it would race
// the server's conn teardown).
func parseRealtimeRequest(w http.ResponseWriter, r *http.Request) (realtimeRequest, []byte, bool) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		if r.Context().Err() != nil {
			return realtimeRequest{}, nil, false
		}
		if httpmw.IsMaxBytesError(err) {
			apierrors.Write(w, http.StatusRequestEntityTooLarge, apierrors.ErrorCodeInvalidRequest, "request body too large")
			return realtimeRequest{}, nil, false
		}
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "request body too large or malformed")
		return realtimeRequest{}, nil, false
	}
	var req realtimeRequest
	if err := json.Unmarshal(body, &req); err != nil {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "malformed JSON: "+err.Error())
		return realtimeRequest{}, nil, false
	}
	if req.Model == "" {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "model is required")
		return realtimeRequest{}, nil, false
	}
	return req, body, true
}

func (gw *gateway) admitRealtime(w http.ResponseWriter, r *http.Request) (admitted, bool) {
	// D4 (ratified SSE-only): a WebSocket upgrade is explicitly refused
	// before any admission or upstream work (upstream call count stays 0).
	if isWebSocketUpgrade(r) {
		apierrors.WriteWithCode(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
			"websocket is not supported; realtime is SSE-only", apierrors.CodeUnsupportedFeature)
		return admitted{}, false
	}
	req, body, ok := parseRealtimeRequest(w, r)
	if !ok {
		return admitted{}, false
	}

	request, ok := gw.admit(w, r, admitInput{
		Endpoint: "realtime",
		Model:    req.Model,
		Body:     body,
		NoRemap:  true,
	})
	if !ok {
		return admitted{}, false
	}
	if !gw.openAICompatRouteReady(w, request.Info.Provider, "realtime", "realtime is not supported for this provider") {
		return admitted{}, false
	}
	return request, true
}

func (gw *gateway) realtime(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	l := logctx.From(r.Context(), gw.log)
	admitted, ok := gw.admitRealtime(w, r)
	if !ok {
		return
	}

	// NEXT-18c (ADR-0001 §5.1) + ratified D3: reservation rides the input
	// pre-estimate (chat-shaped bound — realtime sessions generate output,
	// so the org default out cap applies; MaxTokens stays nil).
	rctx, gate, ok := gw.reservePaidDispatch(r.Context(), w, r, "realtime", admitted, nil, false)
	if !ok {
		return
	}

	client, upstreamBody, apiKey, providerName, upstreamURL, ok := gw.paidUpstreamClient(l, w, gate, admitted, admitted.Info.Provider)
	if !ok {
		return
	}
	// Stream capability precedes the durable start: a writer that cannot
	// flush must fail BEFORE the admission commits and before any paid
	// dispatch — the old post-dispatch 501 both wasted paid work and
	// stranded the admitted row without terminal facts (chat
	// streamRun.admit canon — fail before anything durable, with zero
	// provider arrivals).
	if !requireStreamFlusher(w, gate, true) {
		return
	}
	if !gw.confirmPaidStart(w, l, gate, rctx, invocationKindStream) {
		return
	}
	resp, cancelStream, ok := dialRealtimeSSE(w, rctx, l, gate, client, upstreamBody, apiKey, admitted.Info)
	if !ok {
		return
	}
	defer resp.Body.Close()
	defer cancelStream()

	// The raw-chunk relay writes through the tail tracker so a torn last
	// event is closed before the terminal error frame composes (chat F2
	// canon); the tee is fed from the read side and is unaffected. The
	// relay also returns the terminal hold that defers the session's last
	// successful terminal (response.done status completed) until the
	// terminal facts commit below — the chat [DONE] hold canon.
	tail := &ssePassthroughTail{w: w}
	usage, tee, term, hold, drainErr := gw.realtimeRelay(rctx, tail, tail, resp.Body, cancelStream)
	// Cancellation cleanup: the spill file is removed on every exit —
	// release/drop are idempotent and cleanup is safe to call again.
	defer hold.cleanup()

	ttftMs, hasTTFT := tee.firstTokenMs(started)
	if hasTTFT {
		metrics.UpstreamFirstTokenSeconds.WithLabelValues(providerName, admitted.Info.ModelName).
			Observe(float64(ttftMs) / 1000)
	}
	ext := provider.ComputeCost(usage, providerName, admitted.Info.ModelName)
	settle := realtimeSettle{
		rctx:         rctx,
		w:            w,
		l:            l,
		admitted:     admitted,
		usage:        usage,
		tee:          tee,
		ext:          ext,
		ttftMs:       ttftMs,
		hasTTFT:      hasTTFT,
		started:      started,
		providerName: providerName,
		upstreamURL:  upstreamURL,
		region:       gw.cfg.Region,
		resp:         resp,
	}
	if drainErr != nil {
		gw.finishRealtimeDrainError(settle, tail, hold, term, drainErr)
		return
	}
	gw.finishRealtimeSession(settle, hold)
}

// dialRealtimeSSE opens the paid /v1/realtime SSE session: the stream
// context with its own cancel (the idle watchdog can abort a stalled
// upstream without touching the parent request context; the parent
// deadline — the session ceiling from the model's upstream timeout, with
// the realtime default when the registry entry carries none — still
// applies, stream.go parity), the POST through the pool client, the
// upstream status refusal, and — only after a 200 — the SSE commit point
// headers. The structured 503 precedes that commit point, so it can never
// land after client success headers.
func dialRealtimeSSE(w http.ResponseWriter, rctx context.Context, l *slog.Logger, gate *reservationGate, client *upstream.Client, upstreamBody []byte, apiKey string, info resolver.ModelInfo) (*http.Response, context.CancelFunc, bool) {
	timeout := info.UpstreamTimeout
	if timeout <= 0 {
		timeout = realtimeDefaultTimeout
	}
	streamCtx, cancelStream := context.WithTimeout(rctx, timeout)
	resp, err := client.Do(streamCtx, "/v1/realtime", upstreamBody, apiKey, true, nil)
	if err != nil {
		cancelStream()
		closeUpstream(l, resp)
		gate.finalizeNoEvent(mediaTermination(rctx))
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "upstream request failed")
		return nil, nil, false
	}
	if resp.StatusCode != http.StatusOK {
		closeUpstream(l, resp)
		cancelStream()
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		status, errType := apierrors.MapUpstreamStatus(resp.StatusCode)
		apierrors.Write(w, status, errType, "upstream request failed")
		return nil, nil, false
	}
	// SSE commit point: headers go out only after the upstream answered
	// 200, so every pre-stream failure above keeps the JSON error envelope.
	// The stream capability was checked before the durable start; the
	// writer is a Flusher by construction.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Proxy-Cache", "bypass")
	return resp, cancelStream, true
}

// realtimeSettle carries the inputs shared by the two realtime settle
// paths (abnormal drain and healthy completion): both stamp the same
// analytics facts from the relay's outcome and differ only in the event
// type, the terminal class and the cost/hold handling.
type realtimeSettle struct {
	rctx         context.Context
	w            http.ResponseWriter
	l            *slog.Logger
	admitted     admitted
	usage        provider.Usage
	tee          *boundedBuffer
	ext          provider.ExtendedUsage
	ttftMs       int64
	hasTTFT      bool
	started      time.Time
	providerName string
	upstreamURL  string
	region       string
	resp         *http.Response
}

// realtimeEventBase assembles the analytics event both realtime settle
// paths stamp. The stream was live when a drain error struck, so even
// that settle carries Status 200 — the failure is in-band.
func realtimeEventBase(s realtimeSettle, eventType, errMsg string) eventBase {
	admitted := s.admitted
	base := eventBase{
		EventType:                  eventType,
		RequestID:                  admitted.RequestID,
		SessionID:                  admitted.SessionID,
		Payload:                    string(admitted.Body),
		UpstreamResponse:           s.tee.String(),
		OrgID:                      admitted.OrgID,
		TeamID:                     admitted.TeamID,
		AgentID:                    admitted.AgentID,
		UserID:                     admitted.UserID,
		APIKeyID:                   admitted.APIKeyID,
		SessionKeyID:               admitted.SessionKeyID,
		TaskID:                     admitted.TaskID,
		ModelRequested:             admitted.RequestedModel,
		ModelUsed:                  admitted.Info.ModelName,
		UpstreamURL:                s.upstreamURL,
		StatusCode:                 http.StatusOK,
		DurationMs:                 time.Since(s.started).Milliseconds(),
		TokensIn:                   s.usage.PromptTokens,
		TokensOut:                  s.usage.CompletionTokens,
		CacheReadTokens:            s.usage.CacheReadTokens,
		EstimatedCostUSD:           s.ext.EstimatedCostUSD,
		Endpoint:                   "realtime",
		UsageSource:                usageSourceOrNone(s.usage.Source),
		CostStatus:                 costStatus(false, s.usage.Source, s.ext.PriceKnown),
		Method:                     http.MethodPost,
		FirstTokenMs:               firstTokenMsOrZero(s.ttftMs, s.hasTTFT),
		InferenceRegion:            admitted.Info.Region,
		ModelOriginCountry:         admitted.Info.Provider,
		LogStorageRegion:           s.region,
		ProviderEntityJurisdiction: admitted.Info.Provider,
		Labels:                     labelsFrom(s.rctx),
	}
	if errMsg != "" {
		base.Error = errMsg
	}
	return base
}

// finishRealtimeDrainError settles an abnormally-ended session: the torn
// tail closes first so the error frame starts at an event boundary, and a
// held successful terminal is dropped — the client must NOT observe a
// success terminator for a session that ended abnormally (chat
// failDoneHold canon). The best-effort terminal error frame is contained
// when the client is already gone (stream.go writeSSEError parity);
// partial usage was consumed upstream, so it still bills (G3). The
// withheld event is logged loudly when the terminal facts commit fails
// (finishRequestLogged canon).
func (gw *gateway) finishRealtimeDrainError(s realtimeSettle, tail *ssePassthroughTail, hold *realtimeTerminalHold, term budget.Termination, drainErr error) {
	hold.drop()
	tail.complete()
	switch term {
	case budget.TerminationIdleTimeout:
		writeSSEError(s.w, apierrors.ErrorCodeAPI, "upstream stream idle timeout")
	default:
		writeSSEError(s.w, apierrors.ErrorCodeAPI, "realtime stream interrupted")
	}
	gw.accountUsage(s.rctx, s.w, usageRecord{
		orgID:         s.admitted.OrgID,
		taskID:        s.admitted.TaskID,
		sessionID:     s.admitted.SessionID,
		affinityModel: s.admitted.Info.ModelName,
		usage:         s.usage,
	})
	_, ferr := gw.finishRequest(s.rctx, requestFinish{
		base:        realtimeEventBase(s, "request.failed", "realtime stream ended abnormally: "+drainErr.Error()),
		info:        s.admitted.Info,
		resp:        s.resp,
		termination: term,
		eventNote:   true,
	}, nil)
	if ferr != nil {
		s.l.Error("terminal facts commit failed after errored stream; event withheld from consumer", "error", ferr)
	}
}

// finishRealtimeSession settles the healthy session: usage accounting
// with the computed cost, then the terminal request.completed facts and
// the reservation (NEXT-18c §5.3 Finalize — the termination class tells
// the consumer how the session ended). A failed terminal-facts commit
// discards the deferred successful suffix and closes the live stream
// with the accounting_commit_failed error frame — deliberately NO
// safe-retry language: the work already ran under this invocation
// identity (chat stream canon); the withheld event never reaches the
// consumer. On success the suffix is replayed after the durable write,
// byte-for-byte and in order.
func (gw *gateway) finishRealtimeSession(s realtimeSettle, hold *realtimeTerminalHold) {
	gw.accountUsage(s.rctx, s.w, usageRecord{
		orgID:         s.admitted.OrgID,
		taskID:        s.admitted.TaskID,
		sessionID:     s.admitted.SessionID,
		affinityModel: s.admitted.Info.ModelName,
		usage:         s.usage,
		costUSD:       s.ext.EstimatedCostUSD,
		priceKnown:    s.ext.PriceKnown,
	})
	_, ferr := gw.finishRequest(s.rctx, requestFinish{
		base:        realtimeEventBase(s, "request.completed", ""),
		info:        s.admitted.Info,
		resp:        s.resp,
		termination: budget.TerminationCompleted,
		eventNote:   true,
	}, nil)
	if ferr != nil {
		if !hold.armed {
			// Defensive only: an unarmed stream never dispatches under
			// Preview2 (the durable start fails closed), and nothing was
			// withheld — never append a terminal after a live stream.
			s.l.Error("terminal facts commit failed on unarmed stream", "error", ferr)
			return
		}
		// Central binding: SSE 200 headers are already committed, so the
		// client keeps the live prefix bytes; the deferred successful
		// suffix is discarded and the terminal accounting failure closes
		// the stream with the error frame carrying accounting_commit_failed.
		hold.drop()
		s.l.Error("terminal facts commit failed after streamed dispatch", "error", ferr)
		writeSSEErrorWithCode(s.w, apierrors.ErrorCodeAPI, accountingCommitFailedCode,
			"stream completed but its durable usage record could not be committed; NOT safe to retry — support reconciles the charge")
		return
	}
	// Facts committed: replay the deferred suffix now — the healthy legal
	// stream is delivered byte-for-byte and in order.
	hold.release()
	if hold.replayErr != nil {
		s.l.Error("terminal hold suffix replay failed after committed facts", "error", hold.replayErr)
	}
}

// realtimeRelay pipes the upstream SSE session to the client byte-honestly:
// raw chunks feed the side parser (last usage-bearing event for actual
// billing, D3 — usage is read-based and stays truthful even after the
// client disconnects) and the bounded analytics tee unchanged, while
// client writes are frame-batched — a consumer decodes an event only
// once its blank separator has arrived, so lines of an unterminated
// frame are held back with bounded memory. On an upstream break — and
// at clean EOF, which is not a drain failure — the held frame is
// dispatched only when the end aligned to a line boundary (no
// unterminated partial followed it) and it is a decodable event missing
// just its separator; the salvaged frame is closed with a CRLF blank
// separator — valid after an LF, CRLF or lone-CR last line alike — and
// followed by the usage parser's Flush, so the client stream and the
// settlement see the same terminal event. When the frame is dropped the
// parser is not flushed: a torn event is never billed. The
// unterminated trailing line is dropped either way, as it can never
// become an event. After a failed client write no further bytes are
// written and no further provider bytes are pulled — a streaming upstream
// on the live connection would keep doing paid work for a client that is
// gone; the usage already covers every byte read. The returned terminal
// hold may still carry the session's last successful terminal (response.done
// status completed): the caller releases it after the terminal facts commit,
// or drops it on failure — nothing further is read from the provider either
// way. Returns the parsed usage, the tee, the hold, the drain error (nil on
// clean EOF; a write failure settles as a client cancel) and its Finalize
// termination class (§5.3).
func (gw *gateway) realtimeRelay(rctx context.Context, w http.ResponseWriter, flusher http.Flusher, body io.Reader, cancelStream context.CancelFunc) (usage provider.Usage, tee *boundedBuffer, term budget.Termination, hold *realtimeTerminalHold, drainErr error) {
	var capture boundedBuffer
	tee = &capture
	var idle *idleReader
	reader := body
	if gw.streamIdleTimeout > 0 {
		idle = newIdleReader(body, gw.streamIdleTimeout, cancelStream)
		defer idle.Stop()
		reader = idle
	}
	term = budget.TerminationUpstreamErr
	var relayed int64
	buf := make([]byte, 32*1024)
	sink := newRealtimeRelaySink(w, flusher)
	// Central binding (Preview2 durable accounting, chat [DONE] hold canon):
	// an admitted invocation holds the session's last successful terminal —
	// response.done with response.status completed — until the caller's
	// terminal facts commit succeeds. Unarmed streams (no admission) pass
	// straight through.
	sink.hold.armed = gw.realtimeHoldArmed(rctx)
	for {
		n, rerr := reader.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			relayed += int64(n)
			if relayed > realtimeStreamLimit {
				// Never truncate an SSE stream mid-event: the relay aborts
				// as an upstream error at the cap.
				return sink.usage, tee, budget.TerminationUpstreamErr, sink.hold, errRealtimeStreamTooLarge{}
			}
			_, _ = capture.Write(chunk)
			if lerr := sink.feedChunk(chunk); lerr != nil {
				term, drainErr = sink.lineAbortResult(lerr)
				return sink.usage, tee, term, sink.hold, drainErr
			}
			if sink.lines.Pending() > apiformat.SSEStreamLineLimit {
				// An unterminated line grew past the buffering limit: the
				// relay aborts as an upstream error (bounded memory).
				term, drainErr = sink.lineAbortResult(errRealtimeLineTooLarge{})
				return sink.usage, tee, term, sink.hold, drainErr
			}
		}
		if sink.werr != nil {
			// The client write failed: stop pulling provider bytes — a
			// streaming upstream on the live connection would keep doing
			// paid work for a client that is gone. The usage parser was
			// fed from every byte this chunk carried, so the usage
			// already covers what was paid for.
			return sink.usage, tee, budget.TerminationClientCancel, sink.hold, sink.werr
		}
		if rerr != nil {
			// Clean EOF or a broken upstream read: the tail settles with
			// the same boundary-aligned salvage rule, a recorded write
			// failure settles as a cancel, and a live client stream gets
			// the read error and its termination class.
			term, drainErr = sink.settleEnd(rctx, idle, rerr)
			return sink.usage, tee, term, sink.hold, drainErr
		}
	}
}

// realtimeBreakTerm classifies a broken upstream read: an idle-timeout
// firing outranks a client cancellation, and anything else is an
// upstream error.
func realtimeBreakTerm(rctx context.Context, idle *idleReader) budget.Termination {
	switch {
	case idle != nil && idle.Fired():
		return budget.TerminationIdleTimeout
	case rctx.Err() != nil:
		return budget.TerminationClientCancel
	}
	return budget.TerminationUpstreamErr
}

// newRealtimeRelaySink wires a sink's client write path: a write stops for
// good at the first failure (the error latches; no further provider bytes
// are pulled), every delivered unit flushes, and the terminal hold rides
// the same writer so a replayed suffix records failures and flushes
// identically.
func newRealtimeRelaySink(w http.ResponseWriter, flusher http.Flusher) *realtimeRelaySink {
	s := &realtimeRelaySink{}
	s.write = func(blob []byte) {
		if len(blob) == 0 || s.werr != nil {
			return
		}
		if _, e := w.Write(blob); e != nil {
			s.werr = e // first client-write failure; writes stop and no further provider bytes are pulled
			return
		}
		flusher.Flush()
	}
	s.hold = &realtimeTerminalHold{write: s.write}
	return s
}

// lineAbortResult ends the drain for a line-processing error: an oversized
// line/frame and a spool exhaustion are upstream aborts; any other
// error is a failed client write — the client walked away
// mid-session, and the consumed prefix is billed by the caller (G3
// cancel-settle parity).
func (s *realtimeRelaySink) lineAbortResult(lerr error) (budget.Termination, error) {
	abortTerm := budget.TerminationClientCancel
	var tooLarge errRealtimeLineTooLarge
	var holdIO errRealtimeHoldIO
	if errors.As(lerr, &tooLarge) || errors.As(lerr, &holdIO) {
		// Bounded memory: the relay aborts as an upstream error, and a
		// spool exhaustion happened BEFORE any suffix byte was
		// delivered — no successful terminal was seen, so the drain
		// error path stays terminal-safe.
		abortTerm = budget.TerminationUpstreamErr
	}
	return abortTerm, lerr
}

// settleEnd finishes the relay at the upstream's end. Clean EOF is not a
// drain failure; a broken read gets the same boundary-aligned salvage as
// EOF — the closed frame keeps the client stream and the settlement on
// the same event — and then returns the read error with its Finalize
// termination class (§5.3). A settle/line error classifies through
// lineAbortResult; a recorded client write failure still settles as a
// cancel — the client never saw the stream through.
func (s *realtimeRelaySink) settleEnd(rctx context.Context, idle *idleReader, rerr error) (budget.Termination, error) {
	if lerr := s.settleTail(); lerr != nil {
		return s.lineAbortResult(lerr)
	}
	if s.werr != nil {
		return budget.TerminationClientCancel, s.werr
	}
	if errors.Is(rerr, io.EOF) {
		return budget.TerminationCompleted, nil
	}
	return realtimeBreakTerm(rctx, idle), rerr
}

// realtimeHoldArmed reports whether the request context carries an
// admission-backed invocation identity: only such streams hold their
// successful terminal for the caller's terminal facts commit.
func (gw *gateway) realtimeHoldArmed(rctx context.Context) bool {
	id := invocationIdentityFrom(rctx)
	return gw.invocations != nil && id != nil && id.Admitted()
}

// realtimeRelaySink owns the per-session framing state of one realtime
// relay: whole frames route through the terminal hold (live before the
// first completed response.done, spooled after), the side parser sees
// every byte read (last usage-bearing event wins, D3), and the first
// client-write failure latches so no further provider bytes are pulled.
type realtimeRelaySink struct {
	write  func([]byte)          // frame-batched client write
	werr   error                 // first client-write failure
	hold   *realtimeTerminalHold // session suffix spool
	parser apiformat.SSEParser   // usage extraction
	lines  apiformat.SSELineSplitter
	frames apiformat.SSEFrameBuffer
	usage  provider.Usage
}

// feedChunk parses one raw chunk for usage and routes its complete
// lines through the frame sink.
func (s *realtimeRelaySink) feedChunk(chunk []byte) error {
	for _, ev := range s.parser.Feed(chunk) {
		if u, ok := realtimeUsageFromEvent([]byte(ev.Data)); ok {
			s.usage = u // last usage-bearing event wins (carryStreamUsage parity)
		}
	}
	// Frame-batch the client writes: only whole frames (through their
	// blank separator) leave the relay while the upstream is still
	// running.
	for _, line := range s.lines.Feed(chunk) {
		if lerr := s.processLine(line); lerr != nil {
			return lerr
		}
	}
	return nil
}

// processLine routes one complete upstream line: keepalive comments ride
// no event and pass through immediately when the suffix has not started
// (downstream idle timeouts stay reset; the frame buffer never grows on
// them; inside a deferred suffix they spool like any other byte), field
// lines batch into the frame buffer, and a blank separator flushes the
// whole frame through the hold — live before the first successful
// terminal, spooled after it.
func (s *realtimeRelaySink) processLine(line []byte) error {
	if apiformat.SSECommentLine(line) {
		return s.hold.admit(line)
	}
	blank, overflow := s.frames.Add(line, apiformat.SSEStreamLineLimit)
	if overflow {
		// An unterminated frame grew past the buffering limit: the relay
		// aborts as an upstream error (bounded memory).
		return errRealtimeLineTooLarge{}
	}
	if blank {
		return s.hold.admit(append(s.frames.Take(), line...))
	}
	return nil
}

// settleTail ends the framing at a stream break or clean EOF: the
// splitter's trailing lone CR resolves into a complete line (the CR was
// received — it terminates its line under the grammar whether or not a
// further LF ever arrives); the held frame is salvaged only when no
// unterminated partial followed it and it is a decodable event missing
// just its separator. The salvaged frame is closed with a CRLF blank
// separator — valid after an LF, CRLF or lone-CR last line alike — and
// followed by the usage parser's Flush, so the settlement bills what the
// upstream actually sent; a dropped frame leaves the parser unflushed —
// a torn event is never billed.
func (s *realtimeRelaySink) settleTail() error {
	flushLines, partial := s.lines.Flush()
	for _, line := range flushLines {
		if lerr := s.processLine(line); lerr != nil {
			return lerr
		}
	}
	if len(partial) > 0 {
		return nil
	}
	if s.frames.Salvageable() {
		if lerr := s.hold.admit(append(s.frames.Take(), '\r', '\n')); lerr != nil {
			return lerr
		}
	} else if len(flushLines) == 0 || string(flushLines[0]) != "\r" {
		return nil
	}
	// A final lone CR can complete the blank separator at EOF. The side
	// parser must see that boundary even when no frame needs salvage.
	for _, ev := range s.parser.Flush() {
		if u, ok := realtimeUsageFromEvent([]byte(ev.Data)); ok {
			s.usage = u
		}
	}
	return nil
}

// errRealtimeStreamTooLarge marks a relay aborted at realtimeStreamLimit.
type errRealtimeStreamTooLarge struct{}

func (errRealtimeStreamTooLarge) Error() string {
	return "upstream stream exceeds the realtime size limit"
}

// errRealtimeLineTooLarge marks a relay aborted because a single
// unterminated SSE line or frame grew past apiformat.SSEStreamLineLimit.
type errRealtimeLineTooLarge struct{}

func (errRealtimeLineTooLarge) Error() string {
	return "upstream realtime SSE line or frame exceeds the buffering limit"
}

// realtimeUsageFromEvent extracts usage from one SSE event data payload: a
// top-level usage block (chat-style frames) or the nested response.usage
// (realtime response.done). ok is false when the payload carries none.
func realtimeUsageFromEvent(data []byte) (provider.Usage, bool) {
	var doc struct {
		Usage    json.RawMessage `json:"usage"`
		Response *struct {
			Usage json.RawMessage `json:"usage"`
		} `json:"response"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return provider.Usage{}, false
	}
	raw := doc.Usage
	if len(raw) == 0 && doc.Response != nil {
		raw = doc.Response.Usage
	}
	if len(raw) == 0 {
		return provider.Usage{}, false
	}
	wrapper := []byte(`{"usage":` + string(raw) + `}`)
	return tokenUsageBlock(wrapper)
}

// realtimeTerminalHoldLimit caps the RAM the terminal hold spends on the
// deferred suffix; beyond it the suffix spills to a temporary file (disk
// usage is bounded by realtimeStreamLimit, which caps the whole session).
const realtimeTerminalHoldLimit = 1 << 20

// realtimeTerminalHold defers the client-facing delivery of the session's
// ENTIRE successful suffix — everything from the first response.done whose
// response.status is completed onward, including any further protocol
// events (multiple responses, trailing metadata) — until the caller's
// terminal facts commit succeeds (chat [DONE] hold canon generalized to the
// session shape): a committed stream replays the suffix byte-for-byte and
// in order, so a healthy legal stream is delivered unaltered; a failed
// commit discards the suffix and closes the stream with the
// accounting_commit_failed error frame — the client never observes a
// successful terminal (nor anything after it) for an unaccounted session.
//
// Bounded by construction: traffic BEFORE the first successful terminal
// streams live and is never buffered (the common one-response session
// defers only its terminal and nothing else); the deferred suffix lives in
// a 1 MiB RAM window and spills to one temporary file when larger, and the
// total relay is already capped at realtimeStreamLimit. Spool exhaustion
// (I/O error) fails CLEANLY: the relay aborts as an upstream error before
// any suffix byte was delivered, so the failure paths stay terminal-safe.
// Keepalive comments in the live prefix pass through as before; comments in
// the suffix are part of its bytes and replay with it.
//
// Single-owner: the relay goroutine admits units; the endpoint goroutine
// that called the relay then calls release or drop exactly once, and the
// endpoint's deferred cleanup guarantees the spill file is removed on every
// exit including cancellation.
type realtimeTerminalHold struct {
	write     func([]byte) // the relay's writeBlob: records write errors, flushes
	armed     bool         // admission-backed stream: hold is active
	suffixing bool         // first successful terminal seen: defer everything after
	ram       []byte       // deferred suffix bytes while ≤ realtimeTerminalHoldLimit
	spill     *os.File     // suffix tail once the RAM window overflowed
	done      bool         // release or drop already ran
	replayErr error        // spill read failure during release (facts committed; logged by the endpoint)
}

// admit routes one complete relayed unit (a whole frame including its
// separator, or a keepalive comment). Pre-suffix units stream live; the
// first successful terminal and every unit after it are spooled. Spool I/O
// failure returns a clean abort error — no suffix byte was delivered.
func (h *realtimeTerminalHold) admit(unit []byte) error {
	if !h.armed {
		h.write(unit)
		return nil
	}
	if !h.suffixing && !realtimeCompletedResponseDone(unit) {
		h.write(unit)
		return nil
	}
	h.suffixing = true
	if h.spill != nil {
		if _, err := h.spill.Write(unit); err != nil {
			return errRealtimeHoldIO{err}
		}
		return nil
	}
	if len(h.ram)+len(unit) > realtimeTerminalHoldLimit {
		f, err := os.CreateTemp("", "yb-realtime-hold-*")
		if err != nil {
			return errRealtimeHoldIO{err}
		}
		if _, err := f.Write(h.ram); err != nil {
			_ = f.Close()
			_ = os.Remove(f.Name())
			return errRealtimeHoldIO{err}
		}
		if _, err := f.Write(unit); err != nil {
			_ = f.Close()
			_ = os.Remove(f.Name())
			return errRealtimeHoldIO{err}
		}
		h.spill = f
		h.ram = nil
		return nil
	}
	h.ram = append(h.ram, unit...)
	return nil
}

// release replays the deferred suffix after the terminal facts committed —
// byte-for-byte, in order, through the same writer (which still records
// write failures and flushes per unit). Nil-receiver safe; idempotent.
func (h *realtimeTerminalHold) release() {
	if h == nil || h.done {
		return
	}
	h.done = true
	defer h.cleanup()
	if h.spill != nil {
		if _, err := h.spill.Seek(0, io.SeekStart); err != nil {
			h.replayErr = err
			return
		}
		buf := make([]byte, 32*1024)
		for {
			n, err := h.spill.Read(buf)
			if n > 0 {
				h.write(buf[:n])
			}
			if err == io.EOF {
				return
			}
			if err != nil {
				// The durable facts committed; a spill read failure must
				// not silently truncate the client stream — surface it for
				// the endpoint to log loudly.
				h.replayErr = err
				return
			}
		}
	}
	h.write(h.ram)
	h.ram = nil
}

// drop discards the deferred suffix — the facts did not commit; the caller
// closes the stream with the accounting error frame instead. Nil-receiver
// safe; idempotent.
func (h *realtimeTerminalHold) drop() {
	if h == nil || h.done {
		return
	}
	h.done = true
	h.ram = nil
	h.cleanup()
}

// cleanup closes and removes the spill file; safe when none exists and
// idempotent (called from release/drop and the endpoint's defer).
func (h *realtimeTerminalHold) cleanup() {
	if h == nil || h.spill == nil {
		return
	}
	_ = h.spill.Close()
	_ = os.Remove(h.spill.Name())
	h.spill = nil
}

// errRealtimeHoldIO marks the terminal hold's spool failing (RAM window
// overflow with no spill file creatable/writable, or a spill write error):
// the relay aborts cleanly with no suffix byte delivered.
type errRealtimeHoldIO struct{ err error }

func (e errRealtimeHoldIO) Error() string {
	return "realtime terminal hold spool failed: " + e.err.Error()
}

func (e errRealtimeHoldIO) Unwrap() error { return e.err }

// realtimeCompletedResponseDone reports whether one complete SSE frame
// (including its separator) is a response.done whose response.status is
// completed. The frame is bounded by apiformat.SSEStreamLineLimit upstream;
// failure/incomplete response.done frames are not successful terminals and
// are never held.
func realtimeCompletedResponseDone(frame []byte) bool {
	events := apiformat.ParseSSE(frame)
	if len(events) != 1 || strings.TrimSpace(events[0].Event) != "response.done" {
		return false
	}
	var doc struct {
		Response *struct {
			Status string `json:"status"`
		} `json:"response"`
	}
	if err := json.Unmarshal([]byte(events[0].Data), &doc); err != nil || doc.Response == nil {
		return false
	}
	return doc.Response.Status == "completed"
}

// isWebSocketUpgrade reports whether the client asked for a WebSocket
// upgrade (D4: refused, realtime is SSE-only).
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

// firstTokenMsOrZero stamps the time-to-first-byte sample when observed.
func firstTokenMsOrZero(ms int64, ok bool) int64 {
	if !ok {
		return 0
	}
	return ms
}
