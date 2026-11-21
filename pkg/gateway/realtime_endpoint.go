package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
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
func (gw *gateway) realtime(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	l := logctx.From(r.Context(), gw.log)
	// D4 (ratified SSE-only): a WebSocket upgrade is explicitly refused
	// before any admission or upstream work (upstream call count stays 0).
	if isWebSocketUpgrade(r) {
		apierrors.WriteWithCode(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
			"websocket is not supported; realtime is SSE-only", apierrors.CodeUnsupportedFeature)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		// N3 (audio parity): the client walked away mid-body — the
		// response target is gone; writing the envelope would race the
		// server's conn teardown.
		if r.Context().Err() != nil {
			return
		}
		if httpmw.IsMaxBytesError(err) {
			apierrors.Write(w, http.StatusRequestEntityTooLarge, apierrors.ErrorCodeInvalidRequest, "request body too large")
			return
		}
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "request body too large or malformed")
		return
	}
	var req struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "malformed JSON: "+err.Error())
		return
	}
	if req.Model == "" {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "model is required")
		return
	}

	admitted, ok := gw.admit(w, r, admitInput{
		Endpoint: "realtime",
		Model:    req.Model,
		Body:     body,
		NoRemap:  true,
	})
	if !ok {
		return
	}
	if !openAICompatProvider(admitted.Info.Provider) {
		apierrors.WriteWithCode(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
			"realtime is not supported for this provider", "realtime_not_supported_for_provider")
		return
	}
	if gw.pool == nil {
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "upstream is not configured")
		return
	}

	// NEXT-18c (ADR-0001 §5.1) + ratified D3: reservation rides the input
	// pre-estimate (chat-shaped bound — realtime sessions generate output,
	// so the org default out cap applies; MaxTokens stays nil). The minted
	// invocation identity rides the same context so the confirmed start and
	// the terminal facts bind to this request's admission row.
	rctx := withInvocationIdentity(r.Context(), admitted.Invocation)
	gate, ok := gw.reservationPlan(w, r, "realtime",
		gw.reservationRequest(rctx, admitted.OrgID, admitted.TeamID, admitted.AgentID, admitted.SessionKeyID,
			admitted.Info, admitted.Body, nil, false))
	if !ok {
		return
	}
	rctx = withReservationGate(rctx, gate)
	if !gate.reserve(rctx) {
		return
	}

	timeout := admitted.Info.UpstreamTimeout
	if timeout <= 0 {
		timeout = realtimeDefaultTimeout
	}
	// The stream gets its own cancel so the idle watchdog can abort a
	// stalled upstream without touching the parent request context; the
	// parent deadline (the session ceiling) still applies (stream.go
	// parity).
	streamCtx, cancelStream := context.WithTimeout(rctx, timeout)
	defer cancelStream()

	providerName := admitted.Info.Provider
	if providerName == "" {
		providerName = "openai"
	}
	apiKey := admitted.Info.UpstreamAPIKey
	if apiKey == "" {
		apiKey = gw.getUpstreamAPIKey()
	}
	upstreamURL := gw.upstreamURL(admitted.Info)
	client, err := gw.pool.Get(upstreamURL, providerName)
	if err != nil {
		l.Warn("upstream client unavailable", "provider", providerName, "error", err.Error())
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "failed to initialise upstream client")
		return
	}
	upstreamBody := upstream.OverrideModelRaw(admitted.Body, admitted.Info.ModelName)
	// Stream capability precedes the durable start: a writer that cannot
	// flush must fail BEFORE the admission commits and before any paid
	// dispatch — the old post-dispatch 501 both wasted paid work and
	// stranded the admitted row without terminal facts (chat
	// streamRun.admit canon — fail before anything durable, with zero
	// provider arrivals).
	if _, ok := w.(http.Flusher); !ok {
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		apierrors.Write(w, http.StatusNotImplemented, apierrors.ErrorCodeAPI, "streaming not supported by server")
		return
	}
	// Preview2 durable accounting: the confirmed start commits immediately
	// BEFORE the first paid provider dispatch — after every fallible local
	// setup step above (pool wiring, model remap, stream capability), so a
	// local failure never strands a durable admission for a request that
	// never dispatched. The kind binds to the only transport this surface
	// dispatches (SSE). Fail closed: an unwritten start (write error,
	// timeout or lost ACK — outcome unknown) refuses the request with ZERO
	// provider arrivals under the history_unavailable envelope, and the
	// escrow is released. The structured 503 precedes the SSE commit point
	// below, so it can never land after client success headers.
	if err := gw.confirmPaidInvocation(rctx, invocationKindStream); err != nil {
		gate.finalizeNoEvent(budget.TerminationPolicyDenied)
		l.Warn("refusing paid dispatch: durable start unwritten", "error", err)
		writeInvocationStartRefusal(w, err)
		return
	}
	resp, err := client.Do(streamCtx, "/v1/realtime", upstreamBody, apiKey, true, nil)
	if err != nil {
		closeUpstream(l, resp)
		gate.finalizeNoEvent(mediaTermination(rctx))
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "upstream request failed")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		status, errType := apierrors.MapUpstreamStatus(resp.StatusCode)
		apierrors.Write(w, status, errType, "upstream request failed")
		return
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
	if drainErr != nil {
		// Best-effort terminal error frame (contained when the client is
		// already gone — stream.go writeSSEError parity); partial usage was
		// consumed upstream, so it still bills (G3). The torn tail closes
		// first so the error frame starts at an event boundary, and a held
		// successful terminal is dropped — the client must NOT observe a
		// success terminator for a session that ended abnormally (chat
		// failDoneHold canon).
		hold.drop()
		tail.complete()
		switch term {
		case budget.TerminationIdleTimeout:
			writeSSEError(w, apierrors.ErrorCodeAPI, "upstream stream idle timeout")
		default:
			writeSSEError(w, apierrors.ErrorCodeAPI, "realtime stream interrupted")
		}
		gw.accountUsage(rctx, w, usageRecord{
			orgID:         admitted.OrgID,
			taskID:        admitted.TaskID,
			sessionID:     admitted.SessionID,
			affinityModel: admitted.Info.ModelName,
			usage:         usage,
		})
		_, ferr := gw.finishRequest(rctx, requestFinish{
			base: eventBase{
				EventType:                  "request.failed",
				RequestID:                  admitted.RequestID,
				SessionID:                  admitted.SessionID,
				Payload:                    string(admitted.Body),
				UpstreamResponse:           tee.String(),
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
				StatusCode:                 http.StatusOK, // the stream was live; the failure is in-band
				DurationMs:                 time.Since(started).Milliseconds(),
				TokensIn:                   usage.PromptTokens,
				TokensOut:                  usage.CompletionTokens,
				CacheReadTokens:            usage.CacheReadTokens,
				EstimatedCostUSD:           ext.EstimatedCostUSD,
				Endpoint:                   "realtime",
				UsageSource:                usageSourceOrNone(usage.Source),
				CostStatus:                 costStatus(false, usage.Source, ext.PriceKnown),
				Method:                     http.MethodPost,
				Error:                      "realtime stream ended abnormally: " + drainErr.Error(),
				FirstTokenMs:               firstTokenMsOrZero(ttftMs, hasTTFT),
				InferenceRegion:            admitted.Info.Region,
				ModelOriginCountry:         admitted.Info.Provider,
				LogStorageRegion:           gw.cfg.Region,
				ProviderEntityJurisdiction: admitted.Info.Provider,
				Labels:                     labelsFrom(rctx),
			},
			info:        admitted.Info,
			resp:        resp,
			termination: term,
			eventNote:   true,
		}, nil)
		if ferr != nil {
			// The client's stream already ended in the SSE error frame; the
			// withheld event is logged loudly (finishRequestLogged canon).
			l.Error("terminal facts commit failed after errored stream; event withheld from consumer", "error", ferr)
		}
		return
	}

	gw.accountUsage(rctx, w, usageRecord{
		orgID:         admitted.OrgID,
		taskID:        admitted.TaskID,
		sessionID:     admitted.SessionID,
		affinityModel: admitted.Info.ModelName,
		usage:         usage,
		costUSD:       ext.EstimatedCostUSD,
		priceKnown:    ext.PriceKnown,
	})
	_, ferr := gw.finishRequest(rctx, requestFinish{
		base: eventBase{
			EventType:                  "request.completed",
			RequestID:                  admitted.RequestID,
			SessionID:                  admitted.SessionID,
			Payload:                    string(admitted.Body),
			UpstreamResponse:           tee.String(),
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
			StatusCode:                 http.StatusOK,
			DurationMs:                 time.Since(started).Milliseconds(),
			TokensIn:                   usage.PromptTokens,
			TokensOut:                  usage.CompletionTokens,
			CacheReadTokens:            usage.CacheReadTokens,
			EstimatedCostUSD:           ext.EstimatedCostUSD,
			Endpoint:                   "realtime",
			UsageSource:                usageSourceOrNone(usage.Source),
			CostStatus:                 costStatus(false, usage.Source, ext.PriceKnown),
			Method:                     http.MethodPost,
			FirstTokenMs:               firstTokenMsOrZero(ttftMs, hasTTFT),
			InferenceRegion:            admitted.Info.Region,
			ModelOriginCountry:         admitted.Info.Provider,
			LogStorageRegion:           gw.cfg.Region,
			ProviderEntityJurisdiction: admitted.Info.Provider,
			Labels:                     labelsFrom(rctx),
		},
		info: admitted.Info,
		resp: resp,
		// NEXT-18c: settle the reservation with the actual spend (§5.3
		// Finalize); the termination class tells the consumer how the
		// session ended.
		termination: budget.TerminationCompleted,
		eventNote:   true,
	}, nil)
	if ferr != nil {
		if !hold.armed {
			// Defensive only: an unarmed stream never dispatches under
			// Preview2 (the durable start fails closed), and nothing was
			// withheld — never append a terminal after a live stream.
			l.Error("terminal facts commit failed on unarmed stream", "error", ferr)
			return
		}
		// Central binding: SSE 200 headers are already committed, so the
		// client keeps the live prefix bytes; the deferred successful
		// suffix is discarded and the terminal accounting failure closes
		// the stream with the error frame carrying accounting_commit_failed
		// — deliberately NO safe-retry language: the work already ran under
		// this invocation identity (chat stream canon). The withheld event
		// never reaches the consumer.
		hold.drop()
		l.Error("terminal facts commit failed after streamed dispatch", "error", ferr)
		writeSSEErrorWithCode(w, apierrors.ErrorCodeAPI, accountingCommitFailedCode,
			"stream completed but its durable usage record could not be committed; NOT safe to retry — support reconciles the charge")
		return
	}
	// Facts committed: replay the deferred suffix now — the healthy legal
	// stream is delivered byte-for-byte and in order.
	hold.release()
	if hold.replayErr != nil {
		l.Error("terminal hold suffix replay failed after committed facts", "error", hold.replayErr)
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
	sink := &realtimeRelaySink{}
	sink.write = func(blob []byte) {
		if len(blob) == 0 || sink.werr != nil {
			return
		}
		if _, e := w.Write(blob); e != nil {
			sink.werr = e // first client-write failure; writes stop and no further provider bytes are pulled
			return
		}
		flusher.Flush()
	}
	// Central binding (Preview2 durable accounting, chat [DONE] hold canon):
	// an admitted invocation holds the session's last successful terminal —
	// response.done with response.status completed — until the caller's
	// terminal facts commit succeeds. Unarmed streams (no admission) pass
	// straight through.
	sink.hold = &realtimeTerminalHold{
		write: sink.write,
		armed: gw.invocations != nil && invocationIdentityFrom(rctx) != nil && invocationIdentityFrom(rctx).Admitted(),
	}
	// lineAbort ends the drain for a line-processing error: an oversized
	// line/frame and a spool exhaustion are upstream aborts; any other
	// error is a failed client write — the client walked away
	// mid-session, and the consumed prefix is billed by the caller (G3
	// cancel-settle parity).
	lineAbort := func(lerr error) (provider.Usage, *boundedBuffer, budget.Termination, *realtimeTerminalHold, error) {
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
		return sink.usage, tee, abortTerm, sink.hold, lerr
	}
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
				return lineAbort(lerr)
			}
			if sink.lines.Pending() > apiformat.SSEStreamLineLimit {
				// An unterminated line grew past the buffering limit: the
				// relay aborts as an upstream error (bounded memory).
				return sink.usage, tee, budget.TerminationUpstreamErr, sink.hold, errRealtimeLineTooLarge{}
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
		if rerr == io.EOF {
			// Clean end: EOF is not a drain failure; the tail settles with
			// the same boundary-aligned salvage rule. A recorded client
			// write failure still settles as a cancel — the client never
			// saw the stream through.
			if lerr := sink.settleTail(); lerr != nil {
				return lineAbort(lerr)
			}
			if sink.werr != nil {
				return sink.usage, tee, budget.TerminationClientCancel, sink.hold, sink.werr
			}
			return sink.usage, tee, budget.TerminationCompleted, sink.hold, nil
		}
		if rerr != nil {
			// Broken upstream: same boundary-aligned salvage as EOF — the
			// closed frame keeps the client stream and the settlement on
			// the same event — then the termination class and the read
			// error return.
			if lerr := sink.settleTail(); lerr != nil {
				return lineAbort(lerr)
			}
			if sink.werr != nil {
				return sink.usage, tee, budget.TerminationClientCancel, sink.hold, sink.werr
			}
			return sink.usage, tee, realtimeBreakTerm(rctx, idle), sink.hold, rerr
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
	if len(partial) > 0 || !s.frames.Salvageable() {
		return nil
	}
	if lerr := s.hold.admit(append(s.frames.Take(), '\r', '\n')); lerr != nil {
		return lerr
	}
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
	var event string
	var data []byte
	for _, line := range bytes.Split(frame, []byte("\n")) {
		line = bytes.TrimSuffix(line, []byte("\r"))
		if after, ok := bytes.CutPrefix(line, []byte("event:")); ok {
			event = strings.TrimSpace(string(after))
			continue
		}
		if after, ok := bytes.CutPrefix(line, []byte("data:")); ok {
			if len(data) > 0 {
				data = append(data, '\n')
			}
			data = append(data, bytes.TrimPrefix(after, []byte(" "))...)
		}
	}
	if event != "response.done" || len(data) == 0 {
		return false
	}
	var doc struct {
		Response *struct {
			Status string `json:"status"`
		} `json:"response"`
	}
	if err := json.Unmarshal(data, &doc); err != nil || doc.Response == nil {
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
