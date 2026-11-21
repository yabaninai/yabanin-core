package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/reireirei/yabanin/pkg/apiformat"
	"github.com/reireirei/yabanin/pkg/budget"
	apierrors "github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/logctx"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/upstream"
)

const responsesBodyLimit = 8 << 20

func (gw *gateway) responsesNative(w http.ResponseWriter, r *http.Request, body []byte) {
	started := time.Now()
	l := logctx.From(r.Context(), gw.log)
	var probe struct {
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
	}
	_ = json.Unmarshal(body, &probe)
	admitted, ok := gw.admit(w, r, admitInput{
		Endpoint: "responses.native",
		Model:    probe.Model,
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
	guarded, policyEvent, ok := gw.policyPreUpstream(w, r, "responses", admitted.Info.ModelName, admitted.Info.Provider, admitted.Body)
	if !ok {
		return
	}
	admitted.Body = guarded
	// Serving provider of the single-candidate client pool (hoisted for the
	prov := admitted.Info.Provider
	if prov == "" {
		prov = "openai"
	}
	// hint foreign to the serving provider refuses here, before any
	// reservation.
	if !gw.enforceSingularRouteHint(w, r, prov) {
		return
	}

	// NEXT-18c (ADR-0001 §5.1): pre-check + reserve before the upstream
	// call (no cache branch on this pipeline). The gate rides the
	// request-derived context for the finishers below.
	rctx := withPolicyEvent(r.Context(), policyEvent)
	rctx = withInvocationIdentity(rctx, admitted.Invocation)
	gate, ok := gw.reservationPlan(w, r, "responses.native",
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
	client, err := gw.pool.Get(upstreamURL, prov)
	if err != nil {
		l.Warn("upstream client unavailable", "provider", prov, "error", err.Error())
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "failed to initialise upstream client")
		return
	}
	upstreamBody := upstream.OverrideModelRaw(admitted.Body, admitted.Info.ModelName)
	// Preview2 durable accounting: the confirmed start commits immediately
	// BEFORE the first paid provider dispatch — after every fallible local
	// setup step above (pool wiring, model remap), so a local failure never
	// strands a durable admission for a request that never dispatched. One
	// admission per request; the JSON and stream branches below share it
	// and the kind binds to the transport actually dispatched. Fail closed:
	// an unwritten start (write error, timeout or lost ACK — outcome
	// unknown) refuses the request with ZERO provider arrivals under the
	// history_unavailable envelope, and the escrow is released.
	if err := gw.confirmPaidInvocation(rctx, invocationKindForChat(probe.Stream)); err != nil {
		gate.finalizeNoEvent(budget.TerminationPolicyDenied)
		l.Warn("refusing paid dispatch: durable start unwritten", "error", err)
		writeInvocationStartRefusal(w, err)
		return
	}
	if probe.Stream {
		// W-TIMEOUT: streams carry no whole-request deadline; the transport's
		// ResponseHeaderTimeout plus the idle watchdog below bound them.
		gw.responsesNativeStream(w, r, rctx, gate, admitted, client, upstreamBody, apiKey, upstreamURL, started)
		return
	}
	gw.responsesNativeJSON(w, r, rctx, gate, admitted, client, upstreamBody, apiKey, upstreamURL, started, l)
}

// responsesNativeJSON serves the non-streaming native /v1/responses
// request: one whole-request upstream roundtrip with timeout, usage and
// post-upstream policy applied to the buffered reply, durable settlement
// before the client sees a payable success, and the byte-identical
// forward.
func (gw *gateway) responsesNativeJSON(w http.ResponseWriter, r *http.Request, rctx context.Context, gate *reservationGate, admitted admitted, client *upstream.Client, upstreamBody []byte, apiKey, upstreamURL string, started time.Time, l *slog.Logger) {
	timeout := admitted.Info.UpstreamTimeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(rctx, timeout)
	defer cancel()
	resp, err := client.Do(ctx, "/v1/responses", upstreamBody, apiKey, false, nil)
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
	limited, err := io.ReadAll(io.LimitReader(resp.Body, responsesBodyLimit))
	if err != nil {
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "failed to read upstream response")
		return
	}
	if resp.StatusCode != http.StatusOK {
		if ferr := gw.finishResponsesNative(w, rctx, admitted, provider.Usage{}, upstreamURL, resp.StatusCode, started, resp, "request.failed", "upstream request failed", ""); ferr != nil {
			// The client envelope is already the upstream failure; the
			// withheld event is logged loudly (finishRequestLogged canon).
			l.Error("terminal facts commit failed; event withheld from consumer", "error", ferr)
		}
		copyResponsesPassthrough(w.Header(), resp.Header)
		if ct := resp.Header.Get("Content-Type"); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(limited)
		return
	}
	usage := parseResponsesUsage(limited)
	// OP-8: post-upstream policy hook. Usage was parsed from the ORIGINAL
	// body (the tokens were consumed); a mask replaces what the client and
	// the finisher see; a deny answers 400 instead of the upstream body.
	if gw.policyRuntime != nil {
		masked, postEvent, denied := gw.policyPostUpstream(r, "responses", admitted.Info.ModelName, admitted.Info.Provider, limited)
		if postEvent != "" {
			rctx = withPolicyEvent(rctx, appendPolicyEvents(policyEventFrom(rctx), postEvent))
		}
		if denied {
			if ferr := gw.finishResponsesNative(w, rctx, admitted, usage, upstreamURL, http.StatusBadRequest, started, resp, "request.failed", "response blocked by organization policy", ""); ferr != nil {
				l.Error("terminal facts commit failed; event withheld from consumer", "error", ferr)
			}
			apierrors.WriteWithCode(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
				"response blocked by organization policy", policyDenyErrorCode)
			return
		}
		limited = masked
	}
	if ferr := gw.finishResponsesNative(w, rctx, admitted, usage, upstreamURL, http.StatusOK, started, resp, "request.completed", "", ""); ferr != nil {
		// Central binding: usage was dispatched but its durable record did
		// not commit — the client must not see the upstream body as a
		// payable success (never a re-dispatch; support reconciles).
		writeTerminalAccountingFailure(w)
		return
	}
	// N03-P06-T02: same provider-derived transparency the OpenAI-compat
	// JSON path reports (finalizeChatJSON); before WriteHeader below.
	setPromptCacheHeader(w, usage)
	copyResponsesPassthrough(w.Header(), resp.Header)
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	} else {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(limited)
}

func (gw *gateway) responsesNativeStream(w http.ResponseWriter, r *http.Request, rctx context.Context, gate *reservationGate, admitted admitted, client *upstream.Client, upstreamBody []byte, apiKey, upstreamURL string, started time.Time) {
	l := logctx.From(r.Context(), gw.log)
	streamCtx, cancelStream := context.WithCancel(r.Context())
	defer cancelStream()
	resp, err := client.Do(streamCtx, "/v1/responses", upstreamBody, apiKey, true, nil)
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
		limited, readErr := io.ReadAll(io.LimitReader(resp.Body, responsesBodyLimit))
		if readErr != nil {
			gate.finalizeNoEvent(budget.TerminationUpstreamErr)
			apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "failed to read upstream response")
			return
		}
		if ferr := gw.finishResponsesNative(w, rctx, admitted, provider.Usage{}, upstreamURL, resp.StatusCode, started, resp, "request.failed", "upstream request failed", ""); ferr != nil {
			l.Error("terminal facts commit failed; event withheld from consumer", "error", ferr)
		}
		copyResponsesPassthrough(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(limited)
		return
	}
	copyResponsesPassthrough(w.Header(), resp.Header)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	body := io.Reader(resp.Body)
	var idle *idleReader
	if gw.streamIdleTimeout > 0 {
		idle = newIdleReader(resp.Body, gw.streamIdleTimeout, cancelStream)
		defer idle.Stop()
		body = idle
	}
	// The relay writes through the terminal hold into the tail tracker:
	// a torn last event is closed before the response.failed frame
	// composes (chat F2 canon) and the success terminal is ordered after
	// the terminal-facts commit (Preview2 central binding, the chat
	// drain's doneWatch canon).
	hold := gw.armNativeTerminalHold(w, rctx, nativeEventName, respNativeSuccessTerminals, respNativeFailureTerminals)
	tail := &ssePassthroughTail{w: hold}
	usage, terminal, relayErr := relayResponsesSSE(tail, body)
	// N03-P06-T02: SSE headers are already committed; the provider
	// prompt-cache outcome rides the HTTP trailer. Covers both ends: the
	// completed branch and the failure branch (the partial usage parsed
	// before the break is still the real upstream usage).
	setPromptCacheTrailer(w, usage)
	// A delivered terminal is authoritative: once the relay passed
	// response.completed/incomplete/failed downstream the stream ended on
	// the wire (a success terminal may still sit at the accounting seam
	// pending its facts commit) and the settlement follows that terminal
	// — a late transport error cannot retroactively fail a response that
	// was fully produced and delivered. Only a cut BEFORE any terminal is
	// a stream failure.
	if relayErr != nil && r.Context().Err() == nil && terminal == "" {
		gw.finishResponsesStreamDrainFailure(w, rctx, l, tail, admitted, usage, upstreamURL, started, resp, idle, relayErr)
		return
	}
	if terminal == "response.failed" {
		gw.finishResponsesStreamUpstreamFailure(w, rctx, l, admitted, usage, upstreamURL, started, resp)
		return
	}
	if ferr := gw.finishResponsesNative(w, rctx, admitted, usage, upstreamURL, http.StatusOK, started, resp, "request.completed", "", ""); ferr != nil {
		// SSE 200 headers are already committed: the client keeps the
		// stream, and the terminal accounting failure closes it with the
		// protocol-shaped frame carrying accounting_commit_failed (the
		// chat stream canon: NOT safe to retry — support reconciles
		// the charge). The withheld event never reaches the consumer;
		// when the relay already delivered response.failed the stream
		// ended client-side and the commit failure is log-only — never a
		// second terminal.
		l.Error("terminal facts commit failed after streamed dispatch", "error", ferr)
		hold.fail()
		if !hold.failureSeen() {
			writeResponsesStreamAccountingFailure(w)
		}
		return
	}
	hold.release()
}

// finishResponsesStreamDrainFailure settles a native /v1/responses stream
// that broke before any delivered terminal: the consumed prefix is
// recorded for token budgets (D1 canon — request.failed creates no charge
// intent), the client stream is closed with a protocol-shaped failure
// frame at the event boundary the tail tracker holds, and the terminal
// facts ride the request.failed finisher.
func (gw *gateway) finishResponsesStreamDrainFailure(w http.ResponseWriter, rctx context.Context, l *slog.Logger, tail *ssePassthroughTail, admitted admitted, usage provider.Usage, upstreamURL string, started time.Time, resp *http.Response, idle *idleReader, relayErr error) {
	idleAbort := idle != nil && idle.Fired()
	detail := "stream drain failed: " + relayErr.Error()
	term := budget.TerminationUpstreamErr
	if idleAbort {
		detail = "upstream stream idle timeout"
		term = budget.TerminationIdleTimeout
	}
	gw.accountUsage(rctx, w, usageRecord{
		orgID:     admitted.OrgID,
		taskID:    admitted.TaskID,
		sessionID: admitted.SessionID,
		usage:     usage,
	})
	tail.complete()
	writeResponsesStreamFailed(w, detail)
	if ferr := gw.finishResponsesNative(w, rctx, admitted, usage, upstreamURL, http.StatusOK, started, resp, "request.failed", detail, term); ferr != nil {
		l.Error("terminal facts commit failed; event withheld from consumer", "error", ferr)
	}
}

// finishResponsesStreamUpstreamFailure settles a delivered upstream
// response.failed terminal: the provider usage is recorded with no charge
// intent and no second client terminal is written — the stream already
// ended client-side on the upstream's own failure frame.
func (gw *gateway) finishResponsesStreamUpstreamFailure(w http.ResponseWriter, rctx context.Context, l *slog.Logger, admitted admitted, usage provider.Usage, upstreamURL string, started time.Time, resp *http.Response) {
	gw.accountUsage(rctx, w, usageRecord{
		orgID:     admitted.OrgID,
		taskID:    admitted.TaskID,
		sessionID: admitted.SessionID,
		usage:     usage,
	})
	if ferr := gw.finishResponsesNative(w, rctx, admitted, usage, upstreamURL, http.StatusOK, started, resp, "request.failed", "upstream response.failed", ""); ferr != nil {
		l.Error("terminal facts commit failed; event withheld from consumer", "error", ferr)
	}
}

// writeResponsesStreamFailed emits the protocol-shaped terminal failure
// frame for a native /v1/responses stream that broke after the 200/SSE
// commit (best-effort: the client may already be gone).
func writeResponsesStreamFailed(w http.ResponseWriter, message string) {
	writeResponsesStreamFailedCode(w, "server_error", message)
}

// writeResponsesStreamAccountingFailure closes a stream whose terminal
// accounting could not be committed after the provider already served it:
// the same external code and no-safe-retry language as the JSON refusal
// (writeTerminalAccountingFailure), in the native /v1/responses frame
// shape. Best-effort: the client may already be gone.
func writeResponsesStreamAccountingFailure(w http.ResponseWriter) {
	writeResponsesStreamFailedCode(w, accountingCommitFailedCode,
		"stream completed but its durable usage record could not be committed; NOT safe to retry — support reconciles the charge")
}

func writeResponsesStreamFailedCode(w http.ResponseWriter, code, message string) {
	payload := map[string]any{
		"type": "response.failed",
		"response": map[string]any{
			"id":     "",
			"object": "response",
			"status": "failed",
			"error":  map[string]any{"code": code, "message": message},
			"output": []any{},
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return
	}
	if _, err := fmt.Fprintf(w, "event: response.failed\ndata: %s\n\n", raw); err != nil {
		return
	}
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}

// relayResponsesSSE pipes the upstream Responses SSE stream to the client
// verbatim. It returns three facts the caller needs to settle the request:
// the provider usage parsed off the events read from upstream (already
// consumed there, so authoritative even when the client disconnected
// mid-drain), the name of the terminal event (response.completed/
// incomplete/failed) the client actually received — "" when none was
// delivered — and the error that ended the drain: the first failed client
// write, or the upstream read error. After a failed write no further bytes
// are written, but the drain continues so the usage stays truthful. Frames
// are dispatched whole: a consumer decodes an event only once its blank
// separator has arrived, so lines of an unterminated frame are held back
// with bounded memory. On an upstream break — or a clean EOF, which is not
// a drain failure — the held frame is dispatched only when the end aligned
// to a line boundary AND it is a decodable event missing just its
// separator; the salvaged frame is closed with a CRLF blank separator,
// valid after an LF, CRLF or lone-CR last line alike, so every terminator
// dialect dispatches instead of lingering as a pending event the client
// discards at stream end. It flows through the same usage parser, keeping
// the client stream and the settlement on the same events. Any other
// unterminated frame is dropped so the caller's failure frame composes at
// an event boundary. The delivered-terminal return lets the caller honor
// the one-terminal contract: a late failure after a delivered terminal
// must not emit a second terminal event. An oversized line or frame ends
// the drain as an upstream error.
// responsesStreamRelay carries one native /v1/responses drain's state
// (the streamRun canon): the client write path, the event parser, the
// usage and delivered-terminal observers, the frame accumulator, and the
// first client-write failure that stops further provider pulls.
type responsesStreamRelay struct {
	w        http.ResponseWriter
	flusher  http.Flusher
	parser   apiformat.SSEParser
	usage    provider.Usage
	terminal string
	frames   apiformat.SSEFrameBuffer
	werr     error // first client-write failure; writes stop and no further provider bytes are pulled (usage is read-based)
}

func newResponsesStreamRelay(w http.ResponseWriter) *responsesStreamRelay {
	rl := &responsesStreamRelay{w: w}
	if f, ok := w.(http.Flusher); ok {
		rl.flusher = f
	}
	return rl
}

// note applies one parsed event's usage and — when the client received
// it — terminal classification.
func (rl *responsesStreamRelay) note(ev apiformat.SSEEvent, delivered bool) {
	switch name := nativeEventName(ev); name {
	// The input-token part arrives on response.created, so a cut
	// mid-stream still bills the consumed prefix; any later terminal
	// event overwrites it with the full usage. Terminal tracking is
	// delivered-only: an event the client never received is not one of
	// the client stream's terminals.
	case "response.created", "response.completed", "response.incomplete", "response.failed":
		if next := parseResponsesUsage([]byte(ev.Data)); next.Source != "" {
			rl.usage = next
		}
		if delivered && name != "response.created" {
			rl.terminal = name
		}
	}
}

// writeFrame delivers one complete upstream record — a comment line or a
// whole frame, separator included — to the client and settles its parsed
// usage and terminal classification. Frames are dispatched whole: an
// event is only decodable once its blank separator has arrived
// (apiformat.SSEFrameBuffer).
func (rl *responsesStreamRelay) writeFrame(blob []byte) {
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
	for _, ev := range append(rl.parser.Feed(blob), rl.parser.Flush()...) {
		rl.note(ev, delivered)
	}
}

// drain pumps the upstream line reader until the stream ends: a
// client-write failure (after the already-buffered paid bytes settle), an
// oversized line or frame, an upstream break, a clean EOF, or the
// authoritative delivered terminal. cleanEnd reports which end it was:
// only a clean end settles the parser's pending event afterwards.
func (rl *responsesStreamRelay) drain(lr *apiformat.SSELineReader) (stopErr error, cleanEnd bool) {
	for {
		if rl.werr != nil && !lr.Buffered() {
			// The client write failed: stop pulling provider bytes — a
			// streaming upstream on the live connection would keep doing
			// paid work for a client that is gone. Frames already read
			// still settle usage (writeFrame parsed them for exactly
			// this); flushParser applies the same delivered rule. No
			// buffered bytes means nothing already-paid remains.
			break
		}
		line, rerr := lr.ReadLine()
		if rerr == apiformat.ErrSSELineLimit {
			// Oversized upstream line: drop it and the held frame; the
			// caller's response.failed frame closes the client stream.
			return apiformat.ErrSSELineLimit, false
		}
		if rerr != nil && !errors.Is(rerr, io.EOF) {
			// Broken upstream (cut mid-line): the unterminated partial is
			// withheld; salvage a boundary-aligned decodable frame closed
			// with its separator so the failure frame composes at an
			// event boundary.
			if len(line) == 0 && rl.frames.Salvageable() {
				rl.writeFrame(append(rl.frames.Take(), '\r', '\n'))
			}
			if rl.werr != nil {
				return rl.werr, false
			}
			return rerr, false
		}
		if rerr != nil {
			// io.EOF — clean end, same boundary-aligned salvage.
			if len(line) == 0 && rl.frames.Salvageable() {
				rl.writeFrame(append(rl.frames.Take(), '\r', '\n'))
			}
			break
		}
		if apiformat.SSECommentLine(line) {
			// Keepalive comments ride no event: forward immediately
			// instead of frame-batching them.
			rl.writeFrame(line)
			continue
		}
		blank, overflow := rl.frames.Add(line, apiformat.SSEStreamLineLimit)
		if overflow {
			return apiformat.ErrSSELineLimit, false
		}
		if blank {
			// Blank separator: the frame is complete — dispatch it whole,
			// verbatim, separator included.
			rl.writeFrame(append(rl.frames.Take(), line...))
			if rl.terminal != "" {
				// The provider declared the authoritative terminal
				// (completed, incomplete or failed): settle the known
				// usage and stop pulling upstream bytes — a provider that
				// holds the connection open after the final event must
				// not delay the client's terminal or the facts commit on
				// physical EOF. Post-terminal bytes are not part of the
				// response, there is no re-dispatch, and the caller's
				// deferred body close aborts the connection.
				break
			}
		}
	}
	return nil, true
}

// flushParser settles the parser's pending event at a clean end: a blob
// ending in a lone CR leaves the separator pending until this flush. Its
// bytes were written unless the client write already failed, so it
// settles with the same delivered rule.
func (rl *responsesStreamRelay) flushParser() {
	for _, ev := range rl.parser.Flush() {
		rl.note(ev, rl.werr == nil)
	}
}

func relayResponsesSSE(w http.ResponseWriter, body io.Reader) (provider.Usage, string, error) {
	rl := newResponsesStreamRelay(w)
	stopErr, cleanEnd := rl.drain(apiformat.NewSSELineReader(bufio.NewReader(body), apiformat.SSEStreamLineLimit))
	if cleanEnd {
		rl.flushParser()
		return rl.usage, rl.terminal, rl.werr
	}
	return rl.usage, rl.terminal, stopErr
}

// nativeEventName resolves an SSE record's event name for terminal
// classification: the event field when present, else the data payload's
// type member — the wire carries terminals either way, including
// split-data frames the parser joins.
func nativeEventName(ev apiformat.SSEEvent) string {
	if ev.Event != "" {
		return ev.Event
	}
	var doc struct {
		Type string `json:"type"`
	}
	if json.Unmarshal([]byte(ev.Data), &doc) != nil {
		return ""
	}
	return doc.Type
}

func parseResponsesUsage(raw []byte) provider.Usage {
	var doc struct {
		Response struct {
			Usage *responsesUsageBody `json:"usage"`
		} `json:"response"`
		Usage *responsesUsageBody `json:"usage"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return provider.Usage{}
	}
	body := doc.Usage
	if body == nil {
		body = doc.Response.Usage
	}
	if body == nil || (body.Input == nil && body.Output == nil) {
		return provider.Usage{}
	}
	usage := provider.Usage{Source: provider.UsageSourceProvider}
	if body.Input != nil {
		usage.PromptTokens = *body.Input
	}
	if body.Output != nil {
		usage.CompletionTokens = *body.Output
	}
	if body.Details != nil && body.Details.Cached != nil {
		usage.CacheReadTokens = *body.Details.Cached
	}
	return usage
}

type responsesUsageBody struct {
	Input   *int64 `json:"input_tokens"`
	Output  *int64 `json:"output_tokens"`
	Details *struct {
		Cached *int64 `json:"cached_tokens"`
	} `json:"input_tokens_details"`
}

func copyResponsesPassthrough(dst, src http.Header) {
	for _, key := range []string{"Retry-After", "X-Request-Id"} {
		if value := src.Get(key); value != "" {
			dst.Set(key, value)
		}
	}
}

// finishResponsesNative closes the native responses request. termHint
// overrides the non-completed termination class (the stream drain-failure
// branch distinguishes idle-timeout from upstream error, mirroring the chat
// finishDrainFailure canon); empty keeps the default classification. It
// returns the terminal-facts commit error so success call sites can convert
// the client reply (writeTerminalAccountingFailure / the SSE accounting
// frame); failure call sites log it (finishRequestLogged canon).
func (gw *gateway) finishResponsesNative(w http.ResponseWriter, ctx context.Context, admitted admitted, usage provider.Usage, upstreamURL string, status int, started time.Time, resp *http.Response, eventType, errText string, termHint budget.Termination) error {
	ext := provider.ComputeCost(usage, admitted.Info.Provider, admitted.Info.ModelName)
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
	switch {
	case eventType == "request.completed":
		term = completionTermination(ctx)
	case termHint != "":
		term = termHint
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
			Endpoint:                   "responses",
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
