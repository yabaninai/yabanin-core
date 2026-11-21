package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
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
	// so the org default out cap applies; MaxTokens stays nil).
	rctx := r.Context()
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
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Proxy-Cache", "bypass")
	if _, ok := w.(http.Flusher); !ok {
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		apierrors.Write(w, http.StatusNotImplemented, apierrors.ErrorCodeAPI, "streaming not supported by server")
		return
	}

	// The raw-chunk relay writes through the tail tracker so a torn last
	// event is closed before the terminal error frame composes (chat F2
	// canon); the tee is fed from the read side and is unaffected.
	tail := &ssePassthroughTail{w: w}
	usage, tee, term, drainErr := gw.realtimeRelay(rctx, tail, tail, resp.Body, cancelStream)

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
		// first so the error frame starts at an event boundary.
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
		_, _ = gw.finishRequest(rctx, requestFinish{
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
	_, _ = gw.finishRequest(rctx, requestFinish{
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
// gone; the usage already covers every byte read. Returns the parsed
// usage, the tee, the drain error (nil on clean EOF; a write failure
// settles as a client cancel) and its Finalize termination class (§5.3).
func (gw *gateway) realtimeRelay(rctx context.Context, w http.ResponseWriter, flusher http.Flusher, body io.Reader, cancelStream context.CancelFunc) (usage provider.Usage, tee *boundedBuffer, term budget.Termination, drainErr error) {
	var capture boundedBuffer
	tee = &capture
	var parser apiformat.SSEParser
	var idle *idleReader
	reader := body
	if gw.streamIdleTimeout > 0 {
		idle = newIdleReader(body, gw.streamIdleTimeout, cancelStream)
		defer idle.Stop()
		reader = idle
	}
	term = budget.TerminationUpstreamErr
	var relayed int64
	var lines apiformat.SSELineSplitter
	var frames apiformat.SSEFrameBuffer
	var werr error // first client-write failure; writes stop and no further provider bytes are pulled
	buf := make([]byte, 32*1024)
	writeBlob := func(blob []byte) {
		if len(blob) == 0 || werr != nil {
			return
		}
		if _, e := w.Write(blob); e != nil {
			werr = e
			return
		}
		flusher.Flush()
	}
	// processLine routes one complete upstream line: keepalive comments
	// ride no event and pass through immediately (downstream idle
	// timeouts stay reset; the frame buffer never grows on them), field
	// lines batch into the frame buffer, and a blank separator flushes
	// the whole frame to the client.
	processLine := func(line []byte) error {
		if apiformat.SSECommentLine(line) {
			writeBlob(line)
			return nil
		}
		blank, overflow := frames.Add(line, apiformat.SSEStreamLineLimit)
		if overflow {
			// An unterminated frame grew past the buffering limit: the
			// relay aborts as an upstream error (bounded memory).
			return errRealtimeLineTooLarge{}
		}
		if blank {
			writeBlob(append(frames.Take(), line...))
		}
		return nil
	}
	// lineAbort ends the drain for a line-processing error: an oversized
	// line/frame is an upstream abort; any other error is a failed client
	// write — the client walked away mid-session, and the consumed
	// prefix is billed by the caller (G3 cancel-settle parity).
	lineAbort := func(lerr error) (provider.Usage, *boundedBuffer, budget.Termination, error) {
		var tooLarge errRealtimeLineTooLarge
		if errors.As(lerr, &tooLarge) {
			return usage, tee, budget.TerminationUpstreamErr, lerr
		}
		return usage, tee, budget.TerminationClientCancel, lerr
	}
	// settleTail ends the framing at a stream break or clean EOF: the
	// splitter's trailing lone CR resolves into a complete line (the CR
	// was received — it terminates its line under the grammar whether or
	// not a further LF ever arrives); the held frame is salvaged only
	// when no unterminated partial followed it and it is a decodable
	// event missing just its separator. The salvaged frame is closed
	// with a CRLF blank separator — valid after an LF, CRLF or lone-CR
	// last line alike — and followed by the usage parser's Flush, so the
	// settlement bills what the upstream actually sent; a dropped frame
	// leaves the parser unflushed — a torn event is never billed.
	settleTail := func() error {
		flushLines, partial := lines.Flush()
		for _, line := range flushLines {
			if lerr := processLine(line); lerr != nil {
				return lerr
			}
		}
		if len(partial) > 0 || !frames.Salvageable() {
			return nil
		}
		writeBlob(append(frames.Take(), '\r', '\n'))
		for _, ev := range parser.Flush() {
			if u, ok := realtimeUsageFromEvent([]byte(ev.Data)); ok {
				usage = u
			}
		}
		return nil
	}
	for {
		n, rerr := reader.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			relayed += int64(n)
			if relayed > realtimeStreamLimit {
				// Never truncate an SSE stream mid-event: the relay aborts
				// as an upstream error at the cap.
				return usage, tee, budget.TerminationUpstreamErr, errRealtimeStreamTooLarge{}
			}
			_, _ = capture.Write(chunk)
			for _, ev := range parser.Feed(chunk) {
				if u, ok := realtimeUsageFromEvent([]byte(ev.Data)); ok {
					usage = u // last usage-bearing event wins (carryStreamUsage parity)
				}
			}
			// Frame-batch the client writes: only whole frames (through
			// their blank separator) leave the relay while the upstream is
			// still running.
			for _, line := range lines.Feed(chunk) {
				if lerr := processLine(line); lerr != nil {
					return lineAbort(lerr)
				}
			}
			if lines.Pending() > apiformat.SSEStreamLineLimit {
				// An unterminated line grew past the buffering limit: the
				// relay aborts as an upstream error (bounded memory).
				return usage, tee, budget.TerminationUpstreamErr, errRealtimeLineTooLarge{}
			}
		}
		if werr != nil {
			// The client write failed: stop pulling provider bytes — a
			// streaming upstream on the live connection would keep doing
			// paid work for a client that is gone. The usage parser was
			// fed above from every byte this chunk carried, so the usage
			// already covers what was paid for.
			return usage, tee, budget.TerminationClientCancel, werr
		}
		if rerr == io.EOF {
			// Clean end: EOF is not a drain failure; the tail settles with
			// the same boundary-aligned salvage rule. A recorded client
			// write failure still settles as a cancel — the client never
			// saw the stream through.
			if lerr := settleTail(); lerr != nil {
				return lineAbort(lerr)
			}
			if werr != nil {
				return usage, tee, budget.TerminationClientCancel, werr
			}
			return usage, tee, budget.TerminationCompleted, nil
		}
		if rerr != nil {
			// Broken upstream: same boundary-aligned salvage as EOF — the
			// closed frame keeps the client stream and the settlement on
			// the same event — then the termination class and the read
			// error return.
			if lerr := settleTail(); lerr != nil {
				return lineAbort(lerr)
			}
			if werr != nil {
				return usage, tee, budget.TerminationClientCancel, werr
			}
			switch {
			case idle != nil && idle.Fired():
				term = budget.TerminationIdleTimeout
			case rctx.Err() != nil:
				term = budget.TerminationClientCancel
			}
			return usage, tee, term, rerr
		}
	}
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
