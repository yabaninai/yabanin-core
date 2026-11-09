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
	if probe.Stream {
		// W-TIMEOUT: streams carry no whole-request deadline; the transport's
		// ResponseHeaderTimeout plus the idle watchdog below bound them.
		gw.messagesNativeStream(w, r, gate, admitted, client, upstreamBody, apiKey, upstreamURL, extra, started)
		return
	}
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
	limited, err := io.ReadAll(io.LimitReader(resp.Body, messagesResponseLimit))
	if err != nil {
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "failed to read upstream response")
		return
	}
	if resp.StatusCode != http.StatusOK {
		gw.forwardAnthropicError(w, r, admitted, resp, limited, upstreamURL, started)
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
			gw.finishNativeMessages(w, rctx, admitted, usage, upstreamURL, http.StatusBadRequest, started, resp, "request.failed", "response blocked by organization policy")
			apierrors.WriteWithCode(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
				"response blocked by organization policy", policyDenyErrorCode)
			return
		}
		limited = masked
	}
	gw.finishNativeMessages(w, rctx, admitted, usage, upstreamURL, http.StatusOK, started, resp, "request.completed", "")
	// N03-P06-T02: same provider-derived transparency the OpenAI-compat
	// JSON path reports (finalizeChatJSON); before WriteHeader below.
	setPromptCacheHeader(w, usage)
	copyAnthropicPassthrough(w.Header(), resp.Header)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(limited)
}

func (gw *gateway) messagesNativeStream(w http.ResponseWriter, r *http.Request, gate *reservationGate, admitted admitted, client *upstream.Client, upstreamBody []byte, apiKey, upstreamURL string, extra http.Header, started time.Time) {
	l := logctx.From(r.Context(), gw.log)
	streamCtx, cancelStream := context.WithCancel(r.Context())
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
		gw.forwardAnthropicError(w, r, admitted, resp, limited, upstreamURL, started)
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
	usage := relayAnthropicSSE(w, body)
	// N03-P06-T02: SSE headers are already committed; the provider
	// prompt-cache outcome rides the HTTP trailer (usage is final here).
	setPromptCacheTrailer(w, usage)
	gw.finishNativeMessages(w, r.Context(), admitted, usage, upstreamURL, http.StatusOK, started, resp, "request.completed", "")
}

// messagesStreamLineLimit bounds the per-line buffering of the native SSE
// relay. Upstreams are trusted for correctness, not for size discipline: a
// pathological or hostile provider can send a single multi-megabyte SSE
// line, and an unbounded ReadBytes would buffer it (and every such line)
// in gateway memory. 8 MiB is far above any legitimate frame (values ride
// JSON events, not bulk payloads) and far below any real request budget.
const messagesStreamLineLimit = 8 << 20

// errAnthropicLineLimit marks a line that exceeded messagesStreamLineLimit.
// It is never shown to clients: the relay drops the line and the T03
// synthesis closes the client stream instead.
var errAnthropicLineLimit = errors.New("anthropic: upstream SSE line exceeds the line limit")

// readAnthropicLine reads one upstream line, byte-identical including the
// terminating '\n' when present. When the line grows past limit the rest of
// the line is drained and errAnthropicLineLimit is returned (the partial
// bytes are dropped with it).
func readAnthropicLine(r *bufio.Reader, limit int) ([]byte, error) {
	var line []byte
	for {
		frag, err := r.ReadSlice('\n')
		line = append(line, frag...)
		if err == bufio.ErrBufferFull {
			if len(line) > limit {
				for {
					// Discard the remainder of the oversized line; only the
					// loop exit condition matters here.
					_, err = r.ReadSlice('\n')
					if err != bufio.ErrBufferFull {
						break
					}
				}
				return nil, errAnthropicLineLimit
			}
			continue
		}
		return line, err
	}
}

// relayAnthropicSSE forwards the upstream Anthropic SSE stream to the client
// byte-identically while accounting usage. It also tracks stream lifecycle:
// when the upstream ends without a terminal event — transport cut,
// ErrAbortHandler, or the idle watchdog canceling the read — the still-open
// content blocks are closed (ascending index order) and one terminal error
// frame in the shared adapted shape is synthesized (N07-P02-T03, the native
// twin of the adapted writer's D2 closing in emitStreamErrorLocked).
// message_stop is never fabricated, an explicit upstream error event is
// never duplicated, and the finish classification is untouched (D1: native
// stays request.completed with the partial usage).
func relayAnthropicSSE(w http.ResponseWriter, body io.Reader) provider.Usage {
	reader := bufio.NewReader(body)
	var parser apiformat.SSEParser
	var acc anthStreamUsage
	open := map[int]struct{}{}
	sawStop, sawError := false, false
	var flusher http.Flusher
	if f, ok := w.(http.Flusher); ok {
		flusher = f
	}
	track := func(ev apiformat.SSEEvent) {
		switch ev.Event {
		case "content_block_start":
			var doc struct {
				Index *int `json:"index"`
			}
			// A start frame without an explicit index is a malformed block
			// declaration: tracking it would invent index 0 and synthesize a
			// content_block_stop for a block the upstream never declared.
			if json.Unmarshal([]byte(ev.Data), &doc) == nil && doc.Index != nil {
				open[*doc.Index] = struct{}{}
			}
		case "content_block_stop":
			var doc struct {
				Index int `json:"index"`
			}
			if json.Unmarshal([]byte(ev.Data), &doc) == nil {
				delete(open, doc.Index)
			}
		case "message_stop":
			sawStop = true
		case "error":
			sawError = true
		}
	}
	for {
		line, err := readAnthropicLine(reader, messagesStreamLineLimit)
		if err == errAnthropicLineLimit {
			// Oversized upstream line: drop it whole, stop relaying. The
			// synthesis below closes the client stream (no stop was seen);
			// the caller's deferred upstream body close aborts the provider
			// connection, so the tail is never produced.
			slog.Debug("native relay dropped oversized upstream line", "limit_bytes", messagesStreamLineLimit)
			break
		}
		if len(line) > 0 {
			_, _ = w.Write(line)
			if flusher != nil {
				flusher.Flush()
			}
			for _, ev := range parser.Feed(line) {
				acc.note(ev)
				track(ev)
			}
		}
		if err != nil {
			break
		}
	}
	for _, ev := range parser.Flush() {
		acc.note(ev)
		track(ev)
	}
	if !sawStop && !sawError {
		closeOpenAnthropicBlocks(w, flusher, open)
	}
	return acc.usage()
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
	name := ev.Event
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

func (gw *gateway) forwardAnthropicError(w http.ResponseWriter, r *http.Request, admitted admitted, resp *http.Response, body []byte, upstreamURL string, started time.Time) {
	gw.finishNativeMessages(w, r.Context(), admitted, provider.Usage{}, upstreamURL, resp.StatusCode, started, resp, "request.failed", "upstream request failed")
	copyAnthropicPassthrough(w.Header(), resp.Header)
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	} else {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}

func (gw *gateway) finishNativeMessages(w http.ResponseWriter, ctx context.Context, admitted admitted, usage provider.Usage, upstreamURL string, status int, started time.Time, resp *http.Response, eventType, errText string) {
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
	gw.finishRequest(ctx, requestFinish{
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
