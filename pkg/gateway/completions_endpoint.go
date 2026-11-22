package cli

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/reireirei/yabanin/pkg/budget"
	apierrors "github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/logctx"
	"github.com/reireirei/yabanin/pkg/pipeline"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// completionsRequest is the validated client shape of the legacy
// completions route.
type completionsRequest struct {
	Model     string `json:"model"`
	Stream    bool   `json:"stream"`
	MaxTokens *int   `json:"max_tokens"`
}

// parseCompletionsRequest reads and validates the client request. Unlike
// the 413-refusing routes, a body read failure here answers plain 400 (this
// legacy surface never distinguished the gateway payload cap).
func parseCompletionsRequest(w http.ResponseWriter, r *http.Request) (completionsRequest, []byte, bool) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "request body too large or malformed")
		return completionsRequest{}, nil, false
	}
	var req completionsRequest
	if err := json.Unmarshal(body, &req); err != nil {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "malformed JSON: "+err.Error())
		return completionsRequest{}, nil, false
	}
	if req.Model == "" {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "model is required")
		return completionsRequest{}, nil, false
	}
	return req, body, true
}

// completionsPolicyGuards runs the OP-8 unified policy stage pre-upstream
// plus this route's pre-reservation refusals: a client route hint foreign
// to the serving provider, and stream_prefix/stream_final policies this
// surface cannot honor (shadow mode never refuses; a cold policy store
// stays fail-open). ok is false once the refusal was written.
func (gw *gateway) completionsPolicyGuards(w http.ResponseWriter, r *http.Request, admitted admitted, stream bool) (guarded []byte, policyEvent, providerName string, ok bool) {
	guarded, policyEvent, ok = gw.policyPreUpstream(w, r, "completions", admitted.Info.ModelName, admitted.Info.Provider, admitted.Body)
	if !ok {
		return nil, "", "", false
	}
	// Serving provider of the single-candidate client pool (hoisted for
	// the hint check below and the dispatch).
	providerName = admitted.Info.Provider
	if providerName == "" {
		providerName = "openai"
	}
	if !gw.enforceSingularRouteHint(w, r, providerName) {
		return nil, "", "", false
	}
	if stream && gw.unenforceableStreamPolicies(r.Context(), admitted.OrgID, admitted.Info.ModelName) {
		apierrors.WriteWithCode(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
			"stream policies are not enforced on legacy completions streams", "stream_policy_unsupported_surface")
		return nil, "", "", false
	}
	return guarded, policyEvent, providerName, true
}

// requireStreamFlusher refuses a streaming dispatch before the durable
// start when the writer cannot flush (chat streamRun.admit canon — fail
// before anything durable, with zero provider arrivals).
func requireStreamFlusher(w http.ResponseWriter, gate *reservationGate, stream bool) bool {
	if !stream {
		return true
	}
	if _, ok := w.(http.Flusher); !ok {
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		apierrors.Write(w, http.StatusNotImplemented, apierrors.ErrorCodeAPI, "streaming not supported by server")
		return false
	}
	return true
}

func (gw *gateway) completions(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	l := logctx.From(r.Context(), gw.log)
	req, body, ok := parseCompletionsRequest(w, r)
	if !ok {
		return
	}

	admitted, ok := gw.admit(w, r, admitInput{
		Endpoint: "completions",
		Model:    req.Model,
		Body:     body,
	})
	if !ok {
		return
	}
	if !gw.openAICompatRouteReady(w, admitted.Info.Provider, "completions", "completions are not supported for this provider") {
		return
	}

	// OP-8: unified policy-pipeline run point (pre-upstream, before the
	// reservation and the forward). One call site for both branches of this
	// endpoint (streaming hooks arrive with OP-4); the decision record rides
	// rctx into the finisher's event.
	guarded, policyEvent, providerName, ok := gw.completionsPolicyGuards(w, r, admitted, req.Stream)
	if !ok {
		return
	}
	admitted.Body = guarded

	// NEXT-18c (ADR-0001 §5.1): pre-check, then reserve — this pipeline has
	// no cache branch, so both stages run back-to-back before the upstream
	// call. The gate rides the request-derived context for the finalize
	// stages below. One admission serves BOTH transports below; the kind
	// binds to the one actually dispatched.
	rctx, gate, ok := gw.reservePaidDispatch(withPolicyEvent(r.Context(), policyEvent), w, r, "completions", admitted, reservationMaxTokens(req.MaxTokens), false)
	if !ok {
		return
	}

	client, upstreamBody, apiKey, providerName, upstreamURL, ok := gw.paidUpstreamClient(l, w, gate, admitted, providerName)
	if !ok {
		return
	}
	if !requireStreamFlusher(w, gate, req.Stream) {
		return
	}
	if !gw.confirmPaidStart(w, l, gate, rctx, invocationKindForChat(req.Stream)) {
		return
	}

	if req.Stream {
		// W-TIMEOUT: streams carry no whole-request deadline; the transport's
		// ResponseHeaderTimeout plus the idle watchdog below bound them.
		gw.completionsStream(w, r, rctx, gate, admitted, client, upstreamBody, apiKey, providerName, upstreamURL, started, l)
		return
	}

	gw.relayCompletionsJSON(completionsJSONDispatch{
		r: r, rctx: rctx, w: w, l: l, gate: gate, admitted: admitted,
		client: client, upstreamBody: upstreamBody, apiKey: apiKey,
		body: body, providerName: providerName, upstreamURL: upstreamURL,
		started: started,
	})
}

// completionsJSONDispatch carries the non-streaming dispatch inputs that
// outlive the shared pipeline stages.
type completionsJSONDispatch struct {
	r            *http.Request
	rctx         context.Context
	w            http.ResponseWriter
	l            *slog.Logger
	gate         *reservationGate
	admitted     admitted
	client       *upstream.Client
	upstreamBody []byte
	apiKey       string
	body         []byte // the client's raw body (usage-estimate fallback)
	providerName string
	upstreamURL  string
	started      time.Time
}

// relayCompletionsJSON performs the paid non-streaming /v1/completions
// dispatch and settle: bounded read, adapter usage parsing, the OP-8
// post-upstream policy hook (a deny answers 400 with the settle already
// run), the durable finishCompletion settle and the byte-honest reply.
func (gw *gateway) relayCompletionsJSON(d completionsJSONDispatch) {
	timeout := d.admitted.Info.UpstreamTimeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(d.rctx, timeout)
	defer cancel()
	resp, err := d.client.Do(ctx, "/v1/completions", d.upstreamBody, d.apiKey, false, nil)
	if err != nil {
		closeUpstream(d.l, resp)
		d.gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		apierrors.Write(d.w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "upstream request failed")
		return
	}
	defer resp.Body.Close()
	limited, err := io.ReadAll(io.LimitReader(resp.Body, embeddingsResponseLimit+1))
	if err != nil {
		d.gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		d.w.Header().Set("X-Should-Retry", "false")
		apierrors.Write(d.w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "failed to read upstream response")
		return
	}
	if resp.StatusCode != http.StatusOK {
		d.gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		status, errType := apierrors.MapUpstreamStatus(resp.StatusCode)
		apierrors.Write(d.w, status, errType, "upstream request failed")
		return
	}
	if len(limited) > embeddingsResponseLimit {
		d.gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		d.w.Header().Set("X-Should-Retry", "false")
		apierrors.Write(d.w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "upstream response too large")
		return
	}
	usage := completionsUsage(limited, d.body, d.client.Adapter())
	// OP-8: post-upstream policy hook. Usage was parsed from the ORIGINAL
	// body (the tokens were consumed); a mask replaces what the client and
	// the finisher see; a deny answers 400 instead of the upstream body.
	if gw.policyRuntime != nil {
		masked, postEvent, denied := gw.policyPostUpstream(d.r, "completions", d.admitted.Info.ModelName, d.admitted.Info.Provider, limited)
		if postEvent != "" {
			d.rctx = withPolicyEvent(d.rctx, appendPolicyEvents(policyEventFrom(d.rctx), postEvent))
		}
		if denied {
			if ferr := gw.finishCompletion(d.w, d.rctx, d.admitted, usage, d.providerName, d.upstreamURL, http.StatusBadRequest, d.started, resp); ferr != nil {
				// The client envelope is already the policy denial; the
				// withheld event is logged loudly (finishRequestLogged
				// canon).
				d.l.Error("terminal facts commit failed; event withheld from consumer", "error", ferr)
			}
			apierrors.WriteWithCode(d.w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
				"response blocked by organization policy", policyDenyErrorCode)
			return
		}
		limited = masked
	}
	if ferr := gw.finishCompletion(d.w, d.rctx, d.admitted, usage, d.providerName, d.upstreamURL, http.StatusOK, d.started, resp); ferr != nil {
		// Central binding: usage was dispatched but its durable record did
		// not commit — the client must not see the upstream body as a
		// payable success (never a re-dispatch; support reconciles).
		d.l.Error("terminal facts commit failed; withholding reply", "error", ferr)
		writeTerminalAccountingFailure(d.w)
		return
	}
	// N03-P06-T02: provider prompt-cache transparency on the legacy
	// completions JSON path (absent for estimated usage — never fabricated).
	setPromptCacheHeader(d.w, usage)
	d.w.Header().Set("Content-Type", "application/json")
	d.w.WriteHeader(http.StatusOK)
	_, _ = d.w.Write(limited)
}

func (gw *gateway) completionsStream(w http.ResponseWriter, r *http.Request, rctx context.Context, gate *reservationGate, admitted admitted, client *upstream.Client, upstreamBody []byte, apiKey, providerName, upstreamURL string, started time.Time, l *slog.Logger) {
	upstreamBody, clientWantsUsage := ensureStreamUsage(upstreamBody, providerName, gw.streamUsageProviders)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Proxy-Cache", "bypass")

	// The caller checked the stream capability BEFORE the durable start,
	// so the writer is a Flusher by construction (a non-flusher writer
	// never reaches this function — it answered 501 with no admission).
	flusher, _ := w.(http.Flusher)

	// The stream context derives from the request-derived rctx (identity,
	// gate, policy record ride it into the finisher) — client
	// cancellation still propagates from the parent request context.
	streamCtx, cancelStream := context.WithCancel(rctx)
	defer cancelStream()

	resp, err := client.Do(streamCtx, "/v1/completions", upstreamBody, apiKey, true, nil)
	if err != nil {
		closeUpstream(l, resp)
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		writeSSEError(w, apierrors.ErrorCodeAPI, "upstream request failed")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		writeSSEError(w, apierrors.ErrorCodeAPI, "upstream request failed")
		return
	}

	body := io.Reader(resp.Body)
	if gw.streamIdleTimeout > 0 {
		idle := newIdleReader(resp.Body, gw.streamIdleTimeout, cancelStream)
		defer idle.Stop()
		body = idle
	}
	resp.Body = struct {
		io.Reader
		io.Closer
	}{body, resp.Body}

	handler := provider.NewStreamHandlerWithOptions("openai", admitted.Info.ModelName, provider.StreamOptions{
		SuppressUsageOnlyChunk: !clientWantsUsage,
		RequestBytes:           len(upstreamBody),
		// Legacy completions canon: a complete JSON data line that lost
		// only its blank separator to a transport cut is still dispatched
		// whole before the drain-failure error frame ([DONE], torn lines,
		// cancellation and policy-wrapped chat stay excluded — provider
		// scoping). The other three relays implement the same salvage at
		// the gateway frame buffer (apiformat.SSEFrameBuffer).
		RecoverLegacyCompletionLine: true,
	})
	// N03-P01: watch the terminal — a late failure after the client already
	// saw the [DONE] terminator must not emit a second terminal event. The
	// tail tracker sits under the watch so a torn last event is closed
	// before the drain-failure error frame composes (chat F2 canon).
	tail := &ssePassthroughTail{w: w}
	watch := newSSETerminalWatch(tail)
	// Central binding (Preview2 durable accounting, chat drain canon): an
	// admitted invocation holds the client-facing [DONE] until its terminal
	// facts commit — release happens exactly once after the durable write;
	// a failed write drops the terminator and surfaces the typed accounting
	// error frame instead.
	if h := invocationIdentityFrom(rctx); h != nil && h.Admitted() && gw.invocations != nil {
		watch.armDoneHold()
	}
	usage, drainErr := handler.HandleStream(streamCtx, watch, flusher, resp)
	gw.settleCompletionsStream(rctx, w, l, gate, admitted, providerName, upstreamURL, started, resp, watch, tail, usage, drainErr)
}

// settleCompletionsStream applies the stream drain outcome: a drain failure
// drops the held [DONE], settles the escrow with zero spend and closes with
// the plain error frame (NEXT-18c: no analytics event on this path — the
// reconciler's grace sweep owns the admitted-without-facts row); a failed
// terminal-facts commit replaces the held terminator with the
// accounting_commit_failed frame (chat stream canon — deliberately NO
// safe-retry language: the work already ran under this invocation
// identity); success releases the held [DONE] exactly once after the
// durable write.
func (gw *gateway) settleCompletionsStream(rctx context.Context, w http.ResponseWriter, l *slog.Logger, gate *reservationGate, admitted admitted, providerName, upstreamURL string, started time.Time, resp *http.Response, watch *sseTerminalWatch, tail *ssePassthroughTail, usage provider.Usage, drainErr error) {
	if drainErr != nil {
		watch.failDoneHold()
		term := budget.TerminationUpstreamErr
		if rctx.Err() != nil {
			term = budget.TerminationClientCancel
		}
		gate.finalizeNoEvent(term)
		if !watch.sawDone() {
			tail.complete()
			writeSSEError(w, apierrors.ErrorCodeAPI, "stream drain failed")
		}
		return
	}
	// N03-P06-T02: stream headers committed long ago; outcome rides the
	// trailer once HandleStream returns final usage.
	setPromptCacheTrailer(w, usage)
	if ferr := gw.finishCompletion(w, rctx, admitted, usage, providerName, upstreamURL, http.StatusOK, started, resp); ferr != nil {
		// Central binding: the held terminator is dropped and replaced by
		// the accounting error frame — deliberately NO safe-retry language:
		// the work already ran under this invocation identity (chat stream
		// canon).
		watch.failDoneHold()
		writeSSEErrorWithCode(w, apierrors.ErrorCodeAPI, accountingCommitFailedCode,
			"stream completed but its durable usage record could not be committed; NOT safe to retry — support reconciles the charge")
		l.Error("terminal facts commit failed after paid stream; [DONE] withheld from client",
			"invocation_id", invocationIDFromCtx(rctx), "error", ferr)
		return
	}
	watch.releaseDoneHold()
}

func closeUpstream(l *slog.Logger, resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	if cerr := resp.Body.Close(); cerr != nil && l != nil {
		l.Debug("close upstream body", "error", cerr)
	}
}

// completionsUsage parses upstream usage through the serving provider's
// adapter so the non-streaming completions path consumes the same shared
// parser as every OpenAI-compatible adapter (N03-P06-T04): transparent
// prompt-cache fields (prompt_tokens_details.cached_tokens, legacy
// prompt_cache_hit_tokens) must reach billing instead of being silently
// dropped at this seam. A body without a provider usage block keeps the
// pre-existing request-length estimate fallback.
func completionsUsage(body, request []byte, adapter provider.Provider) provider.Usage {
	u := adapter.ParseUsage(body)
	if u.Source == provider.UsageSourceProvider {
		if u.TotalTokens == 0 {
			u.TotalTokens = u.PromptTokens + u.CompletionTokens
		}
		return u
	}
	n := int64((len(request) + 3) / 4)
	return provider.Usage{PromptTokens: n, TotalTokens: n, Source: provider.UsageSourceEstimated}
}

// finishCompletion settles the legacy completions response durably — the
// usage record, terminal facts and the reservation — and returns the
// terminal-facts commit error so each transport can apply its canon:
// buffered callers withhold the upstream body, the stream caller drops
// the held [DONE] and closes with the accounting error frame.
func (gw *gateway) finishCompletion(w http.ResponseWriter, ctx context.Context, admitted admitted, usage provider.Usage, providerName, upstreamURL string, status int, started time.Time, resp *http.Response) error {
	ext := provider.ComputeCost(usage, providerName, admitted.Info.ModelName)
	gw.accountUsage(ctx, w, usageRecord{
		orgID:      admitted.OrgID,
		taskID:     admitted.TaskID,
		sessionID:  admitted.SessionID,
		usage:      usage,
		costUSD:    ext.EstimatedCostUSD,
		priceKnown: ext.PriceKnown,
	})
	_, ferr := gw.finishRequest(ctx, requestFinish{
		base: eventBase{
			EventType:      "request.completed",
			RequestID:      admitted.RequestID,
			SessionID:      admitted.SessionID,
			Payload:        string(admitted.Body),
			OrgID:          admitted.OrgID,
			TeamID:         admitted.TeamID,
			AgentID:        admitted.AgentID,
			UserID:         admitted.UserID,
			APIKeyID:       admitted.APIKeyID,
			SessionKeyID:   admitted.SessionKeyID,
			TaskID:         admitted.TaskID,
			ModelRequested: admitted.RequestedModel,
			ModelUsed:      admitted.Info.ModelName,
			UpstreamURL:    upstreamURL,
			StatusCode:     int64(status),
			DurationMs:     time.Since(started).Milliseconds(),
			TokensIn:       usage.PromptTokens,
			TokensOut:      usage.CompletionTokens,
			// N03-P06-T05: the event must carry the same provider-reported
			// cache reads the bill used — a discounted EstimatedCostUSD with
			// zero CacheReadTokens would make the analytics ledger
			// irreproducible from its own fields (parity with chat/messages/
			// responses/rerank/images finishers).
			CacheReadTokens:            usage.CacheReadTokens,
			CacheCreationTokens:        usage.CacheCreationTokens,
			EstimatedCostUSD:           ext.EstimatedCostUSD,
			Endpoint:                   "completions",
			UsageSource:                usageSourceOrNone(usage.Source),
			CostStatus:                 costStatus(false, usage.Source, ext.PriceKnown),
			Method:                     http.MethodPost,
			InferenceRegion:            admitted.Info.Region,
			ModelOriginCountry:         admitted.Info.Provider,
			LogStorageRegion:           gw.cfg.Region,
			ProviderEntityJurisdiction: admitted.Info.Provider,
			Labels:                     labelsFrom(ctx),
			Policy:                     policyEventFrom(ctx), // OP-8: decision record (OP-9 contract)
		},
		info:        admitted.Info,
		resp:        resp,
		termination: completionTermination(ctx),
		// NEXT-18c: settle the reservation and stamp tuples + termination
		// (§5.3 Finalize). Resale is not computed on this pipeline; the
		// wallet actual falls back to the base quote — the consumer's
		// own rule.
		eventNote: true,
	}, nil)
	return ferr
}

// completionTermination classifies a finished completion for the Finalize
// contract (§5.3): a dead request context means the client walked away.
func completionTermination(ctx context.Context) budget.Termination {
	if ctx.Err() != nil {
		return budget.TerminationClientCancel
	}
	return budget.TerminationCompleted
}

// unenforceableStreamPolicies reports whether the org has stream_prefix or
// stream_final policies attached to the "completions" endpoint (N03-P03-T09).
// The streaming-policy seam is built by the chat serveStream only, so those
// attachments can never be enforced here; the completions handler uses this
// to refuse explicitly instead of relaying a silently unprotected stream.
// Enforce mode only: shadow never breaks working streams, and a cold or
// unavailable runtime fails open exactly like the seam's own plan lookup.
func (gw *gateway) unenforceableStreamPolicies(ctx context.Context, orgID, model string) bool {
	rt := gw.policyRuntime
	if rt == nil || orgID == "" || rt.mode != PolicyModeEnforce {
		return false
	}
	q := policyQuery{endpoint: "completions", hook: pipeline.HookStreamPrefix, model: model, keyLabels: principalKeyLabels(ctx)}
	if len(rt.streamPlans(ctx, orgID, q)) > 0 {
		return true
	}
	q.hook = pipeline.HookStreamFinal
	return len(rt.streamPlans(ctx, orgID, q)) > 0
}
