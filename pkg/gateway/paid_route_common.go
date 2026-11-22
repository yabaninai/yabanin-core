package cli

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/reireirei/yabanin/pkg/budget"
	apierrors "github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/httpmw"
	"github.com/reireirei/yabanin/pkg/logctx"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/retry"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// The paid inference routes (embeddings, moderations, rerank, completions,
// realtime) share one admission-to-settlement pipeline whose stages must run
// in one exact order (ADR-0001 §5.1, Preview2 durable accounting): read and
// validate, admit, refuse unsupported provider/pool, reserve, wire the
// dispatch, confirm the durable start, dispatch, settle. These helpers are
// that shared pipeline — a route handler composes them and owns only its
// route-specific request shape, upstream path and usage parser. Every helper
// answers false/nil once the refusal response was already written, so the
// caller's `if !ok { return }` preserves today's write-once behavior.

// readRouteBody reads the request body of the paid inference routes. The
// 10 MiB gateway cap (httpmw.MaxBody) answers 413 — the contract's
// payload-size refusal (audio/images parity); any other read failure
// answers 400.
func readRouteBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		if httpmw.IsMaxBytesError(err) {
			apierrors.Write(w, http.StatusRequestEntityTooLarge, apierrors.ErrorCodeInvalidRequest, "request body too large")
			return nil, false
		}
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "request body too large or malformed")
		return nil, false
	}
	return body, true
}

// openAICompatRouteReady refuses, after admission but before any durable
// reservation side effect, a provider that cannot serve this route and an
// unwired upstream pool. unsupportedMsg is the route's contract message; the
// machine code derives from the endpoint name.
func (gw *gateway) openAICompatRouteReady(w http.ResponseWriter, providerName, endpoint, unsupportedMsg string) bool {
	if !openAICompatProvider(providerName) {
		apierrors.WriteWithCode(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
			unsupportedMsg, endpoint+"_not_supported_for_provider")
		return false
	}
	if gw.pool == nil {
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "upstream is not configured")
		return false
	}
	return true
}

// reservePaidDispatch binds the minted invocation identity and the
// reservation gate to the request context and runs the plan + reserve
// stages. maxTokens/embeddingsBound pass through to the bound request — the
// non-generating routes reserve embeddings-style with out_cap = 0.
func (gw *gateway) reservePaidDispatch(ctx context.Context, w http.ResponseWriter, r *http.Request, endpoint string, admitted admitted, maxTokens *int64, embeddingsBound bool) (context.Context, *reservationGate, bool) {
	rctx := withInvocationIdentity(ctx, admitted.Invocation)
	req := gw.reservationRequest(rctx, admitted.OrgID, admitted.TeamID, admitted.AgentID, admitted.SessionKeyID,
		admitted.Info, admitted.Body, maxTokens, embeddingsBound)
	return gw.reservePlannedRequest(rctx, w, r, endpoint, req)
}

func (gw *gateway) reservePlannedRequest(rctx context.Context, w http.ResponseWriter, r *http.Request, endpoint string, req budget.Request) (context.Context, *reservationGate, bool) {
	gate, ok := gw.reservationPlan(w, r, endpoint, req)
	if !ok {
		return nil, nil, false
	}
	rctx = withReservationGate(rctx, gate)
	if !gate.reserve(rctx) {
		return nil, nil, false
	}
	return rctx, gate, true
}

// paidUpstreamClient resolves the dispatch inputs shared by the paid
// inference routes: the serving provider name (openai default), the gateway
// API-key fallback, the upstream URL, the single-candidate pool client and
// the model-remapped request body.
func (gw *gateway) paidUpstreamClient(l *slog.Logger, w http.ResponseWriter, gate *reservationGate, admitted admitted, providerName string) (client *upstream.Client, upstreamBody []byte, apiKey, defaultedProvider, upstreamURL string, ok bool) {
	if providerName == "" {
		providerName = "openai"
	}
	apiKey = admitted.Info.UpstreamAPIKey
	if apiKey == "" {
		apiKey = gw.getUpstreamAPIKey()
	}
	upstreamURL = gw.upstreamURL(admitted.Info)
	client, err := gw.pool.Get(upstreamURL, providerName)
	if err != nil {
		l.Warn("upstream client unavailable", "provider", providerName, "error", err.Error())
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "failed to initialise upstream client")
		return nil, nil, "", "", "", false
	}
	return client, upstream.OverrideModelRaw(admitted.Body, admitted.Info.ModelName), apiKey, providerName, upstreamURL, true
}

// confirmPaidStart commits the confirmed start immediately BEFORE the first
// paid provider dispatch — after every fallible local setup step, so a local
// failure never strands a durable admission for a request that never
// dispatched. Fail closed: an unwritten start (write error, timeout or lost
// ACK — outcome unknown) refuses the request with ZERO provider arrivals
// under the history_unavailable envelope, and the escrow is released.
func (gw *gateway) confirmPaidStart(w http.ResponseWriter, l *slog.Logger, gate *reservationGate, rctx context.Context, kind string) bool {
	if err := gw.confirmPaidInvocation(rctx, kind); err != nil {
		gate.finalizeNoEvent(budget.TerminationPolicyDenied)
		l.Warn("refusing paid dispatch: durable start unwritten", "error", err)
		writeInvocationStartRefusal(w, err)
		return false
	}
	return true
}

// bufferedJSONFinish carries the settle inputs of the buffered JSON routes.
type bufferedJSONFinish struct {
	rctx         context.Context
	w            http.ResponseWriter
	admitted     admitted
	usage        provider.Usage
	providerName string
	endpoint     string
	upstreamURL  string
	started      time.Time
	resp         *http.Response
	payload      []byte
}

// finishBufferedJSONRoute settles the buffered JSON routes (embeddings,
// moderations, rerank): usage accounting, the terminal request.completed
// facts and the reservation, then the byte-honest upstream reply. On a
// failed terminal-facts commit the client must not see the upstream body as
// a payable success (never a re-dispatch; support reconciles) — the 500
// accounting envelope answers instead.
func (gw *gateway) finishBufferedJSONRoute(f bufferedJSONFinish) {
	admitted := f.admitted
	ext := provider.ComputeCost(f.usage, f.providerName, admitted.Info.ModelName)
	gw.accountUsage(f.rctx, f.w, usageRecord{
		orgID:      admitted.OrgID,
		taskID:     admitted.TaskID,
		sessionID:  admitted.SessionID,
		usage:      f.usage,
		costUSD:    ext.EstimatedCostUSD,
		priceKnown: ext.PriceKnown,
	})

	_, ferr := gw.finishRequest(f.rctx, requestFinish{
		base: eventBase{
			EventType:                  "request.completed",
			RequestID:                  admitted.RequestID,
			SessionID:                  admitted.SessionID,
			Payload:                    string(admitted.Body),
			OrgID:                      admitted.OrgID,
			TeamID:                     admitted.TeamID,
			AgentID:                    admitted.AgentID,
			UserID:                     admitted.UserID,
			APIKeyID:                   admitted.APIKeyID,
			SessionKeyID:               admitted.SessionKeyID,
			TaskID:                     admitted.TaskID,
			ModelRequested:             admitted.RequestedModel,
			ModelUsed:                  admitted.Info.ModelName,
			UpstreamURL:                f.upstreamURL,
			StatusCode:                 http.StatusOK,
			DurationMs:                 time.Since(f.started).Milliseconds(),
			TokensIn:                   f.usage.PromptTokens,
			TokensOut:                  f.usage.CompletionTokens,
			CacheReadTokens:            f.usage.CacheReadTokens,
			EstimatedCostUSD:           ext.EstimatedCostUSD,
			Endpoint:                   f.endpoint,
			UsageSource:                usageSourceOrNone(f.usage.Source),
			CostStatus:                 costStatus(false, f.usage.Source, ext.PriceKnown),
			Method:                     http.MethodPost,
			InferenceRegion:            admitted.Info.Region,
			ModelOriginCountry:         admitted.Info.Provider,
			LogStorageRegion:           gw.cfg.Region,
			ProviderEntityJurisdiction: admitted.Info.Provider,
			Labels:                     labelsFrom(f.rctx),
		},
		info: admitted.Info,
		resp: f.resp,
		// NEXT-18c: settle the reservation and stamp tuples + termination
		// (§5.3 Finalize). No resale on this pipeline; the wallet actual
		// falls back to the base quote — the consumer's own rule.
		termination: completionTermination(f.rctx),
		eventNote:   true,
	}, nil)
	if ferr != nil {
		// Central binding: usage was dispatched but its durable record did
		// not commit — the client must not see the upstream body as a
		// payable success (never a re-dispatch; support reconciles).
		logctx.From(f.rctx, gw.log).Error("terminal facts commit failed; withholding reply", "error", ferr)
		writeTerminalAccountingFailure(f.w)
		return
	}

	f.w.Header().Set("Content-Type", "application/json")
	f.w.WriteHeader(http.StatusOK)
	_, _ = f.w.Write(f.payload)
}

// A provider has already answered. Repeating the paid request can incur another charge.
func writePaidBodyError(w http.ResponseWriter, message string) {
	w.Header().Set("X-Should-Retry", "false")
	apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, message)
}

// An unknown post-dispatch outcome must not invite a duplicate paid call.
func writeNativeDispatchError(w http.ResponseWriter, err error) {
	if retry.DefinitelyNotSent(err) {
		w.Header().Set("X-Should-Retry", "true")
	} else {
		w.Header().Set("X-Should-Retry", "false")
	}
	apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "upstream request failed")
}

// Keep provider errors within their passthrough bound. A success needs one
// extra byte to distinguish an exact fit from a truncated answer.
func readNativeBufferedBody(w http.ResponseWriter, gate *reservationGate, resp *http.Response, limit int64) ([]byte, bool) {
	readLimit := limit
	if resp.StatusCode == http.StatusOK {
		readLimit++
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, readLimit))
	if err != nil {
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		writePaidBodyError(w, "failed to read upstream response")
		return nil, false
	}
	if int64(len(body)) > limit {
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		writePaidBodyError(w, "upstream response too large")
		return nil, false
	}
	return body, true
}
