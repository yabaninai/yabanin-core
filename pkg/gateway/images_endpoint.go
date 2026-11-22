package cli

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"

	apierrors "github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/httpmw"
	"github.com/reireirei/yabanin/pkg/logctx"
	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// imagesResponseLimit bounds the buffered upstream images response (64 MiB,
// embeddings parity): data[].b64_json payloads are opaque base64 that the
// gateway passes through without parsing the image bytes.
const imagesResponseLimit = 64 << 20

// non-streaming OpenAI-compat images pipeline. One egress to the resolved
// upstream host (SSRF-gated by the upstream client); data[].url items are
// never dereferenced (D5). Edits/streaming are not promised (D3).
// imagesRequest is the validated /v1/images/generations JSON probe: the
// fields the admission, reservation and settlement phases need. n/size are
// upstream-owned semantics passed through verbatim (no per-parameter
// validation).
type imagesRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	N      *int64 `json:"n"`
}

// readImagesRequest decodes and validates the /v1/images/generations
// request body. ok=false means the caller already answered the client.
func readImagesRequest(w http.ResponseWriter, r *http.Request) (req imagesRequest, body []byte, ok bool) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		// The 10 MiB gateway cap (httpmw.MaxBody) answers 413 — the
		// anything else is a malformed body 400.
		if httpmw.IsMaxBytesError(err) {
			apierrors.Write(w, http.StatusRequestEntityTooLarge, apierrors.ErrorCodeInvalidRequest, "request body too large")
			return req, nil, false
		}
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "request body too large or malformed")
		return req, nil, false
	}
	if err := json.Unmarshal(body, &req); err != nil {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "malformed JSON: "+err.Error())
		return req, nil, false
	}
	if req.Model == "" {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "model is required")
		return req, nil, false
	}
	if req.Prompt == "" {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "prompt is required")
		return req, nil, false
	}
	return req, body, true
}

// non-streaming OpenAI-compat images pipeline. One egress to the resolved
// upstream host (SSRF-gated by the upstream client); data[].url items are
// never dereferenced (D5). Edits/streaming are not promised (D3).
func (gw *gateway) imagesGenerations(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	l := logctx.From(r.Context(), gw.log)
	req, body, ok := readImagesRequest(w, r)
	if !ok {
		return
	}
	admitted, ok := gw.admit(w, r, admitInput{
		Endpoint: "images.generation",
		Model:    req.Model,
		Body:     body,
		NoRemap:  true,
	})
	if !ok {
		return
	}
	if !gw.openAICompatRouteReady(w, admitted.Info.Provider, "images", "images are not supported for this provider") {
		return
	}

	// NEXT-18c (ADR-0001 §5.1): pre-check + reserve before the upstream call.
	// Image generation has no chat-shaped out_cap; n/size are upstream-owned
	// semantics passed through verbatim (no per-parameter validation). The
	// input-side image payload counting rides reservationInputProfile.
	// T02: the bound is per REQUESTED IMAGE — n × the catalog per-image
	// rate; models the unit catalog does not price per image (azure
	// per-pixel variants) keep the token estimate path and are refused in
	// enforce mode as unpriced (fail-closed, I3).
	rctx := r.Context()
	rctx = withInvocationIdentity(rctx, admitted.Invocation)
	rctx, gate, ok := gw.reservePlannedRequest(rctx, w, r, "images.generation",
		withUnitDemand(
			gw.reservationRequest(rctx, admitted.OrgID, admitted.TeamID, admitted.AgentID, admitted.SessionKeyID,
				admitted.Info, admitted.Body, nil, false),
			pricing.UnitPerImage, imagesRequestCount(req.N)))
	if !ok {
		return
	}

	ctx, cancel, client, apiKey, upstreamURL, ok := gw.mediaDispatch(w, rctx, l, gate, admitted)
	if !ok {
		return
	}
	defer cancel()
	upstreamBody := upstream.OverrideModelRaw(admitted.Body, admitted.Info.ModelName)
	if !gw.confirmPaidStart(w, l, gate, rctx, invocationKindChat) {
		return
	}

	resp, err := client.Do(ctx, "/v1/images/generations", upstreamBody, apiKey, false, nil)
	if err != nil {
		closeUpstream(l, resp)
		gate.finalizeNoEvent(mediaTermination(rctx))
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "upstream request failed")
		return
	}
	defer resp.Body.Close()

	limited, ok := readMediaResponse(w, rctx, gate, resp, imagesResponseLimit, "upstream response too large")
	if !ok {
		return
	}
	gw.finishImagesGeneration(rctx, w, l, admitted, providerName(admitted), upstreamURL, resp, started, req, limited)
}

// finishImagesGeneration settles the served images response durably —
// token usage or the T02 per-image fallback, the usage record, terminal
// facts — then writes the upstream JSON byte-identical.
func (gw *gateway) finishImagesGeneration(rctx context.Context, w http.ResponseWriter, l *slog.Logger, admitted admitted, prov, upstreamURL string, resp *http.Response, started time.Time, req imagesRequest, limited []byte) {
	usage, source := imagesUsage(limited)
	ext := provider.ComputeCost(usage, prov, admitted.Info.ModelName)
	// T02: token-priced responses (usage blocks on gpt-image models) keep
	// their token quote; unpriced ones bill n × the catalog per-image rate
	// (cost_status "priced" even with no usage block). Without a per-image
	// rate the legacy unknown-price settlement stands.
	unitPriced := false
	if !ext.PriceKnown {
		if entry, ok := gw.unitPrice(prov, admitted.Info.ModelName, pricing.UnitPerImage); ok {
			ext.EstimatedCostUSD = entry.Rate * imagesRequestCount(req.N)
			ext.PriceKnown = true
			unitPriced = true
		}
	}
	gw.accountUsage(rctx, w, usageRecord{
		orgID:      admitted.OrgID,
		taskID:     admitted.TaskID,
		sessionID:  admitted.SessionID,
		usage:      usage,
		costUSD:    ext.EstimatedCostUSD,
		priceKnown: ext.PriceKnown,
	})

	_, ferr := gw.finishRequest(rctx, requestFinish{
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
			UpstreamURL:                upstreamURL,
			StatusCode:                 http.StatusOK,
			DurationMs:                 time.Since(started).Milliseconds(),
			TokensIn:                   usage.PromptTokens,
			TokensOut:                  usage.CompletionTokens,
			CacheReadTokens:            usage.CacheReadTokens,
			EstimatedCostUSD:           ext.EstimatedCostUSD,
			Endpoint:                   "images.generation",
			UsageSource:                usageSourceOrNone(source),
			CostStatus:                 costStatusUnit(costStatus(false, source, ext.PriceKnown), unitPriced),
			Method:                     http.MethodPost,
			InferenceRegion:            admitted.Info.Region,
			ModelOriginCountry:         admitted.Info.Provider,
			LogStorageRegion:           gw.cfg.Region,
			ProviderEntityJurisdiction: admitted.Info.Provider,
			Labels:                     labelsFrom(rctx),
		},
		info: admitted.Info,
		resp: resp,
		// NEXT-18c: settle the reservation and stamp tuples + termination
		// (§5.3 Finalize). No resale on this pipeline; the wallet actual
		// falls back to the base quote — the consumer's own rule.
		// N3 + owner review 0574aa1: the provider fully served and was paid
		// for its 200 (an interrupted read returned above with no fabricated
		// usage). Whether the client transport is still alive only picks the
		// termination outcome (completionTermination → client_cancel) and
		// whether success bytes are written below — the KNOWN usage settles
		// durably either way (terminal facts ride the WithoutCancel funnel).
		termination: completionTermination(rctx),
		eventNote:   true,
	}, nil)
	if ferr != nil {
		// Central binding: usage was dispatched but its durable record did
		// not commit — the client must not see the upstream body as a
		// payable success (never a re-dispatch; support reconciles).
		l.Error("terminal facts commit failed; withholding reply", "error", ferr)
		writeTerminalAccountingFailure(w)
		return
	}
	if rctx.Err() != nil {
		// N3: the client walked away after the provider was paid — no
		// success bytes to the dead transport; the settlement above already
		// carries the known usage with the cancellation recorded.
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(limited)
}

// imagesUsage parses the OpenAI images usage block when present:
// input_tokens/output_tokens/total_tokens plus the cached-token detail.
// An absent or malformed block yields zero tokens with UsageSourceNone —
// no fabricated estimate (contract D4 default).
func imagesUsage(body []byte) (provider.Usage, string) {
	var parsed struct {
		Usage *struct {
			InputTokens       int64 `json:"input_tokens"`
			OutputTokens      int64 `json:"output_tokens"`
			TotalTokens       int64 `json:"total_tokens"`
			InputTokenDetails *struct {
				CachedTokens int64 `json:"cached_tokens"`
			} `json:"input_tokens_details"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || parsed.Usage == nil {
		return provider.Usage{}, provider.UsageSourceNone
	}
	u := provider.Usage{
		PromptTokens:     parsed.Usage.InputTokens,
		CompletionTokens: parsed.Usage.OutputTokens,
		TotalTokens:      parsed.Usage.TotalTokens,
		Source:           provider.UsageSourceProvider,
	}
	if parsed.Usage.InputTokenDetails != nil {
		u.CacheReadTokens = parsed.Usage.InputTokenDetails.CachedTokens
	}
	return u, provider.UsageSourceProvider
}
