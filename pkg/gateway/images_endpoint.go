package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/reireirei/yabanin/pkg/budget"
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
func (gw *gateway) imagesGenerations(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	l := logctx.From(r.Context(), gw.log)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		// The 10 MiB gateway cap (httpmw.MaxBody) answers 413 — the
		// anything else is a malformed body 400.
		if httpmw.IsMaxBytesError(err) {
			apierrors.Write(w, http.StatusRequestEntityTooLarge, apierrors.ErrorCodeInvalidRequest, "request body too large")
			return
		}
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "request body too large or malformed")
		return
	}
	var req struct {
		Model  string `json:"model"`
		Prompt string `json:"prompt"`
		N      *int64 `json:"n"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "malformed JSON: "+err.Error())
		return
	}
	if req.Model == "" {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "model is required")
		return
	}
	if req.Prompt == "" {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "prompt is required")
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
	if !openAICompatProvider(admitted.Info.Provider) {
		apierrors.WriteWithCode(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
			"images are not supported for this provider", "images_not_supported_for_provider")
		return
	}
	if gw.pool == nil {
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "upstream is not configured")
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
	gate, ok := gw.reservationPlan(w, r, "images.generation",
		withUnitDemand(
			gw.reservationRequest(rctx, admitted.OrgID, admitted.TeamID, admitted.AgentID, admitted.SessionKeyID,
				admitted.Info, admitted.Body, nil, false),
			pricing.UnitPerImage, imagesRequestCount(req.N)))
	if !ok {
		return
	}
	rctx = withReservationGate(rctx, gate)
	if !gate.reserve(rctx) {
		return
	}

	timeout := admitted.Info.UpstreamTimeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(rctx, timeout)
	defer cancel()

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
	resp, err := client.Do(ctx, "/v1/images/generations", upstreamBody, apiKey, false, nil)
	if err != nil {
		if resp != nil && resp.Body != nil {
			if cerr := resp.Body.Close(); cerr != nil {
				l.Debug("close upstream body", "error", cerr)
			}
		}
		gate.finalizeNoEvent(mediaTermination(rctx))
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "upstream request failed")
		return
	}
	defer resp.Body.Close()

	// Read one byte past the limit so an oversized upstream body is refused
	// as an upstream error instead of being silently truncated (the gateway
	// never delivers a partial image payload).
	limited, err := io.ReadAll(io.LimitReader(resp.Body, imagesResponseLimit+1))
	if err != nil {
		gate.finalizeNoEvent(mediaTermination(rctx))
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "failed to read upstream response")
		return
	}
	if len(limited) > imagesResponseLimit {
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "upstream response too large")
		return
	}
	if resp.StatusCode != http.StatusOK {
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		status, errType := apierrors.MapUpstreamStatus(resp.StatusCode)
		apierrors.Write(w, status, errType, "upstream request failed")
		return
	}
	if rctx.Err() != nil {
		// N3: the client walked away while the response was in flight —
		// settle the escrow with no spend event and publish no
		// request.completed success event (audio pipeline parity).
		gate.finalizeNoEvent(budget.TerminationClientCancel)
		return
	}

	usage, source := imagesUsage(limited)
	ext := provider.ComputeCost(usage, providerName, admitted.Info.ModelName)
	// T02: token-priced responses (usage blocks on gpt-image models) keep
	// their token quote; unpriced ones bill n × the catalog per-image rate
	// (cost_status "priced" even with no usage block). Without a per-image
	// rate the legacy unknown-price settlement stands.
	unitPriced := false
	if !ext.PriceKnown {
		if entry, ok := gw.unitPrice(providerName, admitted.Info.ModelName, pricing.UnitPerImage); ok {
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

	gw.finishRequest(rctx, requestFinish{
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
		termination: completionTermination(rctx),
		eventNote:   true,
	}, nil)

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
