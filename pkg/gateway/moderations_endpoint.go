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
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// moderationsResponseLimit bounds the buffered upstream moderations response
// (64 MiB, images/embeddings parity): results[] category scores are opaque
// JSON the gateway passes through without re-classifying anything itself.
const moderationsResponseLimit = 64 << 20

// moderationsMaxInputs caps the array form of the input field (contract
// subset matrix): one moderations call classifies at most 256 items.
const moderationsMaxInputs = 256

// upstream passthrough of {model, input} to the OpenAI-compat
// /v1/moderations path with the categories/scores response relayed
// byte-honestly. Usage accounting follows D3: provider tokens when the
// upstream reports them, zero + UsageSourceNone otherwise — OpenAI's
// moderations carry no usage block, and that stays no_usage, never a
// fabricated estimate or a silent zero-priced success.
func (gw *gateway) moderations(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	l := logctx.From(r.Context(), gw.log)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		// The 10 MiB gateway cap (httpmw.MaxBody) answers 413 — the
		// contract's payload-size refusal (audio/images parity,
		if httpmw.IsMaxBytesError(err) {
			apierrors.Write(w, http.StatusRequestEntityTooLarge, apierrors.ErrorCodeInvalidRequest, "request body too large")
			return
		}
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "request body too large or malformed")
		return
	}
	var req struct {
		Model string          `json:"model"`
		Input json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "malformed JSON: "+err.Error())
		return
	}
	if req.Model == "" {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "model is required")
		return
	}
	if !moderationsInputValid(w, req.Input) {
		return
	}

	admitted, ok := gw.admit(w, r, admitInput{
		Endpoint: "moderations",
		Model:    req.Model,
		Body:     body,
		NoRemap:  true,
	})
	if !ok {
		return
	}
	if !openAICompatProvider(admitted.Info.Provider) {
		apierrors.WriteWithCode(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
			"moderations are not supported for this provider", "moderations_not_supported_for_provider")
		return
	}
	if gw.pool == nil {
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "upstream is not configured")
		return
	}

	// NEXT-18c (ADR-0001 §5.1) + ratified D3: reservation rides the
	// embeddings-style input pre-estimate (no generated output tokens,
	// out_cap = 0); the wallet settles on the actual provider usage below.
	rctx := r.Context()
	gate, ok := gw.reservationPlan(w, r, "moderations",
		gw.reservationRequest(rctx, admitted.OrgID, admitted.TeamID, admitted.AgentID, admitted.SessionKeyID,
			admitted.Info, admitted.Body, nil, true))
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
	resp, err := client.Do(ctx, "/v1/moderations", upstreamBody, apiKey, false, nil)
	if err != nil {
		closeUpstream(l, resp)
		gate.finalizeNoEvent(mediaTermination(rctx))
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "upstream request failed")
		return
	}
	defer resp.Body.Close()

	// Read one byte past the limit so an oversized upstream body is refused
	// as an upstream error instead of being silently truncated (images
	// parity; the gateway never delivers a partial moderations payload).
	limited, err := io.ReadAll(io.LimitReader(resp.Body, moderationsResponseLimit+1))
	if err != nil {
		gate.finalizeNoEvent(mediaTermination(rctx))
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "failed to read upstream response")
		return
	}
	if len(limited) > moderationsResponseLimit {
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

	usage := moderationsUsage(limited)
	ext := provider.ComputeCost(usage, providerName, admitted.Info.ModelName)
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
			Endpoint:                   "moderations",
			UsageSource:                usageSourceOrNone(usage.Source),
			CostStatus:                 costStatus(false, usage.Source, ext.PriceKnown),
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

// moderationsInputValid validates the input field locally: a non-empty JSON
// string, or an array of at most moderationsMaxInputs items. Element shape
// is upstream-owned and passed through verbatim.
func moderationsInputValid(w http.ResponseWriter, raw json.RawMessage) bool {
	if len(raw) == 0 || string(raw) == "null" {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "input is required")
		return false
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		// Not an array: only the plain string form is accepted.
		var s string
		if err := json.Unmarshal(raw, &s); err != nil || s == "" {
			apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
				"input must be a non-empty string or an array of items")
			return false
		}
		return true
	}
	if len(items) == 0 {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "input must not be empty")
		return false
	}
	if len(items) > moderationsMaxInputs {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
			"too many input items: the limit is 256 per request")
		return false
	}
	return true
}

// moderationsUsage parses the upstream moderations usage block when present
// (compat providers may report one). An absent or malformed block yields
// zero tokens with UsageSourceNone — no fabricated estimate (D3
// actual-billing default; OpenAI moderations carry no usage block).
func moderationsUsage(body []byte) provider.Usage {
	u, ok := tokenUsageBlock(body)
	if !ok {
		return provider.Usage{}
	}
	return u
}
