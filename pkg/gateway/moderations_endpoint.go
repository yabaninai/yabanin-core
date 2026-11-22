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
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// moderationsResponseLimit bounds the buffered upstream moderations response
// (64 MiB, images/embeddings parity): results[] category scores are opaque
// JSON the gateway passes through without re-classifying anything itself.
const moderationsResponseLimit = 64 << 20

// moderationsMaxInputs caps the array form of the input field (contract
// subset matrix): one moderations call classifies at most 256 items.
const moderationsMaxInputs = 256

// moderationsRequest is the validated client shape of the moderations
// route.
type moderationsRequest struct {
	Model string          `json:"model"`
	Input json.RawMessage `json:"input"`
}

// parseModerationsRequest reads and validates the client request. Every
// refusal lands BEFORE admission, so a rejected request leaves no durable
// trace.
func parseModerationsRequest(w http.ResponseWriter, r *http.Request) (moderationsRequest, []byte, bool) {
	body, ok := readRouteBody(w, r)
	if !ok {
		return moderationsRequest{}, nil, false
	}
	var req moderationsRequest
	if err := json.Unmarshal(body, &req); err != nil {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "malformed JSON: "+err.Error())
		return moderationsRequest{}, nil, false
	}
	if req.Model == "" {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "model is required")
		return moderationsRequest{}, nil, false
	}
	if !moderationsInputValid(w, req.Input) {
		return moderationsRequest{}, nil, false
	}
	return req, body, true
}

// upstream passthrough of {model, input} to the OpenAI-compat
// /v1/moderations path with the categories/scores response relayed
// byte-honestly. Usage accounting follows D3: provider tokens when the
// upstream reports them, zero + UsageSourceNone otherwise — OpenAI's
// moderations carry no usage block, and that stays no_usage, never a
// fabricated estimate or a silent zero-priced success.
func (gw *gateway) moderations(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	l := logctx.From(r.Context(), gw.log)
	req, body, ok := parseModerationsRequest(w, r)
	if !ok {
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
	if !gw.openAICompatRouteReady(w, admitted.Info.Provider, "moderations", "moderations are not supported for this provider") {
		return
	}
	// NEXT-18c (ADR-0001 §5.1) + ratified D3: reservation rides the
	// embeddings-style input pre-estimate (no generated output tokens,
	// out_cap = 0); the wallet settles on the actual provider usage below.
	rctx, gate, ok := gw.reservePaidDispatch(r.Context(), w, r, "moderations", admitted, nil, true)
	if !ok {
		return
	}
	client, upstreamBody, apiKey, providerName, upstreamURL, ok := gw.paidUpstreamClient(l, w, gate, admitted, admitted.Info.Provider)
	if !ok {
		return
	}
	if !gw.confirmPaidStart(w, l, gate, rctx, invocationKindChat) {
		return
	}
	resp, usage, limited, ok := relayModerationsResponse(rctx, w, l, gate, client, admitted.Info, upstreamBody, apiKey)
	if resp != nil {
		// The settle stages below keep the body open (headers ride the
		// finish event); it closes after the reply is written.
		defer resp.Body.Close()
	}
	if !ok {
		return
	}
	gw.finishBufferedJSONRoute(bufferedJSONFinish{
		rctx: rctx, w: w, admitted: admitted, usage: usage,
		providerName: providerName, endpoint: "moderations", upstreamURL: upstreamURL,
		started: started, resp: resp, payload: limited,
	})
}

// relayModerationsResponse performs the paid /v1/moderations dispatch and
// buffers the upstream reply. On failure the refusal response was already
// written; the returned response (non-nil after a successful dial) still
// owns its open body, so the caller defers the close and the settle stages
// keep today's ordering.
func relayModerationsResponse(rctx context.Context, w http.ResponseWriter, l *slog.Logger, gate *reservationGate, client *upstream.Client, info resolver.ModelInfo, upstreamBody []byte, apiKey string) (*http.Response, provider.Usage, []byte, bool) {
	timeout := info.UpstreamTimeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(rctx, timeout)
	defer cancel()
	resp, err := client.Do(ctx, "/v1/moderations", upstreamBody, apiKey, false, nil)
	if err != nil {
		closeUpstream(l, resp)
		gate.finalizeNoEvent(mediaTermination(rctx))
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "upstream request failed")
		return nil, provider.Usage{}, nil, false
	}

	// Read one byte past the limit so an oversized upstream body is refused
	// as an upstream error instead of being silently truncated (images
	// parity; the gateway never delivers a partial moderations payload).
	limited, err := io.ReadAll(io.LimitReader(resp.Body, moderationsResponseLimit+1))
	if err != nil {
		gate.finalizeNoEvent(mediaTermination(rctx))
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "failed to read upstream response")
		return resp, provider.Usage{}, nil, false
	}
	if len(limited) > moderationsResponseLimit {
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "upstream response too large")
		return resp, provider.Usage{}, nil, false
	}
	if resp.StatusCode != http.StatusOK {
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		status, errType := apierrors.MapUpstreamStatus(resp.StatusCode)
		apierrors.Write(w, status, errType, "upstream request failed")
		return resp, provider.Usage{}, nil, false
	}
	return resp, moderationsUsage(limited), limited, true
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
