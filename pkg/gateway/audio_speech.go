package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/reireirei/yabanin/pkg/budget"
	apierrors "github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/httpmw"
	"github.com/reireirei/yabanin/pkg/logctx"
	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// audioResponseLimit caps how many upstream response bytes an audio endpoint
// embeddingsResponseLimit. A payload past the cap is answered 502, never
// truncated to the client.
const audioResponseLimit = 64 << 20

// JSON in, upstream binary audio out byte-identical with the upstream
// Content-Type. Admission, reservation (out_cap=0), limits and the event
// contract mirror the embeddings pipeline; usage is "none" (D2 — no audio
// pricing exists, no invented per-minute/per-character cost).
// speechRequest is the validated /v1/audio/speech JSON probe: the fields
// the admission, reservation and settlement phases need. The stream flag
// is validated during the read but never forwarded — SSE audio is outside
// the v1 subset (M5/D5).
type speechRequest struct {
	Model string `json:"model"`
	Input string `json:"input"`
	Voice string `json:"voice"`
}

// readSpeechRequest decodes and validates the /v1/audio/speech request
// body. ok=false means the caller already answered the client.
func readSpeechRequest(w http.ResponseWriter, r *http.Request) (req speechRequest, body []byte, ok bool) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		if r.Context().Err() != nil {
			// N3: the client walked away mid-body — the response target is
			// gone and writing the envelope would race the server's conn
			// teardown.
			return req, nil, false
		}
		writeAudioBodyError(w, err)
		return req, nil, false
	}
	var probe struct {
		speechRequest
		Stream bool `json:"stream"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "malformed JSON: "+err.Error())
		return req, nil, false
	}
	// M5/D5: SSE audio streaming is outside the v1 subset — reject before
	// any admission or upstream work (upstream call count stays 0).
	if probe.Stream || audioWantsEventStream(r) {
		apierrors.WriteWithCode(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
			"audio streaming is not supported", apierrors.CodeUnsupportedFeature)
		return req, nil, false
	}
	if probe.Model == "" {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "model is required")
		return req, nil, false
	}
	if probe.Input == "" {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "input is required")
		return req, nil, false
	}
	if probe.Voice == "" {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "voice is required")
		return req, nil, false
	}
	return probe.speechRequest, body, true
}

// JSON in, upstream binary audio out byte-identical with the upstream
// Content-Type. Admission, reservation (out_cap=0), limits and the event
// contract mirror the embeddings pipeline; usage is "none" (D2 — no audio
// pricing exists, no invented per-minute/per-character cost).
func (gw *gateway) audioSpeech(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	l := logctx.From(r.Context(), gw.log)
	req, body, ok := readSpeechRequest(w, r)
	if !ok {
		return
	}
	admitted, ok := gw.admit(w, r, admitInput{
		Endpoint: "audio.speech",
		Model:    req.Model,
		Body:     body,
		NoRemap:  true,
	})
	if !ok {
		return
	}
	if !openAICompatProvider(admitted.Info.Provider) {
		apierrors.WriteWithCode(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
			"speech is not supported for this provider", "speech_not_supported_for_provider")
		return
	}
	if gw.pool == nil {
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "upstream is not configured")
		return
	}

	// output tokens, out_cap = 0. T02: the bound is per INPUT CHARACTER
	// (utf-8 rune count) times the catalog per-character rate; a model the
	// unit catalog does not price per character (gpt-4o-mini-tts bills
	// tokens) keeps the token-free estimate path and is refused in enforce
	// mode as unpriced (fail-closed, I3).
	rctx := r.Context()
	rctx = withInvocationIdentity(rctx, admitted.Invocation)
	gate, ok := gw.reservationPlan(w, r, "audio.speech",
		withUnitDemand(
			gw.reservationRequest(rctx, admitted.OrgID, admitted.TeamID, admitted.AgentID, admitted.SessionKeyID,
				admitted.Info, admitted.Body, nil, true),
			pricing.UnitPerCharacter, float64(utf8.RuneCountInString(req.Input))))
	if !ok {
		return
	}
	rctx = withReservationGate(rctx, gate)
	if !gate.reserve(rctx) {
		return
	}

	ctx, cancel, client, apiKey, upstreamURL, ok := gw.mediaDispatch(w, rctx, l, gate, admitted)
	if !ok {
		return
	}
	defer cancel()
	upstreamBody := upstream.OverrideModelRaw(admitted.Body, admitted.Info.ModelName)
	// Preview2 durable accounting: the confirmed start commits immediately
	// BEFORE the first paid provider dispatch — after every fallible local
	// setup step above (pool wiring, model remap), so a local failure never
	// strands a durable admission for a request that never dispatched.
	// Fail closed: an unwritten start (write error, timeout or lost ACK —
	// outcome unknown) refuses the request with ZERO provider arrivals
	// under the history_unavailable envelope, and the escrow is released.
	if err := gw.confirmPaidInvocation(rctx, invocationKindChat); err != nil {
		gate.finalizeNoEvent(budget.TerminationPolicyDenied)
		l.Warn("refusing paid dispatch: durable start unwritten", "error", err)
		writeInvocationStartRefusal(w, err)
		return
	}
	resp, err := client.Do(ctx, "/v1/audio/speech", upstreamBody, apiKey, false, nil)
	if err != nil {
		closeUpstream(l, resp)
		gate.finalizeNoEvent(mediaTermination(rctx))
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "upstream request failed")
		return
	}
	defer resp.Body.Close()

	audio, over, err := readAudioResponse(resp.Body)
	if err != nil {
		gate.finalizeNoEvent(mediaTermination(rctx))
		writePaidBodyError(w, "failed to read upstream response")
		return
	}
	if over {
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		writePaidBodyError(w, "upstream response exceeds the audio size limit")
		return
	}
	if resp.StatusCode != http.StatusOK {
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		status, errType := apierrors.MapUpstreamStatus(resp.StatusCode)
		apierrors.Write(w, status, errType, "upstream request failed")
		return
	}
	gw.finishAudioSpeech(rctx, w, l, admitted, providerName(admitted), upstreamURL, resp, started, req.Input, audio)
}

// providerName resolves the upstream provider an admitted media request
// dispatches to: the admission-resolved provider, defaulting to the
// OpenAI-compat base.
func providerName(admitted admitted) string {
	if admitted.Info.Provider == "" {
		return "openai"
	}
	return admitted.Info.Provider
}

// mediaDispatch prepares the paid upstream dispatch shared by the media
// pipelines (speech, transcriptions, images): the whole-request timeout
// context, the upstream client for the resolved provider, and its
// addressing and key material. The pool failure finalizes the reservation
// gate and answers the client; ok=false means the caller is done.
func (gw *gateway) mediaDispatch(w http.ResponseWriter, rctx context.Context, l *slog.Logger, gate *reservationGate, admitted admitted) (ctx context.Context, cancel context.CancelFunc, client *upstream.Client, apiKey, upstreamURL string, ok bool) {
	timeout := admitted.Info.UpstreamTimeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel = context.WithTimeout(rctx, timeout)
	apiKey = admitted.Info.UpstreamAPIKey
	if apiKey == "" {
		apiKey = gw.getUpstreamAPIKey()
	}
	upstreamURL = gw.upstreamURL(admitted.Info)
	client, err := gw.pool.Get(upstreamURL, providerName(admitted))
	if err != nil {
		l.Warn("upstream client unavailable", "provider", providerName(admitted), "error", err.Error())
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "failed to initialise upstream client")
		cancel()
		return nil, nil, nil, "", "", false
	}
	return ctx, cancel, client, apiKey, upstreamURL, true
}

// finishAudioSpeech settles the served speech response durably — D2/T02
// pricing, the usage record, terminal facts — then writes the audio bytes
// byte-identical with the upstream Content-Type.
func (gw *gateway) finishAudioSpeech(rctx context.Context, w http.ResponseWriter, l *slog.Logger, admitted admitted, prov, upstreamURL string, resp *http.Response, started time.Time, input string, audio []byte) {
	// D2: token usage does not exist for speech — TokensIn/TokensOut stay 0
	// and the usage source is "none". T02: when the pinned unit catalog
	// prices the model per character, the cost is rate × unicode input
	// characters (cost_status "priced"); otherwise ComputeCost yields the
	// legacy unknown price (cost_status "no_usage"), never a fabricated
	// zero-priced success.
	usage := provider.Usage{Source: provider.UsageSourceNone}
	ext := provider.ComputeCost(usage, prov, admitted.Info.ModelName)
	unitPriced := false
	if !ext.PriceKnown {
		if entry, ok := gw.unitPrice(prov, admitted.Info.ModelName, pricing.UnitPerCharacter); ok {
			ext.EstimatedCostUSD = entry.Rate * float64(utf8.RuneCountInString(input))
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
			TokensIn:                   0,
			TokensOut:                  0,
			EstimatedCostUSD:           ext.EstimatedCostUSD,
			Endpoint:                   "audio.speech",
			UsageSource:                usageSourceOrNone(usage.Source),
			CostStatus:                 costStatusUnit(costStatus(false, usage.Source, ext.PriceKnown), unitPriced),
			Method:                     http.MethodPost,
			InferenceRegion:            admitted.Info.Region,
			ModelOriginCountry:         admitted.Info.Provider,
			LogStorageRegion:           gw.cfg.Region,
			ProviderEntityJurisdiction: admitted.Info.Provider,
			Labels:                     labelsFrom(rctx),
		},
		info: admitted.Info,
		resp: resp,
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

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(audio)
}

// audioUsage parses the optional usage block of an upstream audio JSON
// response (transcriptions). It returns the input/output token counts and
// the usage source: "provider" only when the upstream actually reported a
// usage object, "" otherwise (the caller maps "" to "none").
func audioUsage(body []byte) (int64, int64, string) {
	var parsed struct {
		Usage *struct {
			PromptTokens *int64 `json:"prompt_tokens"`
			InputTokens  *int64 `json:"input_tokens"`
			OutputTokens *int64 `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || parsed.Usage == nil {
		return 0, 0, ""
	}
	var in int64
	switch {
	case parsed.Usage.PromptTokens != nil:
		in = *parsed.Usage.PromptTokens
	case parsed.Usage.InputTokens != nil:
		in = *parsed.Usage.InputTokens
	}
	var out int64
	if parsed.Usage.OutputTokens != nil {
		out = *parsed.Usage.OutputTokens
	}
	return in, out, provider.UsageSourceProvider
}

// readAudioResponse reads up to audioResponseLimit bytes and reports whether
// the upstream payload exceeds the cap (one extra byte is read to detect it).
func readAudioResponse(body io.Reader) (data []byte, over bool, err error) {
	data, err = io.ReadAll(io.LimitReader(body, audioResponseLimit+1))
	if err != nil {
		return nil, false, err
	}
	if len(data) > audioResponseLimit {
		return nil, true, nil
	}
	return data, false, nil
}

// writeAudioBodyError maps a request-body read failure: the 10 MiB gateway
// else is a malformed body 400.
func writeAudioBodyError(w http.ResponseWriter, err error) {
	if httpmw.IsMaxBytesError(err) || errors.Is(err, errAudioPartTooLarge) || errors.Is(err, errAudioFieldTooLarge) || errors.Is(err, errAudioMultipartPartsLimit) {
		apierrors.Write(w, http.StatusRequestEntityTooLarge, apierrors.ErrorCodeInvalidRequest, "request body too large")
		return
	}
	if errors.Is(err, errAudioMultipleFiles) {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "multiple file parts are not supported")
		return
	}
	apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "request body too large or malformed")
}

// audioWantsEventStream reports whether the client asked for an SSE audio
// stream (M5 — rejected 400 unsupported_feature before admission).
func audioWantsEventStream(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/event-stream")
}

// mediaTermination classifies a media-pipeline failure (audio and images)
// for the finalize contract: a dead request context means the client walked
// away (N3), not an upstream error.
func mediaTermination(rctx context.Context) budget.Termination {
	if rctx.Err() != nil {
		return budget.TerminationClientCancel
	}
	return budget.TerminationUpstreamErr
}
