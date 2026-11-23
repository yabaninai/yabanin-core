package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"time"

	"github.com/reireirei/yabanin/pkg/budget"
	apierrors "github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/logctx"
	"github.com/reireirei/yabanin/pkg/pricing"
	"github.com/reireirei/yabanin/pkg/provider"
)

// audioFormPart is one collected multipart part: a text form field or the
// binary file part. The request stream can be read only once, so parts are
// collected during the admission pass and re-encoded afterwards; the file
// part stays in memory bounded by the 10 MiB gateway body cap.
type audioFormPart struct {
	name        string
	filename    string
	contentType string
	value       string // text form fields
	data        []byte // file part bytes
	file        bool
}

const (
	audioMaxMultipartParts = 32
	// Keep the existing 10 MiB route body allowance compatible: a text field
	// may consume the whole request budget, while the aggregate body cap keeps
	// retained multipart data bounded.
	audioMaxFieldBytes = 10 << 20
)

var (
	errAudioMultipartPartsLimit = errors.New("audio multipart part count exceeds limit")
	errAudioFieldTooLarge       = errors.New("audio multipart field exceeds limit")
	errAudioPartTooLarge        = errors.New("audio multipart file exceeds limit")
	errAudioMultipleFiles       = errors.New("audio multipart has multiple files")
)

// multipart/form-data in, upstream JSON out byte-identical. The form is
// stream-parsed (never ParseMultipartForm full-buffering), admission runs on
// a metadata-only text projection (D3 — audio bytes are never persisted,
// D4 — guards scan the text fields, not the binary part), and the multipart
// stream is rebuilt with the model field rewritten to the resolved registry
// name before the upstream call.
// readTranscriptionRequest stream-parses and validates the
// /v1/audio/transcriptions multipart form. ok=false means the caller
// already answered the client (or the client walked away — N3).
func readTranscriptionRequest(w http.ResponseWriter, r *http.Request) (parts []audioFormPart, ok bool) {
	mr, err := r.MultipartReader()
	if err != nil {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
			"expected a multipart/form-data request")
		return nil, false
	}
	parts, err = audioReadForm(mr)
	if err != nil {
		if r.Context().Err() != nil {
			// N3: the client walked away mid-upload — the response target is
			// gone and writing the envelope would race the server's conn
			// teardown (found by the wire test under -race)
			return nil, false
		}
		writeAudioBodyError(w, err)
		return nil, false
	}
	if audioFieldValue(parts, "model") == "" {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "model is required")
		return nil, false
	}
	if audioFilePart(parts) == nil {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "file is required")
		return nil, false
	}
	return parts, true
}

// multipart/form-data in, upstream JSON out byte-identical. The form is
// stream-parsed (never ParseMultipartForm full-buffering), admission runs on
// a metadata-only text projection (D3 — audio bytes are never persisted,
// D4 — guards scan the text fields, not the binary part), and the multipart
// stream is rebuilt with the model field rewritten to the resolved registry
// name before the upstream call.
func (gw *gateway) audioTranscriptions(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	l := logctx.From(r.Context(), gw.log)
	parts, ok := readTranscriptionRequest(w, r)
	if !ok {
		return
	}
	model := audioFieldValue(parts, "model")
	filePart := audioFilePart(parts)
	admitted, ok := gw.admit(w, r, admitInput{
		Endpoint: "audio.transcriptions",
		Model:    model,
		Body:     audioFormMetadata(parts, filePart),
		NoRemap:  true,
	})
	if !ok {
		return
	}
	if !gw.openAICompatRouteReady(w, admitted.Info.Provider, "transcriptions", "transcriptions are not supported for this provider") {
		return
	}

	rctx := r.Context()
	rctx = withInvocationIdentity(rctx, admitted.Invocation)
	// T02: the bound is per AUDIO SECOND derived conservatively from the
	// payload size (8 kbit/s floor, rounded up); models the unit catalog
	// does not price per second keep the token-free estimate path and are
	// refused in enforce mode as unpriced (fail-closed, I3).
	breq := gw.reservationRequest(rctx, admitted.OrgID, admitted.TeamID, admitted.AgentID, admitted.SessionKeyID,
		admitted.Info, admitted.Body, nil, true)
	breq = withUnitDemand(breq, pricing.UnitPerAudioSecond, transcriptionReservationSeconds(len(filePart.data)))
	rctx, gate, ok := gw.reservePlannedRequest(rctx, w, r, "audio.transcriptions", breq)
	if !ok {
		return
	}

	ctx, cancel, client, apiKey, upstreamURL, ok := gw.mediaDispatch(w, rctx, l, gate, admitted)
	if !ok {
		return
	}
	defer cancel()
	rebuilt, extra, err := audioRebuild(parts, admitted.Info.ModelName)
	if err != nil {
		gate.finalizeNoEvent(budget.TerminationUpstreamErr)
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "failed to encode upstream request")
		return
	}
	if !gw.confirmPaidStart(w, l, gate, rctx, invocationKindChat) {
		return
	}

	resp, err := client.Do(ctx, "/v1/audio/transcriptions", rebuilt, apiKey, false, extra)
	if err != nil {
		closeUpstream(l, resp)
		gate.finalizeNoEvent(mediaTermination(rctx))
		apierrors.Write(w, http.StatusBadGateway, apierrors.ErrorCodeAPI, "upstream request failed")
		return
	}
	defer resp.Body.Close()

	limited, ok := readMediaResponse(w, rctx, gate, resp, audioResponseLimit, "upstream response exceeds the audio size limit")
	if !ok {
		return
	}
	gw.finishAudioTranscription(rctx, w, l, admitted, providerName(admitted), upstreamURL, resp, started, limited)
}

// finishAudioTranscription settles the served transcription durably —
// provider usage or the T02 per-second fallback, the usage record,
// terminal facts — then writes the upstream JSON byte-identical with the
// upstream Content-Type.
func (gw *gateway) finishAudioTranscription(rctx context.Context, w http.ResponseWriter, l *slog.Logger, admitted admitted, prov, upstreamURL string, resp *http.Response, started time.Time, limited []byte) {
	// Usage is "provider" only when the upstream JSON carries a usage block
	tokensIn, tokensOut, source := audioUsage(limited)
	usage := provider.Usage{
		PromptTokens:     tokensIn,
		CompletionTokens: tokensOut,
		TotalTokens:      tokensIn + tokensOut,
		Source:           source,
	}
	ext := provider.ComputeCost(usage, prov, admitted.Info.ModelName)
	// T02: when the upstream reported no token usage and the pinned unit
	// catalog prices the model per audio second, the cost is rate × the
	// verbose_json duration. Responses without a duration (plain
	// text/JSON) stay on the legacy unknown-price settlement — the
	// size-derived reservation quantity is never reused for billing.
	unitPriced := false
	if source == "" && !ext.PriceKnown {
		if entry, ok := gw.unitPrice(prov, admitted.Info.ModelName, pricing.UnitPerAudioSecond); ok {
			if secs, ok := transcriptionResponseDuration(limited); ok {
				ext.EstimatedCostUSD = entry.Rate * secs
				ext.PriceKnown = true
				unitPriced = true
			}
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
			TokensIn:                   tokensIn,
			TokensOut:                  tokensOut,
			EstimatedCostUSD:           ext.EstimatedCostUSD,
			Endpoint:                   "audio.transcriptions",
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
		contentType = "application/json"
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(limited)
}

// audioReadForm stream-parses the multipart reader into ordered parts: text
// fields as strings, file parts as bytes. Read errors (including the 10 MiB
// MaxBytesReader cap and mid-stream truncation) propagate to the caller.
func audioReadForm(mr *multipart.Reader) ([]audioFormPart, error) {
	var parts []audioFormPart
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			return parts, nil
		}
		if err != nil {
			return nil, err
		}
		if len(parts) >= audioMaxMultipartParts {
			return nil, errAudioMultipartPartsLimit
		}
		limit := int64(audioMaxFieldBytes + 1)
		if p.FileName() != "" {
			limit = 10*1024*1024 + 1
		}
		data, err := io.ReadAll(io.LimitReader(p, limit))
		if err != nil {
			return nil, err
		}
		if p.FileName() != "" {
			for _, existing := range parts {
				if existing.file {
					return nil, errAudioMultipleFiles
				}
			}
			if len(data) > 10*1024*1024 {
				return nil, errAudioPartTooLarge
			}
			parts = append(parts, audioFormPart{
				name:        p.FormName(),
				filename:    p.FileName(),
				contentType: p.Header.Get("Content-Type"),
				data:        data,
				file:        true,
			})
			continue
		}
		if len(data) > audioMaxFieldBytes {
			return nil, errAudioFieldTooLarge
		}
		parts = append(parts, audioFormPart{name: p.FormName(), value: string(data)})
	}
}

// audioFieldValue returns the first text-field value with the given name.
func audioFieldValue(parts []audioFormPart, name string) string {
	for _, p := range parts {
		if !p.file && p.name == name {
			return p.value
		}
	}
	return ""
}

// audioFilePart returns the first file part, or nil when the request has none.
func audioFilePart(parts []audioFormPart) *audioFormPart {
	for i := range parts {
		if parts[i].file {
			return &parts[i]
		}
	}
	return nil
}

// the text form fields plus file name, size and content type. Raw audio
// bytes never reach the event stream; egress guards scan this text
// projection only, never the binary part (D4 recommended default).
func audioFormMetadata(parts []audioFormPart, file *audioFormPart) []byte {
	meta := make(map[string]any, len(parts)+1)
	for _, p := range parts {
		if !p.file {
			meta[p.name] = p.value
		}
	}
	meta["file"] = map[string]any{
		"filename":     file.filename,
		"size":         len(file.data),
		"content_type": file.contentType,
	}
	out, err := json.Marshal(meta)
	if err != nil {
		return []byte("{}")
	}
	return out
}

// audioRebuild is the handler's rebuild seam: a package variable so tests
// can force the defensive encode failure the bytes.Buffer-backed multipart
// writer cannot produce by itself (audioRebuildForm's write targets cannot
// return errors under the pinned toolchain).
var audioRebuild = audioRebuildForm

// audioRebuildForm re-encodes the collected parts into the upstream multipart
// stream: the model field value is replaced with the resolved registry model
// name, every other text field is preserved and the file part is copied
// byte-identical. The returned header carries the new boundary so the
// existing applyExtraHeaders override replaces the adapter's
// application/json Content-Type — no provider/upstream signature change.
func audioRebuildForm(parts []audioFormPart, model string) ([]byte, http.Header, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, part := range parts {
		if !part.file {
			value := part.value
			if part.name == "model" {
				value = model
			}
			if err := mw.WriteField(part.name, value); err != nil {
				return nil, nil, err
			}
			continue
		}
		hdr := make(textproto.MIMEHeader, 2)
		hdr.Set("Content-Disposition",
			mime.FormatMediaType("form-data", map[string]string{"name": part.name, "filename": part.filename}))
		if part.contentType != "" {
			hdr.Set("Content-Type", part.contentType)
		}
		fw, err := mw.CreatePart(hdr)
		if err != nil {
			return nil, nil, err
		}
		if _, err := io.Copy(fw, bytes.NewReader(part.data)); err != nil {
			return nil, nil, err
		}
	}
	if err := mw.Close(); err != nil {
		return nil, nil, err
	}
	extra := http.Header{}
	extra.Set("Content-Type", "multipart/form-data; boundary="+mw.Boundary())
	return buf.Bytes(), extra, nil
}
