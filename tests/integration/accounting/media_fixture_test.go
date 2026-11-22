//go:build integration

package accounting

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

// Media-family fixture extensions: the binary speech and multipart
// transcription codecs the ten-family sweep documented as omitted for
// codec scope (refusalfamilies_test.go). Ledger semantics are identical
// to the JSON families — arrival, dispatch, receipt — with one
// codec-specific rule mirrored from the product's own pre-admission
// contract (audio_transcriptions.go): a body that is not parseable
// multipart, a missing model field, or anything but exactly one file
// part is a 400 that is recorded as an arrival but never a dispatch.

const (
	// fixtureSpeechContentType is the upstream Content-Type of the
	// deterministic speech artifact; the product relays it verbatim.
	fixtureSpeechContentType = "audio/wav"
	// fixtureSpeechInput is the synthesis text of every speech request.
	// Its rune count is the product's per-character reservation demand;
	// no unit catalog is seeded on this stand, so the demand never
	// becomes a price and the durable outcome stays the explicit
	// unpriced status.
	fixtureSpeechInput = "accounting acceptance speech probe"
	// fixtureSpeechVoice is the requested voice; the fixture accepts any.
	fixtureSpeechVoice = "fixture"
	// fixtureSpeechSamples is the PCM sample count of the artifact:
	// 8000 samples = 0.5s mono 16-bit at 8kHz.
	fixtureSpeechSamples = 8000
)

const (
	// fixtureTranscribeText is the transcript text of the healthy reply.
	fixtureTranscribeText = "fixture transcription text"
	// fixtureTranscribePromptTokens/OutputTokens are distinct from every
	// JSON family (chat 7/3, embeddings 7/0): a durable row can satisfy
	// only this family, so a fixture copy bug surfaces as a token
	// mismatch. 11 input tokens at the seeded 2.0 per-M input rate and
	// zero-markup resale settle to exactly 22 micro-USD — distinct from
	// chat's 32.
	fixtureTranscribePromptTokens = 11
	fixtureTranscribeOutputTokens = 0
	// fixtureTranscribeMicroUSDCost is the independently computed signed
	// wallet debit of the healthy transcription control.
	fixtureTranscribeMicroUSDCost = 22
	// fixtureTranscribeAudioFile is the healthy upload's filename.
	fixtureTranscribeAudioFile = "probe.wav"
	// fixtureTranscribeBadUsageFile carries the corruption marker: the
	// fixture replies 200 with a malformed usage block (string token
	// count), which the product must treat as no usage — never invented
	// tokens, never a fabricated price.
	fixtureTranscribeBadUsageFile = "probe.bad-usage.wav"
	// fixtureTranscribeAudioContentType is the upload part content type.
	fixtureTranscribeAudioContentType = "audio/wav"
)

// fixtureTranscribeBadUsageMark keys the corrupted-usage fixture mode off
// the upload filename; the product rewrites only the model field and
// relays every other form value, so the marker reaches the fixture.
const fixtureTranscribeBadUsageMark = "bad-usage"

// fixtureTranscribeReply is the healthy transcription reply, built from a
// fixed-key-order template so the byte-exact relay assertion has an exact
// expected string.
func fixtureTranscribeReply() string {
	return fmt.Sprintf(`{"text":%q,"usage":{"prompt_tokens":%d,"total_tokens":%d}}`,
		fixtureTranscribeText, fixtureTranscribePromptTokens, fixtureTranscribePromptTokens)
}

// fixtureTranscribeBadUsageReply is the corrupted-usage variant the
// fail-closed control asserts: a 200 reply whose usage block cannot parse
// as token counts.
const fixtureTranscribeBadUsageReply = `{"text":"fixture transcription text","usage":{"prompt_tokens":"eleven","total_tokens":11}}`

// fixtureWAVBytes builds the deterministic WAV artifact served by the
// speech family: a 44-byte RIFF/WAVE header and PCM samples from a pure
// counter function. Pure and constant — the fixture, the healthy
// validator and every corruption control derive from the same bytes.
func fixtureWAVBytes() []byte {
	const header = 44
	const sampleRate = 8000
	dataLen := fixtureSpeechSamples * 2
	out := make([]byte, header+dataLen)
	copy(out, "RIFF")
	binary.LittleEndian.PutUint32(out[4:], uint32(36+dataLen))
	copy(out[8:], "WAVE")
	copy(out[12:], "fmt ")
	binary.LittleEndian.PutUint32(out[16:], 16) // PCM chunk size
	binary.LittleEndian.PutUint16(out[20:], 1)  // PCM format
	binary.LittleEndian.PutUint16(out[22:], 1)  // mono
	binary.LittleEndian.PutUint32(out[24:], sampleRate)
	binary.LittleEndian.PutUint32(out[28:], sampleRate*2) // byte rate
	binary.LittleEndian.PutUint16(out[32:], 2)            // block align
	binary.LittleEndian.PutUint16(out[34:], 16)           // bits per sample
	copy(out[36:], "data")
	binary.LittleEndian.PutUint32(out[40:], uint32(dataLen))
	for i := 0; i < fixtureSpeechSamples; i++ {
		// Deterministic, non-constant samples: a mutated or truncated
		// relay cannot coincide with the original.
		binary.LittleEndian.PutUint16(out[header+2*i:], uint16(i*251+103))
	}
	return out
}

// serveAudioSpeech delivers the deterministic WAV artifact with the
// binary content type the product relays verbatim. Dispatch and the hold
// barrier were already applied by serve/serveAccepted.
func (f *fixture) serveAudioSpeech(w http.ResponseWriter, rid, model, path string) {
	artifact := fixtureWAVBytes()
	w.Header().Set("Content-Type", fixtureSpeechContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(artifact)))
	w.WriteHeader(http.StatusOK)
	f.writeMediaResponse(w, rid, path, artifact)
}

// serveTranscriptionRequest parses and serves the multipart codec,
// mirroring the product's own pre-admission contract so the fixture can
// prove the gateway relayed a well-formed upload: not-multipart, missing
// model, zero or multiple file parts are 400s recorded as arrivals
// without dispatches. A valid upload is dispatched, held at the barrier
// and answered with the healthy reply — or, when the filename carries
// the corruption marker, with the malformed usage block.
func (f *fixture) serveTranscriptionRequest(w http.ResponseWriter, r *http.Request, rid string) {
	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "expected multipart/form-data", http.StatusBadRequest)
		return
	}
	model, filename, files, err := scanTranscriptionParts(mr)
	if err != nil {
		http.Error(w, "invalid multipart body", http.StatusBadRequest)
		return
	}
	switch {
	case model == "":
		http.Error(w, "model is required", http.StatusBadRequest)
		return
	case files == 0:
		http.Error(w, "file is required", http.StatusBadRequest)
		return
	case files > 1:
		http.Error(w, "multiple file parts", http.StatusBadRequest)
		return
	}

	f.append("dispatches", fixtureRecord{RequestID: rid, Path: r.URL.Path, AuthOK: true})
	if !f.waitForResponseRelease(r, rid) {
		return
	}
	reply := fixtureTranscribeReply()
	if strings.Contains(filename, fixtureTranscribeBadUsageMark) {
		reply = fixtureTranscribeBadUsageReply
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	f.writeMediaResponse(w, rid, r.URL.Path, []byte(reply))
}

func (f *fixture) writeMediaResponse(w http.ResponseWriter, rid, path string, payload []byte) {
	n, err := w.Write(payload)
	if err != nil || n != len(payload) {
		f.t.Logf("fixture: media response %s wrote %d of %d bytes: %v", rid, n, len(payload), err)
		return
	}
	f.append("receipts", fixtureRecord{RequestID: rid, Path: path, AuthOK: true})
}

// scanTranscriptionParts walks a multipart upload once, collecting the
// model field value, the last file part's filename and the file-part
// count. File bytes are discarded (bounded), mirroring the product's
// pre-admission validation contract.
func scanTranscriptionParts(mr *multipart.Reader) (model, filename string, files int, err error) {
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", "", 0, err
		}
		if part.FileName() == "" {
			if part.FormName() == "model" {
				value, _ := io.ReadAll(io.LimitReader(part, 1<<20))
				model = string(bytes.TrimSpace(value))
			}
			continue
		}
		files++
		filename = part.FileName()
		_, _ = io.Copy(io.Discard, io.LimitReader(part, 64<<20))
	}
	return model, filename, files, nil
}

// mediaReply is one binary-safe client outcome: raw response bytes, the
// relayed Content-Type and the transport error, if any.
type mediaReply struct {
	status      int
	body        []byte
	contentType string
	err         error
}

// httpPostSpeech sends one audio/speech request and returns the raw
// response bytes and Content-Type — binary-safe, unlike the JSON probe
// helpers. extra request headers (e.g. Accept: text/event-stream) are
// applied after the defaults and may be nil.
func httpPostSpeech(timeout time.Duration, url, apiKey, requestID, model, input, voice string, extra ...map[string]string) (status int, body []byte, contentType string, err error) {
	payload, err := json.Marshal(map[string]string{"model": model, "input": input, "voice": voice})
	if err != nil {
		return 0, nil, "", err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("X-Request-ID", requestID)
	for _, m := range extra {
		for k, v := range m {
			req.Header.Set(k, v)
		}
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, "", err
	}
	defer resp.Body.Close()
	body, err = io.ReadAll(io.LimitReader(resp.Body, 64<<20+1))
	if err != nil {
		return resp.StatusCode, nil, "", err
	}
	return resp.StatusCode, body, resp.Header.Get("Content-Type"), nil
}

// multipartFile is one upload part of a transcription request probe.
type multipartFile struct {
	filename    string
	contentType string
	data        []byte
}

// httpPostMultipart sends one multipart/form-data transcription request
// and returns the relayed response Content-Type. model may be ""
// (missing-model control); files may be empty (missing-file control) or
// hold more than one entry (multiple-files control). extraFields are
// additional text form fields.
func httpPostMultipart(timeout time.Duration, url, apiKey, requestID, model string, extraFields map[string]string, files ...multipartFile) (status int, body string, contentType string, err error) {
	bodyBuf, contentType, err := buildTranscriptionBody(model, extraFields, files)
	if err != nil {
		return 0, "", "", err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(bodyBuf.Bytes()))
	if err != nil {
		return 0, "", "", err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("X-Request-ID", requestID)
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, "", "", err
	}
	return resp.StatusCode, string(raw), resp.Header.Get("Content-Type"), nil
}

// buildTranscriptionBody encodes the multipart/form-data upload: text
// fields first, then each file part. It returns the finished buffer and
// the body's Content-Type (the multipart boundary).
func buildTranscriptionBody(model string, extraFields map[string]string, files []multipartFile) (*bytes.Buffer, string, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range extraFields {
		_ = mw.WriteField(k, v)
	}
	if model != "" {
		_ = mw.WriteField("model", model)
	}
	for _, file := range files {
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition",
			fmt.Sprintf(`form-data; name="file"; filename=%q`, file.filename))
		if file.contentType != "" {
			h.Set("Content-Type", file.contentType)
		}
		part, err := mw.CreatePart(h)
		if err != nil {
			return nil, "", err
		}
		if _, err := part.Write(file.data); err != nil {
			return nil, "", err
		}
	}
	if err := mw.Close(); err != nil {
		return nil, "", err
	}
	return &buf, mw.FormDataContentType(), nil
}
