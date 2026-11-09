package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/httpmw"
	"github.com/reireirei/yabanin/pkg/resolver"
)

// buildAudioMultipart encodes a transcription request exactly the way a
// client would: text fields first, then the binary file part.
func buildAudioMultipart(t *testing.T, fields map[string]string, fieldName, filename, contentType string, file []byte) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, name := range []string{"model", "language", "prompt", "response_format", "temperature"} {
		if v, ok := fields[name]; ok {
			if err := mw.WriteField(name, v); err != nil {
				t.Fatal(err)
			}
		}
	}
	if file != nil {
		h := make(map[string][]string)
		h["Content-Disposition"] = []string{
			`form-data; name="` + fieldName + `"; filename="` + filename + `"`,
		}
		if contentType != "" {
			h["Content-Type"] = []string{contentType}
		}
		fw, err := mw.CreatePart(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(file); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), mw.FormDataContentType()
}

func postAudioTranscriptions(t *testing.T, gw *gateway, body []byte, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/audio/transcriptions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	gw.routes(r)
	r.ServeHTTP(rec, req)
	return rec
}

func audioTranscriptionModel(upstreamURL string) resolver.ModelInfo {
	return resolver.ModelInfo{
		ModelName:      "whisper-1",
		Provider:       "openai",
		UpstreamURL:    upstreamURL,
		UpstreamAPIKey: "up-key",
		Enabled:        true,
	}
}

// parseUpstreamMultipart decodes a captured upstream multipart request back
// into field values and the raw file bytes.
func parseUpstreamMultipart(t *testing.T, r *http.Request) (fields map[string]string, file []byte, fileHeader string) {
	t.Helper()
	mr, err := r.MultipartReader()
	if err != nil {
		t.Fatalf("captured request is not multipart: %v", err)
	}
	fields = map[string]string{}
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			return fields, file, fileHeader
		}
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(p)
		if err != nil {
			t.Fatal(err)
		}
		if p.FileName() != "" {
			file = raw
			fileHeader = p.Header.Get("Content-Type")
			continue
		}
		fields[p.FormName()] = string(raw)
	}
}

// TestAudioTranscriptions_HappyPathSynthesizedWAV is example E1 / matrix
// row M3: a synthesized canonical WAV (audio_testsynth_test.go) crosses the
// rebuild byte-identical (sha256-pinned in-process), the model form field
// carries the resolved registry name, the multipart Content-Type overrides
// the adapter's application/json, and the completion event reports
// metadata-only payload with usage source "none".
func TestAudioTranscriptions_HappyPathSynthesizedWAV(t *testing.T) {
	wav := audioFixtureBytes(t, "hello.wav")
	wantSum := sha256.Sum256(wav)

	var calls atomic.Int64
	var gotFields map[string]string
	var gotFile []byte
	var gotFileHeader string
	var gotContentType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/v1/audio/transcriptions" {
			t.Errorf("upstream path %s", r.URL.Path)
		}
		gotContentType = r.Header.Get("Content-Type")
		gotFields, gotFile, gotFileHeader = parseUpstreamMultipart(t, r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"text":"hello world"}`))
	}))
	defer server.Close()

	gw := newAudioGateway(t, audioTranscriptionModel(server.URL))
	var evPtr atomic.Value
	evPtr.Store((*eventpub.Event)(nil))
	gw.eventNote = func(e *eventpub.Event) { evPtr.Store(e) }

	body, contentType := buildAudioMultipart(t, map[string]string{
		"model":           "m",
		"language":        "en",
		"prompt":          "greeting",
		"response_format": "json",
		"temperature":     "0",
	}, "file", "hello.wav", "audio/wav", wav)
	rec := postAudioTranscriptions(t, gw, body, contentType)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != `{"text":"hello world"}` {
		t.Fatalf("response body %q", rec.Body.String())
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream calls %d", calls.Load())
	}
	if gotFields["model"] != "whisper-1" {
		t.Fatalf("upstream model field %q, want resolved registry name whisper-1", gotFields["model"])
	}
	if gotFields["language"] != "en" || gotFields["prompt"] != "greeting" || gotFields["response_format"] != "json" || gotFields["temperature"] != "0" {
		t.Fatalf("text fields not preserved: %+v", gotFields)
	}
	if sha256.Sum256(gotFile) != wantSum {
		t.Fatalf("file part not byte-identical: got %d bytes want %d", len(gotFile), len(wav))
	}
	if gotFileHeader != "audio/wav" {
		t.Fatalf("file part content type %q", gotFileHeader)
	}
	if !bytes.HasPrefix([]byte(gotContentType), []byte("multipart/form-data; boundary=")) {
		t.Fatalf("upstream content type %q, want multipart boundary override", gotContentType)
	}

	ev := evPtr.Load().(*eventpub.Event)
	if ev == nil {
		t.Fatal("no request.completed event")
	}
	if ev.Endpoint != "audio.transcriptions" || ev.UsageSource != "none" || ev.TokensIn != 0 || ev.TokensOut != 0 {
		t.Fatalf("event %+v", ev)
	}
	if ev.ModelUsed != "whisper-1" || ev.StatusCode != http.StatusOK {
		t.Fatalf("event %+v", ev)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(ev.Payload), &payload); err != nil {
		t.Fatalf("event payload is not metadata JSON: %q", ev.Payload)
	}
	if payload["model"] != "m" {
		t.Fatalf("event payload model %v, want the client-sent form value", payload["model"])
	}
	fileMeta, ok := payload["file"].(map[string]any)
	if !ok || fileMeta["filename"] != "hello.wav" || fileMeta["content_type"] != "audio/wav" {
		t.Fatalf("event payload file metadata %v", payload["file"])
	}
}

// TestAudioTranscriptions_ProviderUsage: when the upstream JSON carries a
// usage block, the event reports provider-sourced tokens.
func TestAudioTranscriptions_ProviderUsage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"text":"ok","usage":{"prompt_tokens":5,"output_tokens":2}}`))
	}))
	defer server.Close()

	gw := newAudioGateway(t, audioTranscriptionModel(server.URL))
	var evPtr atomic.Value
	evPtr.Store((*eventpub.Event)(nil))
	gw.eventNote = func(e *eventpub.Event) { evPtr.Store(e) }

	wav := audioFixtureBytes(t, "hello.wav")
	body, contentType := buildAudioMultipart(t, map[string]string{"model": "m"}, "file", "hello.wav", "audio/wav", wav)
	rec := postAudioTranscriptions(t, gw, body, contentType)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	ev := evPtr.Load().(*eventpub.Event)
	if ev == nil || ev.UsageSource != "provider" || ev.TokensIn != 5 || ev.TokensOut != 2 {
		t.Fatalf("event %+v", ev)
	}
}

// TestAudioTranscriptions_MissingFile is example E2: no file part answers
// 400 "file is required" with the upstream call count at zero and no
// completed event (no reservation settled as spend).
func TestAudioTranscriptions_MissingFile(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()

	gw := newAudioGateway(t, audioTranscriptionModel(server.URL))
	var evPtr atomic.Value
	evPtr.Store((*eventpub.Event)(nil))
	gw.eventNote = func(e *eventpub.Event) { evPtr.Store(e) }

	body, contentType := buildAudioMultipart(t, map[string]string{"model": "m"}, "file", "hello.wav", "audio/wav", nil)
	rec := postAudioTranscriptions(t, gw, body, contentType)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	var env struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Error.Message != "file is required" || env.Error.Type != "invalid_request_error" {
		t.Fatalf("envelope %s", rec.Body.String())
	}
	if calls.Load() != 0 {
		t.Fatalf("upstream called %d times", calls.Load())
	}
	if ev := evPtr.Load().(*eventpub.Event); ev != nil {
		t.Fatalf("completed event on rejected request: %+v", ev)
	}
}

func TestAudioReadFormMultipartPartLimitBoundary(t *testing.T) {
	for _, count := range []int{audioMaxMultipartParts, audioMaxMultipartParts + 1} {
		t.Run(fmt.Sprintf("%d_parts", count), func(t *testing.T) {
			var body bytes.Buffer
			writer := multipart.NewWriter(&body)
			for i := 0; i < count; i++ {
				if err := writer.WriteField("field", "value"); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			parts, err := audioReadForm(multipart.NewReader(&body, writer.Boundary()))
			if count == audioMaxMultipartParts {
				if err != nil || len(parts) != count {
					t.Fatalf("audioReadForm returned %d parts, err=%v; want %d accepted", len(parts), err, count)
				}
				return
			}
			if !errors.Is(err, errAudioMultipartPartsLimit) {
				t.Fatalf("audioReadForm error=%v, want parts-limit error", err)
			}
		})
	}
}

func TestAudioTranscriptions_HTTPMultipartPartLimit(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _, _ = parseUpstreamMultipart(t, r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"text":"ok"}`))
	}))
	defer server.Close()
	gw := newAudioGateway(t, audioTranscriptionModel(server.URL))

	makeRequest := func(count int) ([]byte, string) {
		t.Helper()
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		if err := writer.WriteField("model", "m"); err != nil {
			t.Fatal(err)
		}
		for i := 1; i < count-1; i++ {
			if err := writer.WriteField(fmt.Sprintf("field-%d", i), "value"); err != nil {
				t.Fatal(err)
			}
		}
		part, err := writer.CreateFormFile("file", "audio.wav")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write([]byte("audio")); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		return body.Bytes(), writer.FormDataContentType()
	}

	for _, tc := range []struct {
		parts int
		want  int
	}{{audioMaxMultipartParts, http.StatusOK}, {audioMaxMultipartParts + 1, http.StatusRequestEntityTooLarge}} {
		body, contentType := makeRequest(tc.parts)
		rec := postAudioTranscriptions(t, gw, body, contentType)
		if rec.Code != tc.want {
			t.Errorf("%d parts: status=%d body=%s, want %d", tc.parts, rec.Code, rec.Body.String(), tc.want)
		}
		if tc.want == http.StatusOK && rec.Body.String() != `{"text":"ok"}` {
			t.Errorf("%d parts: response=%q", tc.parts, rec.Body.String())
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("upstream calls=%d, want only the 32-part request", got)
	}
}

// TestAudioTranscriptions_RequestValidation covers the remaining 400 shapes:
// missing model and a non-multipart content type.
func TestAudioTranscriptions_RequestValidation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer server.Close()
	gw := newAudioGateway(t, audioTranscriptionModel(server.URL))

	t.Run("missing model", func(t *testing.T) {
		body, contentType := buildAudioMultipart(t, map[string]string{}, "file", "hello.wav", "audio/wav", []byte{1})
		rec := postAudioTranscriptions(t, gw, body, contentType)
		if rec.Code != http.StatusBadRequest || !bytes.Contains(rec.Body.Bytes(), []byte(`"model is required"`)) {
			t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("non multipart", func(t *testing.T) {
		rec := postAudioTranscriptions(t, gw, []byte(`{"model":"m"}`), "application/json")
		if rec.Code != http.StatusBadRequest || errorType(t, rec) != "invalid_request_error" {
			t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
		}
	})
}

// TestAudioTranscriptions_TruncatedMultipart: a mid-stream interruption
// (truncated upload) never reaches the upstream and publishes no event.
func TestAudioTranscriptions_TruncatedMultipart(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()

	gw := newAudioGateway(t, audioTranscriptionModel(server.URL))
	var evPtr atomic.Value
	evPtr.Store((*eventpub.Event)(nil))
	gw.eventNote = func(e *eventpub.Event) { evPtr.Store(e) }

	wav := audioFixtureBytes(t, "hello.wav")
	body, contentType := buildAudioMultipart(t, map[string]string{"model": "m"}, "file", "hello.wav", "audio/wav", wav)
	truncated := body[:len(body)/2]
	rec := postAudioTranscriptions(t, gw, truncated, contentType)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if calls.Load() != 0 {
		t.Fatalf("upstream called %d times on truncated upload", calls.Load())
	}
	if ev := evPtr.Load().(*eventpub.Event); ev != nil {
		t.Fatalf("completed event on truncated upload: %+v", ev)
	}
}

// TestAudioTranscriptions_FileTooLarge is limit N2: a file part pushing the
// body past the 10 MiB cap answers 413 with the upstream call count at zero.
func TestAudioTranscriptions_FileTooLarge(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()

	gw := newAudioGateway(t, audioTranscriptionModel(server.URL))
	r := chi.NewRouter()
	r.Use(httpmw.MaxBody(10 * 1024 * 1024))
	gw.routes(r)

	big := make([]byte, 10*1024*1024+4096)
	for i := range big {
		big[i] = byte(i % 251)
	}
	body, contentType := buildAudioMultipart(t, map[string]string{"model": "m"}, "file", "big.wav", "audio/wav", big)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/audio/transcriptions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if calls.Load() != 0 {
		t.Fatalf("upstream called %d times on oversized body", calls.Load())
	}
}

// TestAudioTranscriptions_UnsupportedFormatUpstream4xx is matrix row M6/N1:
// the gateway forwards bytes un-sniffed; an upstream format rejection maps
// into the standard envelope — and the captured upstream request still
// carries the byte-identical file part.
func TestAudioTranscriptions_UnsupportedFormatUpstream4xx(t *testing.T) {
	mp3 := audioFixtureBytes(t, "hello.mp3")
	wantSum := sha256.Sum256(mp3)
	var gotFile []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fields, file, _ := parseUpstreamMultipart(t, r)
		if fields["model"] != "whisper-1" {
			t.Errorf("upstream model %q", fields["model"])
		}
		gotFile = file
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"unsupported container","type":"invalid_request_error"}}`))
	}))
	defer server.Close()

	gw := newAudioGateway(t, audioTranscriptionModel(server.URL))
	body, contentType := buildAudioMultipart(t, map[string]string{"model": "m"}, "file", "hello.mp3", "audio/mpeg", mp3)
	rec := postAudioTranscriptions(t, gw, body, contentType)

	if rec.Code != http.StatusBadRequest || errorType(t, rec) != "invalid_request_error" {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if sha256.Sum256(gotFile) != wantSum {
		t.Fatalf("file part not byte-identical: got %d bytes want %d", len(gotFile), len(mp3))
	}
}

// buildAudioMultipartExact encodes a transcription request with a fixed
// boundary and pads the prompt text field so the encoded body is exactly
// size bytes — needed for the 10 MiB request-cap boundary tests.
func buildAudioMultipartExact(t *testing.T, size int, file []byte) ([]byte, string) {
	t.Helper()
	build := func(pad int) []byte {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		if err := mw.SetBoundary("audioboundary0123456789"); err != nil {
			t.Fatal(err)
		}
		if err := mw.WriteField("model", "m"); err != nil {
			t.Fatal(err)
		}
		if pad > 0 {
			if err := mw.WriteField("prompt", strings.Repeat("p", pad)); err != nil {
				t.Fatal(err)
			}
		}
		h := make(map[string][]string)
		h["Content-Disposition"] = []string{`form-data; name="file"; filename="padded.wav"`}
		h["Content-Type"] = []string{"audio/wav"}
		fw, err := mw.CreatePart(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(file); err != nil {
			t.Fatal(err)
		}
		if err := mw.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	base := len(build(0))
	framing := len(build(1)) - base - 1
	pad := size - base - framing
	if pad < 0 {
		t.Fatalf("body without padding already %d bytes, want exactly %d", base+framing, size)
	}
	body := build(pad)
	if len(body) != size {
		t.Fatalf("encoded body %d bytes, want exactly %d", len(body), size)
	}
	return body, "multipart/form-data; boundary=audioboundary0123456789"
}

// TestAudioTranscriptions_MultipartContentTypeRejected: a missing boundary
// parameter, a boundary that does not match the body and a non form-data
// multipart subtype are all refused 400 invalid_request_error before
// admission — upstream call count stays zero.
func TestAudioTranscriptions_MultipartContentTypeRejected(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()
	gw := newAudioGateway(t, audioTranscriptionModel(server.URL))

	wav := audioFixtureBytes(t, "hello.wav")
	body, _ := buildAudioMultipart(t, map[string]string{"model": "m"}, "file", "hello.wav", "audio/wav", wav)
	cases := []struct {
		name        string
		contentType string
	}{
		{name: "missing boundary", contentType: "multipart/form-data"},
		{name: "mismatched boundary", contentType: "multipart/form-data; boundary=otherboundary"},
		{name: "non form-data subtype", contentType: "multipart/byteranges; boundary=abc123"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := postAudioTranscriptions(t, gw, body, tc.contentType)
			if rec.Code != http.StatusBadRequest || errorType(t, rec) != "invalid_request_error" {
				t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("upstream called %d times on bad content type", calls.Load())
	}
}

// TestAudioTranscriptions_FilePartWithoutFilename: an upload part named
// "file" without the filename parameter parses as a text field, so no file
// part exists — refused 400 "file is required" with the upstream call count
// at zero and no event (a diagnosable refusal, nothing half-admitted).
func TestAudioTranscriptions_FilePartWithoutFilename(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()

	gw := newAudioGateway(t, audioTranscriptionModel(server.URL))
	var evPtr atomic.Value
	evPtr.Store((*eventpub.Event)(nil))
	gw.eventNote = func(e *eventpub.Event) { evPtr.Store(e) }

	wav := audioFixtureBytes(t, "hello.wav")
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.WriteField("model", "m"); err != nil {
		t.Fatal(err)
	}
	hdr := make(map[string][]string)
	hdr["Content-Disposition"] = []string{`form-data; name="file"`}
	fw, err := mw.CreatePart(hdr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(wav); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}

	rec := postAudioTranscriptions(t, gw, buf.Bytes(), mw.FormDataContentType())
	if rec.Code != http.StatusBadRequest || !bytes.Contains(rec.Body.Bytes(), []byte("file is required")) {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if calls.Load() != 0 {
		t.Fatalf("upstream called %d times", calls.Load())
	}
	if ev := evPtr.Load().(*eventpub.Event); ev != nil {
		t.Fatalf("completed event on rejected upload: %+v", ev)
	}
}

// TestAudioTranscriptions_CorruptBytesForwardedVerbatim: the gateway makes
// no format promise (M6) — a corrupt WAV (valid RIFF header, garbage tail)
// and a zero-byte file part cross to the upstream byte-identical; whether
// the payload is acceptable is decided by the upstream alone.
func TestAudioTranscriptions_CorruptBytesForwardedVerbatim(t *testing.T) {
	wav := audioFixtureBytes(t, "hello.wav")
	cases := []struct {
		name    string
		file    []byte
		wantSum [sha256.Size]byte
	}{
		{name: "corrupt wav", file: append(append([]byte{}, wav[:44]...), bytes.Repeat([]byte{0xDE, 0xAD}, 50)...)},
		{name: "empty file", file: []byte{}},
	}
	for i := range cases {
		cases[i].wantSum = sha256.Sum256(cases[i].file)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotFile []byte
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, file, _ := parseUpstreamMultipart(t, r)
				gotFile = file
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"text":"accepted"}`))
			}))
			defer server.Close()

			gw := newAudioGateway(t, audioTranscriptionModel(server.URL))
			body, contentType := buildAudioMultipart(t, map[string]string{"model": "m"}, "file", "broken.wav", "audio/wav", tc.file)
			rec := postAudioTranscriptions(t, gw, body, contentType)

			if rec.Code != http.StatusOK {
				t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
			}
			if sha256.Sum256(gotFile) != tc.wantSum {
				t.Fatalf("file part not byte-identical: got %d bytes want %d", len(gotFile), len(tc.file))
			}
		})
	}
}

// TestAudioTranscriptions_BodyLimitExactBoundary pins the 10 MiB request cap
// from both sides: a multipart body padded to exactly the cap is admitted and
// reaches the upstream, one byte over is answered 413 with the upstream call
// count at zero (single file part far below the cap, total body decides).
func TestAudioTranscriptions_BodyLimitExactBoundary(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		fields, _, _ := parseUpstreamMultipart(t, r)
		if fields["model"] != "whisper-1" {
			t.Errorf("upstream model %q", fields["model"])
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"text":"ok"}`))
	}))
	defer server.Close()

	wav := audioFixtureBytes(t, "hello.wav")
	cases := []struct {
		name       string
		size       int
		wantStatus int
	}{
		{name: "exactly at limit", size: 10 * 1024 * 1024, wantStatus: http.StatusOK},
		{name: "limit+1", size: 10*1024*1024 + 1, wantStatus: http.StatusRequestEntityTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls.Store(0)
			gw := newAudioGateway(t, audioTranscriptionModel(server.URL))
			r := chi.NewRouter()
			r.Use(httpmw.MaxBody(10 * 1024 * 1024))
			gw.routes(r)

			body, contentType := buildAudioMultipartExact(t, tc.size, wav)
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/audio/transcriptions", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer test-key")
			req.Header.Set("Content-Type", contentType)
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
			}
			if tc.wantStatus == http.StatusOK {
				if rec.Body.String() != `{"text":"ok"}` {
					t.Fatalf("response body %q", rec.Body.String())
				}
				if calls.Load() != 1 {
					t.Fatalf("upstream calls %d, want 1 at exact cap", calls.Load())
				}
				return
			}
			if errorType(t, rec) != "invalid_request_error" {
				t.Fatalf("envelope %s", rec.Body.String())
			}
			if calls.Load() != 0 {
				t.Fatalf("upstream called %d times on oversized body", calls.Load())
			}
		})
	}
}

// TestAudioTranscriptions_ResponseLimitOver: an upstream JSON response past
// the 64 MiB cap is refused 502 api_error — never truncated to the client —
// with no completed event and none of the refused bytes in the envelope.
func TestAudioTranscriptions_ResponseLimitOver(t *testing.T) {
	marker := []byte("AUDIOLEAKMARKER")
	payload := bytes.Repeat(marker, audioResponseLimit/len(marker)+2)
	payload = payload[:audioResponseLimit+1]
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(payload)
	}))
	defer server.Close()

	gw := newAudioGateway(t, audioTranscriptionModel(server.URL))
	var evPtr atomic.Value
	evPtr.Store((*eventpub.Event)(nil))
	gw.eventNote = func(e *eventpub.Event) { evPtr.Store(e) }

	wav := audioFixtureBytes(t, "hello.wav")
	body, contentType := buildAudioMultipart(t, map[string]string{"model": "m"}, "file", "hello.wav", "audio/wav", wav)
	rec := postAudioTranscriptions(t, gw, body, contentType)

	if rec.Code != http.StatusBadGateway || errorType(t, rec) != "api_error" {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if bytes.Contains(rec.Body.Bytes(), marker) {
		t.Fatalf("refusal echoes refused upstream bytes")
	}
	if ev := evPtr.Load().(*eventpub.Event); ev != nil {
		t.Fatalf("completed event on over-limit response: %+v", ev)
	}
}

// TestAudioTranscriptions_UpstreamAuthMaskedNoLeak: upstream 401 is masked
// to 502 api_error — the envelope carries the fixed refusal message, never
// the upstream body or any file bytes, and no completed event is published.
func TestAudioTranscriptions_UpstreamAuthMaskedNoLeak(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"detail":"internal-upstream-secret"}`))
	}))
	defer server.Close()

	gw := newAudioGateway(t, audioTranscriptionModel(server.URL))
	var evPtr atomic.Value
	evPtr.Store((*eventpub.Event)(nil))
	gw.eventNote = func(e *eventpub.Event) { evPtr.Store(e) }

	wav := audioFixtureBytes(t, "hello.wav")
	body, contentType := buildAudioMultipart(t, map[string]string{"model": "m"}, "file", "hello.wav", "audio/wav", wav)
	rec := postAudioTranscriptions(t, gw, body, contentType)

	if rec.Code != http.StatusBadGateway || errorType(t, rec) != "api_error" {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("internal-upstream-secret")) {
		t.Fatalf("envelope leaks upstream body: %s", rec.Body.String())
	}
	if bytes.Contains(rec.Body.Bytes(), wav) {
		t.Fatalf("envelope echoes audio bytes")
	}
	if ev := evPtr.Load().(*eventpub.Event); ev != nil {
		t.Fatalf("completed event on upstream error: %+v", ev)
	}
}

// TestAudioTranscriptions_ClientCancelMidUpload is the upload-phase stream
// break (N3): a client hanging up mid-multipart never reaches the upstream
// and publishes no completed event — a dead upload never settles as spend.
func TestAudioTranscriptions_ClientCancelMidUpload(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()

	gw := newAudioGateway(t, audioTranscriptionModel(server.URL))
	evCh := make(chan *eventpub.Event, 1)
	gw.eventNote = func(e *eventpub.Event) { evCh <- e }

	router := chi.NewRouter()
	gw.routes(router)
	gwServer := httptest.NewServer(router)
	defer gwServer.Close()

	big := make([]byte, 8*1024*1024)
	for i := range big {
		big[i] = byte(i % 251)
	}
	body, contentType := buildAudioMultipart(t, map[string]string{"model": "m"}, "file", "big.wav", "audio/wav", big)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pr, pw := io.Pipe()
	statusCh := make(chan int, 1)
	go func() {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, gwServer.URL+"/v1/audio/transcriptions", pr)
		if err != nil {
			statusCh <- -1
			return
		}
		req.Header.Set("Authorization", "Bearer test-key")
		req.Header.Set("Content-Type", contentType)
		resp, err := gwServer.Client().Do(req)
		if err != nil {
			statusCh <- 0
			return
		}
		status := resp.StatusCode
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		statusCh <- status
	}()

	handed := make(chan struct{})
	go func() {
		defer close(handed)
		_, _ = pw.Write(body[:64*1024])
	}()
	<-handed
	time.Sleep(300 * time.Millisecond) // the gateway is parked mid-multipart-read
	cancel()
	_ = pw.Close()

	if status := <-statusCh; status == http.StatusOK {
		t.Fatalf("canceled upload answered 200")
	}
	if calls.Load() != 0 {
		t.Fatalf("upstream called %d times on canceled upload", calls.Load())
	}
	select {
	case ev := <-evCh:
		t.Fatalf("published success event on canceled upload: %+v", ev)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestAudioTranscriptions_DoubleRequestIdempotency: two identical requests
// are processed independently — both reach the upstream with a byte-identical
// file part and the rewritten model field, and settle exactly two separate
// completed events (no cross-request state, no double-settled single spend).
func TestAudioTranscriptions_DoubleRequestIdempotency(t *testing.T) {
	wav := audioFixtureBytes(t, "hello.wav")
	wantSum := sha256.Sum256(wav)
	var mu sync.Mutex
	var sums [][sha256.Size]byte
	var models []string
	var events []*eventpub.Event
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		fields, file, _ := parseUpstreamMultipart(t, r)
		mu.Lock()
		sums = append(sums, sha256.Sum256(file))
		models = append(models, fields["model"])
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"text":"hi"}`))
	}))
	defer server.Close()

	gw := newAudioGateway(t, audioTranscriptionModel(server.URL))
	gw.eventNote = func(e *eventpub.Event) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	}

	body, contentType := buildAudioMultipart(t, map[string]string{"model": "m"}, "file", "hello.wav", "audio/wav", wav)
	for i := 0; i < 2; i++ {
		rec := postAudioTranscriptions(t, gw, body, contentType)
		if rec.Code != http.StatusOK || rec.Body.String() != `{"text":"hi"}` {
			t.Fatalf("request %d: status %d body %s", i, rec.Code, rec.Body.String())
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("upstream calls %d", calls.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(sums) != 2 || sums[0] != wantSum || sums[1] != wantSum {
		t.Fatalf("file parts not byte-identical across requests: %v", sums)
	}
	if len(models) != 2 || models[0] != "whisper-1" || models[1] != "whisper-1" {
		t.Fatalf("model rewrite not stable across requests: %v", models)
	}
	if len(events) != 2 {
		t.Fatalf("events %d, want exactly one completed per request", len(events))
	}
	for _, ev := range events {
		if ev.EventType != "request.completed" || ev.StatusCode != http.StatusOK || ev.ModelUsed != "whisper-1" {
			t.Fatalf("event %+v", ev)
		}
	}
}
