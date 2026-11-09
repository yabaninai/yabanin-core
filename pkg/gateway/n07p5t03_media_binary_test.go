package cli

// N07-P05-T03 verification pins for the media/binary pipelines
// (/v1/audio/transcriptions, /v1/audio/speech, /v1/images/generations):
//
//   - multipart/binary handling — a second file part is refused before any
//     egress and its buffered bytes never echo into an envelope;
//   - parsing fidelity — quirky filenames (spaces, quotes, UTF-8) and file
//     parts without a Content-Type survive the parse → metadata → rebuild
//     round trip byte-identical;
//   - content types — the upstream response Content-Type passes through
//     verbatim, an absent header defaults to application/json, and the
//     speech input ignores the request Content-Type (the JSON body decides);
//   - sizes — the 10 MiB per-text-field bound rejects oversized fields;
//   - cancellation — a client cancel during the upstream images call
//     produces 502 api_error with exactly one egress attempt and no
//     success event (audio parity is pinned by the existing
//     *ClientCancelMid* tests).
//
// The audio N3 guards (no success event once the client is gone) are also
// covered here through the wire-provable cancellation windows; the
// sub-millisecond post-read window on all three pipelines is parity
// hardening verified by code review, not wire-testable deterministically.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/resolver"
)

// n07p5t03WriteFilePart appends one multipart file part with an RFC-compliant
// Content-Disposition (mime.FormatMediaType handles quoting and RFC 2231
// encoding for non-ASCII filenames) and an optional Content-Type.
func n07p5t03WriteFilePart(t *testing.T, mw *multipart.Writer, name, filename, contentType string, data []byte) {
	t.Helper()
	hdr := make(textproto.MIMEHeader, 2)
	hdr.Set("Content-Disposition",
		mime.FormatMediaType("form-data", map[string]string{"name": name, "filename": filename}))
	if contentType != "" {
		hdr.Set("Content-Type", contentType)
	}
	fw, err := mw.CreatePart(hdr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(data); err != nil {
		t.Fatal(err)
	}
}

// n07p5t03TranscriptionBody encodes a minimal transcription request the way
// a client would: the model field first, then the binary file part. Returns
// the body and its multipart Content-Type.
func n07p5t03TranscriptionBody(t *testing.T, wav []byte, filename, fileContentType string) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.WriteField("model", "m"); err != nil {
		t.Fatal(err)
	}
	n07p5t03WriteFilePart(t, mw, "file", filename, fileContentType, wav)
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), mw.FormDataContentType()
}

// TestN07P5T03_ImagesCancelMidUpstreamCall_NoEvent pins the cancellation
// contract for the images pipeline while the gateway is parked inside the
// upstream call: 502 api_error, exactly one egress attempt (no retry), no
// request.completed success event and no usage settlement.
func TestN07P5T03_ImagesCancelMidUpstreamCall_NoEvent(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		close(started)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	defer close(release)

	info := resolver.ModelInfo{
		ModelName:      "gpt-image-1-canon",
		Provider:       "openai",
		UpstreamURL:    server.URL,
		UpstreamAPIKey: "up",
		Enabled:        true,
	}
	gw := imagesTestGateway(t, info, server.URL)
	var ev atomic.Value
	ev.Store((*eventpub.Event)(nil))
	gw.eventNote = func(e *eventpub.Event) { ev.Store(e) }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	timer := time.AfterFunc(10*time.Second, cancel)
	defer timer.Stop()

	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/images/generations",
		strings.NewReader(`{"model":"m","prompt":"cancelled mid call"}`))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router := chi.NewRouter()
	gw.routes(router)
	done := make(chan struct{})
	go func() {
		defer close(done)
		router.ServeHTTP(rec, req)
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never received the images call")
	}
	// The gateway is now parked inside the upstream client call.
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if got := errorType(t, rec); got != "api_error" {
		t.Fatalf("error type %q, want api_error", got)
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream attempts %d, want exactly 1 (no retry after cancel)", calls.Load())
	}
	if got := ev.Load().(*eventpub.Event); got != nil {
		t.Fatalf("canceled request published a success event: %+v", got)
	}
}

// TestN07P5T03_TranscriptionsMultipleFileParts_Rejected pins the multipart
// guard: a second file part is refused 400 before any egress, publishes no
// event, and the bytes buffered for the second file never echo into the
// error envelope (temporary-data containment).
func TestN07P5T03_TranscriptionsMultipleFileParts_Rejected(t *testing.T) {
	wav := audioFixtureBytes(t, "hello.wav")
	marker := bytes.Repeat([]byte{0xBD}, 512)
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"text":"must never be reached"}`))
	}))
	defer server.Close()

	gw := newAudioGateway(t, audioTranscriptionModel(server.URL))
	var ev atomic.Value
	ev.Store((*eventpub.Event)(nil))
	gw.eventNote = func(e *eventpub.Event) { ev.Store(e) }

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.WriteField("model", "m"); err != nil {
		t.Fatal(err)
	}
	n07p5t03WriteFilePart(t, mw, "file", "hello.wav", "audio/wav", wav)
	n07p5t03WriteFilePart(t, mw, "extra_audio", "leaked.bin", "application/octet-stream", marker)
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}

	rec := postAudioTranscriptions(t, gw, buf.Bytes(), mw.FormDataContentType())

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if got := errorType(t, rec); got != "invalid_request_error" {
		t.Fatalf("error type %q, want invalid_request_error", got)
	}
	if !strings.Contains(rec.Body.String(), "multiple file parts are not supported") {
		t.Fatalf("envelope message missing: %s", rec.Body.String())
	}
	if calls.Load() != 0 {
		t.Fatalf("upstream attempts %d, want 0 (reject before egress)", calls.Load())
	}
	if got := ev.Load().(*eventpub.Event); got != nil {
		t.Fatalf("rejected request published an event: %+v", got)
	}
	if bytes.Contains(rec.Body.Bytes(), marker) {
		t.Fatal("buffered second-file bytes echoed into the error envelope")
	}
}

// TestN07P5T03_TranscriptionsResponseContentType pins the response content
// type contract: the upstream Content-Type passes through verbatim (the
// response_format surface — text/plain is a legal upstream choice), and a
// response without any Content-Type header defaults to application/json.
func TestN07P5T03_TranscriptionsResponseContentType(t *testing.T) {
	wav := audioFixtureBytes(t, "hello.wav")

	t.Run("upstream header passthrough", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(`{"text":"hi"}`))
		}))
		defer server.Close()

		gw := newAudioGateway(t, audioTranscriptionModel(server.URL))
		body, contentType := n07p5t03TranscriptionBody(t, wav, "hello.wav", "audio/wav")
		rec := postAudioTranscriptions(t, gw, body, contentType)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("Content-Type"); got != "text/plain" {
			t.Fatalf("content type %q, want the upstream text/plain passthrough", got)
		}
	})

	t.Run("missing upstream header defaults to application/json", func(t *testing.T) {
		// A Go http server sniffs and sets a Content-Type on every
		// non-empty body, so the default branch is pinned against a raw
		// HTTP/1.1 responder whose response carries no Content-Type at all.
		const body = `{"text":"raw"}`
		var lc net.ListenConfig
		ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ln.Close() }()
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer func() { _ = conn.Close() }()
					req, err := http.ReadRequest(bufio.NewReader(conn))
					if err != nil {
						return
					}
					_, _ = io.Copy(io.Discard, req.Body)
					_ = req.Body.Close()
					resp := "HTTP/1.1 200 OK\r\nContent-Length: " +
						strconv.Itoa(len(body)) + "\r\nConnection: close\r\n\r\n" + body
					_, _ = io.Copy(conn, strings.NewReader(resp))
				}()
			}
		}()

		gw := newAudioGateway(t, audioTranscriptionModel("http://"+ln.Addr().String()))
		raw, contentType := n07p5t03TranscriptionBody(t, wav, "hello.wav", "audio/wav")
		rec := postAudioTranscriptions(t, gw, raw, contentType)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("Content-Type"); got != "application/json" {
			t.Fatalf("content type %q, want the application/json default", got)
		}
		if strings.TrimSpace(rec.Body.String()) != body {
			t.Fatalf("passthrough body %q", rec.Body.String())
		}
	})
}

// TestN07P5T03_RebuildPreservesFilePartHeaders pins parsing fidelity across
// the parse → metadata → rebuild chain: a filename with spaces, quotes and
// UTF-8 survives the multipart parse and the RFC-compliant rebuild to the
// upstream (parsed back to the exact same string), a file part without a
// Content-Type stays headerless upstream, the file bytes cross byte-identical,
// and the event metadata projection carries the filename and an empty
// content_type without the binary payload.
func TestN07P5T03_RebuildPreservesFilePartHeaders(t *testing.T) {
	const filename = `take "2" — отчёт.wav`
	wav := audioFixtureBytes(t, "hello.wav")
	wantSum := sha256.Sum256(wav)

	var (
		gotFilename   string
		gotFileHeader string
		gotModel      string
		gotFile       []byte
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mr, err := r.MultipartReader()
		if err != nil {
			t.Errorf("captured request is not multipart: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Errorf("upstream part: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			raw, err := io.ReadAll(p)
			if err != nil {
				t.Errorf("upstream part read: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if p.FileName() != "" {
				gotFilename = p.FileName()
				gotFileHeader = p.Header.Get("Content-Type")
				gotFile = raw
				continue
			}
			gotModel = string(raw)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"text":"ok"}`))
	}))
	defer server.Close()

	gw := newAudioGateway(t, audioTranscriptionModel(server.URL))
	var ev atomic.Value
	ev.Store((*eventpub.Event)(nil))
	gw.eventNote = func(e *eventpub.Event) { ev.Store(e) }

	raw, contentType := n07p5t03TranscriptionBody(t, wav, filename, "")
	rec := postAudioTranscriptions(t, gw, raw, contentType)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if gotFilename != filename {
		t.Fatalf("upstream filename %q, want %q", gotFilename, filename)
	}
	if gotFileHeader != "" {
		t.Fatalf("rebuilt file part Content-Type %q, want headerless", gotFileHeader)
	}
	if gotModel != "whisper-1" {
		t.Fatalf("upstream model field %q, want the resolved whisper-1", gotModel)
	}
	if sha256.Sum256(gotFile) != wantSum {
		t.Fatal("file bytes changed across the rebuild")
	}

	got := ev.Load().(*eventpub.Event)
	if got == nil {
		t.Fatal("no request.completed event")
	}
	var meta struct {
		File struct {
			Filename    string `json:"filename"`
			Size        int    `json:"size"`
			ContentType string `json:"content_type"`
		} `json:"file"`
	}
	if err := json.Unmarshal([]byte(got.Payload), &meta); err != nil {
		t.Fatalf("event payload %s: %v", got.Payload, err)
	}
	if meta.File.Filename != filename {
		t.Fatalf("event filename %q, want %q", meta.File.Filename, filename)
	}
	if meta.File.ContentType != "" {
		t.Fatalf("event content_type %q, want empty", meta.File.ContentType)
	}
	if meta.File.Size != len(wav) {
		t.Fatalf("event size %d, want %d", meta.File.Size, len(wav))
	}
	if strings.Contains(got.Payload, hex.EncodeToString(wantSum[:4])) {
		t.Fatal("binary audio bytes leaked into the event payload")
	}
}

// TestN07P5T03_AudioReadFormFieldOverLimit pins the per-text-field bound at
// the parser level: a text field above audioMaxFieldBytes fails with
// errAudioFieldTooLarge (defense in depth — the gateway body cap answers
// first on the wire, the parser bound catches callers that bypass it).
func TestN07P5T03_AudioReadFormFieldOverLimit(t *testing.T) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.WriteField("model", "m"); err != nil {
		t.Fatal(err)
	}
	if err := mw.WriteField("prompt", strings.Repeat("a", audioMaxFieldBytes+1)); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	mr := multipart.NewReader(&buf, mw.Boundary())
	parts, err := audioReadForm(mr)
	if !errors.Is(err, errAudioFieldTooLarge) {
		t.Fatalf("error %v, want errAudioFieldTooLarge", err)
	}
	if parts != nil {
		t.Fatalf("parser returned parts on failure: %d parts", len(parts))
	}
}

// TestN07P5T03_SpeechInputContentTypeLenient pins the speech input content
// type contract: the pipeline is content-type agnostic on the input side —
// the JSON body decides, a text/plain request Content-Type neither reroutes
// the request nor changes the response.
func TestN07P5T03_SpeechInputContentTypeLenient(t *testing.T) {
	mp3 := audioFixtureBytes(t, "hello.mp3")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "audio/mpeg")
		_, _ = w.Write(mp3)
	}))
	defer server.Close()

	gw := newAudioGateway(t, audioTestModel(server.URL))
	var ev atomic.Value
	ev.Store((*eventpub.Event)(nil))
	gw.eventNote = func(e *eventpub.Event) { ev.Store(e) }

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/audio/speech",
		strings.NewReader(`{"model":"tts","input":"hello","voice":"alloy"}`))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	router := chi.NewRouter()
	gw.routes(router)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if !bytes.Equal(rec.Body.Bytes(), mp3) {
		t.Fatal("speech audio bytes are not byte-identical passthrough")
	}
	if got := rec.Header().Get("Content-Type"); got != "audio/mpeg" {
		t.Fatalf("content type %q, want the upstream audio/mpeg", got)
	}
	if got := ev.Load().(*eventpub.Event); got == nil {
		t.Fatal("no request.completed event")
	}
}
