package cli

// TEST-ONLY coverage recovery (critical-Go gate, slice G3): independent
// behavioral and fault-injection tests for the error and edge arms of
// audio_speech.go and audio_transcriptions.go. Every harness here is local
// to this file (g3 prefix) after the neighboring audio test patterns; no
// existing file, shared helper or production path is modified.
//
// Target spans (go cover format startLINE.COL,endLINE.COL):
//
//	audio_speech.go          51.4,52.1    body read error + dead request context → silent N3 return
//	                         123.3,124.1  reservation denial → return
//	                         128.3,129.1  mediaDispatch failure → return
//	                         138.3,142.1  upstream Do failure → 502 upstream request failed
//	                         180.3,185.1  mediaDispatch pool.Get failure → 502 failed to initialise upstream client
//	                         264.3,267.1  terminal facts commit failure → 500 accounting_commit_failed
//	                         277.3,278.1  missing upstream Content-Type → application/octet-stream
//	audio_transcriptions.go  73.4,74.1    form read error + dead request context → silent N3 return
//	                         128.3,129.1  reservation denial → return
//	                         133.3,134.1  mediaDispatch failure → return
//	                         138.3,141.1  UNCOVERED — defensive: see TestGWCovG3_TranscriptionRebuildFormAdversarialParts
//	                         143.3,144.1  unconfirmed paid start → 503 history_unavailable
//	                         148.3,152.1  upstream Do failure → 502 upstream request failed
//	                         246.3,249.1  terminal facts commit failure → 500 accounting_commit_failed

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/config"
	apierrors "github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// g3ErrBody is a request body whose reads always fail, standing in for a
// client transport that died mid-upload.
type g3ErrBody struct{ err error }

func (b g3ErrBody) Read([]byte) (int, error) { return 0, b.err }

// g3Model returns the registry row both audio routes resolve ("tts" for
// speech, "m" for transcriptions map to the same upstream).
func g3Model(upstreamURL string) resolver.ModelInfo {
	return resolver.ModelInfo{
		ModelName:      "g3-audio-model",
		Provider:       "openai",
		UpstreamURL:    upstreamURL,
		UpstreamAPIKey: "up-key",
		Enabled:        true,
	}
}

// g3Gateway mirrors newAudioGateway: strict-key auth, a stub resolver, an
// empty upstream pool and an explicit fake invocation store whose fault
// knobs (admitErr/factsErr) the tests below script.
func g3Gateway(t *testing.T, info resolver.ModelInfo) *gateway {
	t.Helper()
	return &gateway{
		cfg:         config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: info.UpstreamURL},
		log:         slog.New(slog.DiscardHandler),
		auth:        NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
		res:         stubModelResolver{"m": info, "tts": info},
		pool:        upstream.NewPool(upstream.Options{}),
		invocations: &fakeInvocationStore{},
	}
}

// g3Store fetches the wired fake invocation store for row assertions.
func g3Store(t *testing.T, gw *gateway) *fakeInvocationStore {
	t.Helper()
	store, ok := gw.invocations.(*fakeInvocationStore)
	require.True(t, ok, "g3 harness wires the fake invocation store")
	return store
}

// g3Identity stamps the trusted identity header set the handler-direct
// convention requires (the auth middleware would strip client copies).
func g3Identity(r *http.Request) {
	r.Header.Set("X-Org-Id", "org-g3")
	r.Header.Set("X-Team-Id", "team-g3")
	r.Header.Set("X-API-Key-Id", "key-g3")
	r.Header.Set("X-Session-Id", "sess-g3")
	r.Header.Set("X-Session-Key-Id", "ybs-g3")
	r.Header.Set("X-Agent-Id", "agent-g3")
	r.Header.Set("X-User-Id", "user-g3")
	r.Header.Set("X-Yabanin-Task", "task-g3")
}

func g3PostSpeech(t *testing.T, gw *gateway, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/audio/speech", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	g3Identity(req)
	rec := httptest.NewRecorder()
	gw.audioSpeech(rec, req)
	return rec
}

func g3PostTranscription(t *testing.T, gw *gateway, body []byte, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/audio/transcriptions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", contentType)
	g3Identity(req)
	rec := httptest.NewRecorder()
	gw.audioTranscriptions(rec, req)
	return rec
}

// g3WAV synthesizes a small canonical PCM WAV (44-byte header + payload).
// The gateway must not sniff it, but a well-formed container keeps the
// upload fixture honest.
func g3WAV(payloadBytes uint32) []byte {
	hdr := make([]byte, 44)
	copy(hdr[0:4], "RIFF")
	binary.LittleEndian.PutUint32(hdr[4:8], 36+payloadBytes)
	copy(hdr[8:12], "WAVE")
	copy(hdr[12:16], "fmt ")
	binary.LittleEndian.PutUint32(hdr[16:20], 16)
	hdr[20] = 1 // PCM
	hdr[22] = 1 // mono
	binary.LittleEndian.PutUint32(hdr[24:28], 8000)
	binary.LittleEndian.PutUint32(hdr[28:32], 16000)
	hdr[32] = 2
	hdr[34] = 16
	copy(hdr[36:40], "data")
	binary.LittleEndian.PutUint32(hdr[40:44], payloadBytes)
	out := make([]byte, 0, int(44+payloadBytes))
	out = append(out, hdr...)
	for i := range int(payloadBytes) {
		out = append(out, byte(i%251))
	}
	return out
}

// g3Upload encodes a client-shaped transcription form: the model text
// field followed by the binary file part.
func g3Upload(t *testing.T, model, filename string, file []byte) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if model != "" {
		if err := mw.WriteField("model", model); err != nil {
			t.Fatal(err)
		}
	}
	if file != nil {
		hdr := make(textproto.MIMEHeader, 2)
		hdr.Set("Content-Disposition",
			mime.FormatMediaType("form-data", map[string]string{"name": "file", "filename": filename}))
		hdr.Set("Content-Type", "audio/wav")
		fw, err := mw.CreatePart(hdr)
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

// g3Route drives either audio route against one gateway/upstream pair so
// table cases assert both transports with identical expectations.
type g3Route struct {
	name string
	post func(t *testing.T, gw *gateway) *httptest.ResponseRecorder
}

func g3Routes() []g3Route {
	return []g3Route{
		{"speech", func(t *testing.T, gw *gateway) *httptest.ResponseRecorder {
			t.Helper()
			return g3PostSpeech(t, gw, `{"model":"tts","input":"g3 coverage","voice":"alloy"}`)
		}},
		{"transcriptions", func(t *testing.T, gw *gateway) *httptest.ResponseRecorder {
			t.Helper()
			body, contentType := g3Upload(t, "m", "g3.wav", g3WAV(512))
			return g3PostTranscription(t, gw, body, contentType)
		}},
	}
}

// g3Envelope decodes the standard error envelope.
func g3Envelope(t *testing.T, rec *httptest.ResponseRecorder) (errType, code, message string) {
	t.Helper()
	var env struct {
		Error struct {
			Type    string `json:"type"`
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env))
	return env.Error.Type, env.Error.Code, env.Error.Message
}

// g3HistoryProbe scripts the durable-history consult.
type g3HistoryProbe struct {
	state budget.HistoryState
	err   error
}

func (p g3HistoryProbe) ProbeHistory(context.Context) (budget.HistoryState, error) {
	return p.state, p.err
}

// g3HistoryOutageAdmission wires a reservation controller whose history
// consult reports a write outage under the default reject policy: the plan
// stage then denies terminally with 503 history_unavailable.
func g3HistoryOutageAdmission(t *testing.T) *budget.Admission {
	t.Helper()
	adm := budget.NewAdmission(nil, budget.ScopedRateSource{}, slog.New(slog.DiscardHandler),
		"g3-test-replica", budget.ModeOff, nil, budget.DefaultAdmissionConfig())
	adm.SetHistoryAdmission(budget.NewHistoryAdmission(
		g3HistoryProbe{state: budget.HistoryStateWriteUnavailable, err: errors.New("g3: history signal stale")},
		budget.HistoryModeReject, slog.New(slog.DiscardHandler)))
	adm.Start(context.Background()) // no-op under ModeOff
	return adm
}

// TestGWCovG3_SpeechBodyReadErrorCancelledContext pins the N3 arm of
// readSpeechRequest (audio_speech.go 51.4,52.1): a body read failure with
// a dead request context must stay silent — writing the envelope would
// race the connection teardown — while a live context maps the same
// failure to the diagnosable 400 arm.
func TestGWCovG3_SpeechBodyReadErrorCancelledContext(t *testing.T) {
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
	}))
	defer server.Close()
	gw := g3Gateway(t, g3Model(server.URL))
	store := g3Store(t, gw)
	bodyErr := errors.New("g3: wire reset mid-body")

	// Control: same failure, live context → 400 malformed-body envelope.
	live := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/audio/speech", g3ErrBody{err: bodyErr})
	live.Header.Set("Content-Type", "application/json")
	g3Identity(live)
	liveRec := httptest.NewRecorder()
	gw.audioSpeech(liveRec, live)
	require.Equal(t, http.StatusBadRequest, liveRec.Code, liveRec.Body.String())
	errType, _, msg := g3Envelope(t, liveRec)
	require.Equal(t, apierrors.ErrorCodeInvalidRequest, errType)
	require.Contains(t, msg, "request body too large or malformed")

	// Target: dead context → the handler must write nothing at all.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dead := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/audio/speech", g3ErrBody{err: bodyErr})
	dead.Header.Set("Content-Type", "application/json")
	g3Identity(dead)
	rec := httptest.NewRecorder()
	gw.audioSpeech(rec, dead.WithContext(ctx))
	require.Equal(t, http.StatusOK, rec.Code, "a silent handler leaves the recorder's default code untouched")
	require.Empty(t, rec.Body.String(), "no error envelope may be written to a dead transport")
	require.Empty(t, rec.Header(), "no headers may be written to a dead transport")
	require.Zero(t, hits.Load())
	require.Empty(t, store.admitted)
	require.Empty(t, store.facts)
}

// TestGWCovG3_TranscriptionBodyReadErrorCancelledContext pins the N3 arm
// of readTranscriptionRequest (audio_transcriptions.go 73.4,74.1): a form
// read failure with a dead request context stays silent; a live context
// maps the same failure to 400.
func TestGWCovG3_TranscriptionBodyReadErrorCancelledContext(t *testing.T) {
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
	}))
	defer server.Close()
	gw := g3Gateway(t, g3Model(server.URL))
	store := g3Store(t, gw)
	bodyErr := errors.New("g3: wire reset mid-upload")
	const ct = "multipart/form-data; boundary=g3boundary"

	// Control: same failure, live context → 400 malformed-body envelope.
	live := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/audio/transcriptions", g3ErrBody{err: bodyErr})
	live.Header.Set("Content-Type", ct)
	g3Identity(live)
	liveRec := httptest.NewRecorder()
	gw.audioTranscriptions(liveRec, live)
	require.Equal(t, http.StatusBadRequest, liveRec.Code, liveRec.Body.String())
	errType, _, msg := g3Envelope(t, liveRec)
	require.Equal(t, apierrors.ErrorCodeInvalidRequest, errType)
	require.Contains(t, msg, "request body too large or malformed")

	// Target: dead context → the handler must write nothing at all.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dead := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/audio/transcriptions", g3ErrBody{err: bodyErr})
	dead.Header.Set("Content-Type", ct)
	g3Identity(dead)
	rec := httptest.NewRecorder()
	gw.audioTranscriptions(rec, dead.WithContext(ctx))
	require.Equal(t, http.StatusOK, rec.Code, "a silent handler leaves the recorder's default code untouched")
	require.Empty(t, rec.Body.String(), "no error envelope may be written to a dead transport")
	require.Empty(t, rec.Header(), "no headers may be written to a dead transport")
	require.Zero(t, hits.Load())
	require.Empty(t, store.admitted)
	require.Empty(t, store.facts)
}

// TestGWCovG3_AudioRouteReservationDenied pins the reservation-denial
// returns (audio_speech.go 123.3,124.1; audio_transcriptions.go
// 128.3,129.1): a durable-history write outage under reject policy
// refuses the request before any reservation or dispatch, with the exact
// history_unavailable envelope and zero provider arrivals.
func TestGWCovG3_AudioRouteReservationDenied(t *testing.T) {
	for _, route := range g3Routes() {
		t.Run(route.name, func(t *testing.T) {
			var hits atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
			}))
			defer server.Close()
			gw := g3Gateway(t, g3Model(server.URL))
			gw.admission = g3HistoryOutageAdmission(t)
			store := g3Store(t, gw)

			rec := route.post(t, gw)
			require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
			_, code, msg := g3Envelope(t, rec)
			require.Equal(t, "history_unavailable", code)
			require.Contains(t, msg, "durable request history temporarily unavailable")
			require.Zero(t, hits.Load())
			require.Empty(t, store.admitted, "the refusal predates the paid start: no durable admission row exists")
			require.Empty(t, store.facts)
		})
	}
}

// TestGWCovG3_AudioRouteUpstreamClientUnavailable pins the mediaDispatch
// pool failures (audio_speech.go 128.3,129.1 and 180.3,185.1;
// audio_transcriptions.go 133.3,134.1): an unconstructible upstream
// client (base URL rejected by validation) answers 502 and stops the
// route before the paid start.
func TestGWCovG3_AudioRouteUpstreamClientUnavailable(t *testing.T) {
	for _, route := range g3Routes() {
		t.Run(route.name, func(t *testing.T) {
			// Non-http scheme: the pool's base-URL validation refuses it,
			// so no client can be constructed for the dispatch.
			gw := g3Gateway(t, g3Model("ftp://g3-upstream.invalid"))
			store := g3Store(t, gw)

			rec := route.post(t, gw)
			require.Equal(t, http.StatusBadGateway, rec.Code, rec.Body.String())
			errType, _, msg := g3Envelope(t, rec)
			require.Equal(t, apierrors.ErrorCodeAPI, errType)
			require.Contains(t, msg, "failed to initialise upstream client")
			require.Empty(t, store.admitted, "the failure predates the paid start: no durable admission row exists")
			require.Empty(t, store.facts)
		})
	}
}

// TestGWCovG3_AudioRouteUpstreamDispatchFailed pins the upstream Do
// failures (audio_speech.go 138.3,142.1; audio_transcriptions.go
// 148.3,152.1): the pool constructs a client but the transport cannot
// reach the origin (closed server) → 502 upstream request failed, zero
// arrivals, admitted row left for the reconciler sweep, no facts.
func TestGWCovG3_AudioRouteUpstreamDispatchFailed(t *testing.T) {
	for _, route := range g3Routes() {
		t.Run(route.name, func(t *testing.T) {
			var hits atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
			}))
			server.Close() // the address is now refused: pool ok, dispatch cannot
			gw := g3Gateway(t, g3Model(server.URL))
			store := g3Store(t, gw)

			rec := route.post(t, gw)
			require.Equal(t, http.StatusBadGateway, rec.Code, rec.Body.String())
			errType, _, msg := g3Envelope(t, rec)
			require.Equal(t, apierrors.ErrorCodeAPI, errType)
			require.Contains(t, msg, "upstream request failed")
			require.Zero(t, hits.Load())
			require.Len(t, store.admitted, 1, "the paid start was confirmed — the reconciler sweep owns the admitted row")
			require.Empty(t, store.facts, "a failed dispatch settles no terminal facts")
		})
	}
}

// TestGWCovG3_TranscriptionUnconfirmedPaidStart pins audio_transcriptions.go
// 143.3,144.1: when the durable start cannot be confirmed the route
// refuses with the history_unavailable family — the paid call was not
// sent — and nothing reaches the provider or the ledger.
func TestGWCovG3_TranscriptionUnconfirmedPaidStart(t *testing.T) {
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"text":"never"}`))
	}))
	defer server.Close()
	gw := g3Gateway(t, g3Model(server.URL))
	store := g3Store(t, gw)
	store.admitErr = errors.New("g3: durable start unavailable")

	body, contentType := g3Upload(t, "m", "g3.wav", g3WAV(256))
	rec := g3PostTranscription(t, gw, body, contentType)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	_, code, msg := g3Envelope(t, rec)
	require.Equal(t, "history_unavailable", code)
	require.Contains(t, msg, "the paid call was not sent")
	require.Zero(t, hits.Load())
	require.Empty(t, store.admitted)
	require.Empty(t, store.facts)
}

// TestGWCovG3_AudioRouteTerminalFactsCommitFailed pins the terminal-facts
// funnel failures (audio_speech.go 264.3,267.1; audio_transcriptions.go
// 246.3,249.1): the provider already answered, but the durable usage
// record could not be committed — the paid answer is withheld (never
// surfaced as a payable success) and the client is told NOT to retry.
func TestGWCovG3_AudioRouteTerminalFactsCommitFailed(t *testing.T) {
	const marker = "G3-UPSTREAM-ANSWER-MARKER"
	for _, route := range g3Routes() {
		t.Run(route.name, func(t *testing.T) {
			var hits atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				w.Header().Set("Content-Type", "audio/mpeg")
				_, _ = w.Write([]byte(marker))
			}))
			defer server.Close()
			gw := g3Gateway(t, g3Model(server.URL))
			store := g3Store(t, gw)
			store.factsErr = errors.New("g3: terminal write unavailable")

			rec := route.post(t, gw)
			require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
			errType, code, msg := g3Envelope(t, rec)
			require.Equal(t, apierrors.ErrorCodeAPI, errType)
			require.Equal(t, "accounting_commit_failed", code)
			require.Contains(t, msg, "NOT safe to retry")
			require.Equal(t, "false", rec.Header().Get("X-Should-Retry"))
			require.NotContains(t, rec.Body.String(), marker, "the paid upstream answer must be withheld, not surfaced")
			require.EqualValues(t, 1, hits.Load())
			require.Len(t, store.admitted, 1)
			require.Empty(t, store.facts, "the failed commit leaves no durable facts row (the reconciler owns the admitted row)")
		})
	}
}

// TestGWCovG3_SpeechResponseWithoutContentType pins audio_speech.go
// 277.3,278.1: an upstream 200 with a body but no Content-Type header must
// be answered as application/octet-stream (audio is binary by default).
// net/http's server sniffs a Content-Type for ordinary handlers, so the
// stub hijacks the connection and writes the raw response by hand.
func TestGWCovG3_SpeechResponseWithoutContentType(t *testing.T) {
	const marker = "G3-RAW-AUDIO"
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer func() { require.NoError(t, conn.Close()) }()
		// 200 with a body and deliberately NO Content-Type header.
		if _, err := fmt.Fprintf(rw, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(marker), marker); err != nil {
			t.Errorf("raw write: %v", err)
			return
		}
		_ = rw.Flush()
	}))
	defer server.Close()

	gw := g3Gateway(t, g3Model(server.URL))
	store := g3Store(t, gw)
	rec := g3PostSpeech(t, gw, `{"model":"tts","input":"g3 no content type","voice":"alloy"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, "application/octet-stream", rec.Header().Get("Content-Type"))
	require.Equal(t, marker, rec.Body.String())
	require.EqualValues(t, 1, hits.Load())
	require.Len(t, store.admitted, 1)
	require.Len(t, store.facts, 1)
}

// TestGWCovG3_TranscriptionRebuildFormAdversarialParts documents why span
// audio_transcriptions.go:138.3,141.1 stays uncovered: the handler's
// form-rebuild error arm is defensive. audioRebuildForm encodes into a
// bytes.Buffer and every error it can return originates in writes to that
// buffer (WriteField/CreatePart/io.Copy/Close); bytes.Buffer writes cannot
// fail, and no seam lets a test inject a failing writer without a
// production change (forbidden for this TEST-ONLY slice). The adversarial
// inputs a client can actually deliver all rebuild successfully, which
// this test pins directly against the helper.
func TestGWCovG3_TranscriptionRebuildFormAdversarialParts(t *testing.T) {
	file := g3WAV(64)
	cases := []struct {
		name  string
		parts []audioFormPart
	}{
		{"no parts", nil},
		{"text fields only", []audioFormPart{
			{name: "model", value: "m"},
			{name: "language", value: `en"`},
		}},
		{"quote-and-backslash filename", []audioFormPart{
			{name: "model", value: "m"},
			{name: "file", filename: `we"ird\name.wav`, contentType: "audio/wav", data: file, file: true},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rebuilt, extra, err := audioRebuildForm(tc.parts, "g3-resolved-model")
			require.NoError(t, err)
			require.NotEmpty(t, rebuilt)
			require.True(t, strings.HasPrefix(extra.Get("Content-Type"), "multipart/form-data; boundary="))

			// The rebuilt stream round-trips: text fields survive (model
			// rewritten) and file bytes are preserved verbatim.
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/audio/transcriptions", bytes.NewReader(rebuilt))
			req.Header.Set("Content-Type", extra.Get("Content-Type"))
			mr, err := req.MultipartReader()
			require.NoError(t, err)
			var sawModel string
			var sawFile []byte
			for {
				p, err := mr.NextPart()
				if errors.Is(err, io.EOF) {
					break
				}
				require.NoError(t, err)
				raw, err := io.ReadAll(p)
				require.NoError(t, err)
				if p.FileName() != "" {
					sawFile = raw
					continue
				}
				if p.FormName() == "model" {
					sawModel = string(raw)
				}
			}
			hasModel, hasFile := false, false
			for _, p := range tc.parts {
				if p.name == "model" {
					hasModel = true
				}
				if p.file {
					hasFile = true
				}
			}
			if hasModel {
				require.Equal(t, "g3-resolved-model", sawModel)
			}
			if hasFile {
				require.Equal(t, file, sawFile)
			}
		})
	}
}
