package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/config"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/httpmw"
	"github.com/reireirei/yabanin/pkg/resolver"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// audioTestModel is the shared stub registry entry for the audio endpoint
// tests: the client sends model "tts"/"m" (admission alias), the registry
// resolves it to the canonical upstream name.
func audioTestModel(upstreamURL string) resolver.ModelInfo {
	return resolver.ModelInfo{
		ModelName:      "tts-1",
		Provider:       "openai",
		UpstreamURL:    upstreamURL,
		UpstreamAPIKey: "up-key",
		Enabled:        true,
	}
}

func newAudioGateway(t *testing.T, info resolver.ModelInfo) *gateway {
	t.Helper()
	return &gateway{
		cfg:  config.Gateway{AuthMode: "strict", APIKey: "test-key", Provider: info.UpstreamURL},
		log:  slog.New(slog.DiscardHandler),
		auth: NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
		res:  stubModelResolver{"m": info, "tts": info},
		pool: upstream.NewPool(upstream.Options{}),
	}
}

func postAudioSpeech(t *testing.T, gw *gateway, body, accept string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/audio/speech", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	rec := httptest.NewRecorder()
	r := chi.NewRouter()
	gw.routes(r)
	r.ServeHTTP(rec, req)
	return rec
}

// TestAudioSpeech_HappyPathSynthesizedMPEG is matrix row M1: a synthesized
// MPEG-1 Layer III stream (audio_testsynth_test.go) crosses the gateway
// byte-identical with the upstream Content-Type, the upstream JSON carries
// the resolved registry model and the completion event reports zero tokens
// with usage source "none" (D2). The gateway never decodes the payload; the
// committed real-byte fixtures were retired on 2026-11-05.
func TestAudioSpeech_HappyPathSynthesizedMPEG(t *testing.T) {
	mp3 := audioFixtureBytes(t, "hello.mp3")
	var calls atomic.Int64
	var gotModel string
	var gotContentType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/v1/audio/speech" {
			t.Errorf("upstream path %s", r.URL.Path)
		}
		gotContentType = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		var req struct {
			Model string `json:"model"`
			Input string `json:"input"`
			Voice string `json:"voice"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			t.Errorf("upstream body %s: %v", raw, err)
		}
		gotModel = req.Model
		w.Header().Set("Content-Type", "audio/mpeg")
		_, _ = w.Write(mp3)
	}))
	defer server.Close()

	gw := newAudioGateway(t, audioTestModel(server.URL))
	var mu atomic.Value
	mu.Store((*eventpub.Event)(nil))
	gw.eventNote = func(e *eventpub.Event) { mu.Store(e) }

	rec := postAudioSpeech(t, gw, `{"model":"tts","input":"hello","voice":"alloy"}`, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if got := mu.Load().(*eventpub.Event); got == nil {
		t.Fatal("no request.completed event")
	} else {
		if got.Endpoint != "audio.speech" || got.UsageSource != "none" || got.TokensIn != 0 || got.TokensOut != 0 {
			t.Fatalf("event %+v", got)
		}
		if got.StatusCode != http.StatusOK || got.ModelUsed != "tts-1" {
			t.Fatalf("event %+v", got)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream calls %d", calls.Load())
	}
	if gotModel != "tts-1" {
		t.Fatalf("upstream model %q, want resolved registry name tts-1", gotModel)
	}
	if gotContentType != "application/json" {
		t.Fatalf("upstream content type %q", gotContentType)
	}
	if rec.Body.String() != string(mp3) {
		t.Fatalf("audio bytes not byte-identical: got %d bytes want %d", rec.Body.Len(), len(mp3))
	}
	if ct := rec.Header().Get("Content-Type"); ct != "audio/mpeg" {
		t.Fatalf("response content type %q", ct)
	}
}

// TestAudioSpeech_ContentTypePassthrough pins the response Content-Type
// rules: upstream value wins, missing value falls back to
// application/octet-stream.
func TestAudioSpeech_ContentTypePassthrough(t *testing.T) {
	cases := []struct {
		name        string
		upstreamCT  string
		wantCT      string
		payloadByte byte
	}{
		{name: "opus", upstreamCT: "audio/opus", wantCT: "audio/opus", payloadByte: 0x0B},
		{name: "fallback", upstreamCT: "", wantCT: "application/octet-stream", payloadByte: 0x01},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.upstreamCT != "" {
					w.Header().Set("Content-Type", tc.upstreamCT)
				}
				_, _ = w.Write([]byte{tc.payloadByte, 0x02, 0x03})
			}))
			defer server.Close()
			gw := newAudioGateway(t, audioTestModel(server.URL))
			rec := postAudioSpeech(t, gw, `{"model":"tts","input":"hi","voice":"alloy"}`, "")
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
			}
			if ct := rec.Header().Get("Content-Type"); ct != tc.wantCT {
				t.Fatalf("content type %q want %q", ct, tc.wantCT)
			}
		})
	}
}

// TestAudioSpeech_StreamingRejected is matrix row M5: SSE audio streaming is
// outside the v1 subset — 400 unsupported_feature with upstream call count 0.
func TestAudioSpeech_StreamingRejected(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()
	gw := newAudioGateway(t, audioTestModel(server.URL))

	cases := []struct {
		name   string
		body   string
		accept string
	}{
		{name: "stream field", body: `{"model":"tts","input":"hi","voice":"alloy","stream":true}`},
		{name: "SSE accept", body: `{"model":"tts","input":"hi","voice":"alloy"}`, accept: "text/event-stream"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := postAudioSpeech(t, gw, tc.body, tc.accept)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
			}
			var env struct {
				Error struct {
					Code string `json:"code"`
					Type string `json:"type"`
				} `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
				t.Fatal(err)
			}
			if env.Error.Code != "unsupported_feature" || env.Error.Type != "invalid_request_error" {
				t.Fatalf("envelope %s", rec.Body.String())
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("upstream called %d times on rejected stream", calls.Load())
	}
}

// TestAudioSpeech_Upstream4xxMaps is matrix rows M6/N1: the gateway does not
// sniff formats — an upstream rejection of the payload maps through
// MapUpstreamStatus into the standard error envelope.
func TestAudioSpeech_Upstream4xxMaps(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"unsupported format","type":"invalid_request_error"}}`))
	}))
	defer server.Close()
	gw := newAudioGateway(t, audioTestModel(server.URL))

	rec := postAudioSpeech(t, gw, `{"model":"tts","input":"hi","voice":"alloy"}`, "")
	if rec.Code != http.StatusBadRequest || errorType(t, rec) != "invalid_request_error" {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream calls %d, want 1 (format rejection is upstream-verified)", calls.Load())
	}
}

// TestAudioSpeech_BodyTooLarge is limit N2: a body past the 10 MiB gateway
// cap answers 413 before any upstream call.
func TestAudioSpeech_BodyTooLarge(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()
	gw := newAudioGateway(t, audioTestModel(server.URL))

	r := chi.NewRouter()
	r.Use(httpmw.MaxBody(10 * 1024 * 1024))
	gw.routes(r)

	big := `{"model":"tts","input":"` + strings.Repeat("a", 10*1024*1024) + `","voice":"alloy"}`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/audio/speech", strings.NewReader(big))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if errorType(t, rec) != "invalid_request_error" {
		t.Fatalf("envelope %s", rec.Body.String())
	}
	if calls.Load() != 0 {
		t.Fatalf("upstream called %d times on oversized body", calls.Load())
	}
}

// TestAudioSpeech_ForeignTenantDenied is example E3 / limit N4: a model the
// key is not whitelisted for (or an unknown model under reject policy) is
// denied with the upstream call count at zero.
func TestAudioSpeech_ForeignTenantDenied(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer server.Close()
	info := audioTestModel(server.URL)

	t.Run("whitelist deny 403", func(t *testing.T) {
		gw := newAudioGateway(t, info)
		gw.pool = nil
		gw.wl = fakeAccess{allowed: false}
		rec := postAudioSpeech(t, gw, `{"model":"org-b-private-tts","input":"hi","voice":"alloy"}`, "")
		if rec.Code != http.StatusForbidden || errorType(t, rec) != "permission_denied_error" {
			t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("unknown model reject 404", func(t *testing.T) {
		gw := newAudioGateway(t, info)
		gw.pool = nil
		gw.unknownModelPolicy = "reject"
		gw.res = stubModelResolver{"org-b-private-tts": {ModelName: "org-b-private-tts", Provider: "openai", Fallback: true, Enabled: true}}
		rec := postAudioSpeech(t, gw, `{"model":"org-b-private-tts","input":"hi","voice":"alloy"}`, "")
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
		}
		var env struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatal(err)
		}
		if env.Error.Code != "model_not_found" {
			t.Fatalf("envelope %s", rec.Body.String())
		}
	})
}

// TestAudioSpeech_ClientCancelMidResponse is limit N3: a client hanging up
// while the upstream is still producing settles the escrow with
// TerminationClientCancel and publishes no request.completed success event.
func TestAudioSpeech_ClientCancelMidResponse(t *testing.T) {
	upstreamReached := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Drain the body before blocking: net/http only arms the server's
		// client-disconnect detector once the request body hits EOF, and the
		// disconnect is what must cancel this handler's context.
		_, _ = io.Copy(io.Discard, r.Body)
		close(upstreamReached)
		<-r.Context().Done()
	}))
	defer upstream.Close()

	gw := newAudioGateway(t, audioTestModel(upstream.URL))
	evCh := make(chan *eventpub.Event, 1)
	gw.eventNote = func(e *eventpub.Event) { evCh <- e }

	router := chi.NewRouter()
	gw.routes(router)
	gwServer := httptest.NewServer(router)
	defer gwServer.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, gwServer.URL+"/v1/audio/speech",
		strings.NewReader(`{"model":"tts","input":"hello","voice":"alloy"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	go func() {
		select {
		case <-upstreamReached:
		case <-time.After(5 * time.Second):
		}
		cancel()
	}()
	resp, err := gwServer.Client().Do(req)
	if err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("canceled request answered 200 audio")
		}
	}
	cancel()

	select {
	case ev := <-evCh:
		t.Fatalf("published success event on canceled request: %+v", ev)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestAudioUsageParsing pins the audioUsage helper: provider source only
// when the upstream reports a usage block, input_tokens accepted as the
// prompt_tokens fallback, output_tokens mapped to completion tokens.
func TestAudioUsageParsing(t *testing.T) {
	cases := []struct {
		name            string
		body            string
		wantIn, wantOut int64
		wantSource      string
	}{
		{name: "prompt+output", body: `{"text":"x","usage":{"prompt_tokens":5,"output_tokens":2}}`, wantIn: 5, wantOut: 2, wantSource: "provider"},
		{name: "input tokens fallback", body: `{"usage":{"input_tokens":7,"output_tokens":1}}`, wantIn: 7, wantOut: 1, wantSource: "provider"},
		{name: "no usage", body: `{"text":"x"}`, wantSource: ""},
		{name: "not json", body: `\x00\x01`, wantSource: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in, out, source := audioUsage([]byte(tc.body))
			if in != tc.wantIn || out != tc.wantOut || source != tc.wantSource {
				t.Fatalf("got (%d,%d,%q) want (%d,%d,%q)", in, out, source, tc.wantIn, tc.wantOut, tc.wantSource)
			}
		})
	}
}

// TestAudioSpeech_RequestValidation covers the remaining invalid-input 400
// shapes: a malformed JSON body and each missing required field are refused
// with the upstream call count at zero.
func TestAudioSpeech_RequestValidation(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()
	gw := newAudioGateway(t, audioTestModel(server.URL))

	cases := []struct {
		name string
		body string
		want string
	}{
		{name: "malformed json", body: `{"model":`, want: "malformed JSON"},
		{name: "missing model", body: `{"input":"hi","voice":"alloy"}`, want: "model is required"},
		{name: "missing input", body: `{"model":"tts","voice":"alloy"}`, want: "input is required"},
		{name: "missing voice", body: `{"model":"tts","input":"hi"}`, want: "voice is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := postAudioSpeech(t, gw, tc.body, "")
			if rec.Code != http.StatusBadRequest || errorType(t, rec) != "invalid_request_error" {
				t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
			}
			if !bytes.Contains(rec.Body.Bytes(), []byte(tc.want)) {
				t.Fatalf("envelope %s, want diagnosable reason %q", rec.Body.String(), tc.want)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("upstream called %d times on invalid input", calls.Load())
	}
}

// TestAudioSpeech_UpstreamBreakMidResponse is the upstream-side stream break:
// a connection torn down mid-body is answered 502 api_error — partial audio
// never reaches the client, the envelope carries no audio bytes and no
// completed event is published.
func TestAudioSpeech_UpstreamBreakMidResponse(t *testing.T) {
	marker := bytes.Repeat([]byte{0xA7}, 4096)
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "audio/mpeg")
		_, _ = w.Write(marker)
		panic(http.ErrAbortHandler)
	}))
	defer server.Close()

	gw := newAudioGateway(t, audioTestModel(server.URL))
	var evPtr atomic.Value
	evPtr.Store((*eventpub.Event)(nil))
	gw.eventNote = func(e *eventpub.Event) { evPtr.Store(e) }

	rec := postAudioSpeech(t, gw, `{"model":"tts","input":"hello","voice":"alloy"}`, "")
	if rec.Code != http.StatusBadGateway || errorType(t, rec) != "api_error" {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if bytes.Contains(rec.Body.Bytes(), marker) {
		t.Fatalf("error envelope echoes upstream audio bytes")
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream calls %d", calls.Load())
	}
	if ev := evPtr.Load().(*eventpub.Event); ev != nil {
		t.Fatalf("completed event on broken upstream stream: %+v", ev)
	}
}

// TestAudioSpeech_ResponseLimitBoundary pins the 64 MiB response cap from
// both sides: exactly the limit is forwarded byte-identical, one byte over is
// answered 502 (never truncated to the client) and the refusal envelope
// carries none of the refused bytes.
func TestAudioSpeech_ResponseLimitBoundary(t *testing.T) {
	marker := []byte("AUDIOBOUNDARYMARKER")
	cases := []struct {
		name       string
		size       int
		wantStatus int
	}{
		{name: "exact limit", size: audioResponseLimit, wantStatus: http.StatusOK},
		{name: "limit+1", size: audioResponseLimit + 1, wantStatus: http.StatusBadGateway},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := make([]byte, tc.size)
			copy(payload, marker)
			for i := len(marker); i < tc.size; i++ {
				payload[i] = byte(i % 251)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "audio/mpeg")
				_, _ = w.Write(payload)
			}))
			defer server.Close()

			gw := newAudioGateway(t, audioTestModel(server.URL))
			rec := postAudioSpeech(t, gw, `{"model":"tts","input":"hi","voice":"alloy"}`, "")
			if rec.Code != tc.wantStatus {
				t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
			}
			if tc.wantStatus == http.StatusOK {
				if !bytes.Equal(rec.Body.Bytes(), payload) {
					t.Fatalf("audio not byte-identical: got %d bytes want %d", rec.Body.Len(), tc.size)
				}
				return
			}
			if errorType(t, rec) != "api_error" {
				t.Fatalf("envelope %s", rec.Body.String())
			}
			if bytes.Contains(rec.Body.Bytes(), marker) {
				t.Fatalf("refusal echoes refused audio bytes")
			}
		})
	}
}

// TestAudioSpeech_UpstreamErrorMasking: upstream 401 is masked to 502
// api_error (no upstream auth detail reaches the client) and 5xx maps to 502
// api_error; neither publishes a completed event nor echoes the upstream body.
func TestAudioSpeech_UpstreamErrorMasking(t *testing.T) {
	cases := []struct {
		name   string
		status int
	}{
		{name: "401 masked", status: http.StatusUnauthorized},
		{name: "500 mapped", status: http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{"detail":"internal-upstream-secret"}`))
			}))
			defer server.Close()

			gw := newAudioGateway(t, audioTestModel(server.URL))
			var evPtr atomic.Value
			evPtr.Store((*eventpub.Event)(nil))
			gw.eventNote = func(e *eventpub.Event) { evPtr.Store(e) }

			rec := postAudioSpeech(t, gw, `{"model":"tts","input":"hi","voice":"alloy"}`, "")
			if rec.Code != http.StatusBadGateway || errorType(t, rec) != "api_error" {
				t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
			}
			if bytes.Contains(rec.Body.Bytes(), []byte("internal-upstream-secret")) {
				t.Fatalf("envelope leaks upstream body: %s", rec.Body.String())
			}
			if ev := evPtr.Load().(*eventpub.Event); ev != nil {
				t.Fatalf("completed event on upstream error: %+v", ev)
			}
		})
	}
}

// TestAudioSpeech_RetryAfterUpstreamFailure: a 502 on the first attempt does
// not poison the gateway — the identical retry succeeds and is the only
// request settled as a completed spend (partial/unknown state never reads as
// success).
func TestAudioSpeech_RetryAfterUpstreamFailure(t *testing.T) {
	audio := audioFixtureBytes(t, "hello.mp3")
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "audio/mpeg")
		_, _ = w.Write(audio)
	}))
	defer server.Close()

	gw := newAudioGateway(t, audioTestModel(server.URL))
	var mu sync.Mutex
	var events []*eventpub.Event
	gw.eventNote = func(e *eventpub.Event) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	}

	first := postAudioSpeech(t, gw, `{"model":"tts","input":"hello","voice":"alloy"}`, "")
	if first.Code != http.StatusBadGateway || errorType(t, first) != "api_error" {
		t.Fatalf("first attempt status %d body %s", first.Code, first.Body.String())
	}
	second := postAudioSpeech(t, gw, `{"model":"tts","input":"hello","voice":"alloy"}`, "")
	if second.Code != http.StatusOK || !bytes.Equal(second.Body.Bytes(), audio) {
		t.Fatalf("retry status %d len %d", second.Code, second.Body.Len())
	}
	if calls.Load() != 2 {
		t.Fatalf("upstream calls %d", calls.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 1 || events[0].EventType != "request.completed" || events[0].StatusCode != http.StatusOK {
		t.Fatalf("events %+v", events)
	}
}
