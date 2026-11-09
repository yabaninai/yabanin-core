//go:build integration

package integration

// boundary — a full cli.RunGatewayServer stack (auth, 10 MiB MaxBody, rate
// limit, admission, credit reservation, async event publisher on real Redis,
// DB model registry) talking to a real upstream HTTP server over TCP.
//
// The pkg/gateway audio_* unit tests pin the exact refusal envelopes and the
// 10 MiB / 64 MiB byte boundaries; this file verifies the supported subset
// flows and the negative scenarios (unsupported format, large file, stream
// break) across the actual wire, with billing evidence read back from the
// Redis event stream and the org credit balance.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/gateway"
)

const audioIntAPIKey = "audio-integration-key"

// audioSeedModel is one models_registry row for an audio test.
type audioSeedModel struct {
	name        string
	provider    string
	upstreamURL string
}

// audioIntegrationGateway seeds the shared org, an API key and the given
// registry rows (rows must exist BEFORE the server starts — 5-minute
// resolver cache), then boots the real gateway server on a free port with a
// dedicated event stream. Returns base URL, the Redis client for stream
// reads, the event stream name and the cleanup func.
func audioIntegrationGateway(t *testing.T, ctx context.Context, upstreamURL string, models ...audioSeedModel) (string, *redis.Client, *pgxpool.Pool, string, func()) {
	t.Helper()
	rdb := NewGatewayTestRedis(t, ctx)
	pool := NewGatewayTestDB(t, ctx)

	// Seed the tenancy rows explicitly and fail hard on any error: the
	// shared Seed* helpers t.Skipf on seed failures, which would silently
	// bypass the whole scenario. Order respects the FKs (org → team →
	// wallet/budget), then seedAPIKey adds the api_keys row and the auth
	// resolver cache entry.
	seedAudioIntOrgRow(t, pool,
		"INSERT INTO organizations (id, name, slug) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING",
		testGatewayOrgID, "gateway-audio-int-org", "gateway-audio-int")
	seedAudioIntOrgRow(t, pool,
		"INSERT INTO organizations_teams (id, org_id, name, slug) VALUES ($1, $2, 'gateway-integration-team', 'gatewaytest-team') ON CONFLICT (id) DO NOTHING",
		testGatewayTeamID, testGatewayOrgID)
	seedAudioIntOrgRow(t, pool,
		"INSERT INTO org_credits (org_id, balance_cents, updated_at) VALUES ($1, 100000, now()) ON CONFLICT (org_id) DO NOTHING",
		testGatewayOrgID)
	seedAudioIntOrgRow(t, pool,
		"INSERT INTO team_budgets (team_id, monthly_limit_usd, hard_limit) VALUES ($1, 1000.00, true) ON CONFLICT (team_id) DO NOTHING",
		testGatewayTeamID)
	seedAPIKey(rdb, pool, audioIntAPIKey, testGatewayOrgID)
	for _, m := range models {
		_, err := pool.Exec(ctx,
			`INSERT INTO models_registry (model_name, display_name, tier, upstream_url, provider, enabled)
			 VALUES ($1, $1, 'smart', $2, $3, true)
			 ON CONFLICT (model_name) DO UPDATE SET upstream_url = EXCLUDED.upstream_url, provider = EXCLUDED.provider, enabled = true`,
			m.name, m.upstreamURL, m.provider)
		require.NoError(t, err)
	}

	stream := fmt.Sprintf("gateway-audio-int-%d", time.Now().UnixNano())
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	port := findFreePort(t)
	cfg := config.Gateway{
		ListenAddr:  fmt.Sprintf("127.0.0.1:%d", port),
		AuthMode:    "header",
		PGURI:       gatewayPGURI(),
		Provider:    upstreamURL,
		FallbackKey: audioIntAPIKey,
		EventStream: stream,
	}

	serverCtx, serverCancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = cli.RunGatewayServer(cfg, rdb, pool, integrationTestKMS{}, logger, serverCtx)
	}()

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	waitForGatewayReady(t, baseURL)

	return baseURL, rdb, pool, stream, func() {
		serverCancel()
		select {
		case <-time.After(5 * time.Second):
		case <-done:
		}
	}
}

// seedAudioIntOrgRow runs one idempotent tenancy seed statement and fails
// the test on any error (never skip).
func seedAudioIntOrgRow(t *testing.T, pool *pgxpool.Pool, query string, args ...any) {
	t.Helper()
	_, err := pool.Exec(context.Background(), query, args...)
	require.NoError(t, err)
}

// audioIntWAV builds a deterministic 16-bit mono 8000 Hz RIFF/PCM WAV of
// exactly 44 + 2*samples bytes (canonical header + fixed integer-ramp
// payload). The committed real-byte fixture
// pkg/gateway/testdata/audio/hello.wav (1644 bytes) was retired on
// 2026-11-05 with the provenance QUARANTINE lift (see
// artifacts/rights/provenance-map-2026-11-01.md addendum); synthWAV(800)
// keeps its exact size so size-derived reservation behavior (1000 B/s) is
// unchanged. This mirrors pkg/gateway/audio_testsynth_test.go (the unit
// matrix's canonical synthesizer), kept self-contained because integration
// tests cannot import another package's test helpers.
func audioIntWAV(samples int) []byte {
	const (
		sampleRate = 8000 // Hz — matches the retired hello.wav geometry
		bitDepth   = 16
		channels   = 1
	)
	dataLen := samples * channels * (bitDepth / 8)
	b := make([]byte, 44+dataLen)
	copy(b[0:4], "RIFF")
	binary.LittleEndian.PutUint32(b[4:8], uint32(36+dataLen)) // RIFF chunk size
	copy(b[8:12], "WAVE")
	copy(b[12:16], "fmt ")
	binary.LittleEndian.PutUint32(b[16:20], 16)                             // fmt chunk size (PCM)
	binary.LittleEndian.PutUint16(b[20:22], 1)                              // audio format: PCM
	binary.LittleEndian.PutUint16(b[22:24], channels)                       // mono
	binary.LittleEndian.PutUint32(b[24:28], sampleRate)                     // sample rate, Hz
	binary.LittleEndian.PutUint32(b[28:32], sampleRate*channels*bitDepth/8) // byte rate
	binary.LittleEndian.PutUint16(b[32:34], channels*bitDepth/8)            // block align
	binary.LittleEndian.PutUint16(b[34:36], bitDepth)                       // bits per sample
	copy(b[36:40], "data")
	binary.LittleEndian.PutUint32(b[40:44], uint32(dataLen))
	for i := 0; i < samples; i++ {
		s := int16((i%64)*500) - 15750
		binary.LittleEndian.PutUint16(b[44+2*i:], uint16(s))
	}
	return b
}

// audioIntMPEG builds frames MPEG-1 Layer III audio frames of exactly 417
// bytes each: header FF FB 90 04 (sync, MPEG-1, Layer III, no CRC,
// bitrate index 9 = 128 kbit/s, sample-rate index 0 = 44.1 kHz, no padding,
// stereo) + zeroed silence payload. 144*128000/44100 = 417; 20 frames
// reproduce the retired hello.mp3's exact 8340-byte size (same QUARANTINE
// lift as audioIntWAV). Valid MPEG framing, not an encoder's output — the
// gateway never decodes audio.
func audioIntMPEG(frames int) []byte {
	const frameLen = 417
	b := make([]byte, frames*frameLen)
	for f := 0; f < frames; f++ {
		off := f * frameLen
		b[off] = 0xFF
		b[off+1] = 0xFB // sync + MPEG-1 + Layer III + no CRC
		b[off+2] = 0x90 // 128 kbit/s, 44.1 kHz, no padding
		b[off+3] = 0x04 // stereo, original-home flag
	}
	return b
}

// audioIntMultipart encodes a transcription request: text fields plus one
// binary file part.
func audioIntMultipart(t *testing.T, fields map[string]string, filename, fileContentType string, file []byte) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		require.NoError(t, mw.WriteField(k, v))
	}
	h := make(map[string][]string)
	h["Content-Disposition"] = []string{fmt.Sprintf(`form-data; name="file"; filename=%q`, filename)}
	h["Content-Type"] = []string{fileContentType}
	fw, err := mw.CreatePart(h)
	require.NoError(t, err)
	_, err = fw.Write(file)
	require.NoError(t, err)
	require.NoError(t, mw.Close())
	return buf.Bytes(), mw.FormDataContentType()
}

// audioIntUpstreamMultipart parses a rebuilt multipart body on the upstream
// side and returns the text fields plus file bytes.
func audioIntUpstreamMultipart(t *testing.T, r *http.Request) (map[string]string, []byte) {
	t.Helper()
	mr, err := r.MultipartReader()
	if err != nil {
		t.Errorf("upstream multipart: %v", err)
		return nil, nil
	}
	fields := map[string]string{}
	var file []byte
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Errorf("upstream part: %v", err)
			return fields, file
		}
		data, err := io.ReadAll(p)
		if err != nil {
			t.Errorf("upstream part read: %v", err)
			return fields, file
		}
		if p.FileName() != "" {
			file = data
			continue
		}
		fields[p.FormName()] = string(data)
	}
	return fields, file
}

type audioIntEnvelope struct {
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	} `json:"error"`
}

func audioIntErrorEnvelope(t *testing.T, body []byte) audioIntEnvelope {
	t.Helper()
	var env audioIntEnvelope
	require.NoError(t, json.Unmarshal(body, &env), "envelope %s", body)
	return env
}

// audioIntAwaitCompleted waits for the async request.completed event of an
// audio endpoint; ok=false means none arrived within the grace period.
func audioIntAwaitCompleted(t *testing.T, rdb *redis.Client, stream, endpoint string) (map[string]string, bool) {
	t.Helper()
	return waitForStreamEntry(t, rdb, stream, func(e map[string]string) bool {
		return e["event_type"] == "request.completed" && e["endpoint"] == endpoint
	})
}

func audioIntOrgBalance(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	var cents int64
	err := pool.QueryRow(context.Background(),
		"SELECT balance_cents FROM org_credits WHERE org_id = $1", testGatewayOrgID).Scan(&cents)
	require.NoError(t, err)
	return cents
}

func audioIntPostSpeech(t *testing.T, baseURL, key, body, accept string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/v1/audio/speech", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func audioIntPostForm(t *testing.T, baseURL, key string, body []byte, contentType string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/v1/audio/transcriptions", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", contentType)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// TestIntegration_AudioSpeech_SynthesizedMPEGEndToEnd is acceptance example
// 1 over the wire: a synthesized MPEG-1 Layer III stream
// (audioIntMPEG(20)) crosses the full gateway byte-identical with
// the upstream Content-Type; the completion event reports zero tokens with
// usage_source "none" (D2) and cost_status "no_usage", and the org credit
// balance is untouched (escrow settled at zero spend).
func TestIntegration_AudioSpeech_SynthesizedMPEGEndToEnd(t *testing.T) {
	ctx := t.Context()
	mp3 := audioIntMPEG(20)
	model := fmt.Sprintf("audio-int-tts-%d", time.Now().UnixNano())

	var calls atomic.Int64
	var gotModel atomic.Value
	upSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/v1/audio/speech" {
			t.Errorf("upstream path %s", r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		var req struct {
			Model string `json:"model"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			t.Errorf("upstream body %s: %v", raw, err)
		}
		gotModel.Store(req.Model)
		w.Header().Set("Content-Type", "audio/mpeg")
		_, _ = w.Write(mp3)
	}))
	defer upSrv.Close()

	baseURL, rdb, pool, stream, cleanup := audioIntegrationGateway(t, ctx, upSrv.URL, audioSeedModel{name: model, provider: "openai", upstreamURL: upSrv.URL})
	defer cleanup()

	balanceBefore := audioIntOrgBalance(t, pool)

	resp := audioIntPostSpeech(t, baseURL, audioIntAPIKey,
		fmt.Sprintf(`{"model":%q,"input":"hello","voice":"alloy"}`, model), "")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	got, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "audio/mpeg", resp.Header.Get("Content-Type"))
	require.Equal(t, sha256.Sum256(mp3), sha256.Sum256(got), "audio bytes must survive the wire byte-identical")
	require.Equal(t, model, gotModel.Load(), "upstream must receive the resolved registry model")
	require.Equal(t, int64(1), calls.Load())

	// The completion event is async; the balance settle is synchronous, so
	// after the response the escrow is already released.
	require.Equal(t, balanceBefore, audioIntOrgBalance(t, pool), "speech usage_source none must settle at zero spend")

	entry, ok := audioIntAwaitCompleted(t, rdb, stream, "audio.speech")
	require.True(t, ok, "no request.completed event for speech happy path")
	require.Equal(t, "none", entry["usage_source"])
	require.Equal(t, "no_usage", entry["cost_status"])
	require.Equal(t, "0", entry["tokens_in"])
	require.Equal(t, "0", entry["tokens_out"])
	require.Equal(t, model, entry["model_used"])
	require.Equal(t, "200", entry["status_code"])
	require.Equal(t, testGatewayOrgID, entry["org_id"])
}

// TestIntegration_AudioTranscriptions_SynthesizedWAVEndToEnd is the
// acceptance-1 twin on the multipart side: a synthesized canonical WAV
// (audioIntWAV(800)) crosses the rebuilt multipart boundary byte-identical
// with the model field carrying the registry name, and the upstream usage
// block maps to usage_source "provider" on the completion event.
func TestIntegration_AudioTranscriptions_SynthesizedWAVEndToEnd(t *testing.T) {
	ctx := t.Context()
	wav := audioIntWAV(800)
	model := fmt.Sprintf("audio-int-whisper-%d", time.Now().UnixNano())
	upstreamJSON := []byte(`{"text":"hello world","usage":{"prompt_tokens":3,"output_tokens":5}}`)

	var calls atomic.Int64
	var gotFields atomic.Value
	var gotFile atomic.Value
	upSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		fields, file := audioIntUpstreamMultipart(t, r)
		gotFields.Store(fields)
		gotFile.Store(file)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(upstreamJSON)
	}))
	defer upSrv.Close()

	baseURL, rdb, _, stream, cleanup := audioIntegrationGateway(t, ctx, upSrv.URL, audioSeedModel{name: model, provider: "openai", upstreamURL: upSrv.URL})
	defer cleanup()

	body, contentType := audioIntMultipart(t, map[string]string{"model": model}, "hello.wav", "audio/wav", wav)
	resp := audioIntPostForm(t, baseURL, audioIntAPIKey, body, contentType)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	got, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.JSONEq(t, string(upstreamJSON), string(got), "upstream JSON must cross the boundary intact")
	require.Equal(t, int64(1), calls.Load())

	fields, _ := gotFields.Load().(map[string]string)
	require.Equal(t, model, fields["model"], "upstream model must be the registry name")
	file, _ := gotFile.Load().([]byte)
	require.Equal(t, sha256.Sum256(wav), sha256.Sum256(file), "file part must stay byte-identical through the rebuild")

	entry, ok := audioIntAwaitCompleted(t, rdb, stream, "audio.transcriptions")
	require.True(t, ok, "no request.completed event for transcriptions happy path")
	require.Equal(t, "provider", entry["usage_source"])
	require.Equal(t, "3", entry["tokens_in"])
	require.Equal(t, "5", entry["tokens_out"])
	require.Equal(t, model, entry["model_used"])
	require.Equal(t, "200", entry["status_code"])
	require.Equal(t, testGatewayOrgID, entry["org_id"])
}

// TestIntegration_AudioTranscriptions_BodyCapOverWire is the large-file
// negative through the REAL server middleware: a multipart body past the
// 10 MiB gateway cap answers 413 with zero upstream calls.
func TestIntegration_AudioTranscriptions_BodyCapOverWire(t *testing.T) {
	ctx := t.Context()
	model := fmt.Sprintf("audio-int-cap-%d", time.Now().UnixNano())

	var calls atomic.Int64
	upSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
	}))
	defer upSrv.Close()

	baseURL, rdb, _, stream, cleanup := audioIntegrationGateway(t, ctx, upSrv.URL, audioSeedModel{name: model, provider: "openai", upstreamURL: upSrv.URL})
	defer cleanup()

	big := make([]byte, 10*1024*1024+4096)
	for i := range big {
		big[i] = byte(i % 251)
	}
	body, contentType := audioIntMultipart(t, map[string]string{"model": model}, "big.wav", "audio/wav", big)
	resp := audioIntPostForm(t, baseURL, audioIntAPIKey, body, contentType)
	defer resp.Body.Close()
	require.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
	env := audioIntErrorEnvelope(t, readAll(t, resp))
	require.Equal(t, "invalid_request_error", env.Error.Type)
	require.Equal(t, int64(0), calls.Load(), "oversized body must be refused before any upstream call")

	_, ok := audioIntAwaitCompleted(t, rdb, stream, "audio.transcriptions")
	require.False(t, ok, "no completion event on oversized refusal")
}

// TestIntegration_AudioSpeech_UnsupportedFormatUpstream4xx is the
// unsupported-format negative over the wire: bytes cross un-sniffed, the
// upstream format refusal maps into the standard envelope and no completion
// event is published.
func TestIntegration_AudioSpeech_UnsupportedFormatUpstream4xx(t *testing.T) {
	ctx := t.Context()
	model := fmt.Sprintf("audio-int-fmt-%d", time.Now().UnixNano())

	var calls atomic.Int64
	upSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"unsupported format","type":"invalid_request_error"}}`))
	}))
	defer upSrv.Close()

	baseURL, rdb, _, stream, cleanup := audioIntegrationGateway(t, ctx, upSrv.URL, audioSeedModel{name: model, provider: "openai", upstreamURL: upSrv.URL})
	defer cleanup()

	resp := audioIntPostSpeech(t, baseURL, audioIntAPIKey,
		fmt.Sprintf(`{"model":%q,"input":"hello","voice":"alloy"}`, model), "")
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	env := audioIntErrorEnvelope(t, readAll(t, resp))
	require.Equal(t, "invalid_request_error", env.Error.Type)
	require.Equal(t, int64(1), calls.Load(), "format rejection is upstream-verified")

	_, ok := audioIntAwaitCompleted(t, rdb, stream, "audio.speech")
	require.False(t, ok, "no completion event on upstream format refusal")
}

// TestIntegration_AudioStreamingAndProviderRefused groups the two
// pre-admission refusals: SSE/stream asks and a non-OpenAI-compatible
// registry provider are both answered 400 with zero upstream calls (M5/D5
// and D6 through the real registry).
func TestIntegration_AudioStreamingAndProviderRefused(t *testing.T) {
	ctx := t.Context()
	model := fmt.Sprintf("audio-int-reject-%d", time.Now().UnixNano())
	anthropicModel := model + "-claude"

	var calls atomic.Int64
	upSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
	}))
	defer upSrv.Close()

	baseURL, rdb, _, stream, cleanup := audioIntegrationGateway(t, ctx, upSrv.URL,
		audioSeedModel{name: model, provider: "openai", upstreamURL: upSrv.URL},
		audioSeedModel{name: anthropicModel, provider: "anthropic", upstreamURL: upSrv.URL})
	defer cleanup()

	t.Run("stream flag rejected pre-admission", func(t *testing.T) {
		resp := audioIntPostSpeech(t, baseURL, audioIntAPIKey,
			fmt.Sprintf(`{"model":%q,"input":"hello","voice":"alloy","stream":true}`, model), "")
		defer resp.Body.Close()
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		env := audioIntErrorEnvelope(t, readAll(t, resp))
		require.Equal(t, "unsupported_feature", env.Error.Code)
	})

	t.Run("SSE accept rejected pre-admission", func(t *testing.T) {
		resp := audioIntPostSpeech(t, baseURL, audioIntAPIKey,
			fmt.Sprintf(`{"model":%q,"input":"hello","voice":"alloy"}`, model), "text/event-stream")
		defer resp.Body.Close()
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		env := audioIntErrorEnvelope(t, readAll(t, resp))
		require.Equal(t, "unsupported_feature", env.Error.Code)
	})

	t.Run("anthropic registry row refuses speech", func(t *testing.T) {
		resp := audioIntPostSpeech(t, baseURL, audioIntAPIKey,
			fmt.Sprintf(`{"model":%q,"input":"hello","voice":"alloy"}`, anthropicModel), "")
		defer resp.Body.Close()
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		env := audioIntErrorEnvelope(t, readAll(t, resp))
		require.Equal(t, "speech_not_supported_for_provider", env.Error.Code)
	})

	t.Run("anthropic registry row refuses transcriptions", func(t *testing.T) {
		body, contentType := audioIntMultipart(t, map[string]string{"model": anthropicModel}, "hello.wav", "audio/wav", audioIntWAV(800))
		resp := audioIntPostForm(t, baseURL, audioIntAPIKey, body, contentType)
		defer resp.Body.Close()
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		env := audioIntErrorEnvelope(t, readAll(t, resp))
		require.Equal(t, "transcriptions_not_supported_for_provider", env.Error.Code)
	})

	require.Equal(t, int64(0), calls.Load(), "pre-admission refusals must never reach the upstream")

	_, ok := audioIntAwaitCompleted(t, rdb, stream, "audio.speech")
	require.False(t, ok, "no completion event on refused audio requests")
}

// TestIntegration_AudioSpeech_UpstreamBreakMidResponse is the stream-break
// negative over the wire: the upstream dies mid-audio and the client gets a
// 502 envelope carrying none of the partial audio, with no completion event.
func TestIntegration_AudioSpeech_UpstreamBreakMidResponse(t *testing.T) {
	ctx := t.Context()
	model := fmt.Sprintf("audio-int-break-%d", time.Now().UnixNano())
	marker := bytes.Repeat([]byte{0xA7}, 4096)

	var calls atomic.Int64
	upSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "audio/mpeg")
		_, _ = w.Write(marker)
		panic(http.ErrAbortHandler)
	}))
	defer upSrv.Close()

	baseURL, rdb, _, stream, cleanup := audioIntegrationGateway(t, ctx, upSrv.URL, audioSeedModel{name: model, provider: "openai", upstreamURL: upSrv.URL})
	defer cleanup()

	resp := audioIntPostSpeech(t, baseURL, audioIntAPIKey,
		fmt.Sprintf(`{"model":%q,"input":"hello","voice":"alloy"}`, model), "")
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadGateway, resp.StatusCode)
	got := readAll(t, resp)
	env := audioIntErrorEnvelope(t, got)
	require.Equal(t, "api_error", env.Error.Type)
	require.False(t, bytes.Contains(got, marker), "error envelope must not echo upstream audio bytes")
	require.Equal(t, int64(1), calls.Load())

	_, ok := audioIntAwaitCompleted(t, rdb, stream, "audio.speech")
	require.False(t, ok, "no completion event on broken upstream stream")
}

// TestIntegration_AudioSpeech_ResponseCapOverWire crosses the 64 MiB
// upstream response cap over a real socket: the over-limit payload is
// refused 502, never truncated to the client, with no completion event.
func TestIntegration_AudioSpeech_ResponseCapOverWire(t *testing.T) {
	ctx := t.Context()
	model := fmt.Sprintf("audio-int-respcap-%d", time.Now().UnixNano())

	var calls atomic.Int64
	upSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "audio/wav")
		w.WriteHeader(http.StatusOK)
		chunk := make([]byte, 32*1024)
		for n := int64(0); n <= 64<<20; n += int64(len(chunk)) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer upSrv.Close()

	baseURL, rdb, _, stream, cleanup := audioIntegrationGateway(t, ctx, upSrv.URL, audioSeedModel{name: model, provider: "openai", upstreamURL: upSrv.URL})
	defer cleanup()

	resp := audioIntPostSpeech(t, baseURL, audioIntAPIKey,
		fmt.Sprintf(`{"model":%q,"input":"hello","voice":"alloy"}`, model), "")
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadGateway, resp.StatusCode)
	env := audioIntErrorEnvelope(t, readAll(t, resp))
	require.Equal(t, "api_error", env.Error.Type)
	require.Equal(t, int64(1), calls.Load())

	_, ok := audioIntAwaitCompleted(t, rdb, stream, "audio.speech")
	require.False(t, ok, "no completion event on over-cap upstream response")
}

// TestIntegration_AudioTranscriptions_ClientCancelMidUpload is the N3
// client-cancel negative over the wire: a client hanging up mid-multipart
// upload never reaches the upstream and publishes no completion event.
func TestIntegration_AudioTranscriptions_ClientCancelMidUpload(t *testing.T) {
	ctx := t.Context()
	model := fmt.Sprintf("audio-int-cancel-%d", time.Now().UnixNano())

	var calls atomic.Int64
	upSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
	}))
	defer upSrv.Close()

	baseURL, rdb, _, stream, cleanup := audioIntegrationGateway(t, ctx, upSrv.URL, audioSeedModel{name: model, provider: "openai", upstreamURL: upSrv.URL})
	defer cleanup()

	big := make([]byte, 8*1024*1024)
	for i := range big {
		big[i] = byte(i % 251)
	}
	body, contentType := audioIntMultipart(t, map[string]string{"model": model}, "big.wav", "audio/wav", big)

	reqCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pr, pw := io.Pipe()
	statusCh := make(chan int, 1)
	go func() {
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, baseURL+"/v1/audio/transcriptions", pr)
		if err != nil {
			statusCh <- -1
			return
		}
		req.Header.Set("Authorization", "Bearer "+audioIntAPIKey)
		req.Header.Set("Content-Type", contentType)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			statusCh <- 0
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		statusCh <- resp.StatusCode
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
	require.Equal(t, int64(0), calls.Load(), "canceled upload must not reach the upstream")

	_, ok := audioIntAwaitCompleted(t, rdb, stream, "audio.transcriptions")
	require.False(t, ok, "no completion event on canceled upload")
}

func readAll(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return raw
}
