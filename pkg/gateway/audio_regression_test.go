package cli

// boundary tests. Three regression layers live here:
//
//  1. TestAudioRefusalEnvelopesGolden — golden-style pinning of every audio
//     refusal envelope (exact wire body, status, headers) so the client-facing
//     refusal contract cannot drift silently.
//  2. TestAudioSubsetMatrixWorkingPath — the documented v1 subset matrix
//     (contract §4.4 rows M1/M3) as one table-driven test: real bytes cross
//     the gateway byte-identically, one settled completed event per request
//     with per-request usage attribution.
//  3. TestAudioBillingOneSpendPerRequest — billing/usage invariants across a
//     mixed success/failure/refusal sequence: exactly one settled spend per
//     successful request, refusals never settle, tokens never double-counted.
//
// Negative proofs (exact cap boundaries, verbatim corrupt bytes, cancel
// mid-upload, retry idempotency, leak refutations) stay in
// duplicated here.
//
// The golden file is data: update only with the explicit env gate and commit
// the diff for review:
//
//	AUDIO_ENVELOPES_GOLDEN_UPDATE=1 go test ./pkg/gateway/ -run TestAudioRefusalEnvelopesGolden

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/httpmw"
	"github.com/reireirei/yabanin/pkg/resolver"
)

const (
	audioEnvelopesGoldenPath = "testdata/audio/refusal_envelopes.golden"
	envAudioEnvelopesUpdate  = "AUDIO_ENVELOPES_GOLDEN_UPDATE"
)

// audioErrReader is a request body that fails mid-read with a non-cap error —
// pins the fallback branch of writeAudioBodyError (anything that is not a
// MaxBytesError is a 400 malformed-body refusal).
type audioErrReader struct{}

func (audioErrReader) Read([]byte) (int, error) { return 0, errors.New("disk failure") }

// audioNonCompatModel resolves the admission alias to a provider outside the
// openAICompatProvider gate — the refusal path for the D6 subset claim.
func audioNonCompatModel(upstreamURL string) resolver.ModelInfo {
	return resolver.ModelInfo{
		ModelName:      "cohere-model",
		Provider:       "cohere",
		UpstreamURL:    upstreamURL,
		UpstreamAPIKey: "up-key",
		Enabled:        true,
	}
}

// audioRefusalResult carries everything the golden harness pins per scenario.
type audioRefusalResult struct {
	rec       *httptest.ResponseRecorder
	upstream  int64
	completed []*eventpub.Event
}

// audioRefusalCase is one pinned refusal scenario: fire produces the real
// response through the full router; the harness pins status, envelope body,
// refusal headers, the upstream call count and the absence of a settled
// completed event.
type audioRefusalCase struct {
	name      string
	status    int
	wantCalls int64
	fire      func(t *testing.T) audioRefusalResult
}

// audioRefusalUpstream spins up the shared fake upstream for one scenario and
// returns its URL and the call counter.
func audioRefusalUpstream(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
	}))
	t.Cleanup(server.Close)
	return server, &calls
}

// audioCollectEvents wires an event collector and returns the slice it fills.
func audioCollectEvents(gw *gateway) *[]*eventpub.Event {
	events := make([]*eventpub.Event, 0, 1)
	gw.eventNote = func(e *eventpub.Event) {
		events = append(events, e)
	}
	return &events
}

// audioMultipart builds the standard E1 transcription form for a refusal
// scenario (caller decides which parts to omit).
func audioMultipart(t *testing.T, fields map[string]string, file []byte) ([]byte, string) {
	t.Helper()
	return buildAudioMultipart(t, fields, "file", "hello.wav", "audio/wav", file)
}

// audioOversizedSpeechBody builds a speech JSON body past the 10 MiB cap.
func audioOversizedSpeechBody() string {
	return `{"model":"tts","input":"` + strings.Repeat("a", 10*1024*1024) + `","voice":"alloy"}`
}

// TestAudioRefusalEnvelopesGolden pins every audio refusal envelope to
// testdata/audio/refusal_envelopes.golden: the exact wire body, the status,
// the refusal headers, the upstream call count and the invariant that no
// refusal ever settles a completed (spend) event. A message, type or code
// change turns this red with a per-section diff; update only via the env gate
// and commit the golden diff in the same change.
func TestAudioRefusalEnvelopesGolden(t *testing.T) {
	cases := []audioRefusalCase{
		{
			name:   "speech/stream-field",
			status: http.StatusBadRequest,
			fire: func(t *testing.T) audioRefusalResult {
				t.Helper()
				server, calls := audioRefusalUpstream(t)
				gw := newAudioGateway(t, audioTestModel(server.URL))
				events := audioCollectEvents(gw)
				rec := postAudioSpeech(t, gw, `{"model":"tts","input":"hi","voice":"alloy","stream":true}`, "")
				return audioRefusalResult{rec: rec, upstream: calls.Load(), completed: *events}
			},
		},
		{
			name:   "speech/accept-sse",
			status: http.StatusBadRequest,
			fire: func(t *testing.T) audioRefusalResult {
				t.Helper()
				server, calls := audioRefusalUpstream(t)
				gw := newAudioGateway(t, audioTestModel(server.URL))
				events := audioCollectEvents(gw)
				rec := postAudioSpeech(t, gw, `{"model":"tts","input":"hi","voice":"alloy"}`, "text/event-stream")
				return audioRefusalResult{rec: rec, upstream: calls.Load(), completed: *events}
			},
		},
		{
			name:   "speech/missing-model",
			status: http.StatusBadRequest,
			fire: func(t *testing.T) audioRefusalResult {
				t.Helper()
				server, calls := audioRefusalUpstream(t)
				gw := newAudioGateway(t, audioTestModel(server.URL))
				events := audioCollectEvents(gw)
				rec := postAudioSpeech(t, gw, `{"input":"hi","voice":"alloy"}`, "")
				return audioRefusalResult{rec: rec, upstream: calls.Load(), completed: *events}
			},
		},
		{
			name:   "speech/missing-input",
			status: http.StatusBadRequest,
			fire: func(t *testing.T) audioRefusalResult {
				t.Helper()
				server, calls := audioRefusalUpstream(t)
				gw := newAudioGateway(t, audioTestModel(server.URL))
				events := audioCollectEvents(gw)
				rec := postAudioSpeech(t, gw, `{"model":"tts","voice":"alloy"}`, "")
				return audioRefusalResult{rec: rec, upstream: calls.Load(), completed: *events}
			},
		},
		{
			name:   "speech/missing-voice",
			status: http.StatusBadRequest,
			fire: func(t *testing.T) audioRefusalResult {
				t.Helper()
				server, calls := audioRefusalUpstream(t)
				gw := newAudioGateway(t, audioTestModel(server.URL))
				events := audioCollectEvents(gw)
				rec := postAudioSpeech(t, gw, `{"model":"tts","input":"hi"}`, "")
				return audioRefusalResult{rec: rec, upstream: calls.Load(), completed: *events}
			},
		},
		{
			name:   "speech/malformed-json",
			status: http.StatusBadRequest,
			fire: func(t *testing.T) audioRefusalResult {
				t.Helper()
				server, calls := audioRefusalUpstream(t)
				gw := newAudioGateway(t, audioTestModel(server.URL))
				events := audioCollectEvents(gw)
				rec := postAudioSpeech(t, gw, `{"model":`, "")
				return audioRefusalResult{rec: rec, upstream: calls.Load(), completed: *events}
			},
		},
		{
			name:   "speech/body-unreadable",
			status: http.StatusBadRequest,
			fire: func(t *testing.T) audioRefusalResult {
				t.Helper()
				server, calls := audioRefusalUpstream(t)
				gw := newAudioGateway(t, audioTestModel(server.URL))
				events := audioCollectEvents(gw)
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
					"/v1/audio/speech", audioErrReader{})
				req.Header.Set("Authorization", "Bearer test-key")
				req.Header.Set("Content-Type", "application/json")
				rec := httptest.NewRecorder()
				r := chi.NewRouter()
				gw.routes(r)
				r.ServeHTTP(rec, req)
				return audioRefusalResult{rec: rec, upstream: calls.Load(), completed: *events}
			},
		},
		{
			name:   "speech/oversized-body",
			status: http.StatusRequestEntityTooLarge,
			fire: func(t *testing.T) audioRefusalResult {
				t.Helper()
				server, calls := audioRefusalUpstream(t)
				gw := newAudioGateway(t, audioTestModel(server.URL))
				events := audioCollectEvents(gw)
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
					"/v1/audio/speech", strings.NewReader(audioOversizedSpeechBody()))
				req.Header.Set("Authorization", "Bearer test-key")
				req.Header.Set("Content-Type", "application/json")
				rec := httptest.NewRecorder()
				r := chi.NewRouter()
				r.Use(httpmw.MaxBody(10 * 1024 * 1024))
				gw.routes(r)
				r.ServeHTTP(rec, req)
				return audioRefusalResult{rec: rec, upstream: calls.Load(), completed: *events}
			},
		},
		{
			name:   "speech/provider-not-compat",
			status: http.StatusBadRequest,
			fire: func(t *testing.T) audioRefusalResult {
				t.Helper()
				server, calls := audioRefusalUpstream(t)
				gw := newAudioGateway(t, audioNonCompatModel(server.URL))
				events := audioCollectEvents(gw)
				rec := postAudioSpeech(t, gw, `{"model":"m","input":"hi","voice":"alloy"}`, "")
				return audioRefusalResult{rec: rec, upstream: calls.Load(), completed: *events}
			},
		},
		{
			name:      "speech/upstream-400-mapped",
			status:    http.StatusBadRequest,
			wantCalls: 1,
			fire: func(t *testing.T) audioRefusalResult {
				t.Helper()
				var calls atomic.Int64
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					calls.Add(1)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":{"message":"unsupported format","type":"invalid_request_error"}}`))
				}))
				t.Cleanup(server.Close)
				gw := newAudioGateway(t, audioTestModel(server.URL))
				events := audioCollectEvents(gw)
				rec := postAudioSpeech(t, gw, `{"model":"tts","input":"hi","voice":"alloy"}`, "")
				return audioRefusalResult{rec: rec, upstream: calls.Load(), completed: *events}
			},
		},
		{
			name:      "speech/upstream-401-masked",
			status:    http.StatusBadGateway,
			wantCalls: 1,
			fire: func(t *testing.T) audioRefusalResult {
				t.Helper()
				var calls atomic.Int64
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					calls.Add(1)
					w.WriteHeader(http.StatusUnauthorized)
				}))
				t.Cleanup(server.Close)
				gw := newAudioGateway(t, audioTestModel(server.URL))
				events := audioCollectEvents(gw)
				rec := postAudioSpeech(t, gw, `{"model":"tts","input":"hi","voice":"alloy"}`, "")
				return audioRefusalResult{rec: rec, upstream: calls.Load(), completed: *events}
			},
		},
		{
			name:      "speech/upstream-500-mapped",
			status:    http.StatusBadGateway,
			wantCalls: 1,
			fire: func(t *testing.T) audioRefusalResult {
				t.Helper()
				var calls atomic.Int64
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					calls.Add(1)
					w.WriteHeader(http.StatusInternalServerError)
				}))
				t.Cleanup(server.Close)
				gw := newAudioGateway(t, audioTestModel(server.URL))
				events := audioCollectEvents(gw)
				rec := postAudioSpeech(t, gw, `{"model":"tts","input":"hi","voice":"alloy"}`, "")
				return audioRefusalResult{rec: rec, upstream: calls.Load(), completed: *events}
			},
		},
		{
			name:   "transcriptions/non-multipart",
			status: http.StatusBadRequest,
			fire: func(t *testing.T) audioRefusalResult {
				t.Helper()
				server, calls := audioRefusalUpstream(t)
				gw := newAudioGateway(t, audioTranscriptionModel(server.URL))
				events := audioCollectEvents(gw)
				rec := postAudioTranscriptions(t, gw, []byte(`{"model":"m"}`), "application/json")
				return audioRefusalResult{rec: rec, upstream: calls.Load(), completed: *events}
			},
		},
		{
			name:   "transcriptions/missing-model",
			status: http.StatusBadRequest,
			fire: func(t *testing.T) audioRefusalResult {
				t.Helper()
				server, calls := audioRefusalUpstream(t)
				gw := newAudioGateway(t, audioTranscriptionModel(server.URL))
				events := audioCollectEvents(gw)
				wav := audioFixtureBytes(t, "hello.wav")
				body, ct := audioMultipart(t, map[string]string{}, wav)
				rec := postAudioTranscriptions(t, gw, body, ct)
				return audioRefusalResult{rec: rec, upstream: calls.Load(), completed: *events}
			},
		},
		{
			name:   "transcriptions/missing-file",
			status: http.StatusBadRequest,
			fire: func(t *testing.T) audioRefusalResult {
				t.Helper()
				server, calls := audioRefusalUpstream(t)
				gw := newAudioGateway(t, audioTranscriptionModel(server.URL))
				events := audioCollectEvents(gw)
				body, ct := audioMultipart(t, map[string]string{"model": "m"}, nil)
				rec := postAudioTranscriptions(t, gw, body, ct)
				return audioRefusalResult{rec: rec, upstream: calls.Load(), completed: *events}
			},
		},
		{
			name:   "transcriptions/file-without-filename",
			status: http.StatusBadRequest,
			fire: func(t *testing.T) audioRefusalResult {
				t.Helper()
				server, calls := audioRefusalUpstream(t)
				gw := newAudioGateway(t, audioTranscriptionModel(server.URL))
				events := audioCollectEvents(gw)
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
				return audioRefusalResult{rec: rec, upstream: calls.Load(), completed: *events}
			},
		},
		{
			name:   "transcriptions/provider-not-compat",
			status: http.StatusBadRequest,
			fire: func(t *testing.T) audioRefusalResult {
				t.Helper()
				server, calls := audioRefusalUpstream(t)
				gw := newAudioGateway(t, audioNonCompatModel(server.URL))
				events := audioCollectEvents(gw)
				wav := audioFixtureBytes(t, "hello.wav")
				body, ct := audioMultipart(t, map[string]string{"model": "m"}, wav)
				rec := postAudioTranscriptions(t, gw, body, ct)
				return audioRefusalResult{rec: rec, upstream: calls.Load(), completed: *events}
			},
		},
		{
			name:   "transcriptions/truncated-multipart",
			status: http.StatusBadRequest,
			fire: func(t *testing.T) audioRefusalResult {
				t.Helper()
				server, calls := audioRefusalUpstream(t)
				gw := newAudioGateway(t, audioTranscriptionModel(server.URL))
				events := audioCollectEvents(gw)
				wav := audioFixtureBytes(t, "hello.wav")
				body, ct := audioMultipart(t, map[string]string{"model": "m"}, wav)
				rec := postAudioTranscriptions(t, gw, body[:len(body)/2], ct)
				return audioRefusalResult{rec: rec, upstream: calls.Load(), completed: *events}
			},
		},
		{
			name:   "transcriptions/oversized-body",
			status: http.StatusRequestEntityTooLarge,
			fire: func(t *testing.T) audioRefusalResult {
				t.Helper()
				server, calls := audioRefusalUpstream(t)
				gw := newAudioGateway(t, audioTranscriptionModel(server.URL))
				events := audioCollectEvents(gw)
				body, ct := buildAudioMultipartExact(t, 10*1024*1024+1, []byte{1})
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
					"/v1/audio/transcriptions", bytes.NewReader(body))
				req.Header.Set("Authorization", "Bearer test-key")
				req.Header.Set("Content-Type", ct)
				rec := httptest.NewRecorder()
				r := chi.NewRouter()
				r.Use(httpmw.MaxBody(10 * 1024 * 1024))
				gw.routes(r)
				r.ServeHTTP(rec, req)
				return audioRefusalResult{rec: rec, upstream: calls.Load(), completed: *events}
			},
		},
	}

	var got strings.Builder
	got.WriteString("# R049-04 golden audio refusal envelopes (contract §4/§6 pins).\n")
	got.WriteString("# One section per refusal scenario: the exact wire body the gateway writes.\n")
	got.WriteString("# Regenerate ONLY with: AUDIO_ENVELOPES_GOLDEN_UPDATE=1 go test ./pkg/gateway/ -run TestAudioRefusalEnvelopesGolden\n")

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := tc.fire(t)
			if res.rec.Code != tc.status {
				t.Fatalf("status %d, want %d (body %s)", res.rec.Code, tc.status, res.rec.Body.String())
			}
			if res.upstream != tc.wantCalls {
				t.Fatalf("upstream calls %d, want %d", res.upstream, tc.wantCalls)
			}
			if len(res.completed) != 0 {
				t.Fatalf("refusal settled a completed event: %+v", res.completed)
			}
			if ct := res.rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
				t.Fatalf("refusal content type %q", ct)
			}
			if nosniff := res.rec.Header().Get("X-Content-Type-Options"); nosniff != "nosniff" {
				t.Fatalf("refusal X-Content-Type-Options %q", nosniff)
			}
			var env struct {
				Error struct {
					Message string `json:"message"`
					Type    string `json:"type"`
					Code    string `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(res.rec.Body.Bytes(), &env); err != nil {
				t.Fatalf("refusal body is not an OpenAI envelope: %q", res.rec.Body.String())
			}
			if env.Error.Message == "" || env.Error.Type == "" {
				t.Fatalf("refusal envelope missing message/type: %s", res.rec.Body.String())
			}
			got.WriteString("### " + tc.name + " [" + strconv.Itoa(tc.status) + "]\n")
			got.WriteString(res.rec.Body.String())
		})
	}

	if os.Getenv(envAudioEnvelopesUpdate) != "" {
		if err := os.MkdirAll(filepath.Dir(audioEnvelopesGoldenPath), 0o750); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(audioEnvelopesGoldenPath, []byte(got.String()), 0o600); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("updated %s — commit the diff for review", audioEnvelopesGoldenPath)
		return
	}
	want, err := os.ReadFile(audioEnvelopesGoldenPath) // #nosec G304 -- path is the compile-time testdata constant
	if err != nil {
		t.Fatalf("read golden (generate with %s=1): %v", envAudioEnvelopesUpdate, err)
	}
	wantLines := strings.Split(strings.TrimSuffix(string(want), "\n"), "\n")
	gotLines := strings.Split(strings.TrimSuffix(got.String(), "\n"), "\n")
	if !reflect.DeepEqual(wantLines, gotLines) {
		t.Errorf("audio refusal envelopes drifted from %s (%d golden lines vs %d rendered). Diff (golden → rendered):",
			audioEnvelopesGoldenPath, len(wantLines), len(gotLines))
		for _, d := range goldenLineDiff(wantLines, gotLines) {
			t.Errorf("  %s", d)
		}
	}
}

// audioContainerFixture builds a deterministic, real-magic-byte fixture for
// the documented M3 formats that have no committed file (wav/mp3 use
// testdata/audio). The gateway never decodes audio (matrix row M6) — the
// matrix pins that these bytes cross byte-identically and the upstream alone
// renders the format verdict.
func audioContainerFixture(t *testing.T, format string) []byte {
	t.Helper()
	switch format {
	case "flac":
		// "fLaC" + last-block STREAMINFO metadata header (type 0, 34 bytes).
		b := []byte("fLaC\x80\x00\x00\x22")
		return append(b, make([]byte, 34)...)
	case "m4a":
		// ftyp box: size 28, major brand "M4A ", minor version, compatible brands.
		b := []byte("\x00\x00\x00\x1cftypM4A \x00\x00\x02\x00M4A mp42isom")
		return b
	case "ogg":
		// Ogg page 0: "OggS", version 0, BOS flag, granule, serial, sequence, CRC, 0 segments.
		b := []byte("OggS\x00\x02")
		b = append(b, 0, 0, 0, 0, 0, 0, 0, 0) // granule position
		b = append(b, 0x01, 0x02, 0x03, 0x04) // serial number
		b = append(b, 0x00, 0x00, 0x00, 0x00) // page sequence
		b = append(b, 0x00, 0x00, 0x00, 0x00) // CRC (unchecked by the gateway)
		b = append(b, 0x00)                   // segment count
		return b
	case "webm":
		// EBML master element 0x1A45DFA3, size 31, DocType "webm".
		b := []byte{0x1A, 0x45, 0xDF, 0xA3, 0x9F, 0x42, 0x82, 0x84, 'w', 'e', 'b', 'm'}
		return b
	default:
		t.Fatalf("no synthetic fixture for format %q (wav/mp3 use the committed files)", format)
		return nil
	}
}

// audioMatrixRow is one documented v1 subset row (contract §4.4): the
// working-path shape of a speech or transcription request.
type audioMatrixRow struct {
	name   string
	speech bool
	format string
	file   []byte
	upCT   string
	tokens [2]int64 // transcriptions only: the usage the upstream reports
}

// audioMatrixPayload is the byte-identity target of a matrix row: the
// upstream audio fixture for speech, the upstream JSON for transcriptions.
func audioMatrixPayload(row audioMatrixRow, servedJSON string) []byte {
	if row.speech {
		return row.file
	}
	return []byte(servedJSON)
}

// audioMatrixResponseCT is the pinned response Content-Type of a matrix row:
// the upstream passthrough value for speech, application/json for
// transcriptions.
func audioMatrixResponseCT(row audioMatrixRow) string {
	if row.speech {
		return row.upCT
	}
	return "application/json"
}

// TestAudioSubsetMatrixWorkingPath machine-asserts the documented v1 subset
// matrix (contract §4.4) as one table-driven test: row M1 (speech, openai,
// JSON in → binary mp3 out) and row M3 (transcriptions, openai, multipart
// wav/mp3/flac/m4a/ogg/webm ≤ 10 MiB → JSON out). Every row proves the
// working path end to end: real bytes cross byte-identically (sha256-pinned
// file part), the model field carries the resolved registry name, the
// multipart Content-Type overrides the adapter's application/json, the
// response rides the upstream Content-Type, and the request settles exactly
// one completed event whose usage is attributed to that request alone.
func TestAudioSubsetMatrixWorkingPath(t *testing.T) {
	rows := []audioMatrixRow{{name: "M1 speech/openai mp3", speech: true, format: "mp3",
		file: audioFixtureBytes(t, "hello.mp3"), upCT: "audio/mpeg"},
		{name: "M3 transcriptions/openai wav", format: "wav",
			file: audioFixtureBytes(t, "hello.wav"), upCT: "audio/wav", tokens: [2]int64{1, 2}},
		{name: "M3 transcriptions/openai mp3", format: "mp3",
			file: audioFixtureBytes(t, "hello.mp3"), upCT: "audio/mpeg", tokens: [2]int64{3, 4}},
		{name: "M3 transcriptions/openai flac", format: "flac",
			file: audioContainerFixture(t, "flac"), upCT: "audio/flac", tokens: [2]int64{5, 6}},
		{name: "M3 transcriptions/openai m4a", format: "m4a",
			file: audioContainerFixture(t, "m4a"), upCT: "audio/mp4", tokens: [2]int64{7, 8}},
		{name: "M3 transcriptions/openai ogg", format: "ogg",
			file: audioContainerFixture(t, "ogg"), upCT: "audio/ogg", tokens: [2]int64{9, 10}},
		{name: "M3 transcriptions/openai webm", format: "webm",
			file: audioContainerFixture(t, "webm"), upCT: "video/webm", tokens: [2]int64{11, 12}},
	}
	var (
		mu     sync.Mutex
		events []*eventpub.Event
	)
	collect := func(gw *gateway) {
		gw.eventNote = func(e *eventpub.Event) {
			mu.Lock()
			events = append(events, e)
			mu.Unlock()
		}
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			var (
				gotUpstreamModel    string
				gotUpstreamCT       string
				gotFields           map[string]string
				gotFile             []byte
				gotFileHeader       string
				servedTranscription string
			)
			if !row.speech {
				servedTranscription = `{"text":"` + row.format + ` ok","usage":{"prompt_tokens":` +
					strconv.Itoa(int(row.tokens[0])) + `,"output_tokens":` + strconv.Itoa(int(row.tokens[1])) + `}}`
			}
			var calls atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if row.speech {
					raw, _ := io.ReadAll(r.Body)
					var req struct {
						Model string `json:"model"`
						Input string `json:"input"`
						Voice string `json:"voice"`
					}
					if err := json.Unmarshal(raw, &req); err != nil {
						t.Errorf("upstream body %s: %v", raw, err)
					}
					gotUpstreamModel = req.Model
					gotUpstreamCT = r.Header.Get("Content-Type")
					w.Header().Set("Content-Type", row.upCT)
					_, _ = w.Write(row.file)
					return
				}
				gotUpstreamCT = r.Header.Get("Content-Type")
				gotFields, gotFile, gotFileHeader = parseUpstreamMultipart(t, r)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(servedTranscription))
			}))
			defer server.Close()

			var rec *httptest.ResponseRecorder
			if row.speech {
				gw := newAudioGateway(t, audioTestModel(server.URL))
				collect(gw)
				rec = postAudioSpeech(t, gw, `{"model":"tts","input":"hello","voice":"alloy"}`, "")
			} else {
				gw := newAudioGateway(t, audioTranscriptionModel(server.URL))
				collect(gw)
				body, ct := buildAudioMultipart(t, map[string]string{
					"model": "m", "language": "en", "prompt": "greeting",
					"response_format": "json", "temperature": "0",
				}, "file", "hello."+row.format, row.upCT, row.file)
				rec = postAudioTranscriptions(t, gw, body, ct)
			}

			if rec.Code != http.StatusOK {
				t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
			}
			if calls.Load() != 1 {
				t.Fatalf("upstream calls %d, want exactly 1", calls.Load())
			}
			if !bytes.Equal(rec.Body.Bytes(), audioMatrixPayload(row, servedTranscription)) {
				t.Fatalf("response not byte-identical: got %d bytes", rec.Body.Len())
			}
			if ct := rec.Header().Get("Content-Type"); ct != audioMatrixResponseCT(row) {
				t.Fatalf("response content type %q, want upstream %q", ct, audioMatrixResponseCT(row))
			}
			if row.speech {
				if gotUpstreamModel != "tts-1" {
					t.Fatalf("upstream model %q, want resolved registry name tts-1", gotUpstreamModel)
				}
				if gotUpstreamCT != "application/json" {
					t.Fatalf("upstream content type %q", gotUpstreamCT)
				}
				return
			}
			if gotFields["model"] != "whisper-1" {
				t.Fatalf("upstream model field %q, want resolved registry name whisper-1", gotFields["model"])
			}
			if gotFields["language"] != "en" || gotFields["prompt"] != "greeting" ||
				gotFields["response_format"] != "json" || gotFields["temperature"] != "0" {
				t.Fatalf("text fields not preserved: %+v", gotFields)
			}
			if sha256.Sum256(gotFile) != sha256.Sum256(row.file) {
				t.Fatalf("file part not byte-identical: got %d bytes want %d", len(gotFile), len(row.file))
			}
			if gotFileHeader != row.upCT {
				t.Fatalf("file part content type %q, want %q", gotFileHeader, row.upCT)
			}
			if !bytes.HasPrefix([]byte(gotUpstreamCT), []byte("multipart/form-data; boundary=")) {
				t.Fatalf("upstream content type %q, want multipart boundary override", gotUpstreamCT)
			}
		})
	}

	// Billing/usage invariants across the whole matrix: exactly one settled
	// (completed) event per request, per-request usage attribution, D2 cost
	// semantics (no invented audio pricing).
	mu.Lock()
	defer mu.Unlock()
	if len(events) != len(rows) {
		t.Fatalf("settled events %d, want exactly one per matrix row (%d)", len(events), len(rows))
	}
	tokenAttribution := make(map[[2]int64]int, len(rows))
	speechRows := 0
	for _, ev := range events {
		if ev.EventType != "request.completed" || ev.StatusCode != http.StatusOK {
			t.Fatalf("matrix settled a non-success event: %+v", ev)
		}
		if ev.EstimatedCostUSD != 0 {
			t.Fatalf("audio event carries invented cost %v (D2): %+v", ev.EstimatedCostUSD, ev)
		}
		if ev.Termination != "" {
			t.Fatalf("unexpected reservation stamp on event: %+v", ev)
		}
		switch ev.Endpoint {
		case "audio.speech":
			speechRows++
			if ev.TokensIn != 0 || ev.TokensOut != 0 || ev.UsageSource != "none" || ev.CostStatus != "no_usage" {
				t.Fatalf("speech event broke the D2 usage contract: %+v", ev)
			}
			if ev.ModelRequested != "tts" || ev.ModelUsed != "tts-1" {
				t.Fatalf("speech event model attribution: %+v", ev)
			}
		case "audio.transcriptions":
			key := [2]int64{ev.TokensIn, ev.TokensOut}
			tokenAttribution[key]++
			if ev.UsageSource != "provider" || ev.CostStatus != "unknown_price" {
				t.Fatalf("transcription event usage contract: %+v", ev)
			}
			if ev.ModelRequested != "m" || ev.ModelUsed != "whisper-1" {
				t.Fatalf("transcription event model attribution: %+v", ev)
			}
		default:
			t.Fatalf("unexpected endpoint %q in matrix events", ev.Endpoint)
		}
	}
	if speechRows != 1 {
		t.Fatalf("speech settled events %d, want 1 (M1)", speechRows)
	}
	if len(tokenAttribution) != len(rows)-1 {
		t.Fatalf("usage pairs not unique per request: %v", tokenAttribution)
	}
	for _, row := range rows[1:] {
		if tokenAttribution[row.tokens] != 1 {
			t.Fatalf("usage %v settled %d times, want exactly once", row.tokens, tokenAttribution[row.tokens])
		}
	}
}

// TestAudioBillingOneSpendPerRequest pins the billing invariants across a
// mixed success/failure/refusal sequence: every successful request settles
// exactly one completed spend record with its own upstream-reported usage,
// refusals (429 upstream, missing file, oversized body) settle nothing, and
// total settled tokens equal total upstream-reported tokens — a failed or
// refused attempt never adds, doubles or shifts spend onto another request.
func TestAudioBillingOneSpendPerRequest(t *testing.T) {
	mp3 := audioFixtureBytes(t, "hello.mp3")
	wav := audioFixtureBytes(t, "hello.wav")
	const usageIn, usageOut = int64(7), int64(3)

	var calls atomic.Int64
	var transcriporCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path == "/v1/audio/speech" {
			w.Header().Set("Content-Type", "audio/mpeg")
			_, _ = w.Write(mp3)
			return
		}
		if transcriporCalls.Add(1) == 1 {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"text":"ok","usage":{"prompt_tokens":7,"output_tokens":3}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	gw := newAudioGateway(t, audioTestModel(server.URL))
	gw.res = stubModelResolver{"m": audioTranscriptionModel(server.URL), "tts": audioTestModel(server.URL)}
	var mu sync.Mutex
	var events []*eventpub.Event
	gw.eventNote = func(e *eventpub.Event) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	}

	// 1. Successful speech — settles 0/0 tokens (D2).
	rec := postAudioSpeech(t, gw, `{"model":"tts","input":"hello","voice":"alloy"}`, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("speech status %d body %s", rec.Code, rec.Body.String())
	}

	// 2. Successful transcription — settles exactly the upstream usage (7,3).
	body, ct := audioMultipart(t, map[string]string{"model": "m"}, wav)
	rec = postAudioTranscriptions(t, gw, body, ct)
	if rec.Code != http.StatusOK {
		t.Fatalf("transcription status %d body %s", rec.Code, rec.Body.String())
	}

	// 3. Upstream 429 — refusal, no settled spend.
	body, ct = audioMultipart(t, map[string]string{"model": "m"}, wav)
	rec = postAudioTranscriptions(t, gw, body, ct)
	if rec.Code != http.StatusTooManyRequests || errorType(t, rec) != "rate_limit_exceeded" {
		t.Fatalf("upstream 429 mapped to status %d body %s", rec.Code, rec.Body.String())
	}

	// 4. Missing file — refusal before admission, no settled spend.
	body, ct = audioMultipart(t, map[string]string{"model": "m"}, nil)
	rec = postAudioTranscriptions(t, gw, body, ct)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing-file status %d body %s", rec.Code, rec.Body.String())
	}

	// 5. Oversized speech body — 413 before the upstream, no settled spend.
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/v1/audio/speech", strings.NewReader(audioOversizedSpeechBody()))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	r := chi.NewRouter()
	r.Use(httpmw.MaxBody(10 * 1024 * 1024))
	gw.routes(r)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status %d body %s", rec.Code, rec.Body.String())
	}

	if calls.Load() != 3 { // speech 200 + transcription 200 + transcription 429
		t.Fatalf("upstream calls %d, want 3", calls.Load())
	}
	if transcriporCalls.Load() != 2 {
		t.Fatalf("transcription upstream calls %d, want 2", transcriporCalls.Load())
	}

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 2 {
		t.Fatalf("settled events %d, want exactly 2 (the two 200s)", len(events))
	}
	var settled [2][2]int64
	for i, ev := range events {
		if ev.EventType != "request.completed" || ev.StatusCode != http.StatusOK {
			t.Fatalf("non-success settled event: %+v", ev)
		}
		if ev.EstimatedCostUSD != 0 {
			t.Fatalf("settled event carries invented cost (D2): %+v", ev)
		}
		settled[i] = [2]int64{ev.TokensIn, ev.TokensOut}
	}
	if settled[0] != [2]int64{0, 0} || events[0].UsageSource != "none" || events[0].CostStatus != "no_usage" {
		t.Fatalf("speech spend record: %+v", events[0])
	}
	if settled[1] != [2]int64{usageIn, usageOut} ||
		events[1].UsageSource != "provider" || events[1].CostStatus != "unknown_price" {
		t.Fatalf("transcription spend record %+v, want usage (%d,%d) provider/unknown_price",
			events[1], usageIn, usageOut)
	}
	total := settled[0][0] + settled[0][1] + settled[1][0] + settled[1][1]
	if total != usageIn+usageOut {
		t.Fatalf("settled tokens %d, want exactly the upstream-reported %d (no double count)",
			total, usageIn+usageOut)
	}
}
