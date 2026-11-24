//go:build integration

package accounting

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Media acceptance validators are pure functions over the binary-safe
// client outcome (framing-oracle pattern): the sweep calls them through
// requireNoMediaArtifactError, and the corruption controls in this file
// prove each one REJECTS the artifacts a compromised or buggy product
// could present. A validator that only passes healthy input is not a
// detector.

// healthySpeechArtifact validates the speech family's client artifact
// against the independently known fixture bytes: status 200, the binary
// content type relayed verbatim, RIFF/WAVE magic and byte-exact audio.
func healthySpeechArtifact(rep mediaReply) error {
	if rep.err != nil {
		return fmt.Errorf("client transport error: %w", rep.err)
	}
	if rep.status != httpOK {
		return fmt.Errorf("status %d, want 200 (body %s)", rep.status, clipMedia(rep.body))
	}
	if rep.contentType != fixtureSpeechContentType {
		return fmt.Errorf("content type %q, want the upstream %q relayed verbatim",
			rep.contentType, fixtureSpeechContentType)
	}
	if !bytes.HasPrefix(rep.body, []byte("RIFF")) {
		return fmt.Errorf("body does not start with the RIFF/WAVE magic (body %s)", clipMedia(rep.body))
	}
	if !bytes.Equal(rep.body, fixtureWAVBytes()) {
		return fmt.Errorf("audio bytes differ from the known fixture artifact (%d bytes relayed)", len(rep.body))
	}
	return nil
}

// healthyTranscriptionReply validates the transcription family's client
// artifact: status 200, JSON content type, the byte-identical relay of
// the known reply carrying the family-distinct usage.
func healthyTranscriptionReply(rep mediaReply) error {
	if rep.err != nil {
		return fmt.Errorf("client transport error: %w", rep.err)
	}
	if rep.status != httpOK {
		return fmt.Errorf("status %d, want 200 (body %s)", rep.status, clipMedia(rep.body))
	}
	if ct := rep.contentType; !strings.HasPrefix(ct, "application/json") {
		return fmt.Errorf("content type %q, want application/json", ct)
	}
	if got, want := string(rep.body), fixtureTranscribeReply(); got != want {
		return fmt.Errorf("relayed body %s is not byte-identical to the known reply %s", clipMedia(rep.body), want)
	}
	var doc struct {
		Text  string `json:"text"`
		Usage struct {
			PromptTokens int `json:"prompt_tokens"`
			TotalTokens  int `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(rep.body, &doc); err != nil {
		return fmt.Errorf("reply is not transcription JSON: %v (body %s)", err, clipMedia(rep.body))
	}
	if doc.Text != fixtureTranscribeText || doc.Usage.PromptTokens != fixtureTranscribePromptTokens {
		return fmt.Errorf("reply text/usage = %q/%d, want %q/%d",
			doc.Text, doc.Usage.PromptTokens, fixtureTranscribeText, fixtureTranscribePromptTokens)
	}
	return nil
}

// mediaRefusalArtifact validates the pre-dispatch refusal contract for a
// media family: a transport drop is wrong, anything but 503 is wrong,
// and the 503 must be the structured history_unavailable envelope.
func mediaRefusalArtifact(family string, rep mediaReply) error {
	if rep.err != nil {
		return fmt.Errorf("product: refusal %s: client transport error %v — the request must be refused with the documented 503 history_unavailable contract, not dropped", family, rep.err)
	}
	if rep.status != 503 {
		return fmt.Errorf("product: refusal %s: client status %d, want 503 (body %s) — the documented history_unavailable refusal is missing", family, rep.status, clipMedia(rep.body))
	}
	code, ok := decodeErrorCode(string(rep.body))
	if !ok {
		return fmt.Errorf("product: refusal %s: 503 body is not the documented structured error envelope (body %s)", family, clipMedia(rep.body))
	}
	if code != "history_unavailable" {
		return fmt.Errorf("product: refusal %s: 503 error.code %q, want history_unavailable (body %s)", family, code, clipMedia(rep.body))
	}
	return nil
}

// requireNoMediaArtifactError fails the test when a media validator
// rejected a healthy control artifact.
func requireNoMediaArtifactError(t *testing.T, family, phase string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("harness: %s control %s failed: %v — the family's route, credentials or fixture codec is broken; product assertions below would be meaningless",
			family, phase, err)
	}
}

// clipMedia bounds binary bodies in failure messages.
func clipMedia(b []byte) string {
	s := string(b)
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// TestMediaArtifactValidatorControls is the negative control for the
// media acceptance validators: every corrupted artifact — mutated bytes,
// wrong content type, truncation, empty body, JSON where audio must be,
// invented token counts, a healthy 200 where the refusal contract
// demands 503, an unstructured or wrongly coded 503 — must be REJECTED
// by the validator that backs the acceptance verdict, and every healthy
// artifact must PASS (non-vacuity).
func TestMediaArtifactValidatorControls(t *testing.T) {
	wav := fixtureWAVBytes()
	mutated := bytes.Clone(wav)
	mutated[100] ^= 0xff

	speechCases := []struct {
		name string
		rep  mediaReply
	}{
		{"mutated byte", mediaReply{status: httpOK, contentType: fixtureSpeechContentType, body: mutated}},
		{"wrong content type", mediaReply{status: httpOK, contentType: "text/plain", body: wav}},
		{"truncated artifact", mediaReply{status: httpOK, contentType: fixtureSpeechContentType, body: wav[:len(wav)-1]}},
		{"empty body", mediaReply{status: httpOK, contentType: fixtureSpeechContentType, body: nil}},
		{"json body", mediaReply{status: httpOK, contentType: fixtureSpeechContentType, body: []byte(`{"audio":"not really"}`)}},
		{"wrong status", mediaReply{status: 500, contentType: fixtureSpeechContentType, body: wav}},
		{"transport error", mediaReply{err: fmt.Errorf("connection reset")}},
	}
	for _, c := range speechCases {
		if err := healthySpeechArtifact(c.rep); err == nil {
			t.Errorf("speech validator accepted corrupted artifact %q — the acceptance oracle is blind to this corruption", c.name)
		}
	}
	if err := healthySpeechArtifact(mediaReply{status: httpOK, contentType: fixtureSpeechContentType, body: wav}); err != nil {
		t.Fatalf("speech validator rejected the healthy artifact: %v", err)
	}

	wrongTokens := fmt.Sprintf(`{"text":%q,"usage":{"prompt_tokens":12,"total_tokens":12}}`, fixtureTranscribeText)
	missingUsage := fmt.Sprintf(`{"text":%q}`, fixtureTranscribeText)
	transcribeCases := []struct {
		name string
		rep  mediaReply
	}{
		{"wrong token counts", mediaReply{status: httpOK, contentType: "application/json", body: []byte(wrongTokens)}},
		{"missing usage block", mediaReply{status: httpOK, contentType: "application/json", body: []byte(missingUsage)}},
		{"mutated text", mediaReply{status: httpOK, contentType: "application/json",
			body: []byte(fmt.Sprintf(`{"text":"other text","usage":{"prompt_tokens":%d,"total_tokens":%d}}`, fixtureTranscribePromptTokens, fixtureTranscribePromptTokens))}},
		{"non-json body", mediaReply{status: httpOK, contentType: "application/json", body: []byte("transcription text plain")}},
		{"wrong content type", mediaReply{status: httpOK, contentType: "audio/wav", body: []byte(fixtureTranscribeReply())}},
		{"wrong status", mediaReply{status: 502, contentType: "application/json", body: []byte(fixtureTranscribeReply())}},
	}
	for _, c := range transcribeCases {
		if err := healthyTranscriptionReply(c.rep); err == nil {
			t.Errorf("transcription validator accepted corrupted artifact %q — the acceptance oracle is blind to this corruption", c.name)
		}
	}
	if err := healthyTranscriptionReply(mediaReply{status: httpOK, contentType: "application/json", body: []byte(fixtureTranscribeReply())}); err != nil {
		t.Fatalf("transcription validator rejected the healthy artifact: %v", err)
	}

	refusalCases := []struct {
		name string
		rep  mediaReply
	}{
		{"healthy 200 fake success", mediaReply{status: httpOK, contentType: "application/json", body: []byte(fixtureTranscribeReply())}},
		{"unstructured 503", mediaReply{status: 503, contentType: "text/plain", body: []byte("try again")}},
		{"wrong refusal code", mediaReply{status: 503, contentType: "application/json",
			body: []byte(`{"error":{"message":"x","type":"api_error","param":null,"code":"provider_down"}}`)}},
		{"transport drop", mediaReply{err: fmt.Errorf("connection refused")}},
	}
	for _, c := range refusalCases {
		if err := mediaRefusalArtifact("media control", c.rep); err == nil {
			t.Errorf("refusal validator accepted %q — a fake successful refusal would pass the acceptance oracle", c.name)
		}
	}
	healthyRefusal := `{"error":{"message":"history unavailable","type":"api_error","param":null,"code":"history_unavailable"}}`
	if err := mediaRefusalArtifact("media control", mediaReply{status: 503, contentType: "application/json", body: []byte(healthyRefusal)}); err != nil {
		t.Fatalf("refusal validator rejected the documented refusal envelope: %v", err)
	}
}

// TestMediaFixtureSelfCheck proves the media fixture detector in
// isolation (fixture-self-check discipline): the WAV round trip with
// exact bytes and content type, the healthy and corrupted-usage multipart
// round trips with exact relayed bodies, and the codec pre-admission
// 400s that must never become dispatches — all against real HTTP, no
// Docker, no product binary. A detector that has not proven itself
// cannot back an acceptance verdict.
func TestMediaFixtureSelfCheck(t *testing.T) {
	dir := filepath.Join(os.TempDir(), "yabanin-accounting-fixture", newRunID(t))
	f := startFixture(t, dir, "unit-token")
	t.Cleanup(f.stop)

	// Speech round trip: exact bytes, exact content type, one whole
	// ledger contact on the codec's own path.
	before := f.Snapshot()
	status, body, contentType, err := httpPostSpeech(5*time.Second, f.baseURL()+"/v1/audio/speech",
		"unit-token", "unit-speech", "m", fixtureSpeechInput, fixtureSpeechVoice)
	require.NoError(t, healthySpeechArtifact(mediaReply{status: status, body: body, contentType: contentType, err: err}))
	// Independently encoded mono PCM, 8 kHz, 16 bits, sample[i] = 103 + 251*i.
	require.Equal(t, "f0728b4aa854f8958860c15b8cc9d3c420b52d916a82070806cb986ec7c40a87", fmt.Sprintf("%x", sha256.Sum256(body)))
	require.Equal(t, fixtureTotals{1, 1, 1}, f.Since(before))
	require.Equal(t, []string{"/v1/audio/speech"}, f.ArrivalPaths("unit-speech"))

	// Healthy multipart round trip: byte-identical reply, one contact.
	before = f.Snapshot()
	audio := multipartFile{filename: fixtureTranscribeAudioFile, contentType: fixtureTranscribeAudioContentType, data: fixtureWAVBytes()}
	status, reply, contentType, err := httpPostMultipart(5*time.Second, f.baseURL()+"/v1/audio/transcriptions",
		"unit-token", "unit-tr", "m", nil, audio)
	require.NoError(t, healthyTranscriptionReply(mediaReply{status: status, body: []byte(reply), contentType: contentType, err: err}))
	require.Equal(t, fixtureTotals{1, 1, 1}, f.Since(before))
	require.Equal(t, []string{"/v1/audio/transcriptions"}, f.ArrivalPaths("unit-tr"))

	// Corrupted-usage mode keyed by filename: byte-identical corrupted
	// reply, still a full round trip.
	before = f.Snapshot()
	badUsage := multipartFile{filename: fixtureTranscribeBadUsageFile, contentType: fixtureTranscribeAudioContentType, data: fixtureWAVBytes()}
	status, reply, _, err = httpPostMultipart(5*time.Second, f.baseURL()+"/v1/audio/transcriptions",
		"unit-token", "unit-tr-bad", "m", nil, badUsage)
	require.NoError(t, err)
	require.Equal(t, httpOK, status)
	require.Equal(t, fixtureTranscribeBadUsageReply, reply)
	require.Equal(t, fixtureTotals{1, 1, 1}, f.Since(before))

	// Codec pre-admission 400s: arrivals only, never dispatches.
	bad := []struct {
		name    string
		request func(rid string) (int, string, error)
	}{
		{"not multipart", func(rid string) (int, string, error) {
			return httpPostJSON(5*time.Second, f.baseURL()+"/v1/audio/transcriptions", "unit-token", rid, `{"model":"m"}`)
		}},
		{"no file part", func(rid string) (int, string, error) {
			status, body, _, err := httpPostMultipart(5*time.Second, f.baseURL()+"/v1/audio/transcriptions", "unit-token", rid, "m", nil)
			return status, body, err
		}},
		{"multiple file parts", func(rid string) (int, string, error) {
			status, body, _, err := httpPostMultipart(5*time.Second, f.baseURL()+"/v1/audio/transcriptions", "unit-token", rid, "m", nil, audio, audio)
			return status, body, err
		}},
		{"missing model", func(rid string) (int, string, error) {
			status, body, _, err := httpPostMultipart(5*time.Second, f.baseURL()+"/v1/audio/transcriptions", "unit-token", rid, "", nil, audio)
			return status, body, err
		}},
	}
	for _, c := range bad {
		before := f.Snapshot()
		rid := "unit-bad-" + strings.NewReplacer(" ", "-").Replace(c.name)
		status, reply, err := c.request(rid)
		require.NoError(t, err, c.name)
		require.Equal(t, http.StatusBadRequest, status, "%s: %s", c.name, reply)
		require.Equal(t, fixtureTotals{arrivals: 1}, f.Since(before), c.name)
	}
	f.VerifyEvidence()
}

type interruptedMediaWriter struct {
	*httptest.ResponseRecorder
}

func (w interruptedMediaWriter) Write(body []byte) (int, error) {
	n, _ := w.ResponseRecorder.Write(body[:1])
	return n, io.ErrClosedPipe
}

func TestInterruptedMediaResponseHasNoReceipt(t *testing.T) {
	f := startFixture(t, t.TempDir(), "unit-token")
	t.Cleanup(f.stop)
	audio := multipartFile{filename: fixtureTranscribeAudioFile, contentType: fixtureTranscribeAudioContentType, data: fixtureWAVBytes()}
	multipartBody, contentType, err := buildTranscriptionBody("m", nil, []multipartFile{audio})
	require.NoError(t, err)
	for _, tc := range []struct{ path, body, contentType string }{
		{"/v1/audio/speech", `{"model":"m","input":"hello"}`, "application/json"},
		{"/v1/audio/transcriptions", multipartBody.String(), contentType},
	} {
		t.Run(tc.path, func(t *testing.T) {
			before := f.Snapshot()
			req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", tc.contentType)
			req.Header.Set("Authorization", "Bearer unit-token")
			req.Header.Set("X-Request-ID", "partial-write")
			w := interruptedMediaWriter{httptest.NewRecorder()}
			f.serve(w, req)
			require.Equal(t, http.StatusOK, w.Code)
			require.Equal(t, 1, w.Body.Len())
			require.Equal(t, fixtureTotals{arrivals: 1, dispatches: 1}, f.Since(before))
		})
	}
}
