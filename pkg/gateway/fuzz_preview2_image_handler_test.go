package cli

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/resolver"
)

// FuzzImagesGenerations_HappyPathPromptForwarding fuzzes the successful
// images-generations artifact path: arbitrary generated prompt text is sent
// as a normal JSON string to the local mock upstream, which verifies the
// exact forwarded model and UTF8-normalized prompt, returns the fixed PNG
// fixture, and the passthrough response and accounting event are asserted
// deterministically.
func FuzzImagesGenerations_HappyPathPromptForwarding(f *testing.F) {
	f.Add("a single red cube on a white background")
	f.Add("青い球を白い背景に、枠なし ✓")

	f.Fuzz(func(t *testing.T, prompt string) {
		want := "image: " + strings.ToValidUTF8(prompt, "�")

		upstreamBody := `{"created":1790000000,"data":[{"b64_json":"` +
			base64.StdEncoding.EncodeToString(testTinyPNG) +
			`"}],"usage":{"input_tokens":20,"output_tokens":1424,"total_tokens":1444,` +
			`"input_tokens_details":{"cached_tokens":0}}}`

		server, upstreamPath := startImagesHappyPathUpstream(t, want, upstreamBody)
		defer server.Close()

		info := resolver.ModelInfo{ModelName: "gpt-image-1-canon", Provider: "openai", UpstreamURL: server.URL, UpstreamAPIKey: "up", Enabled: true}
		gw := imagesTestGateway(t, info, server.URL)
		var ev *eventpub.Event
		gw.eventNote = func(e *eventpub.Event) { ev = e }

		body, err := json.Marshal(struct {
			Model  string `json:"model"`
			Prompt string `json:"prompt"`
			N      int    `json:"n"`
			Size   string `json:"size"`
		}{"m", want, 1, "1024x1024"})
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}

		rec := postImages(t, gw, string(body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d %s", rec.Code, rec.Body.String())
		}
		if strings.TrimSpace(rec.Body.String()) != upstreamBody {
			t.Fatalf("passthrough body %q", rec.Body.String())
		}
		if got := upstreamPath.Load(); got != "/v1/images/generations" {
			t.Fatalf("upstream path %v", got)
		}
		if got := rec.Header().Get("Content-Type"); got != "application/json" {
			t.Fatalf("content type %q", got)
		}
		assertImagesCompletedEvent(t, ev)
	})
}

// startImagesHappyPathUpstream starts a private httptest server that records
// the requested path into the returned atomic value, validates the forwarded
// payload against wantPrompt, and replies with the fixed successful
// upstreamBody.
func startImagesHappyPathUpstream(t *testing.T, wantPrompt, upstreamBody string) (*httptest.Server, *atomic.Value) {
	t.Helper()
	var upstreamPath atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamPath.Store(r.URL.Path)
		raw, _ := io.ReadAll(r.Body)
		assertImagesForwardedPayload(t, raw, wantPrompt)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(upstreamBody))
	}))
	return server, &upstreamPath
}

// assertImagesForwardedPayload verifies the exact JSON payload the gateway
// forwarded upstream: the canonical model and the normalized prompt. It runs
// on the server goroutine, so it reports with Errorf only.
func assertImagesForwardedPayload(t *testing.T, raw []byte, wantPrompt string) {
	t.Helper()
	var forwarded struct {
		Model  string `json:"model"`
		Prompt string `json:"prompt"`
	}
	if err := json.Unmarshal(raw, &forwarded); err != nil {
		t.Errorf("upstream body is not JSON: %v: %s", err, raw)
		return
	}
	if forwarded.Model != "gpt-image-1-canon" {
		t.Errorf("upstream body lacks canonical model: %q", forwarded.Model)
	}
	if forwarded.Prompt != wantPrompt {
		t.Errorf("forwarded prompt %q want %q", forwarded.Prompt, wantPrompt)
	}
}

// assertImagesCompletedEvent verifies the captured accounting event: its
// endpoint, token usage taken from the upstream response, status and model.
func assertImagesCompletedEvent(t *testing.T, ev *eventpub.Event) {
	t.Helper()
	if ev == nil {
		t.Fatal("no request.completed event")
	}
	if ev.Endpoint != "images.generation" || ev.TokensIn != 20 || ev.TokensOut != 1424 {
		t.Fatalf("event endpoint/tokens: %+v", ev)
	}
	if ev.StatusCode != http.StatusOK || ev.ModelUsed != "gpt-image-1-canon" {
		t.Fatalf("event status/model: %+v", ev)
	}
}
