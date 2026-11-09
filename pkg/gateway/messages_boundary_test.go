package cli

// Boundary corpus for the native /v1/messages relay. Four aspects:
// multibyte text with CRLF SSE line endings, empty content/delta frames,
// a single oversized SSE frame, and an upstream frame whose
// content_block_start omits the index field (the relay must not invent a
// block index it never saw). Every case pins byte-identical relay and
// single-event billing.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
)

// TestMessagesNative_StreamBoundaryCorpus: each corpus case streams to
// completion; the client bytes must equal the upstream bytes exactly (the
// relay never rewrites frames, not even CRLF or multibyte payloads) and the
// round bills exactly once with the usage the fixture declared.
func TestMessagesNative_StreamBoundaryCorpus(t *testing.T) {
	longText := strings.Repeat("x", 1<<20)
	cases := []struct {
		name    string
		sse     string
		wantIn  int64
		wantOut int64
	}{
		{
			name: "emoji-multibyte-crlf",
			sse: "event: message_start\r\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":3,\"output_tokens\":0}}}\r\n" +
				"\r\n" +
				"event: content_block_start\r\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\r\n" +
				"\r\n" +
				"event: content_block_delta\r\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Привет 🌍 café\"}}\r\n" +
				"\r\n" +
				"event: content_block_stop\r\ndata: {\"type\":\"content_block_stop\",\"index\":0}\r\n" +
				"\r\n" +
				"event: message_delta\r\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":2}}\r\n" +
				"\r\n" +
				"event: message_stop\r\ndata: {\"type\":\"message_stop\"}\r\n" +
				"\r\n",
			wantIn: 3, wantOut: 2,
		},
		{
			name: "empty-text-delta",
			sse: "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\n" +
				"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" +
				"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"\"}}\n\n" +
				"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
				"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":0}}\n\n" +
				"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
			wantIn: 1, wantOut: 0,
		},
		{
			name: "one-mib-single-frame",
			sse: "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":5,\"output_tokens\":0}}}\n\n" +
				"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" +
				"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"" + longText + "\"}}\n\n" +
				"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
				"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":1}}\n\n" +
				"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
			wantIn: 5, wantOut: 1,
		},
		{
			name: "multi-block-interleaved",
			sse: "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":7,\"output_tokens\":0}}}\n\n" +
				"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" +
				"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"a\"}}\n\n" +
				"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"bash\",\"input\":{}}}\n\n" +
				"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"cmd\\\":\\\"ls\\\"}\"}}\n\n" +
				"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"b\"}}\n\n" +
				"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n" +
				"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
				"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":8}}\n\n" +
				"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
			wantIn: 7, wantOut: 8,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write([]byte(tc.sse))
			}))
			defer server.Close()

			gw := nativeMessagesGateway(t, server.URL)
			evCh := make(chan *eventpub.Event, 8)
			var ev *eventpub.Event
			var count int
			restore := observeEvent(func(e *eventpub.Event) {
				if e.Endpoint != "messages" {
					return
				}
				count++
				ev = e
				evCh <- e
			})
			t.Cleanup(restore)

			rec := postMessages(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":16,"messages":[{"role":"user","content":"Hi"}],"stream":true}`)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d %s", rec.Code, rec.Body.String())
			}
			<-evCh
			if rec.Body.String() != tc.sse {
				t.Fatalf("boundary corpus must relay byte-identically\ngot len=%d want len=%d", rec.Body.Len(), len(tc.sse))
			}
			if count != 1 {
				t.Fatalf("%d analytics events, want exactly 1", count)
			}
			if ev == nil || ev.EventType != "request.completed" {
				t.Fatalf("event %+v", ev)
			}
			if ev.TokensIn != tc.wantIn || ev.TokensOut != tc.wantOut {
				t.Fatalf("usage in=%d out=%d, want %d/%d", ev.TokensIn, ev.TokensOut, tc.wantIn, tc.wantOut)
			}
		})
	}
}

// TestMessagesNative_NonStreamBoundaryCorpus: multibyte, empty and long
// request content round-trips byte-identically off-stream, each billed once.
func TestMessagesNative_NonStreamBoundaryCorpus(t *testing.T) {
	longText := strings.Repeat("y", 1<<20)
	cases := []struct {
		name         string
		content      string
		responseJSON string
		wantIn       int64
		wantOut      int64
	}{
		{
			name:         "emoji-multibyte",
			content:      "Привет 🌍 café",
			responseJSON: `{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"🌍 ok"}],"stop_reason":"end_turn","usage":{"input_tokens":3,"output_tokens":2}}`,
			wantIn:       3, wantOut: 2,
		},
		{
			name:         "empty-content",
			content:      "",
			responseJSON: `{"id":"msg_2","type":"message","role":"assistant","content":[],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":0}}`,
			wantIn:       1, wantOut: 0,
		},
		{
			name:         "long-content",
			content:      longText,
			responseJSON: `{"id":"msg_3","type":"message","role":"assistant","content":[{"type":"text","text":"done"}],"stop_reason":"end_turn","usage":{"input_tokens":5,"output_tokens":1}}`,
			wantIn:       5, wantOut: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotContent string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					Messages []struct {
						Content any `json:"content"`
					} `json:"messages"`
				}
				raw, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(raw, &req)
				if len(req.Messages) > 0 {
					if s, ok := req.Messages[0].Content.(string); ok {
						gotContent = s
					}
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.responseJSON))
			}))
			defer server.Close()

			gw := nativeMessagesGateway(t, server.URL)
			evCh := make(chan *eventpub.Event, 8)
			var ev *eventpub.Event
			var count int
			restore := observeEvent(func(e *eventpub.Event) {
				if e.Endpoint != "messages" {
					return
				}
				count++
				ev = e
				evCh <- e
			})
			t.Cleanup(restore)

			reqBody, err := json.Marshal(map[string]any{
				"model":      "claude-3-5-sonnet",
				"max_tokens": 16,
				"messages":   []map[string]any{{"role": "user", "content": tc.content}},
			})
			if err != nil {
				t.Fatal(err)
			}
			rec := postMessages(t, gw, string(reqBody))
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d %s", rec.Code, rec.Body.String())
			}
			<-evCh
			if gotContent != tc.content {
				t.Fatalf("upstream content %q, want %q", gotContent, tc.content)
			}
			if rec.Body.String() != tc.responseJSON {
				t.Fatalf("non-stream boundary relay must be byte-identical\ngot %q", rec.Body.String())
			}
			if count != 1 || ev == nil || ev.EventType != "request.completed" {
				t.Fatalf("%d events, ev %+v", count, ev)
			}
			if ev.TokensIn != tc.wantIn || ev.TokensOut != tc.wantOut {
				t.Fatalf("usage in=%d out=%d, want %d/%d", ev.TokensIn, ev.TokensOut, tc.wantIn, tc.wantOut)
			}
		})
	}
}

// TestMessagesNative_CountTokensBoundary: multibyte and empty content
// count through the native passthrough (no estimation header, upstream
// response byte-identical).
func TestMessagesNative_CountTokensBoundary(t *testing.T) {
	cases := []struct {
		name         string
		content      string
		responseJSON string
	}{
		{name: "emoji-multibyte", content: "🌍 café", responseJSON: `{"input_tokens":9}`},
		{name: "empty-content", content: "", responseJSON: `{"input_tokens":0}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/messages/count_tokens" {
					t.Errorf("upstream path %q", r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.responseJSON))
			}))
			defer server.Close()

			gw := nativeMessagesGateway(t, server.URL)
			reqBody, err := json.Marshal(map[string]any{
				"model":    "claude-3-5-sonnet",
				"messages": []map[string]any{{"role": "user", "content": tc.content}},
			})
			if err != nil {
				t.Fatal(err)
			}
			rec := postCount(t, gw, string(reqBody), true)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d %s", rec.Code, rec.Body.String())
			}
			if rec.Header().Get("X-Yabanin-Estimated") != "" {
				t.Fatalf("native passthrough must not carry the estimation header")
			}
			if rec.Body.String() != tc.responseJSON {
				t.Fatalf("count_tokens body %q, want %q", rec.Body.String(), tc.responseJSON)
			}
		})
	}
}

// TestMessagesNative_StreamMissingIndexStartNotTracked: an upstream frame
// whose content_block_start omits the index field is a malformed block
// declaration — the relay must not invent index 0 for it, so a later cut
// synthesizes only the terminal error and no content_block_stop for an
// index the upstream never declared.
func TestMessagesNative_StreamMissingIndexStartNotTracked(t *testing.T) {
	const sse = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":2,\"output_tokens\":0}}}\n\n" +
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"partial\"}}\n\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(sse))
	}))
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	evCh := make(chan *eventpub.Event, 8)
	restore := observeEvent(func(e *eventpub.Event) { evCh <- e })
	t.Cleanup(restore)

	rec := postMessages(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}],"stream":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	select {
	case <-evCh:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for the finish event\nbody:\n%s", rec.Body.String())
	}
	if rec.Body.String() != sse+"event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"api_error\",\"message\":\"stream interrupted\"}}\n\n" {
		t.Fatalf("cut after a missing-index start must synthesize only the terminal error, no invented content_block_stop\ngot:\n%s", rec.Body.String())
	}
}
