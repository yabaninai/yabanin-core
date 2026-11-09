package apiformat

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixedOpts() ResponsesOptions {
	return ResponsesOptions{
		IDGen:     func(prefix string) string { return prefix + "fixed" },
		Now:       func() time.Time { return time.Unix(1700000000, 0) },
		KeepAlive: -1,
	}
}

func runResponsesStream(t *testing.T, sse []byte, meta ResponsesMeta, opts ResponsesOptions, chunks int) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	w := NewResponsesWriter(rec, meta, opts)
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	if chunks <= 1 {
		_, _ = w.Write(sse)
	} else {
		for i := 0; i < len(sse); i += chunks {
			end := i + chunks
			if end > len(sse) {
				end = len(sse)
			}
			_, _ = w.Write(sse[i:end])
		}
	}
	w.Finish()
	return rec
}

func TestResponsesStream_Fixtures(t *testing.T) {
	text, err := os.ReadFile("testdata/stream_chat_text.sse")
	if err != nil {
		t.Fatal(err)
	}
	tools, err := os.ReadFile("testdata/stream_chat_tools.sse")
	if err != nil {
		t.Fatal(err)
	}
	bad, err := os.ReadFile("testdata/stream_chat_error.sse")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("text", func(t *testing.T) {
		rec := runResponsesStream(t, text, ResponsesMeta{RequestedModel: "gpt-4.1", Stream: true}, fixedOpts(), 1)
		assertResponsesFixture(t, rec.Body.Bytes(), "message", "Hello", "")
		expectSSE(t, "testdata/stream_responses_text.sse", rec.Body.Bytes())
	})
	t.Run("text chunks", func(t *testing.T) {
		one := runResponsesStream(t, text, ResponsesMeta{RequestedModel: "gpt-4.1", Stream: true}, fixedOpts(), 1)
		chunked := runResponsesStream(t, text, ResponsesMeta{RequestedModel: "gpt-4.1", Stream: true}, fixedOpts(), 3)
		if one.Body.String() != chunked.Body.String() {
			t.Fatalf("chunked output differs\n%s\n%s", one.Body.String(), chunked.Body.String())
		}
	})
	t.Run("tools", func(t *testing.T) {
		meta := ResponsesMeta{RequestedModel: "gpt-4.1", Stream: true, CustomToolNames: map[string]bool{"apply_patch": true}}
		rec := runResponsesStream(t, tools, meta, fixedOpts(), 1)
		events := ParseSSE(rec.Body.Bytes())
		if err := ValidateResponsesStream(events); err != nil {
			t.Fatal(err)
		}
		out := completedOutput(t, events)
		if len(out) != 2 || out[0].Type != "function_call" || out[0].Arguments != `{"path":"a"}` {
			t.Fatalf("function %#v", out)
		}
		if out[1].Type != "custom_tool_call" || out[1].Input != "d" {
			t.Fatalf("custom %#v", out[1])
		}
		expectSSE(t, "testdata/stream_responses_tools.sse", rec.Body.Bytes())
		body := rec.Body.String()
		if !containsAll(body, "custom_tool_call_input.delta", "custom_tool_call_input.done") {
			t.Fatalf("missing custom input events:\n%s", body)
		}
	})
	t.Run("error", func(t *testing.T) {
		rec := runResponsesStream(t, bad, ResponsesMeta{Stream: true}, fixedOpts(), 1)
		events := ParseSSE(rec.Body.Bytes())
		if err := ValidateResponsesStream(events); err != nil {
			t.Fatal(err)
		}
		last := events[len(events)-1]
		if last.Event != "response.failed" {
			t.Fatalf("last %s", last.Event)
		}
		var doc struct {
			Response struct {
				Status string `json:"status"`
				Error  struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			} `json:"response"`
		}
		if err := json.Unmarshal([]byte(last.Data), &doc); err != nil {
			t.Fatal(err)
		}
		if doc.Response.Status != "failed" || doc.Response.Error.Code != "boom" || doc.Response.Error.Message != "nope" {
			t.Fatalf("%+v", doc.Response)
		}
		expectSSE(t, "testdata/stream_responses_error.sse", rec.Body.Bytes())
	})
}

func TestResponsesStream_KeepaliveAndRace(t *testing.T) {
	rec := httptest.NewRecorder()
	opts := fixedOpts()
	opts.KeepAlive = 20 * time.Millisecond
	w := NewResponsesWriter(rec, ResponsesMeta{Stream: true, RequestedModel: "m"}, opts)
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	time.Sleep(80 * time.Millisecond)
	var wg sync.WaitGroup
	wg.Add(2)
	payload := []byte("data: {\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ab\"}}]}\n\n")
	go func() {
		defer wg.Done()
		for i := 0; i < len(payload); i += 5 {
			end := i + 5
			if end > len(payload) {
				end = len(payload)
			}
			_, _ = w.Write(payload[i:end])
		}
	}()
	go func() {
		defer wg.Done()
		time.Sleep(30 * time.Millisecond)
		_, _ = w.Write([]byte("data: {\"choices\":[{\"index\":0,\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n"))
	}()
	wg.Wait()
	w.Finish()
	body := rec.Body.String()
	if !containsAll(body, ": keepalive") {
		t.Fatalf("missing keepalive:\n%s", body)
	}
	events := ParseSSE(rec.Body.Bytes())
	if err := ValidateResponsesStream(events); err != nil {
		t.Fatalf("%v\n%s", err, body)
	}
}

func expectSSE(t *testing.T, path string, got []byte) {
	t.Helper()
	want, err := os.ReadFile(path) //nolint:gosec // G304: testdata fixture path, not user input
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != string(got) {
		t.Fatalf("%s mismatch\ngot %s", path, got)
	}
}

func assertResponsesFixture(t *testing.T, raw []byte, kind, text, args string) {
	t.Helper()
	events := ParseSSE(raw)
	if err := ValidateResponsesStream(events); err != nil {
		t.Fatalf("%v\n%s", err, raw)
	}
	out := completedOutput(t, events)
	if len(out) != 1 || out[0].Type != kind {
		t.Fatalf("output %#v", out)
	}
	if text != "" && out[0].Text != text {
		t.Fatalf("text %q", out[0].Text)
	}
	if args != "" && out[0].Arguments != args {
		t.Fatalf("args %q", out[0].Arguments)
	}
}

type completedItem struct {
	Type      string `json:"type"`
	Text      string `json:"-"`
	Arguments string `json:"arguments"`
	Input     string `json:"input"`
	Content   []struct {
		Text string `json:"text"`
	} `json:"content"`
}

func completedOutput(t *testing.T, events []SSEEvent) []completedItem {
	t.Helper()
	var doc struct {
		Response struct {
			Output []completedItem `json:"output"`
		} `json:"response"`
	}
	if err := json.Unmarshal([]byte(events[len(events)-1].Data), &doc); err != nil {
		t.Fatal(err)
	}
	for i := range doc.Response.Output {
		if len(doc.Response.Output[i].Content) > 0 {
			doc.Response.Output[i].Text = doc.Response.Output[i].Content[0].Text
		}
	}
	return doc.Response.Output
}

func containsAll(s string, parts ...string) bool {
	for _, part := range parts {
		if !strings.Contains(s, part) {
			return false
		}
	}
	return true
}
