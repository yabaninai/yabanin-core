package cli

// Negative-scenario pins for the packet's half tool JSON / cancel facets on
// /v1/messages: a client cancel that lands inside a streaming tool_use JSON
// fragment, and an upstream in-band error event arriving after a half-written
// tool_use block. Each pin counts every analytics event the endpoint
// publishes — exactly one billed finish, partial usage, no second billing —
// and checks the client never sees fabricated terminal frames.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
)

// TestMessagesNative_CancelMidToolJSONBillsOnce: the client hangs up while
// the tool_use input_json_delta is streaming. The partial usage seen so far
// is billed exactly once (request.completed, native D1 canon), and no other
// analytics event is published for the request.
func TestMessagesNative_CancelMidToolJSONBillsOnce(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		_, _ = w.Write([]byte("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":7,\"output_tokens\":0}}}\n\n"))
		flusher.Flush()
		_, _ = w.Write([]byte("event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"bash\",\"input\":{}}}\n\n"))
		flusher.Flush()
		for {
			time.Sleep(50 * time.Millisecond)
			if _, err := w.Write([]byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"cmd\\\":\"}}\n\n")); err != nil {
				return
			}
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	gw := nativeMessagesGateway(t, upstream.URL)
	evCh := make(chan *eventpub.Event, 8)
	var messagesEvents int
	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		if e.Endpoint != "messages" {
			return
		}
		messagesEvents++
		if e.EventType == "request.completed" || e.EventType == "request.failed" {
			ev = e
		}
		evCh <- e
	})
	t.Cleanup(restore)

	router := chi.NewRouter()
	gw.routes(router)
	gwServer := httptest.NewServer(router)
	defer gwServer.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, gwServer.URL+"/v1/messages",
		strings.NewReader(`{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}],"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := gwServer.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var partial strings.Builder
	buf := make([]byte, 4096)
	for {
		n, rerr := resp.Body.Read(buf)
		partial.Write(buf[:n])
		if strings.Contains(partial.String(), "input_json_delta") {
			cancel()
		}
		if rerr != nil {
			break
		}
	}
	_ = resp.Body.Close()

	select {
	case <-evCh:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for the finish event\npartial:\n%s", partial.String())
	}
	if ev == nil {
		t.Fatal("missing billed finish event")
	}
	if ev.EventType != "request.completed" {
		t.Fatalf("native cancel must stay request.completed (D1 canon), got %s", ev.EventType)
	}
	if ev.TokensIn != 7 || ev.TokensOut != 0 {
		t.Fatalf("partial usage in=%d out=%d", ev.TokensIn, ev.TokensOut)
	}
	if messagesEvents != 1 {
		t.Fatalf("cancel published %d analytics events, want exactly 1 (no double billing)", messagesEvents)
	}
	if got := partial.String(); !strings.Contains(got, "input_json_delta") || strings.Contains(got, "message_stop") {
		t.Fatalf("cancel must cut the stream mid tool JSON without fabricating message_stop:\n%s", got)
	}
}

// TestMessagesNative_HalfToolJSONThenErrorEventNoSynthesis: the upstream
// opens a tool_use block, streams half of the input JSON, then sends its own
// terminal error event. The half-written block is NOT closed by the relay —
// the explicit upstream error suppresses the synthesized close-open-blocks
// tail (no duplicate stops, no second error frame) — and the stream relays
// byte-identically with the partial usage billed once.
func TestMessagesNative_HalfToolJSONThenErrorEventNoSynthesis(t *testing.T) {
	const sse = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":3,\"output_tokens\":0}}}\n\n" +
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"bash\",\"input\":{}}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"cmd\\\":\"}}\n\n" +
		"event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"Overloaded\"}}\n\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(sse))
	}))
	defer server.Close()

	gw := nativeMessagesGateway(t, server.URL)
	evCh := make(chan *eventpub.Event, 8)
	var messagesEvents int
	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		if e.Endpoint != "messages" {
			return
		}
		messagesEvents++
		if e.EventType == "request.completed" || e.EventType == "request.failed" {
			ev = e
		}
		evCh <- e
	})
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
	if rec.Body.String() != sse {
		t.Fatalf("half tool JSON + upstream error must relay byte-identically (no synthesized stops or second error)\ngot %q", rec.Body.String())
	}
	if messagesEvents != 1 {
		t.Fatalf("published %d analytics events, want exactly 1", messagesEvents)
	}
	if ev == nil || ev.EventType != "request.completed" {
		t.Fatalf("in-band upstream error must stay request.completed (D1 canon), got %+v", ev)
	}
	if ev.TokensIn != 3 || ev.TokensOut != 0 {
		t.Fatalf("partial usage in=%d out=%d", ev.TokensIn, ev.TokensOut)
	}
}

// TestMessages_AdaptedCancelMidToolFragmentBillsOnce: the adapted twin — the
// translated tool-call arguments are buffered upstream until finalize (the
// adapted path never streams half-written tool JSON), so the realistic
// cancel lands while fragments are still buffering next to visible text
// deltas. The client hang-up bills the partial usage exactly once and
// records request.failed (D1 canon); the buffered tool call is never
// announced to the client and no message_stop is fabricated.
func TestMessages_AdaptedCancelMidToolFragmentBillsOnce(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		// Leading usage-only chunk: parsed for accounting but suppressed
		// from the client bytes, so the billed usage is fixed before the
		// cancel lands regardless of fragment timing.
		_, _ = w.Write([]byte("data: {\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5}}\n\n"))
		flusher.Flush()
		for {
			time.Sleep(50 * time.Millisecond)
			// Text delta keeps the client stream alive; the tool-call
			// argument fragment keeps buffering on the translated side.
			frame := "data: {\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"x,\"}}]}\n\n" +
				"data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"cmd\\\":\"}}]}}]}\n\n"
			if _, err := w.Write([]byte(frame)); err != nil {
				return
			}
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	gw := responsesTestGateway(t, upstream.URL)
	evCh := make(chan *eventpub.Event, 8)
	var messagesEvents int
	var ev *eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		if e.Endpoint != "messages" {
			return
		}
		messagesEvents++
		if e.EventType == "request.completed" || e.EventType == "request.failed" {
			ev = e
		}
		evCh <- e
	})
	t.Cleanup(restore)

	router := chi.NewRouter()
	gw.routes(router)
	gwServer := httptest.NewServer(router)
	defer gwServer.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, gwServer.URL+"/v1/messages",
		strings.NewReader(`{"model":"m","max_tokens":8,"messages":[{"role":"user","content":"Hi"}],"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := gwServer.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var partial strings.Builder
	buf := make([]byte, 4096)
	for {
		n, rerr := resp.Body.Read(buf)
		partial.Write(buf[:n])
		if strings.Contains(partial.String(), "content_block_delta") {
			cancel()
		}
		if rerr != nil {
			break
		}
	}
	_ = resp.Body.Close()

	select {
	case <-evCh:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for the finish event\npartial:\n%s", partial.String())
	}
	if ev == nil {
		t.Fatal("missing billed finish event")
	}
	if ev.EventType != "request.failed" {
		t.Fatalf("adapted cancel must be request.failed (D1 canon), got %s", ev.EventType)
	}
	if ev.TokensIn != 3 || ev.TokensOut != 2 {
		t.Fatalf("partial usage in=%d out=%d", ev.TokensIn, ev.TokensOut)
	}
	if !strings.Contains(ev.Error, "stream drain failed") {
		t.Fatalf("error %q", ev.Error)
	}
	if messagesEvents != 1 {
		t.Fatalf("cancel published %d analytics events, want exactly 1 (no double billing)", messagesEvents)
	}
	if got := partial.String(); !strings.Contains(got, "content_block_delta") ||
		strings.Contains(got, "message_stop") ||
		strings.Contains(got, "input_json_delta") {
		t.Fatalf("cancel must cut the stream while the tool call is still buffered: no message_stop and no announced tool JSON allowed:\n%s", got)
	}
}
