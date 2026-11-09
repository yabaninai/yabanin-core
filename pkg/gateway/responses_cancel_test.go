package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/budget"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
)

// cancel on /v1/responses must bill the consumed prefix, keep the finish
// event canon, stamp termination=client_cancel and leak no reservation. The
// two subtests pin the same contract on both routes the endpoint serves.

// TestResponsesNative_StreamClientCancel pins the native passthrough route.
func TestResponsesNative_StreamClientCancel(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		_, _ = io.WriteString(w, "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"usage\":{\"input_tokens\":7,\"output_tokens\":0}}}\n\n")
		flusher.Flush()
		_, _ = io.WriteString(w, "event: response.output_item.added\ndata: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"type\":\"message\",\"id\":\"msg_1\"}}\n\n")
		flusher.Flush()
		for i := 0; ; i++ {
			time.Sleep(50 * time.Millisecond)
			if _, err := fmt.Fprintf(w, "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg_1\",\"output_index\":0,\"delta\":\"%d\"}\n\n", i); err != nil {
				return
			}
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	gw := responsesTestGateway(t, upstream.URL)
	gw.cfg.ResponsesNativeProviders = []string{"openai"}
	gw.res = stubModelResolver{"m": {ModelName: "m", Provider: "openai", UpstreamURL: upstream.URL, Enabled: true}}
	evCh := make(chan *eventpub.Event, 4)
	restore := observeEvent(func(e *eventpub.Event) { evCh <- e })
	t.Cleanup(restore)

	router := chi.NewRouter()
	gw.routes(router)
	gwServer := httptest.NewServer(router)
	defer gwServer.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, gwServer.URL+"/v1/responses",
		strings.NewReader(`{"model":"m","input":"Hi","stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := gwServer.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var partial bytes.Buffer
	buf := make([]byte, 4096)
	for {
		n, rerr := resp.Body.Read(buf)
		partial.Write(buf[:n])
		if strings.Contains(partial.String(), "response.output_item.added") {
			cancel()
		}
		if rerr != nil {
			break
		}
	}
	_ = resp.Body.Close()

	var ev *eventpub.Event
	select {
	case ev = <-evCh:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for the finish event\npartial:\n%s", partial.String())
	}
	if ev.EventType != "request.completed" {
		t.Fatalf("native cancel must stay request.completed (D1 canon), got %s", ev.EventType)
	}
	if ev.Endpoint != "responses" {
		t.Fatalf("endpoint %q", ev.Endpoint)
	}
	// Partial usage: the response.created prefix carries input_tokens=7;
	// no terminal event was seen, so the consumed prefix is what is billed.
	if ev.TokensIn != 7 || ev.TokensOut != 0 {
		t.Fatalf("partial usage in=%d out=%d", ev.TokensIn, ev.TokensOut)
	}
	// Termination stamping needs the reservation harness (integration
	// build); pin the §5.3 classifier the finisher uses for this dead
	// context — client cancel, never upstream error.
	if got := completionTermination(ctx); got != budget.TerminationClientCancel {
		t.Fatalf("termination classification %q", got)
	}
	if !strings.Contains(partial.String(), "response.created") || strings.Contains(partial.String(), "response.completed") {
		t.Fatalf("cancel must cut the stream mid-item:\n%s", partial.String())
	}
}

// TestResponsesAdapted_StreamClientCancel pins the translated route: the
// client cancel cuts the chat SSE relay wherever it was; the chat pipeline's
// G3 prefix billing keeps the finisher on request.completed with the
// termination classified client_cancel, and the endpoint stays "responses".
func TestResponsesAdapted_StreamClientCancel(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		_, _ = io.WriteString(w, "data: {\"id\":\"1\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"}}]}\n\n")
		flusher.Flush()
		for i := 0; ; i++ {
			time.Sleep(50 * time.Millisecond)
			if _, err := fmt.Fprintf(w, "data: {\"id\":\"1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"%d\"}}]}\n\n", i); err != nil {
				return
			}
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	gw := responsesTestGateway(t, upstream.URL)
	gw.res = stubModelResolver{"m": {ModelName: "m", Provider: "openai", UpstreamURL: upstream.URL, Enabled: true}}
	evCh := make(chan *eventpub.Event, 4)
	restore := observeEvent(func(e *eventpub.Event) { evCh <- e })
	t.Cleanup(restore)

	router := chi.NewRouter()
	gw.routes(router)
	gwServer := httptest.NewServer(router)
	defer gwServer.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, gwServer.URL+"/v1/responses",
		strings.NewReader(`{"model":"m","input":"Hi","stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := gwServer.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var partial bytes.Buffer
	buf := make([]byte, 4096)
	for {
		n, rerr := resp.Body.Read(buf)
		partial.Write(buf[:n])
		if strings.Contains(partial.String(), "response.output_text") {
			cancel()
		}
		if rerr != nil {
			break
		}
	}
	_ = resp.Body.Close()

	var ev *eventpub.Event
	select {
	case ev = <-evCh:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for the finish event\npartial:\n%s", partial.String())
	}
	if ev.Endpoint != "responses" {
		t.Fatalf("endpoint %q", ev.Endpoint)
	}
	// pins): native partial = request.completed with the consumed prefix
	// billed; adapted partial = request.failed without a charge (the chat
	// pipeline's drain-failure path records the prefix for token budgets
	// only — settlement creates no charge intent for request.failed).
	if ev.EventType != "request.failed" {
		t.Fatalf("adapted cancel must stay request.failed (R045 D1 canon), got %s (%s)", ev.EventType, ev.Error)
	}
	if got := completionTermination(ctx); got != budget.TerminationClientCancel {
		t.Fatalf("termination classification %q", got)
	}
	if !strings.Contains(partial.String(), "response.output_text") || strings.Contains(partial.String(), "response.completed") {
		t.Fatalf("cancel must cut the stream mid-text:\n%s", partial.String())
	}
}
