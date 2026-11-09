package cli

// failure/boundary matrix for /v1/responses: the named negative
// scenarios (continuation ids, tools, stream break) plus the
// native-vs-adapted parity pins the contract §6 examples rely on. Every
// case reproduces a refusal or break SAFELY against a local mock upstream
// and asserts the observable outcome (status, header, SSE bytes, event).

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
)

// TestResponses_UnsupportedHeader_Stream pins the D2 boundary on the
// streaming translated path: the X-Yabanin-Unsupported indication must ride
// the 200 SSE response headers, not only JSON responses.
func TestResponses_UnsupportedHeader_Stream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		_, _ = io.WriteString(w, "data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"ok\"}}]}\n\n")
		flusher.Flush()
		_, _ = io.WriteString(w, "data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"finish_reason\":\"stop\"}]}\n\n")
		flusher.Flush()
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer upstream.Close()

	gw := responsesTestGateway(t, upstream.URL)
	gw.res = stubModelResolver{"m": {ModelName: "m", Provider: "openai", UpstreamURL: upstream.URL, Enabled: true}}
	rec := postResponses(t, gw, `{"model":"m","input":"Hi","stream":true,"reasoning":{"effort":"low"}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Yabanin-Unsupported"); !strings.Contains(got, "reasoning") {
		t.Fatalf("streaming drop not announced, header %q", got)
	}
	if !strings.Contains(rec.Body.String(), "response.completed") {
		t.Fatalf("stream did not complete:\n%s", rec.Body.String())
	}
}

// TestResponses_UnsupportedHeader_NoFalsePositives pins the other side of
// the D2 boundary: requests whose fields the translation fully supports
// must NOT carry the unsupported header (an empty reasoning object is not a
// drop; the header is a signal, not decoration).
func TestResponses_UnsupportedHeader_NoFalsePositives(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"id":"c","created":1,"model":"m","choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)
	}))
	defer upstream.Close()
	gw := responsesTestGateway(t, upstream.URL)
	gw.res = stubModelResolver{"m": {ModelName: "m", Provider: "openai", UpstreamURL: upstream.URL, Enabled: true}}

	for name, body := range map[string]string{
		"plain":           `{"model":"m","input":"Hi"}`,
		"empty reasoning": `{"model":"m","input":"Hi","reasoning":{}}`,
		"function tool":   `{"model":"m","input":"Hi","tools":[{"type":"function","name":"shell"}]}`,
	} {
		rec := postResponses(t, gw, body)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d %s", name, rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("X-Yabanin-Unsupported"); got != "" {
			t.Fatalf("%s: false-positive unsupported header %q", name, got)
		}
	}
}

// TestUnsupportedHeader_Truncation unit-pins the render cap: the wire
// drop-set is deduplicated (small by construction), so the 1 KiB header
// ceiling is defensive — when a future drop source grows unbounded the
// header degrades to a capped value with an ellipsis, never an oversized
// header.
func TestUnsupportedHeader_Truncation(t *testing.T) {
	var names []string
	for i := 0; i < 200; i++ {
		names = append(names, fmt.Sprintf("field_%03d", i))
	}
	got := unsupportedHeader(names)
	if len(got) > 1024 {
		t.Fatalf("capped header must stay within the 1 KiB ceiling, got %d bytes", len(got))
	}
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("capped header must end with an ellipsis: %q", got[len(got)-32:])
	}
	if got := unsupportedHeader([]string{"reasoning"}); got != "reasoning" {
		t.Fatalf("small set must render verbatim, got %q", got)
	}
}

// TestResponses_Native_NoUnsupportedHeader_Passthrough pins the parity
// boundary: the NATIVE path forwards the body verbatim, so nothing is
// dropped and the header must be absent — the indication belongs to the
// translation, never to the passthrough.
func TestResponses_Native_NoUnsupportedHeader_Passthrough(t *testing.T) {
	var upstreamBody atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		upstreamBody.Store(string(raw))
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"resp_1","object":"response","status":"completed","output":[]}`)
	}))
	defer upstream.Close()

	gw := responsesTestGateway(t, upstream.URL)
	gw.cfg.ResponsesNativeProviders = []string{"openai"}
	gw.res = stubModelResolver{"m": {ModelName: "m", Provider: "openai", UpstreamURL: upstream.URL, Enabled: true}}
	rec := postResponses(t, gw, `{"model":"m","input":"Hi","reasoning":{"effort":"high"}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Yabanin-Unsupported"); got != "" {
		t.Fatalf("native passthrough announced drops it never made: %q", got)
	}
	sent, _ := upstreamBody.Load().(string)
	if !strings.Contains(sent, `"effort":"high"`) {
		t.Fatalf("native path must forward reasoning verbatim, upstream saw %s", sent)
	}
}

// TestResponses_PreviousResponseID_Precedence pins the D1 boundary: the
// stateless rejection is the FIRST decision on the endpoint — before native
// dispatch, model resolution or any upstream traffic — so a continuation id
// never reaches a provider regardless of route or payload shape.
func TestResponses_PreviousResponseID_Precedence(t *testing.T) {
	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer upstream.Close()

	gw := responsesTestGateway(t, upstream.URL)
	gw.cfg.ResponsesNativeProviders = []string{"openai"}
	// No resolver entry for the model: had the rejection not fired first,
	// the request would degrade to the adapted path and hit admission
	// instead of answering the stateless 400.
	gw.res = stubModelResolver{}
	rec := postResponses(t, gw, `{"model":"no-such-model","input":"Hi","previous_response_id":"resp_x"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "previous_response_not_supported") {
		t.Fatalf("body %s", rec.Body.String())
	}
	if n := upstreamHits.Load(); n != 0 {
		t.Fatalf("continuation refusal must precede any upstream traffic, saw %d hits", n)
	}
}

// breakServer answers one request with an SSE prefix and then truncates the
// body far below the declared Content-Length: the gateway's read side gets
// io.ErrUnexpectedEOF — a mid-flight transport break, not a clean EOF.
func breakServer(t *testing.T, prefix string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Length", "16384")
		_, _ = io.WriteString(w, prefix)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		// Returning here under-writes the declared length: the client
		// sees an abrupt truncated stream.
	}))
}

// fix: an upstream-side break after the 200/SSE commit is NOT success —
// request.failed (no charge intent), the consumed prefix recorded on the
// event, a protocol-shaped response.failed frame appended for the client,
// and never a response.completed event. This mirrors the chat drain-failure
func TestResponsesNative_StreamBreak_UpstreamFailure(t *testing.T) {
	upstream := breakServer(t, "event: response.created\n"+
		"data: {\"type\":\"response.created\",\"response\":{\"usage\":{\"input_tokens\":7,\"output_tokens\":0}}}\n\n"+
		"event: response.output_item.added\n"+
		"data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"type\":\"message\",\"id\":\"msg_1\"}}\n\n")
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

	post := func() *http.Response {
		t.Helper()
		req, rerr := http.NewRequestWithContext(t.Context(), http.MethodPost, gwServer.URL+"/v1/responses",
			strings.NewReader(`{"model":"m","input":"Hi","stream":true}`))
		if rerr != nil {
			t.Fatal(rerr)
		}
		req.Header.Set("Authorization", "Bearer test-key")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	resp := post()
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	var ev *eventpub.Event
	select {
	case ev = <-evCh:
	case <-time.After(15 * time.Second):
		t.Fatalf("timed out waiting for the finish event\nstream:\n%s", string(raw))
	}
	if ev.EventType != "request.failed" {
		t.Fatalf("upstream break must not classify success, got %s", ev.EventType)
	}
	if ev.Endpoint != "responses" {
		t.Fatalf("endpoint %q", ev.Endpoint)
	}
	if !strings.Contains(ev.Error, "stream drain failed") {
		t.Fatalf("error %q", ev.Error)
	}
	// The consumed prefix (input_tokens=7 from response.created) rides the
	// failed event for token budgets — recorded, but never charged.
	if ev.TokensIn != 7 {
		t.Fatalf("partial prefix tokens %d", ev.TokensIn)
	}
	if strings.Contains(string(raw), "response.completed") {
		t.Fatalf("broken stream must not contain response.completed:\n%s", string(raw))
	}
	if !strings.Contains(string(raw), "response.failed") {
		t.Fatalf("client must see the terminal failure frame:\n%s", string(raw))
	}
}

// TestResponsesAdapted_StreamBreak_Parity pins the same break through the
// TRANSLATED route: the chat pipeline's drain-failure canon (request.failed,
// "stream drain failed") already covers it — this is the native/adapted
// parity the contract's stream-cancellation family requires.
func TestResponsesAdapted_StreamBreak_Parity(t *testing.T) {
	upstream := breakServer(t, "data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"}}]}\n\n"+
		"data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"par\"}}]}\n\n")
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

	post := func() *http.Response {
		t.Helper()
		req, rerr := http.NewRequestWithContext(t.Context(), http.MethodPost, gwServer.URL+"/v1/responses",
			strings.NewReader(`{"model":"m","input":"Hi","stream":true}`))
		if rerr != nil {
			t.Fatal(rerr)
		}
		req.Header.Set("Authorization", "Bearer test-key")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	resp := post()
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	var ev *eventpub.Event
	select {
	case ev = <-evCh:
	case <-time.After(15 * time.Second):
		t.Fatalf("timed out waiting for the finish event\nstream:\n%s", string(raw))
	}
	if ev.EventType != "request.failed" {
		t.Fatalf("adapted break must stay request.failed, got %s (%s)", ev.EventType, ev.Error)
	}
	if ev.Endpoint != "responses" {
		t.Fatalf("endpoint %q", ev.Endpoint)
	}
	if !strings.Contains(ev.Error, "stream drain failed") {
		t.Fatalf("error %q", ev.Error)
	}
}

// TestResponsesNative_StreamIdleTimeout pins the watchdog branch of the
// same break family: a stalled upstream (silence past the idle timeout) is
// an upstream-side break — request.failed with the idle-timeout detail, and
// the reservation finalized (the finisher runs exactly once).
func TestResponsesNative_StreamIdleTimeout(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		_, _ = io.WriteString(w, "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"usage\":{\"input_tokens\":5,\"output_tokens\":0}}}\n\n")
		flusher.Flush()
		// Stall: never another byte until the test (or the watchdog's
		// cancellation of the gateway request) ends this handler.
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer upstream.Close()
	defer close(release)

	gw := responsesTestGateway(t, upstream.URL)
	gw.cfg.ResponsesNativeProviders = []string{"openai"}
	gw.streamIdleTimeout = 100 * time.Millisecond
	gw.res = stubModelResolver{"m": {ModelName: "m", Provider: "openai", UpstreamURL: upstream.URL, Enabled: true}}
	evCh := make(chan *eventpub.Event, 4)
	restore := observeEvent(func(e *eventpub.Event) { evCh <- e })
	t.Cleanup(restore)

	router := chi.NewRouter()
	gw.routes(router)
	gwServer := httptest.NewServer(router)
	defer gwServer.Close()

	post := func() *http.Response {
		t.Helper()
		req, rerr := http.NewRequestWithContext(t.Context(), http.MethodPost, gwServer.URL+"/v1/responses",
			strings.NewReader(`{"model":"m","input":"Hi","stream":true}`))
		if rerr != nil {
			t.Fatal(rerr)
		}
		req.Header.Set("Authorization", "Bearer test-key")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	resp := post()
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	var ev *eventpub.Event
	select {
	case ev = <-evCh:
	case <-time.After(15 * time.Second):
		t.Fatalf("timed out waiting for the finish event\nstream:\n%s", string(raw))
	}
	if ev.EventType != "request.failed" {
		t.Fatalf("idle abort must classify request.failed, got %s", ev.EventType)
	}
	if !strings.Contains(ev.Error, "upstream stream idle timeout") {
		t.Fatalf("error %q", ev.Error)
	}
	if !strings.Contains(string(raw), "response.failed") {
		t.Fatalf("client must see the terminal failure frame:\n%s", string(raw))
	}
}

// TestResponsesNative_StreamCleanEOF_IsSuccess guards the other side of the
// break boundary: a stream that ends with clean EOF after its terminal
// response.completed event stays a success (chat canon: EOF is not a drain
func TestResponsesNative_StreamCleanEOF_IsSuccess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		_, _ = io.WriteString(w, "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"usage\":{\"input_tokens\":3,\"output_tokens\":0}}}\n\n")
		flusher.Flush()
		_, _ = io.WriteString(w, "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":3,\"output_tokens\":2}}}\n\n")
		flusher.Flush()
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

	post := func() *http.Response {
		t.Helper()
		req, rerr := http.NewRequestWithContext(t.Context(), http.MethodPost, gwServer.URL+"/v1/responses",
			strings.NewReader(`{"model":"m","input":"Hi","stream":true}`))
		if rerr != nil {
			t.Fatal(rerr)
		}
		req.Header.Set("Authorization", "Bearer test-key")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	resp := post()
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	var ev *eventpub.Event
	select {
	case ev = <-evCh:
	case <-time.After(15 * time.Second):
		t.Fatalf("timed out waiting for the finish event\nstream:\n%s", string(raw))
	}
	if ev.EventType != "request.completed" {
		t.Fatalf("clean EOF after the terminal event must stay success, got %s (%s)", ev.EventType, ev.Error)
	}
	if ev.TokensIn != 3 || ev.TokensOut != 2 {
		t.Fatalf("usage in=%d out=%d", ev.TokensIn, ev.TokensOut)
	}
}
