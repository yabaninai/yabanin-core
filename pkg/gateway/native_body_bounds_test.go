package cli

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
)

// Native buffered body-bound regressions. The two buffered native routes
// (Messages, Responses) must refuse an oversized upstream 200 instead of
// publishing a truncated payable success, and an interrupted read after a
// paid dispatch must suppress replay instead of inviting it. Refusals keep
// recovery on the durable admission (finalizeNoEvent: zero actuals, escrow
// swept) and never invent usage: no terminal facts, no analytics event.

const bodyBoundsMessagesClientBody = `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"Hi"}]}`

// bodyBoundsFixture independently observes what the provider did: how many
// times it was contacted, which Content-Length it declared and how many
// bytes it actually served.
type bodyBoundsFixture struct {
	contacts    atomic.Int32
	declaredLen atomic.Int64
	servedBytes atomic.Int64
}

func (f *bodyBoundsFixture) serveBody(t *testing.T, body []byte) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		f.contacts.Add(1)
		w.Header().Set("Content-Type", "application/json")
		n, _ := w.Write(body)
		f.servedBytes.Store(int64(n))
	}
}

// serveShortRead declares the full claimed length and then breaks the
// connection after prefix bytes: the dispatch happened, but the success
// body never arrives completely.
func (f *bodyBoundsFixture) serveShortRead(t *testing.T, body []byte, prefix int) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		f.contacts.Add(1)
		f.declaredLen.Store(int64(len(body)))
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Header().Set("Content-Type", "application/json")
		n, _ := w.Write(body[:prefix])
		f.servedBytes.Store(int64(n))
	}
}

// bodyBoundsBodyOfSize returns a valid route-shaped success body padded to
// exactly size bytes, usage block at the tail so any truncation strips the
// usage — exactly the payable-truncation hazard.
func bodyBoundsBodyOfSize(t *testing.T, prefix, suffix string, size int) []byte {
	t.Helper()
	if size < len(prefix)+len(suffix) {
		t.Fatalf("size %d below fixed envelope %d", size, len(prefix)+len(suffix))
	}
	return []byte(prefix + strings.Repeat("a", size-len(prefix)-len(suffix)) + suffix)
}

func anthropicBodyOfSize(t *testing.T, size int) []byte {
	t.Helper()
	return bodyBoundsBodyOfSize(t,
		`{"id":"msg_bodybounds","type":"message","role":"assistant","model":"claude-upstream","content":[{"type":"text","text":"`,
		`"}],"stop_reason":"end_turn","usage":{"input_tokens":2,"output_tokens":1}}`, size)
}

func responsesBodyOfSize(t *testing.T, size int) []byte {
	t.Helper()
	return bodyBoundsBodyOfSize(t,
		`{"id":"resp_bodybounds","object":"response","output":[{"type":"message","content":[{"type":"output_text","text":"`,
		`"}]}],"usage":{"input_tokens":2,"output_tokens":1}}`, size)
}

// bodyBoundsSummary bounds failure output: a wrongly served megabyte-scale
// success body is summarized, never dumped into the test log.
func bodyBoundsSummary(rec *httptest.ResponseRecorder) string {
	const max = 512
	b := rec.Body.String()
	if len(b) > max {
		return fmt.Sprintf("%d bytes, head %q", len(b), b[:max])
	}
	return b
}

// bodyBoundsEvents captures events via the synchronous finisher hook.
type bodyBoundsEvents struct {
	mu     sync.Mutex
	events []*eventpub.Event
}

func (c *bodyBoundsEvents) hook(e *eventpub.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *bodyBoundsEvents) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}

func newBodyBoundsServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	t.Cleanup(server.Close)
	return server
}

func bodyBoundsMessagesGateway(t *testing.T, upstreamURL string, store *fakeInvocationStore, capture *bodyBoundsEvents) *gateway {
	t.Helper()
	gw := responsesTestGateway(t, upstreamURL)
	gw.res = stubModelResolver{
		"claude-3-5-sonnet": {
			ModelName:      "claude-upstream",
			Provider:       "anthropic",
			UpstreamURL:    upstreamURL,
			UpstreamAPIKey: "upstream-key",
			Enabled:        true,
		},
	}
	gw.invocations = store
	gw.eventNote = capture.hook
	return gw
}

func bodyBoundsResponsesGateway(t *testing.T, upstreamURL string, store *fakeInvocationStore, capture *bodyBoundsEvents) *gateway {
	t.Helper()
	gw := responsesTestGateway(t, upstreamURL)
	gw.cfg.ResponsesNativeProviders = []string{"openai"}
	gw.invocations = store
	gw.eventNote = capture.hook
	return gw
}

// assertRefusalNotPayable checks the shared refusal contract for both
// buffered native routes: the upstream success never reaches the client
// truncated, retries are suppressed after the uncertain paid outcome, and
// recovery stays on the durable admission without inventing usage.
func assertRefusalNotPayable(t *testing.T, rec *httptest.ResponseRecorder, store *fakeInvocationStore, capture *bodyBoundsEvents, fixture *bodyBoundsFixture, wantReason string) {
	t.Helper()
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d %s", rec.Code, bodyBoundsSummary(rec))
	}
	if got := rec.Header().Get("X-Should-Retry"); got != "false" {
		t.Fatalf("X-Should-Retry %q, want false", got)
	}
	if !strings.Contains(rec.Body.String(), wantReason) {
		t.Fatalf("body %s missing reason %q", bodyBoundsSummary(rec), wantReason)
	}
	if strings.Contains(rec.Body.String(), "aaaa") {
		t.Fatalf("upstream padding leaked into refusal body %s", bodyBoundsSummary(rec))
	}
	if n := fixture.contacts.Load(); n != 1 {
		t.Fatalf("provider contacted %d times, want exactly 1", n)
	}
	if n := capture.len(); n != 0 {
		t.Fatalf("%d analytics events published on refusal, want 0", n)
	}
	if len(store.admitted) != 1 {
		t.Fatalf("%d durable admissions, want exactly 1", len(store.admitted))
	}
	if len(store.facts) != 0 {
		t.Fatalf("%d terminal fact records, want 0 (no invented usage)", len(store.facts))
	}
}

func TestMessagesNativeJSON_ExactCapBodyServedAndSettled(t *testing.T) {
	body := anthropicBodyOfSize(t, messagesResponseLimit)
	var fixture bodyBoundsFixture
	server := newBodyBoundsServer(t, fixture.serveBody(t, body))
	store := &fakeInvocationStore{}
	var capture bodyBoundsEvents
	gw := bodyBoundsMessagesGateway(t, server.URL, store, &capture)

	rec := postMessages(t, gw, bodyBoundsMessagesClientBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, bodyBoundsSummary(rec))
	}
	if rec.Body.String() != string(body) {
		t.Fatalf("byte-identical forward broken: got %d bytes, want %d", rec.Body.Len(), len(body))
	}
	if n := fixture.contacts.Load(); n != 1 {
		t.Fatalf("provider contacted %d times, want 1", n)
	}
	if len(store.admitted) != 1 || len(store.facts) != 1 {
		t.Fatalf("admissions %d facts %d, want 1 and 1", len(store.admitted), len(store.facts))
	}
	if store.facts[0].Fields["tokens_in"] != "2" || store.facts[0].Fields["tokens_out"] != "1" {
		t.Fatalf("facts usage %v", store.facts[0].Fields)
	}
	if capture.len() != 1 {
		t.Fatalf("%d events, want exactly the completed one", capture.len())
	}
}

func TestMessagesNativeJSON_OversizedUpstreamRefusedNotTruncated(t *testing.T) {
	body := anthropicBodyOfSize(t, messagesResponseLimit+1)
	var fixture bodyBoundsFixture
	server := newBodyBoundsServer(t, fixture.serveBody(t, body))
	store := &fakeInvocationStore{}
	var capture bodyBoundsEvents
	gw := bodyBoundsMessagesGateway(t, server.URL, store, &capture)

	rec := postMessages(t, gw, bodyBoundsMessagesClientBody)
	assertRefusalNotPayable(t, rec, store, &capture, &fixture, "upstream response too large")
	if n := fixture.servedBytes.Load(); n != int64(len(body)) {
		t.Fatalf("provider served %d bytes, want %d", n, len(body))
	}
}

func TestMessagesNativeJSON_ShortReadSuppressesReplay(t *testing.T) {
	full := anthropicBodyOfSize(t, 4096)
	var fixture bodyBoundsFixture
	server := newBodyBoundsServer(t, fixture.serveShortRead(t, full, 256))
	store := &fakeInvocationStore{}
	var capture bodyBoundsEvents
	gw := bodyBoundsMessagesGateway(t, server.URL, store, &capture)

	rec := postMessages(t, gw, bodyBoundsMessagesClientBody)
	assertRefusalNotPayable(t, rec, store, &capture, &fixture, "failed to read upstream response")
	if fixture.declaredLen.Load() != int64(len(full)) || fixture.servedBytes.Load() != 256 {
		t.Fatalf("provider declared %d served %d, want %d and 256",
			fixture.declaredLen.Load(), fixture.servedBytes.Load(), len(full))
	}
}

func TestResponsesNativeJSON_ExactCapBodyServedAndSettled(t *testing.T) {
	body := responsesBodyOfSize(t, responsesBodyLimit)
	var fixture bodyBoundsFixture
	server := newBodyBoundsServer(t, fixture.serveBody(t, body))
	store := &fakeInvocationStore{}
	var capture bodyBoundsEvents
	gw := bodyBoundsResponsesGateway(t, server.URL, store, &capture)

	rec := postResponses(t, gw, `{"model":"m","input":"Hi"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, bodyBoundsSummary(rec))
	}
	if rec.Body.String() != string(body) {
		t.Fatalf("byte-identical forward broken: got %d bytes, want %d", rec.Body.Len(), len(body))
	}
	if n := fixture.contacts.Load(); n != 1 {
		t.Fatalf("provider contacted %d times, want 1", n)
	}
	if len(store.admitted) != 1 || len(store.facts) != 1 {
		t.Fatalf("admissions %d facts %d, want 1 and 1", len(store.admitted), len(store.facts))
	}
	if store.facts[0].Fields["tokens_in"] != "2" || store.facts[0].Fields["tokens_out"] != "1" {
		t.Fatalf("facts usage %v", store.facts[0].Fields)
	}
	if capture.len() != 1 {
		t.Fatalf("%d events, want exactly the completed one", capture.len())
	}
}

func TestResponsesNativeJSON_OversizedUpstreamRefusedNotTruncated(t *testing.T) {
	body := responsesBodyOfSize(t, responsesBodyLimit+1)
	var fixture bodyBoundsFixture
	server := newBodyBoundsServer(t, fixture.serveBody(t, body))
	store := &fakeInvocationStore{}
	var capture bodyBoundsEvents
	gw := bodyBoundsResponsesGateway(t, server.URL, store, &capture)

	rec := postResponses(t, gw, `{"model":"m","input":"Hi"}`)
	assertRefusalNotPayable(t, rec, store, &capture, &fixture, "upstream response too large")
	if n := fixture.servedBytes.Load(); n != int64(len(body)) {
		t.Fatalf("provider served %d bytes, want %d", n, len(body))
	}
}

func TestResponsesNativeJSON_ShortReadSuppressesReplay(t *testing.T) {
	full := responsesBodyOfSize(t, 4096)
	var fixture bodyBoundsFixture
	server := newBodyBoundsServer(t, fixture.serveShortRead(t, full, 256))
	store := &fakeInvocationStore{}
	var capture bodyBoundsEvents
	gw := bodyBoundsResponsesGateway(t, server.URL, store, &capture)

	rec := postResponses(t, gw, `{"model":"m","input":"Hi"}`)
	assertRefusalNotPayable(t, rec, store, &capture, &fixture, "failed to read upstream response")
	if fixture.declaredLen.Load() != int64(len(full)) || fixture.servedBytes.Load() != 256 {
		t.Fatalf("provider declared %d served %d, want %d and 256",
			fixture.declaredLen.Load(), fixture.servedBytes.Load(), len(full))
	}
}

func TestNativeBufferedProviderErrorBound(t *testing.T) {
	for _, tc := range []struct {
		name, request string
		limit         int
		gateway       func(*testing.T, string, *fakeInvocationStore, *bodyBoundsEvents) *gateway
		post          func(*testing.T, *gateway, string) *httptest.ResponseRecorder
	}{
		{"messages", bodyBoundsMessagesClientBody, messagesResponseLimit, bodyBoundsMessagesGateway, postMessages},
		{"responses", `{"model":"m","input":"Hi"}`, responsesBodyLimit, bodyBoundsResponsesGateway, postResponses},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const document = `{"type":"error","error":{"type":"rate_limit_error","message":"busy"}}`
			body := document + strings.Repeat(" ", tc.limit-len(document))
			server := newBodyBoundsServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = io.WriteString(w, body+"\t")
			})
			gw := tc.gateway(t, server.URL, &fakeInvocationStore{}, &bodyBoundsEvents{})
			rec := tc.post(t, gw, tc.request)
			if rec.Code != http.StatusTooManyRequests || rec.Body.String() != body {
				t.Fatalf("provider error returned status %d and %d bytes, want 429 and %d bytes", rec.Code, rec.Body.Len(), tc.limit)
			}
		})
	}
}
