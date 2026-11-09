package cli

// Interruption and recovery scenarios on /v1/messages: a client retrying
// after a mid-stream break. SSE has no resume token, so recovery is a full
// retry of the same request; the pins hold the ledger honest — the
// interrupted round bills its partial usage exactly once, the retried round
// bills its full usage exactly once, the retried request bytes reach the
// upstream unchanged, and no duplicated or lost analytics event appears.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
)

type rrUpstream struct {
	mu     sync.Mutex
	bodies []string
}

func (u *rrUpstream) snapshot() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.bodies...)
}

const (
	// Round 1: the upstream connection breaks after a partial text delta —
	// no message_stop, just EOF on the wire.
	rrCutStream = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":4,\"output_tokens\":0}}}\n\n" +
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"par\"}}\n\n"
	// Round 2 (the retry): the same request answered completely.
	rrFullStream = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":4,\"output_tokens\":0}}}\n\n" +
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"partial-then-full\"}}\n\n" +
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":9}}\n\n" +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
)

// TestMessagesNative_RetryAfterMidStreamCutNoDuplication: round 1 breaks
// mid-stream (partial billed once, synthesized tail closes the client
// stream), the client resends the identical request, round 2 completes and
// bills once. The upstream receives the same request bytes both times.
func TestMessagesNative_RetryAfterMidStreamCutNoDuplication(t *testing.T) {
	up := &rrUpstream{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := string(readRequestBody(r))
		up.mu.Lock()
		up.bodies = append(up.bodies, raw)
		up.mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		if len(up.bodies) == 1 {
			_, _ = w.Write([]byte(rrCutStream))
			return // EOF: the break the client recovers from
		}
		_, _ = w.Write([]byte(rrFullStream))
	}))
	defer upstream.Close()

	gw := nativeMessagesGateway(t, upstream.URL)
	evCh := make(chan *eventpub.Event, 8)
	var evs []*eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		if e.Endpoint != "messages" {
			return
		}
		evs = append(evs, e)
		evCh <- e
	})
	t.Cleanup(restore)

	const reqBody = `{"model":"claude-3-5-sonnet","max_tokens":16,"messages":[{"role":"user","content":"Hi"}],"stream":true}`
	rec1 := postMessages(t, gw, reqBody)
	if rec1.Code != http.StatusOK {
		t.Fatalf("round 1 status %d %s", rec1.Code, rec1.Body.String())
	}
	want1 := rrCutStream +
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
		"event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"api_error\",\"message\":\"stream interrupted\"}}\n\n"
	if rec1.Body.String() != want1 {
		t.Fatalf("round 1 client stream %q", rec1.Body.String())
	}
	<-evCh

	rec2 := postMessages(t, gw, reqBody)
	if rec2.Code != http.StatusOK {
		t.Fatalf("round 2 status %d %s", rec2.Code, rec2.Body.String())
	}
	if rec2.Body.String() != rrFullStream {
		t.Fatalf("round 2 client stream must be the complete answer\n%s", rec2.Body.String())
	}
	<-evCh

	bodies := up.snapshot()
	if len(bodies) != 2 || bodies[0] != bodies[1] {
		t.Fatalf("retry must resend identical request bytes (%d upstream requests, equal=%v)", len(bodies), len(bodies) == 2 && bodies[0] == bodies[1])
	}
	// Ledger: exactly two completed rounds — the partial then the full —
	// nothing failed, nothing duplicated, nothing lost.
	if len(evs) != 2 {
		t.Fatalf("%d analytics events, want exactly 2", len(evs))
	}
	if evs[0].EventType != "request.completed" || evs[0].TokensIn != 4 || evs[0].TokensOut != 0 {
		t.Fatalf("round 1 event %+v, want completed partial 4/0", evs[0])
	}
	if evs[1].EventType != "request.completed" || evs[1].TokensIn != 4 || evs[1].TokensOut != 9 {
		t.Fatalf("round 2 event %+v, want completed full 4/9", evs[1])
	}
}

// TestMessagesNative_RetryAfterUpstreamTransportAbort: the upstream
// connection aborts mid-response (transport-level, no SSE error frame).
// The native relay still closes the client stream with the synthesized
// tail, bills the partial usage once, and an identical retry succeeds.
func TestMessagesNative_RetryAfterUpstreamTransportAbort(t *testing.T) {
	up := &rrUpstream{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := string(readRequestBody(r))
		up.mu.Lock()
		up.bodies = append(up.bodies, raw)
		up.mu.Unlock()
		if len(up.bodies) == 1 {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte(rrCutStream))
			flusher := w.(http.Flusher)
			flusher.Flush()
			panic(http.ErrAbortHandler) // transport abort mid-response
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(rrFullStream))
	}))
	defer upstream.Close()

	gw := nativeMessagesGateway(t, upstream.URL)
	evCh := make(chan *eventpub.Event, 8)
	var evs []*eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		if e.Endpoint != "messages" {
			return
		}
		evs = append(evs, e)
		evCh <- e
	})
	t.Cleanup(restore)

	const reqBody = `{"model":"claude-3-5-sonnet","max_tokens":16,"messages":[{"role":"user","content":"Hi"}],"stream":true}`
	rec1 := postMessages(t, gw, reqBody)
	if rec1.Code != http.StatusOK {
		t.Fatalf("round 1 status %d %s", rec1.Code, rec1.Body.String())
	}
	if got := rec1.Body.String(); !strings.HasSuffix(got, "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"api_error\",\"message\":\"stream interrupted\"}}\n\n") {
		t.Fatalf("transport abort must still close the client stream with the synthesized error tail:\n%s", got)
	}
	<-evCh

	rec2 := postMessages(t, gw, reqBody)
	if rec2.Code != http.StatusOK || rec2.Body.String() != rrFullStream {
		t.Fatalf("retry status %d body %q", rec2.Code, rec2.Body.String())
	}
	<-evCh

	if len(evs) != 2 {
		t.Fatalf("%d analytics events, want exactly 2", len(evs))
	}
	if evs[0].EventType != "request.completed" || evs[0].TokensIn != 4 || evs[0].TokensOut != 0 {
		t.Fatalf("round 1 event %+v, want completed partial 4/0", evs[0])
	}
	if evs[1].EventType != "request.completed" || evs[1].TokensOut != 9 {
		t.Fatalf("round 2 event %+v, want completed full", evs[1])
	}
}

// TestMessages_AdaptedRetryAfterDrainFailure: the adapted twin — round 1
// drains into a broken upstream and fails (D1 canon), the client resends
// the identical request, round 2 completes. Ledger: one request.failed then
// one request.completed, exactly two events.
func TestMessages_AdaptedRetryAfterDrainFailure(t *testing.T) {
	up := &rrUpstream{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := string(readRequestBody(r))
		up.mu.Lock()
		up.bodies = append(up.bodies, raw)
		up.mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		if len(up.bodies) == 1 {
			// Fixed usage, then one visible text delta, then a transport
			// abort mid-body — the drain failure the client retries from.
			// (A clean EOF without a finish chunk would finalize gracefully
			// instead; the failure ledger needs a read error.)
			_, _ = w.Write([]byte("data: {\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5}}\n\n"))
			flusher.Flush()
			_, _ = w.Write([]byte("data: {\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"par\"}}]}\n\n"))
			flusher.Flush()
			panic(http.ErrAbortHandler)
		}
		_, _ = w.Write([]byte("data: {\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5}}\n\n"))
		flusher.Flush()
		_, _ = w.Write([]byte("data: {\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"partial-then-full\"}}]}\n\n"))
		_, _ = w.Write([]byte("data: {\"choices\":[{\"index\":0,\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":9,\"total_tokens\":12}}\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer upstream.Close()

	gw := responsesTestGateway(t, upstream.URL)
	evCh := make(chan *eventpub.Event, 8)
	var evs []*eventpub.Event
	restore := observeEvent(func(e *eventpub.Event) {
		if e.Endpoint != "messages" {
			return
		}
		evs = append(evs, e)
		evCh <- e
	})
	t.Cleanup(restore)

	const reqBody = `{"model":"m","max_tokens":16,"messages":[{"role":"user","content":"Hi"}],"stream":true}`
	rec1 := postMessages(t, gw, reqBody)
	if rec1.Code != http.StatusOK {
		t.Fatalf("round 1 status %d %s", rec1.Code, rec1.Body.String())
	}
	if got := rec1.Body.String(); strings.Contains(got, "message_stop") {
		t.Fatalf("drain failure must not fabricate message_stop:\n%s", got)
	}
	<-evCh

	rec2 := postMessages(t, gw, reqBody)
	if rec2.Code != http.StatusOK {
		t.Fatalf("round 2 status %d %s", rec2.Code, rec2.Body.String())
	}
	if !strings.Contains(rec2.Body.String(), "partial-then-full") || !strings.Contains(rec2.Body.String(), `"stop_reason":"end_turn"`) {
		t.Fatalf("round 2 client stream must be the complete answer:\n%s", rec2.Body.String())
	}
	<-evCh

	bodies := up.snapshot()
	if len(bodies) != 2 || bodies[0] != bodies[1] {
		t.Fatalf("retry must resend identical request bytes (%d upstream requests)", len(bodies))
	}
	if len(evs) != 2 {
		t.Fatalf("%d analytics events, want exactly 2", len(evs))
	}
	if evs[0].EventType != "request.failed" || evs[0].TokensIn != 3 || evs[0].TokensOut != 2 {
		t.Fatalf("round 1 event %+v, want failed partial 3/2", evs[0])
	}
	if evs[1].EventType != "request.completed" || evs[1].TokensIn != 3 || evs[1].TokensOut != 9 {
		t.Fatalf("round 2 event %+v, want completed full 3/9", evs[1])
	}
}

func readRequestBody(r *http.Request) []byte {
	raw, _ := io.ReadAll(r.Body)
	return raw
}
