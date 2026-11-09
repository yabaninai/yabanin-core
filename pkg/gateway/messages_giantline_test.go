package cli

// N07-P02-T10: giant-line refusal on the native /v1/messages SSE relay.
// The upstream is trusted for correctness, not for size discipline: a
// pathological or hostile upstream can send a single multi-megabyte SSE
// line. The relay must bound its per-line buffering (8 MiB), drop the
// oversized line, stop relaying, and let the T03 synthesis close the
// client stream (open content_block_stop + one terminal error frame,
// message_stop never fabricated) while the caller's deferred upstream body
// close aborts the provider connection. Billing keeps the usage declared
// BEFORE the dropped line (D1: request.completed with partial usage); the
// tail frames after the giant line are never parsed, so their usage is
// never counted.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
)

func TestMessagesNative_GiantLineRefused(t *testing.T) {
	const giantLen = 9 << 20 // 9 MiB single SSE data line, above the 8 MiB cap
	giant := strings.Repeat("a", giantLen)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl, _ := w.(http.Flusher)
		_, _ = w.Write([]byte("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":7,\"output_tokens\":3}}}\n\n"))
		_, _ = w.Write([]byte("event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\"}}\n\n"))
		_, _ = w.Write([]byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"abc\"}}\n\n"))
		if fl != nil {
			fl.Flush()
		}
		_, _ = w.Write([]byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"" + giant + "ZZOVERFLOWZZ\"}}\n\n"))
		// Proper tail: the fix must never relay or parse these.
		_, _ = w.Write([]byte("event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n"))
		_, _ = w.Write([]byte("event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":9}}\n\n"))
		_, _ = w.Write([]byte("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"))
		if fl != nil {
			fl.Flush()
		}
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

	rec := postMessages(t, gw, `{"model":"claude-3-5-sonnet","max_tokens":16,"stream":true,"messages":[{"role":"user","content":"Hi"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()

	// The oversized line is dropped whole: neither the payload nor the
	// proper tail after it may reach the client.
	if strings.Contains(body, "ZZOVERFLOWZZ") {
		t.Fatalf("oversized upstream line was relayed to the client (len %d)", len(body))
	}
	if len(body) > 2<<20 {
		t.Fatalf("client stream grew to %d bytes; per-line cap not enforced", len(body))
	}
	if strings.Contains(body, "message_stop") {
		t.Fatalf("tail frames after the dropped line must not be relayed (stream len %d)", len(body))
	}
	// T03 synthesis closes the stream: open block 0 terminated, one error frame.
	if !strings.Contains(body, `"type":"content_block_stop"`) || !strings.Contains(body, `"type":"error"`) || !strings.Contains(body, "stream interrupted") {
		t.Fatalf("synthesized stream close missing (stream len %d, tail %q)", len(body), tailOf(body, 400))
	}

	// Ledger: exactly one terminal event; billing keeps the usage declared
	// before the dropped line (7 in / 3 out), D1 native classification.
	if len(evs) != 1 {
		t.Fatalf("%d analytics events, want exactly 1: %+v", len(evs), evs)
	}
	if evs[0].EventType != "request.completed" {
		t.Fatalf("event %+v, want request.completed", evs[0])
	}
	if evs[0].TokensIn != 7 || evs[0].TokensOut != 3 {
		t.Fatalf("billing %+v, want in 7 out 3 (tail usage after the dropped line must not count)", evs[0])
	}
	<-evCh
}

func tailOf(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
