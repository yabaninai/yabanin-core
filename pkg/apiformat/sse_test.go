package apiformat

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestSSEParser_SplitAcrossChunks(t *testing.T) {
	const raw = "event: message_start\r\n" +
		": keep-alive\r\n" +
		"data: {\"a\":1}\r\n" +
		"data: {\"b\":2}\r\n" +
		"\r\n"
	var p SSEParser
	var got []SSEEvent
	for i := 0; i < len(raw); i++ {
		got = append(got, p.Feed([]byte{raw[i]})...)
	}
	got = append(got, p.Flush()...)
	if len(got) != 1 {
		t.Fatalf("events = %d, want 1 (%+v)", len(got), got)
	}
	if got[0].Event != "message_start" {
		t.Fatalf("event = %q", got[0].Event)
	}
	if got[0].Data != "{\"a\":1}\n{\"b\":2}" {
		t.Fatalf("data = %q", got[0].Data)
	}
}

func TestSSEParser_FlushWithoutBlankLine(t *testing.T) {
	var p SSEParser
	if ev := p.Feed([]byte("event: ping\ndata: {}")); len(ev) != 0 {
		t.Fatalf("feed emitted early: %+v", ev)
	}
	got := p.Flush()
	if len(got) != 1 || got[0].Event != "ping" || got[0].Data != "{}" {
		t.Fatalf("flush = %+v", got)
	}
	if extra := p.Flush(); len(extra) != 0 {
		t.Fatalf("second flush = %+v", extra)
	}
}

func TestSSEParser_EmptyAndCommentOnly(t *testing.T) {
	var p SSEParser
	if ev := p.Feed(nil); ev != nil {
		t.Fatalf("nil feed = %+v", ev)
	}
	if ev := p.Feed([]byte(": hi\n\n")); len(ev) != 0 {
		t.Fatalf("comment emitted %+v", ev)
	}
}

func TestParseSSE_NoSpaceAfterColon(t *testing.T) {
	got := ParseSSE([]byte("event:done\ndata:ok\n\n"))
	if len(got) != 1 || got[0].Event != "done" || got[0].Data != "ok" {
		t.Fatalf("got %+v", got)
	}
}

// TestSSEParser_UTF8SurvivesAnyChunkSplit pins the chat wire boundary
// (N03-P01-T03): a multi-byte rune split across network chunks must never
// tear — the parser buffers bytes until the line boundary. For EVERY split
// offset the chunked feed must reconstruct exactly the events of a
// single-shot parse, including the [DONE] terminator.
func TestSSEParser_UTF8SurvivesAnyChunkSplit(t *testing.T) {
	const reasoning = "data: {\"choices\":[{\"index\":0,\"delta\":{\"reasoning_content\":\"думаю…\"}}]}\n\n"
	const content = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"привет 🚀 日本語\"}}]}\n\n"
	const done = "data: [DONE]\n\n"
	raw := reasoning + content + done
	want := ParseSSE([]byte(raw))
	if len(want) != 3 || want[1].Data == "" || want[2].Data != "[DONE]" {
		t.Fatalf("single-shot parse = %+v", want)
	}
	for split := 0; split <= len(raw); split++ {
		var p SSEParser
		got := append(p.Feed([]byte(raw[:split])), p.Feed([]byte(raw[split:]))...)
		got = append(got, p.Flush()...)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("split at %d: events %+v, want %+v", split, got, want)
		}
	}
}

// TestSSEParser_UnspacedDONEAndCRLF pins two boundary forms together: the
// compact "data:[DONE]" (no separating space) and CRLF line endings.
func TestSSEParser_UnspacedDONEAndCRLF(t *testing.T) {
	got := ParseSSE([]byte("data: {\"a\":1}\r\n\r\ndata:[DONE]\r\n\r\n"))
	if len(got) != 2 || got[0].Data != "{\"a\":1}" || got[1].Data != "[DONE]" {
		t.Fatalf("got %+v", got)
	}
}

func TestWriteSSEEvent_RoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSSEEvent(&buf, "response.created", []byte("line1\nline2")); err != nil {
		t.Fatal(err)
	}
	got := ParseSSE(buf.Bytes())
	if len(got) != 1 || got[0].Event != "response.created" || got[0].Data != "line1\nline2" {
		t.Fatalf("round trip %+v from %q", got, buf.String())
	}
}

func TestWriteSSEEvent_EmptyData(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSSEEvent(&buf, "", nil); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "data:\n\n" {
		t.Fatalf("body = %q", buf.String())
	}
}

type failWriter struct {
	after int
}

func (f *failWriter) Write(p []byte) (int, error) {
	if f.after == 0 {
		return 0, io.ErrClosedPipe
	}
	f.after--
	return len(p), nil
}

func TestWriteSSEEvent_WriteError(t *testing.T) {
	err := WriteSSEEvent(&failWriter{}, "e", []byte("x"))
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("err = %v", err)
	}
	err = WriteSSEEvent(&failWriter{after: 1}, "e", []byte("x"))
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("data write err = %v", err)
	}
	if !strings.Contains(io.ErrClosedPipe.Error(), "closed") {
		t.Fatal("sentinel changed")
	}
}
