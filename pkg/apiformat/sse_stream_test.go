package apiformat

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// countingReader records how many bytes were ever delivered, so the
// limit tests can prove ReadSSELine stops reading the moment the running
// total crosses the limit instead of draining to the newline.
type countingReader struct {
	data string
	pos  int
	read int
}

func (r *countingReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	r.read += n
	return n, nil
}

// TestReadSSELine_FailsFastOnLimitWithoutDraining: an oversized line is
// failed as soon as the running total crosses the limit — including when
// the crossing happens inside one ReadSlice fragment before any newline —
// and the remainder of the line is NOT read (the caller's deferred body
// close aborts the upstream connection).
func TestReadSSELine_FailsFastOnLimitWithoutDraining(t *testing.T) {
	huge := "data: " + strings.Repeat("x", 300*1024) // one fragment > limit
	rest := "\ndata: after\n\n"
	r := &countingReader{data: huge + rest}
	br := bufio.NewReaderSize(r, 64*1024)

	_, err := ReadSSELine(br, 8192)
	if !errors.Is(err, ErrSSELineLimit) {
		t.Fatalf("want ErrSSELineLimit, got %v", err)
	}
	// The reader may have delivered at most one bufio buffer's worth past
	// the first Read — never the whole line plus its newline.
	if r.read > 64*1024 {
		t.Fatalf("ReadSSELine read %d bytes past the limit; it must fail fast without draining to the newline", r.read-64*1024)
	}
	if r.read >= len(huge) {
		t.Fatalf("ReadSSELine consumed the oversized line (%d of %d bytes read)", r.read, len(huge))
	}
}

// TestReadSSELine_ExactAndPartialLines pins the healthy contract: complete
// lines come back byte-identical with their terminator, CRLF included,
// and an EOF mid-line returns the unterminated partial with io.EOF for
// the caller to withhold.
func TestReadSSELine_ExactAndPartialLines(t *testing.T) {
	br := bufio.NewReader(strings.NewReader("data: a\n\r\ndata: cut"))
	line, err := ReadSSELine(br, 1<<20)
	if err != nil || string(line) != "data: a\n" {
		t.Fatalf("first line: %q, %v", line, err)
	}
	line, err = ReadSSELine(br, 1<<20)
	if err != nil || string(line) != "\r\n" {
		t.Fatalf("crlf line: %q, %v", line, err)
	}
	line, err = ReadSSELine(br, 1<<20)
	if !errors.Is(err, io.EOF) || string(line) != "data: cut" {
		t.Fatalf("eof partial: %q, %v", line, err)
	}
}

// TestSSEFrameBuffer_BoundsBeforeAppend: Add refuses a line that would
// cross the limit without buffering any of it — held memory stays within
// the bound plus at most one already-accepted line.
func TestSSEFrameBuffer_BoundsBeforeAppend(t *testing.T) {
	var f SSEFrameBuffer
	big := bytes.Repeat([]byte("a"), 600)
	if blank, overflow := f.Add(append(append([]byte("data: "), big...), '\n'), 512); blank || !overflow {
		t.Fatalf("oversized line: blank=%v overflow=%v, want false/true", blank, overflow)
	}
	if len(f.buf) != 0 {
		t.Fatalf("oversized line must not be buffered, got %d bytes", len(f.buf))
	}
	// A line within the limit is buffered verbatim, CRLF included.
	line := []byte("data: {\"k\":1}\r\n")
	if blank, overflow := f.Add(line, 512); blank || overflow {
		t.Fatalf("in-limit line: blank=%v overflow=%v", blank, overflow)
	}
	if got := f.Take(); !bytes.Equal(got, line) {
		t.Fatalf("CRLF line not buffered verbatim: %q", got)
	}
}

// TestSSEFrameBuffer_SalvageRules pins the break probe: a decodable
// event missing just its separator is salvageable (multiline data joined
// with LF included), while comment-only, event-only and truncated-JSON
// frames are not.
func TestSSEFrameBuffer_SalvageRules(t *testing.T) {
	var multiline SSEFrameBuffer
	for _, l := range []string{"event: x\n", "data: {\"a\":1,\n", "data: \"b\":2}\n"} {
		if blank, overflow := multiline.Add([]byte(l), 1<<20); blank || overflow {
			t.Fatalf("add %q: blank=%v overflow=%v", l, blank, overflow)
		}
	}
	if !multiline.Salvageable() {
		t.Fatalf("decodable multiline event missing only its separator must be salvageable, joined=%q", multiline.data)
	}

	var truncated SSEFrameBuffer
	for _, l := range []string{"data: {\"a\":1,\n", "data: \"b\":2\n"} {
		_, _ = truncated.Add([]byte(l), 1<<20)
	}
	if truncated.Salvageable() {
		t.Fatalf("truncated multiline JSON must not be salvageable, joined=%q", truncated.data)
	}

	var commentOnly SSEFrameBuffer
	_, _ = commentOnly.Add([]byte(": keepalive\n"), 1<<20)
	if commentOnly.Salvageable() {
		t.Fatalf("comment-only frame carries no event and must not be salvageable")
	}

	var done SSEFrameBuffer
	_, _ = done.Add([]byte("data: [DONE]\n"), 1<<20)
	if !done.Salvageable() {
		t.Fatalf("[DONE] sentinel must be salvageable")
	}
}
