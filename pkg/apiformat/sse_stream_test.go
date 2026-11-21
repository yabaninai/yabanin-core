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
// limit tests can prove the line reader stops reading the moment the
// running total crosses the limit instead of draining to the newline.
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

// TestSSELineReader_FailsFastOnLimitWithoutDraining: an oversized line is
// failed as soon as the running total crosses the limit — including when
// the crossing happens inside one read fragment before any newline —
// and the remainder of the line is NOT read (the caller's deferred body
// close aborts the upstream connection).
func TestSSELineReader_FailsFastOnLimitWithoutDraining(t *testing.T) {
	huge := "data: " + strings.Repeat("x", 300*1024) // one fragment > limit
	rest := "\ndata: after\n\n"
	r := &countingReader{data: huge + rest}
	lr := NewSSELineReader(bufio.NewReaderSize(r, 64*1024), 8192)

	_, err := lr.ReadLine()
	if !errors.Is(err, ErrSSELineLimit) {
		t.Fatalf("want ErrSSELineLimit, got %v", err)
	}
	// The reader may have delivered at most one bufio buffer's worth past
	// the first Read — never the whole line plus its newline.
	if r.read > 64*1024 {
		t.Fatalf("reader read %d bytes past the limit; it must fail fast without draining to the newline", r.read-64*1024)
	}
	if r.read >= len(huge) {
		t.Fatalf("reader consumed the oversized line (%d of %d bytes read)", r.read, len(huge))
	}
}

// TestSSELineReader_ExactAndPartialLines pins the healthy contract: complete
// lines come back byte-identical with their terminator, CRLF included, and
// an EOF mid-line returns the unterminated partial with io.EOF for the
// caller to withhold — after every already-completed line was delivered.
func TestSSELineReader_ExactAndPartialLines(t *testing.T) {
	lr := NewSSELineReader(bufio.NewReader(strings.NewReader("data: a\n\r\ndata: cut")), 1<<20)
	line, err := lr.ReadLine()
	if err != nil || string(line) != "data: a\n" {
		t.Fatalf("first line: %q, %v", line, err)
	}
	line, err = lr.ReadLine()
	if err != nil || string(line) != "\r\n" {
		t.Fatalf("crlf line: %q, %v", line, err)
	}
	line, err = lr.ReadLine()
	if !errors.Is(err, io.EOF) || string(line) != "data: cut" {
		t.Fatalf("eof partial: %q, %v", line, err)
	}
}

// TestSSELineReader_LoneCRTerminatorDeliveredComplete: a stream whose
// final line ends in a lone CR is a complete line at Flush, not an
// unterminated partial — the relay side then sees a boundary-aligned end.
func TestSSELineReader_LoneCRTerminatorDeliveredComplete(t *testing.T) {
	lr := NewSSELineReader(bufio.NewReader(strings.NewReader("data: a\rdata: b\r")), 1<<20)
	line, err := lr.ReadLine()
	if err != nil || string(line) != "data: a\r" {
		t.Fatalf("cr line: %q, %v", line, err)
	}
	line, err = lr.ReadLine()
	if err != nil || string(line) != "data: b\r" {
		t.Fatalf("trailing cr line must be complete at flush: %q, %v", line, err)
	}
}

// TestSSELineSplitter_Terminators pins the one set of boundary rules every
// framing layer shares: LF, CRLF and lone CR each terminate a line, a CR
// split across chunk boundaries resolves once its successor arrives (as
// LF it pairs, as anything else it terminated alone), and Flush resolves
// a trailing CR as a complete line while any other remainder is the
// unterminated partial.
func TestSSELineSplitter_Terminators(t *testing.T) {
	var s SSELineSplitter
	got := s.Feed([]byte("data: a\ndata: b\r"))
	if len(got) != 1 || string(got[0]) != "data: a\n" {
		t.Fatalf("lf line: %q", got)
	}
	if s.Pending() != len("data: b\r") {
		t.Fatalf("pending after trailing cr: %d", s.Pending())
	}
	// The "\n" completes the CRLF held from the previous chunk.
	got = s.Feed([]byte("\ndata: c"))
	if len(got) != 1 || string(got[0]) != "data: b\r\n" {
		t.Fatalf("crlf resolved across chunks: %q", got)
	}
	// A lone CR followed by content terminates its line alone, and the
	// chunk's own trailing CR stays held unresolved.
	got = s.Feed([]byte("\rdata: d\r"))
	if len(got) != 1 || string(got[0]) != "data: c\r" {
		t.Fatalf("lone cr line: %q", got)
	}
	// Comment lines are classified from their first byte.
	if !SSECommentLine([]byte(": ping\n")) || SSECommentLine([]byte("data: x\n")) || SSECommentLine(nil) {
		t.Fatalf("comment classification")
	}
	// Flush: a trailing CR is a complete line; otherwise the remainder is
	// the unterminated partial.
	lines, partial := s.Flush()
	if len(lines) != 1 || string(lines[0]) != "data: d\r" {
		t.Fatalf("flush trailing-cr line: %q %q", lines, partial)
	}
	if partial != nil {
		t.Fatalf("no partial expected after cr flush, got %q", partial)
	}
	var s2 SSELineSplitter
	s2.Feed([]byte("data: cut"))
	lines, partial = s2.Flush()
	if len(lines) != 0 || string(partial) != "data: cut" {
		t.Fatalf("flush unterminated: %q %q", lines, partial)
	}
}

// TestSSELineSplitter_FragmentedLargeLine feeds one 1 MiB line in 1 KiB
// chunks: the line only completes at its terminator, pending tracks the
// held bytes across the whole run, and the emitted line is byte-identical.
func TestSSELineSplitter_FragmentedLargeLine(t *testing.T) {
	payload := "data: " + strings.Repeat("y", 1<<20) + "\n"
	var s SSELineSplitter
	var assembled []byte
	for i := 0; i < len(payload); i += 1024 {
		end := i + 1024
		if end > len(payload) {
			end = len(payload)
		}
		for _, line := range s.Feed([]byte(payload[i:end])) {
			assembled = append(assembled, line...)
		}
	}
	if s.Pending() != 0 {
		t.Fatalf("pending after terminator: %d", s.Pending())
	}
	if !bytes.Equal(assembled, []byte(payload)) {
		t.Fatalf("fragmented line not reassembled byte-identically (%d of %d bytes)", len(assembled), len(payload))
	}
}

// TestSSEParser_CRSeparatedStream: a CR-only stream dispatches its events
// mid-stream exactly like an LF one — the parser shares the splitter's
// terminator rules instead of accumulating until the stream ends. A held
// trailing CR resolves into a blank separator as soon as the next chunk
// arrives (LF pairs into CRLF, any other byte proves a lone-CR blank —
// both blank), so the {a} event dispatches on feed 1; the stream's final
// blank separator resolves at Flush, which emits the pending {b} event.
func TestSSEParser_CRSeparatedStream(t *testing.T) {
	var p SSEParser
	var events []SSEEvent
	feeds := []string{"event: a\rdata: {\"k\":1}\r", "\revent: b\rdata: 2\r", "\r"}
	want := []int{0, 1, 0}
	for i, chunk := range feeds {
		got := p.Feed([]byte(chunk))
		if len(got) != want[i] {
			t.Fatalf("feed %d emitted %d events, want %d: %+v", i, len(got), want[i], got)
		}
		events = append(events, got...)
	}
	if len(events) != 1 || events[0].Event != "a" || events[0].Data != `{"k":1}` {
		t.Fatalf("cr-separated mid-stream dispatch: %+v", events)
	}
	tail := p.Flush()
	if len(tail) != 1 || tail[0].Event != "b" || tail[0].Data != "2" {
		t.Fatalf("flush must emit the cr-terminated pending event: %+v", tail)
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
		t.Fatalf("decodable multiline event missing only its separator must be salvageable")
	}

	var truncated SSEFrameBuffer
	for _, l := range []string{"data: {\"a\":1,\n", "data: \"b\":2\n"} {
		_, _ = truncated.Add([]byte(l), 1<<20)
	}
	if truncated.Salvageable() {
		t.Fatalf("truncated multiline JSON must not be salvageable")
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

	// CR-terminated buffered lines join through the same probe as LF ones.
	var crLines SSEFrameBuffer
	for _, l := range []string{"event: x\r", "data: {\"a\":1}\r"} {
		_, _ = crLines.Add([]byte(l), 1<<20)
	}
	if !crLines.Salvageable() {
		t.Fatalf("CR-terminated decodable event missing only its separator must be salvageable")
	}
}

// errThenEOFReader delivers one chunk together with a non-EOF error — the
// bytes-plus-error transport shape a bufio layer can surface.
type errThenEOFReader struct {
	data string
	err  error
	done bool
}

func (r *errThenEOFReader) Read(p []byte) (int, error) {
	if len(r.data) > 0 {
		n := copy(p, r.data)
		r.data = r.data[n:]
		return n, nil
	}
	if !r.done {
		r.done = true
		return len(":"), r.err // a byte count > 0 alongside the error
	}
	return 0, io.EOF
}

// TestSSELineReader_HoldsReadErrorDeliveredWithBytes: when the transport
// returns (n>0, err) the delivered bytes are complete lines, and the
// error survives — it must be returned after the queue drains, not
// dropped by the byte-count fast path.
func TestSSELineReader_HoldsReadErrorDeliveredWithBytes(t *testing.T) {
	r := &errThenEOFReader{data: ": heartbeat\n", err: io.ErrUnexpectedEOF}
	lr := NewSSELineReader(bufio.NewReader(r), 1<<20)

	line, err := lr.ReadLine()
	if err != nil || string(line) != ": heartbeat\n" {
		t.Fatalf("first read must deliver its bytes as a complete line: %q, %v", line, err)
	}
	if _, err := lr.ReadLine(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("the error delivered alongside bytes must be retained, got %v", err)
	}
}

// bytesWithErrReader returns its whole payload in one Read together
// with err — the read shape a transport cut produces when the final
// buffered chunk and the failure arrive together.
type bytesWithErrReader struct {
	data []byte
	err  error
	done bool
}

func (r *bytesWithErrReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	n := copy(p, r.data)
	return n, r.err
}

// TestSSELineReader_ErrorWithBytesKeepsTornTail: when the final chunk
// carries a torn tail together with its error, the partial must surface
// with the error — finalized exactly like a separate error read — or a
// caller would see a boundary-aligned end and salvage a frame the
// upstream was still writing. Both LF and lone-CR terminator forms, and
// standard EOF delivered with bytes, share the same finalization.
func TestSSELineReader_ErrorWithBytesKeepsTornTail(t *testing.T) {
	cases := []struct {
		name     string
		chunk    string
		err      error
		wantLine string
		wantTorn string
	}{
		{"lf cut with unexpected eof", "data: a\ndata: {", io.ErrUnexpectedEOF, "data: a\n", "data: {"},
		{"lf cut with eof", "data: a\ndata: {", io.EOF, "data: a\n", "data: {"},
		{"cr cut with unexpected eof", "data: a\rdata: {", io.ErrUnexpectedEOF, "data: a\r", "data: {"},
		{"boundary aligned with unexpected eof", "data: a\n", io.ErrUnexpectedEOF, "data: a\n", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lr := NewSSELineReader(bufio.NewReader(&bytesWithErrReader{data: []byte(tc.chunk), err: tc.err}), 1<<20)

			line, err := lr.ReadLine()
			if err != nil || string(line) != tc.wantLine {
				t.Fatalf("complete line must be delivered before the error: %q, %v", line, err)
			}
			torn, err := lr.ReadLine()
			if !errors.Is(err, tc.err) || string(torn) != tc.wantTorn {
				t.Fatalf("torn tail must finalize with the error like a separate error read: %q, %v", torn, err)
			}
			// The error latches: the reader is never polled again.
			torn, err = lr.ReadLine()
			if !errors.Is(err, tc.err) || string(torn) != "" {
				t.Fatalf("the latched error must persist without another read: %q, %v", torn, err)
			}
		})
	}
}

// TestSSELineReader_LimitKeepsQueuedPrefix: a line that crosses the
// limit aborts the stream, but lines already accepted — earlier in the
// same chunk or queued by previous reads — are still dispatched before
// the limit error; only the oversized line is lost. A dropped prefix
// would silently discard frames the upstream completed.
func TestSSELineReader_LimitKeepsQueuedPrefix(t *testing.T) {
	t.Run("valid line before oversized line in one chunk", func(t *testing.T) {
		lr := NewSSELineReader(bufio.NewReader(strings.NewReader(":ok\n:oversized\n")), 4)
		line, err := lr.ReadLine()
		if err != nil || string(line) != ":ok\n" {
			t.Fatalf("valid prefix lost to the limit abort: %q, %v", line, err)
		}
		if _, err := lr.ReadLine(); !errors.Is(err, ErrSSELineLimit) {
			t.Fatalf("missing size rejection: %v", err)
		}
	})
	t.Run("prefix queued by an earlier read", func(t *testing.T) {
		lr := NewSSELineReader(bufio.NewReader(io.MultiReader(
			strings.NewReader(":ok\n"),
			strings.NewReader(":oversized\n"),
		)), 4)
		line, err := lr.ReadLine()
		if err != nil || string(line) != ":ok\n" {
			t.Fatalf("queued prefix lost to the limit abort: %q, %v", line, err)
		}
		if _, err := lr.ReadLine(); !errors.Is(err, ErrSSELineLimit) {
			t.Fatalf("missing size rejection: %v", err)
		}
	})
}

// TestSSELineReader_BoundedCompleteLine: a line that arrives complete in
// one chunk — comment included — is bounded by the same content limit as
// a fragmented one; size, not termination state, defines the failure.
func TestSSELineReader_BoundedCompleteLine(t *testing.T) {
	lr := NewSSELineReader(bufio.NewReader(strings.NewReader(":123456789\n")), 5)
	if _, err := lr.ReadLine(); !errors.Is(err, ErrSSELineLimit) {
		t.Fatalf("single-chunk complete comment over the limit must fail, got %v", err)
	}
}

// BenchmarkSSELineSplitterFragmented measures reassembling a 1 MiB line
// fed in 1 KiB chunks — the worst case for the carried-over scanning
// state, since every chunk resumes mid-line.
func BenchmarkSSELineSplitterFragmented(b *testing.B) {
	payload := []byte("data: " + strings.Repeat("y", 1<<20) + "\n")
	var out [][]byte
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var s SSELineSplitter
		for j := 0; j < len(payload); j += 1024 {
			end := j + 1024
			if end > len(payload) {
				end = len(payload)
			}
			out = append(out, s.Feed(payload[j:end])...)
		}
	}
	_ = out
}
