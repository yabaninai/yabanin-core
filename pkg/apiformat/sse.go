package apiformat

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// SSEEvent is one Server-Sent Event. Data lines are joined with "\n".
type SSEEvent struct {
	Event string
	Data  string
}

// SSELineSplitter incrementally splits a byte stream into complete SSE
// lines under the grammar's three line terminators: LF, CRLF, and a lone
// CR. This is the one set of boundary rules for every framing layer —
// line relays, frame batching, and the event parser all split through
// it, so a CR-terminated upstream stream is framed identically to an LF
// one. A trailing CR at a chunk boundary is held unresolved until the
// next chunk (or Flush) decides CRLF versus a lone-CR terminator.
// Scanning is linear in the bytes fed: each Feed examines only the new
// chunk plus at most one carried-over CR.
type SSELineSplitter struct {
	buf     []byte // bytes of the current incomplete line; no resolved terminator inside
	scanned int    // prefix of buf already scanned for terminators
}

// Feed pushes one chunk and returns the lines it completed, each
// including its terminator, in order. Returned slices alias internal
// storage; they stay valid until the next Feed, which is long enough for
// a caller to copy or write them out.
func (s *SSELineSplitter) Feed(chunk []byte) [][]byte {
	if len(chunk) == 0 {
		return nil
	}
	combined := append(s.buf, chunk...)
	var lines [][]byte
	start := 0
	i := s.scanned
	for i < len(combined) {
		switch combined[i] {
		case '\n':
			lines = append(lines, combined[start:i+1])
			i++
			start = i
		case '\r':
			if i+1 == len(combined) {
				// Trailing CR: CRLF or lone CR — the next chunk decides.
				i++
				continue
			}
			end := i + 1
			if combined[i+1] == '\n' {
				end++
			}
			lines = append(lines, combined[start:end])
			i = end
			start = i
		default:
			i++
		}
	}
	s.buf = combined[start:]
	s.scanned = len(s.buf)
	if n := len(s.buf); n > 0 && s.buf[n-1] == '\r' {
		s.scanned = n - 1 // rescan the unresolved CR with its successor
	}
	return lines
}

// Flush ends the stream: a pending line whose last byte is a CR is a
// complete CR-terminated line; any other remainder is the unterminated
// trailing partial, which can never become a line on its own. Flush is
// terminal — the splitter holds nothing afterwards, so repeated calls
// (a parser double-flush, a retry path) cannot re-emit anything.
func (s *SSELineSplitter) Flush() (lines [][]byte, partial []byte) {
	if n := len(s.buf); n > 0 && s.buf[n-1] == '\r' {
		lines = append(lines, s.buf)
		s.buf = nil
		s.scanned = 0
		return lines, nil
	}
	partial = s.buf
	s.buf = nil
	s.scanned = 0
	return nil, partial
}

// Pending reports the bytes held for the current incomplete line.
func (s *SSELineSplitter) Pending() int {
	return len(s.buf)
}

// SSECommentLine reports whether line is an SSE comment (first byte
// ':'). Comments carry no event fields, so relays forward them as they
// arrive instead of frame-batching them: keepalive heartbeats keep the
// downstream connection warm and never grow the frame buffer.
func SSECommentLine(line []byte) bool {
	return len(line) > 0 && line[0] == ':'
}

// sseLineContent strips one line terminator ('\n', '\r\n', or a lone
// '\r') from a complete line, returning the field content.
func sseLineContent(line []byte) []byte {
	if bytes.HasSuffix(line, []byte("\n")) {
		line = line[:len(line)-1]
	}
	if bytes.HasSuffix(line, []byte("\r")) {
		line = line[:len(line)-1]
	}
	return line
}

// cutSSERest splits rest at its first line terminator, returning the
// line (terminator included) and the remainder. A whole-slice line is
// returned when rest carries no terminator.
func cutSSERest(rest []byte) (line, tail []byte) {
	i := 0
	for i < len(rest) && rest[i] != '\n' && rest[i] != '\r' {
		i++
	}
	if i == len(rest) {
		return rest, nil
	}
	if rest[i] == '\n' {
		return rest[:i+1], rest[i+1:]
	}
	if i+1 < len(rest) && rest[i+1] == '\n' {
		return rest[:i+2], rest[i+2:]
	}
	return rest[:i+1], rest[i+1:]
}

// SSEParser accepts arbitrary byte chunks and yields complete events.
// Line splitting shares SSELineSplitter's terminator rules, so CR-only
// streams dispatch events mid-stream exactly like LF ones. A trailing
// event that never received its blank line is emitted by Flush.
type SSEParser struct {
	split   SSELineSplitter
	event   string
	data    []string
	pending bool
}

// Feed appends b and returns every event completed by a blank line in this chunk.
func (p *SSEParser) Feed(b []byte) []SSEEvent {
	if len(b) == 0 {
		return nil
	}
	var out []SSEEvent
	for _, line := range p.split.Feed(b) {
		if ev, ok := p.pushLine(string(sseLineContent(line))); ok {
			out = append(out, ev)
		}
	}
	return out
}

// Flush emits a trailing event that was not terminated by a blank line.
func (p *SSEParser) Flush() []SSEEvent {
	var out []SSEEvent
	lines, partial := p.split.Flush()
	for _, line := range lines {
		if ev, ok := p.pushLine(string(sseLineContent(line))); ok {
			out = append(out, ev)
		}
	}
	if len(partial) > 0 {
		if ev, ok := p.pushLine(string(sseLineContent(partial))); ok {
			out = append(out, ev)
		}
	}
	if p.pending {
		out = append(out, p.take())
	}
	return out
}

// ParseSSE parses a complete SSE byte slice, including a trailing unterminated event.
func ParseSSE(all []byte) []SSEEvent {
	var p SSEParser
	out := p.Feed(all)
	return append(out, p.Flush()...)
}

// WriteSSEEvent writes "event: X\ndata: Y\n\n". Data containing newlines is
// split into consecutive data lines so ParseSSE reconstructs the same payload.
func WriteSSEEvent(w io.Writer, event string, data []byte) error {
	if event != "" {
		if _, err := io.WriteString(w, "event: "+event+"\n"); err != nil {
			return err
		}
	}
	if len(data) == 0 {
		_, err := io.WriteString(w, "data:\n\n")
		return err
	}
	for _, part := range bytes.Split(data, []byte("\n")) {
		if _, err := io.WriteString(w, "data: "); err != nil {
			return err
		}
		if _, err := w.Write(part); err != nil {
			return err
		}
		if _, err := io.WriteString(w, "\n"); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, "\n")
	return err
}

func (p *SSEParser) pushLine(line string) (SSEEvent, bool) {
	if line == "" {
		if !p.pending {
			return SSEEvent{}, false
		}
		return p.take(), true
	}
	if strings.HasPrefix(line, ":") {
		return SSEEvent{}, false
	}
	name, value, ok := strings.Cut(line, ":")
	if !ok {
		value = ""
	} else if strings.HasPrefix(value, " ") {
		value = value[1:]
	}
	switch name {
	case "event":
		p.event = value
		p.pending = true
	case "data":
		p.data = append(p.data, value)
		p.pending = true
	default:
		// id and retry are ignored; they do not start an event by themselves.
	}
	return SSEEvent{}, false
}

func (p *SSEParser) take() SSEEvent {
	ev := SSEEvent{Event: p.event, Data: strings.Join(p.data, "\n")}
	p.event = ""
	p.data = nil
	p.pending = false
	return ev
}

// SSEStreamLineLimit bounds the per-line and per-frame buffering of the
// SSE relays (chat re-serialization, native messages/responses and the
// realtime write path). Upstreams are trusted for correctness, not for
// size discipline: a pathological or hostile provider can send a single
// multi-megabyte SSE line, and an unbounded read would buffer it (and
// every such line) in gateway memory. 8 MiB is far above any legitimate
// frame (values ride JSON events, not bulk payloads) and far below any
// real request budget. Relays with their own tighter bound pass it to
// the line reader explicitly.
const SSEStreamLineLimit = 8 << 20

// ErrSSELineLimit marks an upstream line that exceeded its buffering
// limit. It is never shown to clients verbatim: the relays drop the
// partial bytes and treat it as an upstream drain failure so the terminal
// frames close the client stream instead.
var ErrSSELineLimit = errors.New("upstream SSE line exceeds the line limit")

// SSELineReader turns a byte stream into complete SSE lines under
// SSELineSplitter's terminator rules, bounded per line. Lines that
// completed before the stream ended are delivered first (each with a
// nil error); the call after the last line returns the unterminated
// trailing partial together with the read error — EOF for a clean end —
// so a caller can tell a boundary-aligned end (empty partial) from a
// cut mid-line (non-empty partial). A read error that arrived alongside
// final bytes finalizes identically to one that arrived alone: the
// chunk's bytes are fed through the splitter first, so a torn tail cut
// mid-line is still reported as a partial instead of vanishing with the
// error — and the reader is never polled again after it errored. The
// limit is enforced
// on the running line total and on every completed line — including one
// that began and ended inside a single chunk — without reading ahead to
// the terminator: the unread remainder of an oversized line is
// abandoned, because the caller's deferred body close aborts the
// upstream connection.
type SSELineReader struct {
	r       *bufio.Reader
	limit   int
	split   SSELineSplitter
	queue   [][]byte
	partial []byte // unterminated tail, set once the stream ended
	rerr    error  // the read error that ended the stream; latched, never polled again
	scratch [32 * 1024]byte
}

// NewSSELineReader bounds each line of r to limit bytes.
func NewSSELineReader(r *bufio.Reader, limit int) *SSELineReader {
	return &SSELineReader{r: r, limit: limit}
}

// Buffered reports whether already-read bytes still await processing:
// queued complete lines, an unterminated partial from an ended stream,
// or bytes sitting in the bufio buffer. A relay whose client write
// failed uses it to keep parsing what was already paid for without
// issuing another provider read — a streaming upstream on a live
// connection would otherwise keep doing paid work for a client that is
// gone.
func (l *SSELineReader) Buffered() bool {
	return len(l.queue) > 0 || l.partial != nil || l.r.Buffered() > 0
}

// ReadLine returns the next complete line (terminator included), or the
// trailing partial with the error that ended the stream.
func (l *SSELineReader) ReadLine() ([]byte, error) {
	for {
		if n := len(l.queue); n > 0 {
			line := l.queue[0]
			l.queue = l.queue[1:]
			return line, nil
		}
		if l.rerr != nil {
			line := l.partial
			l.partial = nil
			return line, l.rerr
		}
		n, err := l.r.Read(l.scratch[:])
		if n > 0 {
			over := false
			for _, line := range l.split.Feed(l.scratch[:n]) {
				if len(sseLineContent(line)) > l.limit {
					// A line that completed inside this chunk never shows
					// up in Pending: check it here too.
					over = true
					break
				}
				l.queue = append(l.queue, line)
			}
			switch {
			case over || l.split.Pending() > l.limit:
				// Bounded memory: the oversized line is abandoned, but
				// lines already queued before it stay — they were
				// accepted, and are dispatched before the limit error.
				// No partial is salvageable from an oversized line.
				l.partial = nil
				l.rerr = ErrSSELineLimit
			case err != nil:
				// The final chunk carried bytes with its error: finalize
				// exactly like a separate error read — the chunk's
				// complete lines first, then the torn tail with the
				// error — and never poll the reader again. EOF with
				// bytes is the same shape as EOF after bytes: a clean
				// boundary-aligned end keeps the partial empty.
				lines, partial := l.split.Flush()
				l.queue = append(l.queue, lines...)
				l.partial = partial
				l.rerr = err
			}
			continue
		}
		if err != nil {
			lines, partial := l.split.Flush()
			l.queue = append(l.queue, lines...)
			l.partial = partial
			l.rerr = err
			continue
		}
	}
}

// SSEFrameBuffer batches complete upstream SSE lines into whole client
// frames. A consumer decodes one event only once its blank separator has
// arrived — the payload is the data lines joined with LF — so lines of an
// unterminated frame are held back (bounded memory) instead of being
// forwarded eagerly. On an upstream break the held frame is dispatched
// only when the caller has established a line-boundary end (no
// unterminated partial followed it) AND the frame is a complete event
// missing just its separator: it must carry data whose LF-joined payload
// is decodable JSON (or the [DONE] sentinel). A frame cut mid-event —
// multiline data missing its tail, a lone event-name line, or any frame
// whose cut fell inside a continuing field — is dropped, so the terminal
// frames compose at an event boundary and event-by-event SDK consumers
// never receive a truncated or data-less event. Comment-only frames
// carry no event and are always dropped when unterminated. The buffer
// holds one copy of the frame bytes; the salvage probe recomputes the
// joined data payload on demand instead of retaining a second copy.
type SSEFrameBuffer struct {
	buf []byte // complete lines (terminators included) of the current frame
}

// Add buffers one complete line (terminator included, verbatim — CRLF
// and CR upstreams stay byte-identical). blank reports the line was a
// frame separator: the caller must flush the frame then. The separator
// line itself is not buffered — the caller composes it onto the flushed
// frame so the stream stays byte-identical. The buffering bound is
// enforced BEFORE appending: when the frame would cross limit nothing is
// buffered and overflow is reported — the caller fails the stream and
// salvages or drops the held frame per the break rules, so held memory
// never exceeds the limit by more than one line already accepted.
// Comment lines (first byte ':') are buffered verbatim like any other
// line, but never count as data for the salvage probe.
func (f *SSEFrameBuffer) Add(line []byte, limit int) (blank, overflow bool) {
	if len(f.buf)+len(line) > limit {
		return false, true
	}
	content := sseLineContent(line)
	if len(content) == 0 {
		return true, false
	}
	f.buf = append(f.buf, line...)
	return false, false
}

// Take returns the buffered frame bytes and resets the buffer.
func (f *SSEFrameBuffer) Take() []byte {
	out := f.buf
	f.buf = nil
	return out
}

// Salvageable reports whether the held incomplete frame is a decodable
// event missing only its separator: at least one data line whose joined
// payload is valid JSON, or the [DONE] terminator.
func (f *SSEFrameBuffer) Salvageable() bool {
	var data []byte
	hasData := false
	rest := f.buf
	for len(rest) > 0 {
		line, tail := cutSSERest(rest)
		rest = tail
		content := sseLineContent(line)
		if len(content) == 0 || content[0] == ':' {
			continue
		}
		if payload, ok := bytes.CutPrefix(content, []byte("data:")); ok {
			payload = bytes.TrimPrefix(payload, []byte(" "))
			if hasData {
				data = append(data, '\n')
			}
			data = append(data, payload...)
			hasData = true
		}
	}
	return hasData && (string(data) == "[DONE]" || json.Valid(data))
}
