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

// SSEParser accepts arbitrary byte chunks and yields complete events.
// A trailing event that never received its blank line is emitted by Flush.
type SSEParser struct {
	buf     []byte
	event   string
	data    []string
	pending bool
}

// Feed appends b and returns every event completed by a blank line in this chunk.
func (p *SSEParser) Feed(b []byte) []SSEEvent {
	if len(b) == 0 {
		return nil
	}
	p.buf = append(p.buf, b...)
	var out []SSEEvent
	for {
		nl := bytes.IndexByte(p.buf, '\n')
		if nl < 0 {
			return out
		}
		line := p.buf[:nl]
		p.buf = p.buf[nl+1:]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if ev, ok := p.pushLine(string(line)); ok {
			out = append(out, ev)
		}
	}
}

// Flush emits a trailing event that was not terminated by a blank line.
func (p *SSEParser) Flush() []SSEEvent {
	var out []SSEEvent
	if len(p.buf) > 0 {
		line := p.buf
		if line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		p.buf = nil
		if ev, ok := p.pushLine(string(line)); ok {
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
// ReadSSELine explicitly.
const SSEStreamLineLimit = 8 << 20

// ErrSSELineLimit marks an upstream line that exceeded its buffering
// limit. It is never shown to clients verbatim: the relays drop the
// partial bytes and treat it as an upstream drain failure so the terminal
// frames close the client stream instead.
var ErrSSELineLimit = errors.New("upstream SSE line exceeds the line limit")

// ReadSSELine reads one upstream line, byte-identical including the
// terminating '\n' when present. The running total is checked after every
// fragment — including the final one before a newline or EOF — so a line
// is failed as soon as it crosses limit, without reading ahead to the
// terminator: the unread remainder of an oversized line is simply
// abandoned, because the caller's deferred body close aborts the upstream
// connection. On EOF mid-line the unterminated partial is returned with
// the error — callers withhold it rather than dispatch a truncated event.
func ReadSSELine(r *bufio.Reader, limit int) ([]byte, error) {
	var line []byte
	for {
		frag, err := r.ReadSlice('\n')
		line = append(line, frag...)
		if len(line) > limit {
			return nil, ErrSSELineLimit
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return line, err
	}
}

// sseLineContent strips one line terminator ('\n', or '\r' of a CRLF
// pair) from a complete line, returning the field content.
func sseLineContent(line []byte) []byte {
	if bytes.HasSuffix(line, []byte("\n")) {
		line = line[:len(line)-1]
	}
	if bytes.HasSuffix(line, []byte("\r")) {
		line = line[:len(line)-1]
	}
	return line
}

// SSEFrameBuffer batches complete upstream SSE lines into whole client
// frames. A consumer decodes one event only once its blank separator has
// arrived — the payload is the data lines joined with LF — so lines of an
// unterminated frame are held back (bounded memory) instead of being
// forwarded eagerly. On an upstream break the held frame is dispatched
// only when it is a complete event missing just the separator: it must
// carry data whose LF-joined payload is decodable JSON (or the [DONE]
// sentinel). A frame cut mid-event — multiline data missing its tail, a
// lone event-name line — is dropped, so the terminal frames compose at an
// event boundary and event-by-event SDK consumers never receive a
// truncated or data-less event. Comment-only frames carry no event and
// are always dropped when unterminated.
type SSEFrameBuffer struct {
	buf     []byte // complete lines (terminators included) of the current frame
	data    []byte // data-line payloads joined with LF, for the salvage probe
	hasData bool
}

// Add buffers one complete line (terminator included, verbatim — CRLF
// upstreams stay CRLF). blank reports the line was a frame separator: the
// caller must flush the frame then. The separator line itself is not
// buffered — the caller composes it onto the flushed frame so the stream
// stays byte-identical. The buffering bound is enforced BEFORE appending:
// when the frame would cross limit nothing is buffered and overflow is
// reported — the caller fails the stream and salvages or drops the held
// frame per the break rules, so held memory never exceeds the limit by
// more than one line already accepted. Comment lines (first byte ':') are
// recognized by that first byte alone and carry no data.
func (f *SSEFrameBuffer) Add(line []byte, limit int) (blank, overflow bool) {
	if len(f.buf)+len(line) > limit {
		return false, true
	}
	content := sseLineContent(line)
	if len(content) == 0 {
		return true, false
	}
	f.buf = append(f.buf, line...)
	if content[0] == ':' {
		// Comment line (SSE keepalive): buffered verbatim like any other
		// line, but it never marks the frame as carrying data.
		return false, false
	}
	if payload, ok := bytes.CutPrefix(content, []byte("data:")); ok {
		payload = bytes.TrimPrefix(payload, []byte(" "))
		if f.hasData {
			f.data = append(f.data, '\n')
		}
		f.data = append(f.data, payload...)
		f.hasData = true
	}
	return false, false
}

// Take returns the buffered frame bytes and resets the buffer.
func (f *SSEFrameBuffer) Take() []byte {
	out := f.buf
	f.buf = nil
	f.data = nil
	f.hasData = false
	return out
}

// Salvageable reports whether the held incomplete frame is a decodable
// event missing only its separator: at least one data line whose joined
// payload is valid JSON, or the [DONE] terminator.
func (f *SSEFrameBuffer) Salvageable() bool {
	return f.hasData && (string(f.data) == "[DONE]" || json.Valid(f.data))
}
