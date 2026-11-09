package apiformat

import (
	"bytes"
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
