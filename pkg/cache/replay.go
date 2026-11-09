// Package cache provides semantic cache storage with Redis and pgvector backends.
package cache

import (
	"net/http"
	"time"
)

// SSEChunk represents a single server-sent event frame captured during streaming.
type SSEChunk struct {
	Data    string `json:"data"`
	DelayMS int64  `json:"delay_ms"` // milliseconds since previous chunk
}

// RecordingWriter wraps an http.ResponseWriter to capture SSE frames during streaming.
//
// STREAM-01: the capture is optional and bounded. NewRecordingWriter keeps
// the historical unlimited behavior; NewRecordingWriterCapped enforces a
// retained-memory ceiling — once the cap is crossed the recorder latches an
// overflow state, stops appending whole (never a partial frame: a truncated
// capture must never become a cache entry that replays as if complete) and
// keeps forwarding client bytes untouched. Callers refuse to write a cache
// entry when Overflowed() is true.
type RecordingWriter struct {
	w          http.ResponseWriter
	chunks     []SSEChunk
	lastFlush  time.Time
	flushed    bool
	maxBytes   int
	maxFrames  int
	captured   int
	overflowed bool
}

// NewRecordingWriter creates a new RecordingWriter for the given response writer.
// The capture is unlimited; prefer NewRecordingWriterCapped on request paths.
func NewRecordingWriter(w http.ResponseWriter) *RecordingWriter {
	return &RecordingWriter{
		w:         w,
		lastFlush: time.Now(),
	}
}

// NewRecordingWriterCapped creates a RecordingWriter that retains at most
// maxBytes of captured frames and maxFrames frames; zero disables that
// dimension. Crossing either cap latches the overflow state: the crossing
// frame and everything after are forwarded to the client but not retained.
func NewRecordingWriterCapped(w http.ResponseWriter, maxBytes, maxFrames int) *RecordingWriter {
	return &RecordingWriter{
		w:         w,
		lastFlush: time.Now(),
		maxBytes:  maxBytes,
		maxFrames: maxFrames,
	}
}

// Header returns the underlying ResponseWriter headers.
func (rw *RecordingWriter) Header() http.Header {
	return rw.w.Header()
}

// WriteHeader records the status code and forwards it.
func (rw *RecordingWriter) WriteHeader(code int) {
	rw.w.WriteHeader(code)
}

// Overflowed reports whether the capture crossed its retained-memory or
// frame ceiling (always false for an unlimited recorder). A true result
// means the capture is a prefix of the real stream: cache writers must
// refuse it — a partial replay would masquerade as a complete answer.
func (rw *RecordingWriter) Overflowed() bool {
	return rw.overflowed
}

// Write intercepts each write, captures the SSE frame, calculates delay, then forwards.
// Client bytes always pass through untouched; only the capture is bounded.
func (rw *RecordingWriter) Write(b []byte) (int, error) {
	now := time.Now()
	delay := now.Sub(rw.lastFlush).Milliseconds()
	if delay < 0 {
		delay = 0
	}
	rw.lastFlush = now

	if rw.overflowed ||
		(rw.maxFrames > 0 && len(rw.chunks) >= rw.maxFrames) ||
		(rw.maxBytes > 0 && rw.captured+len(b) > rw.maxBytes) {
		// STREAM-01: latch and stop retaining — whole-frame granularity, no
		// partial frames, no client-visible effect.
		rw.overflowed = true
		return rw.w.Write(b)
	}

	rw.chunks = append(rw.chunks, SSEChunk{
		Data:    string(b),
		DelayMS: delay,
	})
	rw.captured += len(b)

	return rw.w.Write(b)
}

// Flush forwards the flush to the underlying ResponseWriter if it supports it.
func (rw *RecordingWriter) Flush() {
	if f, ok := rw.w.(http.Flusher); ok {
		f.Flush()
	}
	rw.flushed = true
}

// Chunks returns all captured SSE chunks.
func (rw *RecordingWriter) Chunks() []SSEChunk {
	return rw.chunks
}

// ReplaySSE replays captured SSE chunks to the given ResponseWriter with timing preservation.
func ReplaySSE(w http.ResponseWriter, chunks []SSEChunk, maxDelay time.Duration) {
	flusher, _ := w.(http.Flusher)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accelerate-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	if flusher != nil {
		flusher.Flush()
	}

	for _, c := range chunks {
		if c.DelayMS > 0 {
			d := time.Duration(c.DelayMS) * time.Millisecond
			if maxDelay > 0 && d > maxDelay {
				d = maxDelay
			}
			time.Sleep(d)
		}
		if _, err := w.Write([]byte(c.Data)); err != nil {
			return // client disconnected
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

// ReplaySSEBurst replays all chunks immediately without delays (burst mode).
func ReplaySSEBurst(w http.ResponseWriter, chunks []SSEChunk) {
	flusher, _ := w.(http.Flusher)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	if flusher != nil {
		flusher.Flush()
	}

	for _, c := range chunks {
		if _, err := w.Write([]byte(c.Data)); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

// ReplaySSEPaced replays chunks with equal 10ms intervals (paced mode).
func ReplaySSEPaced(w http.ResponseWriter, chunks []SSEChunk) {
	flusher, _ := w.(http.Flusher)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	if flusher != nil {
		flusher.Flush()
	}

	for _, c := range chunks {
		time.Sleep(10 * time.Millisecond)
		if _, err := w.Write([]byte(c.Data)); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

// ReplayMode controls how cached SSE streams are replayed.
type ReplayMode int

const (
	// ReplayFaithful preserves the original byte stream exactly.
	ReplayFaithful ReplayMode = iota
	// ReplayBurst sends the entire stream immediately.
	ReplayBurst
	// ReplayPaced sends chunks at equal 10ms intervals.
	ReplayPaced
)
