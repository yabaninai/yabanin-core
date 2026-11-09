package cache

// STREAM-01 regressions: the stream-cache recorder is a bounded capture.
// Unlimited retention of every SSE frame turned a long-lived upstream stream
// into unbounded gateway memory; a bounded capture that keeps forwarding
// client bytes while refusing to hand a truncated prefix to the cache writer
// closes both halves (memory + partial-entry poisoning).

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureRW is a plain ResponseWriter stand-in recording every forwarded
// byte, so client passthrough is verifiable.
type captureRW struct {
	rec       *httptest.ResponseRecorder
	forwarded []byte
}

func newCaptureRW() *captureRW { return &captureRW{rec: httptest.NewRecorder()} }

func (c *captureRW) Header() http.Header { return c.rec.Header() }

func (c *captureRW) WriteHeader(code int) { c.rec.WriteHeader(code) }

func (c *captureRW) Write(p []byte) (int, error) {
	c.forwarded = append(c.forwarded, p...)
	return c.rec.Write(p)
}

func TestSTREAM01_RecordingWriterCapped_StopsRetainingKeepsForwarding(t *testing.T) {
	inner := newCaptureRW()
	rw := NewRecordingWriterCapped(inner, 64, 8)

	frame := func(tag string) []byte { return []byte("data: {\"c\":\"" + tag + "\"}\n\n") }

	// First two frames fit (2 x ~22B). The third crosses the byte ceiling:
	// dropped whole, overflow latched, client still receives it.
	require.NoError(t, rw.writeAll(frame("aa")))
	require.NoError(t, rw.writeAll(frame("bb")))
	require.False(t, rw.Overflowed())
	assert.Len(t, rw.Chunks(), 2)

	big := frame(strings.Repeat("z", 80))
	require.NoError(t, rw.writeAll(big))
	assert.True(t, rw.Overflowed(), "crossing the retained-byte ceiling must latch the overflow")
	assert.Len(t, rw.Chunks(), 2, "the crossing frame is dropped whole — never a partial capture")
	assert.Contains(t, string(inner.forwarded), strings.Repeat("z", 80),
		"client bytes pass through the bounded recorder untouched")

	// After the latch nothing more is retained, forwarding continues.
	require.NoError(t, rw.writeAll(frame("cc")))
	assert.Len(t, rw.Chunks(), 2)
	retained := 0
	for _, c := range rw.Chunks() {
		retained += len(c.Data)
	}
	assert.LessOrEqual(t, retained, 64, "retained bytes stay within the ceiling")
}

func TestSTREAM01_RecordingWriterCapped_FrameCeiling(t *testing.T) {
	inner := newCaptureRW()
	rw := NewRecordingWriterCapped(inner, 0, 3) // bytes unlimited, 3 frames

	for i := 0; i < 5; i++ {
		require.NoError(t, rw.writeAll([]byte("data: x\n\n")))
	}
	assert.True(t, rw.Overflowed())
	assert.Len(t, rw.Chunks(), 3, "the frame ceiling stops retention at exactly maxFrames")
	assert.Len(t, inner.forwarded, 5*len("data: x\n\n"), "all frames still reached the client")
}

func TestSTREAM01_RecordingWriterUnlimited_BackwardCompatible(t *testing.T) {
	inner := newCaptureRW()
	rw := NewRecordingWriter(inner)

	for i := 0; i < 100; i++ {
		require.NoError(t, rw.writeAll([]byte("data: x\n\n")))
	}
	assert.False(t, rw.Overflowed(), "the historical constructor stays unlimited")
	assert.Len(t, rw.Chunks(), 100)
}

func TestSTREAM01_ReplayContract_IntactForCappedCapture(t *testing.T) {
	// A capture that finished under the caps must replay identically to one
	// taken with the unlimited constructor — the cap must not alter the
	// replayable content of legitimately-sized streams.
	inner := newCaptureRW()
	rw := NewRecordingWriterCapped(inner, 1<<20, 4096)
	payload := []byte("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n")
	require.NoError(t, rw.writeAll(payload))
	require.NoError(t, rw.writeAll([]byte("data: [DONE]\n\n")))

	rec := httptest.NewRecorder()
	ReplaySSEBurst(rec, rw.Chunks())
	assert.Equal(t, string(append(append([]byte{}, payload...), "data: [DONE]\n\n"...)), rec.Body.String(),
		"a within-caps capture replays byte-for-byte")
}

// writeAll exists to keep the table above honest about error plumbing (the
// recorder forwards Write's result verbatim).
func (rw *RecordingWriter) writeAll(p []byte) error {
	_, err := rw.Write(p)
	return err
}
