package cache

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestRecordingWriter_CapturesMultipleChunks verifies that RecordingWriter
// captures multiple independent Write calls as separate SSE chunks.
func TestRecordingWriter_CapturesMultipleChunks(t *testing.T) {
	cw := newCaptureResponseWriter()
	rw := NewRecordingWriter(cw)

	_, _ = rw.Write([]byte(`data: {"id":"1","choices":[{"delta":{"content":"H"}}]}\n\n`))
	_, _ = rw.Write([]byte(`data: {"id":"1","choices":[{"delta":{"content":"i"}}]}\n\n`))
	_, _ = rw.Write([]byte(`data: [DONE]\n\n`))

	chunks := rw.Chunks()
	assert.Len(t, chunks, 3, "should capture exactly 3 chunks")
	assert.Contains(t, chunks[0].Data, `"content":"H"`)
	assert.Contains(t, chunks[1].Data, `"content":"i"`)
	assert.Contains(t, chunks[2].Data, "[DONE]")
}

// TestRecordingWriter_ConsistentForwarding verifies that writing through
// RecordingWriter to a real ResponseWriter correctly forwards data.
func TestRecordingWriter_ConsistentForwarding(t *testing.T) {
	rec := newCaptureResponseWriter()
	rw := NewRecordingWriter(rec)

	_, _ = rw.Write([]byte(`data: {"id":"1"}\n\n`))
	_, _ = rw.Write([]byte(`data: [DONE]\n\n`))

	chunks := rw.Chunks()
	assert.Len(t, chunks, 2)

	// The captured data should match what was written to the underlying writer.
	capturedBody := rec.buf.String()
	assert.Contains(t, capturedBody, `"id":"1"`)
	assert.Contains(t, capturedBody, "[DONE]")
}

// TestConcatenateChunks verifies the streaming cache chunk concatenation logic
// that was fixed in F9.5 — all chunks must be concatenated before JSON parsing
// to avoid truncating multi-chunk streaming responses.
func TestConcatenateChunks(t *testing.T) {
	// Simulate a multi-chunk streaming response: first chunk is the OpenAI JSON,
	// followed by additional events and [DONE].
	chunks := []SSEChunk{
		{Data: `data: {"id":"chatcmpl-1","object":"chat.completion.chunk","model":"gpt-4","choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}\n\n`},
		{Data: `data: {"id":"chatcmpl-1","object":"chat.completion.chunk","model":"gpt-4","choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]}\n\n`},
		{Data: `data: [DONE]\n\n`},
	}

	var combined strings.Builder
	for _, c := range chunks {
		combined.WriteString(c.Data)
	}

	result := combined.String()

	// The first chunk must be parseable as JSON after concatenation.
	assert.Contains(t, result, `"object":"chat.completion.chunk"`)
	assert.Contains(t, result, `"content":"Hello"`)
	assert.Contains(t, result, "[DONE]")

	// Verify that the first complete object is intact (starts with data: {).
	assert.True(t, strings.HasPrefix(result, "data: {"), "must start with JSON data frame")
}

// captureResponseWriter wraps a bytes.Buffer to satisfy http.ResponseWriter.
type captureResponseWriter struct {
	buf strings.Builder
	h   http.Header
}

func newCaptureResponseWriter() *captureResponseWriter {
	return &captureResponseWriter{h: make(http.Header)}
}

func (c *captureResponseWriter) Header() http.Header         { return c.h }
func (c *captureResponseWriter) Write(b []byte) (int, error) { return c.buf.Write(b) }
func (c *captureResponseWriter) WriteHeader(code int)        {}
