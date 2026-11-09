package cli

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Regression: a client that disconnects mid-stream can make Write/Flush panic
// inside net/http (the server recycles the response once the connection is
// gone). writeSSEError runs on the "stream failed" path — a panic there used
// to kill the handler goroutine before budget accounting and the analytics
// event were published. It must contain the panic itself.

type panickingWriter struct {
	*httptest.ResponseRecorder
	panicOnWrite bool
	panicOnFlush bool
}

func (p *panickingWriter) Write(b []byte) (int, error) {
	if p.panicOnWrite {
		panic("http: response already recycled (client gone)")
	}
	return p.ResponseRecorder.Write(b)
}

func (p *panickingWriter) Flush() {
	if p.panicOnFlush {
		panic("invalid memory address or nil pointer dereference")
	}
}

func TestWriteSSEError_ContainsClientFlushPanic(t *testing.T) {
	w := &panickingWriter{ResponseRecorder: httptest.NewRecorder(), panicOnFlush: true}

	assert.NotPanics(t, func() {
		writeSSEError(w, "api_error", "stream interrupted")
	})
	assert.Contains(t, w.Body.String(), `"error"`, "error frame must still be attempted")
	assert.Contains(t, w.Body.String(), "data: [DONE]")
}

func TestWriteSSEError_ContainsClientWritePanic(t *testing.T) {
	w := &panickingWriter{ResponseRecorder: httptest.NewRecorder(), panicOnWrite: true}

	assert.NotPanics(t, func() {
		writeSSEError(w, "api_error", "stream interrupted")
	})
}

func TestWriteSSEError_HappyPathStillFramed(t *testing.T) {
	w := httptest.NewRecorder()

	writeSSEError(w, "api_error", "boom")

	body := w.Body.String()
	assert.Contains(t, body, `"message":"boom"`)
	assert.Contains(t, body, "data: [DONE]")
}
