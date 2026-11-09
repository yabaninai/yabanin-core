package httpmw

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
)

func TestMaxBody_AllowsSmallBody(t *testing.T) {
	mw := MaxBody(1024)

	var receivedBody string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		receivedBody = string(body)
		w.WriteHeader(http.StatusOK)
	})

	handler := mw(next)

	reqBody := []byte(`{"key": "value"}`)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/test", bytes.NewReader(reqBody))
	rw := httptest.NewRecorder()

	handler.ServeHTTP(rw, req)

	assert.Equal(t, http.StatusOK, rw.Code)
	assert.JSONEq(t, `{"key": "value"}`, receivedBody)
}

func TestMaxBody_RejectsLargeBody(t *testing.T) {
	mw := MaxBody(100) // 100 byte limit

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err != nil {
			if IsMaxBytesError(err) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := mw(next)

	largeBody := bytes.NewReader(make([]byte, 200))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/test", largeBody)
	rw := httptest.NewRecorder()

	handler.ServeHTTP(rw, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, rw.Code)
}

func TestMaxBody_JsonDecoder_DecodesSuccessfully(t *testing.T) {
	mw := MaxBody(1024)

	type Req struct {
		Name string `json:"name"`
		Age  int    `json:"age"`
	}
	var decoded Req

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&decoded); err != nil {
			if IsMaxBytesError(err) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := mw(next)

	reqBody := []byte(`{"name": "Alice", "age": 30}`)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/test", bytes.NewReader(reqBody))
	rw := httptest.NewRecorder()

	handler.ServeHTTP(rw, req)

	assert.Equal(t, http.StatusOK, rw.Code)
	assert.Equal(t, "Alice", decoded.Name)
	assert.Equal(t, 30, decoded.Age)
}

func TestMaxBody_JsonDecoder_RejectsLargeBody(t *testing.T) {
	mw := MaxBody(100) // 100 byte limit

	type Req struct {
		Data string `json:"data"`
	}
	var decoded Req

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&decoded); err != nil {
			if IsMaxBytesError(err) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := mw(next)

	// Send a valid JSON body that exceeds the 100 byte limit.
	// Using strings.Repeat to create a long but valid string value.
	largeData := strings.Repeat("a", 500)
	reqBody := []byte(fmt.Sprintf(`{"data":"%s"}`, largeData))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/test", bytes.NewReader(reqBody))
	rw := httptest.NewRecorder()

	handler.ServeHTTP(rw, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, rw.Code)
}

func TestMaxBody_EmptyBody(t *testing.T) {
	mw := MaxBody(1024)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := mw(next)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/test", bytes.NewReader(nil))
	rw := httptest.NewRecorder()

	handler.ServeHTTP(rw, req)

	assert.Equal(t, http.StatusOK, rw.Code)
}

func TestMaxBody_ZeroLimit_RejectsAllNonEmpty(t *testing.T) {
	mw := MaxBody(0) // zero limit — should reject any body with data

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err != nil {
			if IsMaxBytesError(err) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := mw(next)

	reqBody := []byte(`hello`)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/test", bytes.NewReader(reqBody))
	rw := httptest.NewRecorder()

	handler.ServeHTTP(rw, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, rw.Code)
}

func TestMaxBody_ZeroLimit_AllowsEmpty(t *testing.T) {
	mw := MaxBody(0)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := mw(next)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/test", bytes.NewReader(nil))
	rw := httptest.NewRecorder()

	handler.ServeHTTP(rw, req)

	assert.Equal(t, http.StatusOK, rw.Code)
}

func TestMaxBody_WithChiRouter(t *testing.T) {
	mw := MaxBody(256)

	router := chi.NewRouter()
	router.Use(mw)
	router.Post("/test", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Message string `json:"message"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			if IsMaxBytesError(err) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{"echo": req.Message}); err != nil {
			http.Error(w, "encode error", http.StatusInternalServerError)
			return
		}
	})

	t.Run("small body succeeds", func(t *testing.T) {
		reqBody := []byte(`{"message": "hello"}`)
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/test", bytes.NewReader(reqBody))
		rw := httptest.NewRecorder()

		router.ServeHTTP(rw, req)

		assert.Equal(t, http.StatusOK, rw.Code)
	})

	t.Run("large body rejected", func(t *testing.T) {
		// Valid JSON but too large for the 256-byte limit
		largeData := strings.Repeat("x", 400)
		reqBody := []byte(fmt.Sprintf(`{"message":"%s"}`, largeData))
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/test", bytes.NewReader(reqBody))
		rw := httptest.NewRecorder()

		router.ServeHTTP(rw, req)

		assert.Equal(t, http.StatusRequestEntityTooLarge, rw.Code)
	})
}

func TestIsMaxBytesError(t *testing.T) {
	t.Run("nil error returns false", func(t *testing.T) {
		assert.False(t, IsMaxBytesError(nil))
	})

	t.Run("regular error returns false", func(t *testing.T) {
		assert.False(t, IsMaxBytesError(errors.New("some error")))
	})

	t.Run("our custom MaxBytesError wrapping http.MaxBytesError returns true", func(t *testing.T) {
		stdlibErr := &http.MaxBytesError{}
		err := &MaxBytesError{Limit: 1024, Err: stdlibErr}
		assert.True(t, IsMaxBytesError(err))
	})

	t.Run("raw *http.MaxBytesError returns true", func(t *testing.T) {
		err := &http.MaxBytesError{}
		assert.True(t, IsMaxBytesError(err))
	})

	t.Run("wrapped MaxBytesError returns true", func(t *testing.T) {
		stdlibErr := &http.MaxBytesError{}
		err := fmt.Errorf("wrapped: %w", &MaxBytesError{Limit: 1024, Err: stdlibErr})
		assert.True(t, IsMaxBytesError(err))
	})
}

func TestMaxBody_DoesNotInterfereWithOtherMiddleware(t *testing.T) {
	mw := MaxBody(1024)

	authCalled := false
	requestID := ""

	router := chi.NewRouter()
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID = "test-123"
			r.Header.Set("X-Request-ID", requestID)
			next.ServeHTTP(w, r)
		})
	})
	router.Use(mw)
	router.Post("/test", func(w http.ResponseWriter, r *http.Request) {
		authCalled = true
		body, _ := io.ReadAll(r.Body)
		assert.JSONEq(t, `{"key":"value"}`, string(body))
		w.WriteHeader(http.StatusOK)
	})

	reqBody := []byte(`{"key":"value"}`)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/test", bytes.NewReader(reqBody))
	rw := httptest.NewRecorder()

	router.ServeHTTP(rw, req)

	assert.True(t, authCalled, "handler should have been called")
	assert.Equal(t, http.StatusOK, rw.Code)
}

func TestMaxBody_BodyReadIsLimited(t *testing.T) {
	mw := MaxBody(50) // 50 byte limit

	readBytes := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1024)
		n, err := r.Body.Read(buf)
		readBytes = n
		if err != nil && err != io.EOF {
			if IsMaxBytesError(err) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := mw(next)

	reqBody := bytes.NewReader(make([]byte, 100))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/test", reqBody)
	rw := httptest.NewRecorder()

	handler.ServeHTTP(rw, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, rw.Code)
	// The read should have been limited to ~50 bytes
	assert.LessOrEqual(t, readBytes, 100)
}

func TestMaxBody_LoggerIntegration(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	mw := MaxBody(1024)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		logger.Info("received body", slog.String("body", string(body)))
		w.WriteHeader(http.StatusOK)
	})

	handler := mw(next)

	reqBody := []byte(`{"test":true}`)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/test", bytes.NewReader(reqBody))
	rw := httptest.NewRecorder()

	handler.ServeHTTP(rw, req)

	assert.Equal(t, http.StatusOK, rw.Code)
}

// TestMaxBody_ChunkedOversizedStreamRejectedWithBoundedMemory pins the T05
// negative case at the middleware layer: chunked framing (unknown body
// length — exactly how net/http presents a Transfer-Encoding: chunked
// request) cannot bypass the quota, because MaxBytesReader counts bytes as
// they are READ, not the declared Content-Length; and the reject path stays
// memory-bounded (no buffer ever approaches the stream size).

// unknownLengthBody hides the underlying reader type so httptest.NewRequest
// leaves ContentLength at 0 — the middleware-visible shape of a chunked
// request (streaming body, no up-front size).
type unknownLengthBody struct{ r io.Reader }

func (u unknownLengthBody) Read(p []byte) (int, error) { return u.r.Read(p) }

// zeros is an endless zero stream: the 200 MiB fixture is never materialized.
type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func TestMaxBody_ChunkedOversizedStreamRejectedWithBoundedMemory(t *testing.T) {
	const bodyCap = int64(10 << 20)
	const streamBytes = int64(200 << 20)

	var read int64
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		read = n
		if err != nil && IsMaxBytesError(err) {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/test",
		unknownLengthBody{r: io.LimitReader(zeros{}, streamBytes)})
	// net/http presents a Transfer-Encoding: chunked request to handlers with
	// ContentLength -1 (unknown — pinned empirically in pkg/gateway
	// TestWireAmbiguousFramingResolvedBeforeHandler); httptest.NewRequest
	// mirrors that for non-buffer reader types.
	if req.ContentLength != -1 {
		t.Fatalf("fixture: ContentLength=%d, want -1 (unknown-length / chunked framing)", req.ContentLength)
	}
	rw := httptest.NewRecorder()

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	MaxBody(bodyCap)(next).ServeHTTP(rw, req)
	runtime.ReadMemStats(&after)

	if rw.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("200 MiB chunked stream must answer 413, got %d", rw.Code)
	}
	if read > bodyCap {
		t.Fatalf("handler consumed %d bytes, cap is %d — quota must stop reads at the limit", read, bodyCap)
	}
	// The reject path may stream through reusable small buffers but must never
	// buffer anything near the payload: total allocation stays two orders of
	// magnitude below the 200 MiB stream.
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 64<<20 {
		t.Fatalf("reject path allocated %d bytes for a %d-byte stream — limit must act before large buffers", grew, streamBytes)
	}
}

// TestMaxBodyByPrefix_OverrideAndDefault pins the file-cap limit; every other
// path keeps the default.
func TestMaxBodyByPrefix_OverrideAndDefault(t *testing.T) {
	mw := MaxBodyByPrefix(100, 4096, "/v1/files")

	read := func(path string, size int) int {
		t.Helper()
		code := 0
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := io.ReadAll(r.Body)
			if err != nil {
				code = http.StatusRequestEntityTooLarge
				return
			}
			code = http.StatusOK
		})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, bytes.NewReader(make([]byte, size)))
		rw := httptest.NewRecorder()
		mw(next).ServeHTTP(rw, req)
		return code
	}

	assert.Equal(t, http.StatusOK, read("/v1/files", 2000), "prefix path rides the override limit")
	assert.Equal(t, http.StatusRequestEntityTooLarge, read("/v1/files", 5000), "prefix path still capped by the override")
	assert.Equal(t, http.StatusOK, read("/v1/chat/completions", 80), "other paths keep the default limit")
	assert.Equal(t, http.StatusRequestEntityTooLarge, read("/v1/chat/completions", 200), "other paths capped by the default")
	assert.Equal(t, http.StatusOK, read("/v1/files/abc/content", 2000), "nested files routes share the override")
}

// T07 boundary: the cap is inclusive on the success side. A body of EXACTLY
// maxBytes is delivered in full with no error; the first byte past the cap
// trips *http.MaxBytesError. (The wire-level pair for this boundary lives in
// pkg/gateway TestWireBodyExactCapAccepted / TestWireBodyCapPlusOneRejectedEarly.)
func TestMaxBody_ExactLimitBoundaryAccepted(t *testing.T) {
	const capBytes = 4096
	readAll := func(size int) (int, bool) {
		t.Helper()
		var got int
		var tooLarge bool
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n, err := io.ReadAll(r.Body)
			got = len(n)
			if err != nil {
				tooLarge = IsMaxBytesError(err)
			}
			w.WriteHeader(http.StatusOK)
		})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/x", bytes.NewReader(make([]byte, size)))
		MaxBody(capBytes)(next).ServeHTTP(httptest.NewRecorder(), req)
		return got, tooLarge
	}

	got, tooLarge := readAll(capBytes)
	if tooLarge || got != capBytes {
		t.Fatalf("exact-cap body: read=%d tooLarge=%v, want full %d bytes accepted", got, tooLarge, capBytes)
	}
	got, tooLarge = readAll(capBytes + 1)
	if !tooLarge {
		t.Fatal("cap+1 body must trip *http.MaxBytesError")
	}
	if got > capBytes {
		t.Fatalf("handler consumed %d bytes past the %d-byte cap", got, capBytes)
	}
}

// T07 boundary: prefix selection is TEXTUAL (strings.HasPrefix). A path that
// merely begins with the prefix text — e.g. a hypothetical /v1/fileshare —
// inherits the override cap. No such route exists today (routes.go mounts
// /v1/files and /v1/files/{id}... only), so this is a documented boundary,
// not a reachable defect: adding a route that textually shares the prefix
// silently inherits the larger cap, and a near-miss shorter path keeps the
// default cap.
func TestMaxBodyByPrefix_TextualBoundary(t *testing.T) {
	mw := MaxBodyByPrefix(100, 4096, "/v1/files")

	read := func(path string, size int) int {
		t.Helper()
		code := 0
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := io.ReadAll(r.Body); err != nil {
				code = http.StatusRequestEntityTooLarge
				return
			}
			code = http.StatusOK
		})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, bytes.NewReader(make([]byte, size)))
		rw := httptest.NewRecorder()
		mw(next).ServeHTTP(rw, req)
		return code
	}

	// Near-miss shorter prefix: /v1/file does NOT match /v1/files → default cap.
	assert.Equal(t, http.StatusRequestEntityTooLarge, read("/v1/file", 200), "shorter near-miss path keeps the default cap")
	// Textual overlap: /v1/fileshare DOES match the prefix text → override cap
	// (documents the selection semantics; no such route is mounted today).
	assert.Equal(t, http.StatusOK, read("/v1/fileshare", 2000), "textual prefix overlap inherits the override cap")
	assert.Equal(t, http.StatusOK, read("/v1/files", 2000), "exact prefix path rides the override cap")
}
