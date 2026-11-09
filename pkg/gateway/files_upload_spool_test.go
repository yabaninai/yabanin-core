package cli

// N01-P06 remainder closure — bounded files-upload spooling. The file part
// used to be buffered in RAM (io.ReadAll) from the first received byte until
// CreateFile returned: a client-paced 100 MiB upload held 100 MiB of gateway
// memory for its whole duration. It is now spooled to a capped temp file and
// read back only for the bytea insert. These tests pin the spool boundary,
// the rollback/cleanup contract on every outcome, and — at the wire level —
// the bounded-memory observable for the cap+1 reject.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/batchstore"
	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/httpmw"
	"github.com/reireirei/yabanin/pkg/testdb"
	"github.com/reireirei/yabanin/pkg/upstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// spoolPartReader builds a multipart body over a pipe so the fixture never
// materializes the payload (zeros are streamed in 1 MiB chunks) and returns
// the FIRST form part. size is the file-part payload; the purpose field is
// appended so the envelope matches the real upload shape.
func spoolPartReader(t *testing.T, size int64) *multipart.Part {
	t.Helper()
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	boundary := mw.Boundary()
	go func() {
		defer func() { _ = pw.Close() }()
		defer func() { _ = mw.Close() }()
		fw, err := mw.CreateFormFile("file", "spool.bin")
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		zero := make([]byte, 1<<20)
		var written int64
		for written < size {
			n := size - written
			if n > int64(len(zero)) {
				n = int64(len(zero))
			}
			if _, err := fw.Write(zero[:n]); err != nil {
				_ = pw.CloseWithError(err)
				return
			}
			written += n
		}
		if err := mw.WriteField("purpose", batchstore.PurposeBatchInput); err != nil {
			_ = pw.CloseWithError(err)
		}
	}()
	part, err := multipart.NewReader(pr, boundary).NextPart()
	require.NoError(t, err)
	return part
}

// spoolDirList lists the spool directory contents (rollback observable).
func spoolDirList(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// TestSpoolFilePart_ExactCapBoundary pins the D3 byte boundary at the spool:
// exactly MaxFileSizeBytes is accepted (readBack returns the full payload),
// cap+1 is refused with errFilePartTooLarge and leaves NO temp file behind.
// (Dockerless: the DB-gated HTTP-level pair is
// TestFilesBoundary_ExactCap_Integration.)
func TestSpoolFilePart_ExactCapBoundary(t *testing.T) {
	filesSpoolDir = t.TempDir()
	t.Cleanup(func() { filesSpoolDir = "" })

	t.Run("exact cap accepted", func(t *testing.T) {
		part := spoolPartReader(t, batchstore.MaxFileSizeBytes)
		s, err := spoolFilePart(part)
		require.NoError(t, err)
		defer s.discard()
		assert.Equal(t, batchstore.MaxFileSizeBytes, s.size)
		content, rerr := s.readBack()
		require.NoError(t, rerr)
		assert.Len(t, content, int(batchstore.MaxFileSizeBytes))
		// A byte past the cap inside readBack's LimitReader would still be
		// impossible: the spool only ever holds ≤ cap.
		assert.Equal(t, int64(batchstore.MaxFileSizeBytes), func() int64 {
			info, err := os.Stat(s.file.Name())
			require.NoError(t, err)
			return info.Size()
		}())
	})

	t.Run("cap+1 refused", func(t *testing.T) {
		part := spoolPartReader(t, batchstore.MaxFileSizeBytes+1)
		s, err := spoolFilePart(part)
		require.ErrorIs(t, err, errFilePartTooLarge)
		assert.Nil(t, s)
		assert.Empty(t, spoolDirList(t, filesSpoolDir), "rejected spool must leave no temp file")
	})

	t.Run("small payload round-trips", func(t *testing.T) {
		pr, pw := io.Pipe()
		mw := multipart.NewWriter(pw)
		boundary := mw.Boundary()
		payload := []byte("hello spool\n")
		go func() {
			defer func() { _ = pw.Close() }()
			defer func() { _ = mw.Close() }()
			fw, err := mw.CreateFormFile("file", "small.jsonl")
			if err != nil {
				_ = pw.CloseWithError(err)
				return
			}
			_, _ = fw.Write(payload)
			_ = mw.WriteField("purpose", batchstore.PurposeBatchInput)
		}()
		part, err := multipart.NewReader(pr, boundary).NextPart()
		require.NoError(t, err)
		s, serr := spoolFilePart(part)
		require.NoError(t, serr)
		defer s.discard()
		content, rerr := s.readBack()
		require.NoError(t, rerr)
		assert.Equal(t, payload, content, "spool must round-trip the bytes bit-for-bit")
	})
}

// TestSpoolFilePart_SpoolUnavailable pins the 500-class failure: an
// unwritable spool dir surfaces as errSpoolUnavailable (never a 400-class
// client error), and no partial temp file survives.
func TestSpoolFilePart_SpoolUnavailable(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	filesSpoolDir = missing
	t.Cleanup(func() { filesSpoolDir = "" })

	part := spoolPartReader(t, 1024)
	s, err := spoolFilePart(part)
	require.ErrorIs(t, err, errSpoolUnavailable)
	assert.Nil(t, s)
}

// TestFilesUpload_SpoolCleanupOnEveryOutcome — DB-gated (the handler needs a
// store): whatever the outcome (success, 413 cap+1, malformed envelope,
// multiple file parts, missing file part, bad purpose), the spool directory
// ends EMPTY — temp bytes never outlive the request (rollback contract).
func TestFilesUpload_SpoolCleanupOnEveryOutcome(t *testing.T) {
	pool := testdb.Postgres(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer up.Close()
	gw := filesBatchGateway(t, up.URL, pool)
	router := batchTestRouter(gw)
	org, _ := testOrgs("spoolclean")
	filesSpoolDir = t.TempDir()
	t.Cleanup(func() { filesSpoolDir = "" })

	upload := func(name string, body []byte, contentType string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/files", bytes.NewReader(body))
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		req.Header.Set("X-Org-Id", org)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	multipartBody := func(fileParts int, filename, purpose string, fileSize int) ([]byte, string) {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		for i := 0; i < fileParts; i++ {
			fw, err := mw.CreateFormFile("file", fmt.Sprintf("%s-%d", filename, i))
			require.NoError(t, err)
			_, err = fw.Write(make([]byte, fileSize))
			require.NoError(t, err)
		}
		if purpose != "" {
			require.NoError(t, mw.WriteField("purpose", purpose))
		}
		require.NoError(t, mw.Close())
		return buf.Bytes(), mw.FormDataContentType()
	}

	t.Run("success", func(t *testing.T) {
		body, ct := multipartBody(1, "ok.jsonl", batchstore.PurposeBatchInput, 128)
		rec := upload("success", body, ct)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Empty(t, spoolDirList(t, filesSpoolDir))
		id := fileID(t, rec)
		_, err := gw.batchStore.DeleteFile(context.Background(), org, id)
		require.NoError(t, err)
	})
	t.Run("413 cap+1", func(t *testing.T) {
		rec := uploadFile(t, router, org, "over.bin", batchstore.PurposeBatchInput, make([]byte, batchstore.MaxFileSizeBytes+1))
		require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code, rec.Body.String())
		assert.Contains(t, rec.Body.String(), "file_too_large")
		assert.Empty(t, spoolDirList(t, filesSpoolDir))
	})
	t.Run("400 malformed multipart", func(t *testing.T) {
		rec := upload("malformed", []byte("this is not multipart"), "multipart/form-data; boundary=absent")
		assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		assert.Empty(t, spoolDirList(t, filesSpoolDir))
	})
	t.Run("400 multiple file parts", func(t *testing.T) {
		body, ct := multipartBody(2, "dup.jsonl", batchstore.PurposeBatchInput, 16)
		rec := upload("dup", body, ct)
		assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		assert.Contains(t, rec.Body.String(), "multiple file parts")
		assert.Empty(t, spoolDirList(t, filesSpoolDir), "the FIRST spooled part must be discarded when a duplicate part is refused")
	})
	t.Run("400 missing file part", func(t *testing.T) {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		require.NoError(t, mw.WriteField("purpose", batchstore.PurposeBatchInput))
		require.NoError(t, mw.Close())
		rec := upload("missing", buf.Bytes(), mw.FormDataContentType())
		assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		assert.Empty(t, spoolDirList(t, filesSpoolDir))
	})
	t.Run("400 bad purpose (validated before read-back)", func(t *testing.T) {
		body, ct := multipartBody(1, "fine.jsonl", "fine-tune", 64)
		rec := upload("badpurpose", body, ct)
		assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		assert.Empty(t, spoolDirList(t, filesSpoolDir))
	})
	t.Run("400 missing purpose", func(t *testing.T) {
		body, ct := multipartBody(1, "nopurpose.jsonl", "", 64)
		rec := upload("nopurpose", body, ct)
		assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		assert.Empty(t, spoolDirList(t, filesSpoolDir))
	})
}

// TestWireFilesUploadCapPlusOneSpooledBoundedMemory — DB-gated; the
// limits_wire-pattern pair of the old buffered implementation's exposure. On
// the PRODUCTION server factory (newGatewayHTTPServer) with the real
// MaxBodyByPrefix route cap, a chunked files upload whose file part carries
// MaxFileSizeBytes+1 zero bytes (streamed — the fixture never materializes
// the payload) is rejected 413 (file_too_large), persists NOTHING, leaves NO
// temp file, and the whole exchange allocates far below the payload size:
// the old io.ReadAll path would allocate ≥ ~2× the payload cumulatively
// (append doubling); the spooled path streams through fixed small buffers.
// The 64 MiB bound (two orders of magnitude below 100 MiB+1, same bound as
// the middleware-layer pin in pkg/httpmw) leaves room for runtime/network
// noise while still failing loudly if any payload-sized buffer returns.
func TestWireFilesUploadCapPlusOneSpooledBoundedMemory(t *testing.T) {
	pool := testdb.Postgres(t)
	gw := &gateway{
		cfg:        config.Gateway{AuthMode: "strict", APIKey: "test-key"},
		log:        slog.Default(),
		auth:       NewAuthMiddleware(config.Gateway{AuthMode: "strict", APIKey: "test-key"}, nil),
		pool:       upstream.NewPool(upstream.Options{}),
		batchStore: batchstore.NewStore(pool, nil),
	}
	org := fmt.Sprintf("org-wire-spool-%d", time.Now().UnixNano())
	r := chi.NewRouter()
	r.Use(httpmw.MaxBodyByPrefix(10*1024*1024, batchstore.MaxFileSizeBytes+(1<<20), "/v1/files"))
	r.Post("/v1/files", gw.filesUpload)
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := newGatewayHTTPServer(ln.Addr().String(), r)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	filesSpoolDir = t.TempDir()
	t.Cleanup(func() { filesSpoolDir = "" })

	// The part that streams past the part cap trips errFilePartTooLarge at
	// MaxFileSizeBytes+1 while the total body stays under the 101 MiB wire
	// cap — exactly the request the old ReadAll implementation buffered.
	partBytes := batchstore.MaxFileSizeBytes + 1
	envelopeHead := "--wirebound\r\n" +
		"Content-Disposition: form-data; name=\"file\"; filename=\"over.bin\"\r\n" +
		"Content-Type: application/octet-stream\r\n\r\n"
	envelopeTail := "\r\n--wirebound\r\nContent-Disposition: form-data; name=\"purpose\"\r\n\r\nbatch\r\n--wirebound--\r\n"

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	reqHead := fmt.Sprintf("POST /v1/files HTTP/1.1\r\nHost: gateway.test\r\nX-Org-Id: %s\r\n"+
		"Content-Type: multipart/form-data; boundary=wirebound\r\n"+
		"Transfer-Encoding: chunked\r\n\r\n", org)
	if _, err := io.WriteString(conn, reqHead); err != nil {
		t.Fatal(err)
	}
	// Stream the payload in 1 MiB chunked records from a reused zero buffer.
	// The server rejects as soon as the part cap trips and closes the socket
	// (unconsumed body) — the writer goroutine therefore EXPECTS broken-pipe
	// errors; the response is what this test pins.
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		// Chunk 1 carries the part header (envelope head); the payload rides
		// as 1 MiB records; the closing envelope rides the final chunk.
		chunk := make([]byte, 1<<20)
		sendChunk := func(b []byte) bool {
			if _, err := fmt.Fprintf(conn, "%x\r\n", len(b)); err != nil {
				return false
			}
			if _, err := conn.Write(b); err != nil {
				return false
			}
			_, err := io.WriteString(conn, "\r\n")
			return err == nil
		}
		if !sendChunk([]byte(envelopeHead)) {
			return // server closed early — the expected reject path
		}
		var sent int64
		for sent < partBytes {
			n := partBytes - sent
			if n > int64(len(chunk)) {
				n = int64(len(chunk))
			}
			if !sendChunk(chunk[:n]) {
				return
			}
			sent += n
		}
		_, _ = fmt.Fprintf(conn, "%x\r\n%s0\r\n\r\n", len(envelopeTail), envelopeTail)
	}()
	_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	status, respHead := readHeadBlock(t, conn)
	body, _ := io.ReadAll(io.LimitReader(conn, 8192))
	runtime.ReadMemStats(&after)
	select {
	case <-writeDone:
	case <-time.After(10 * time.Second):
		t.Fatal("writer goroutine stuck after the response was read")
	}
	_ = conn.Close()

	if !strings.Contains(status, "413") {
		t.Fatalf("cap+1 files upload must answer 413, got %q %q %s", status, respHead, body)
	}
	if !strings.Contains(string(body), "file_too_large") {
		t.Fatalf("413 must carry the file_too_large error code, got %q %q %s", status, respHead, body)
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 64<<20 {
		t.Fatalf("cap+1 reject path allocated %d bytes for a %d-byte stream — upload must spool, not buffer", grew, partBytes)
	}
	assert.Empty(t, spoolDirList(t, filesSpoolDir), "wire-level reject must leave no temp file")
	files, err := gw.batchStore.ListFiles(context.Background(), org, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Fatalf("rejected upload persisted %d file(s)", len(files))
	}
}
