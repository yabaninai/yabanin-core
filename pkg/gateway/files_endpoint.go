package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/batchstore"
	apierrors "github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/httpmw"
)

// filesSpoolDir redirects the upload spool location (tests only; empty means
// the OS temp dir). Production keeps the default: each in-flight upload may
// occupy up to the route wire cap (~MaxFileSizeBytes + 1 MiB envelope slack)
// of TEMPORARY DISK — the same order it previously occupied in RAM for the
// whole client-paced upload, now bounded to the server-paced insert window.
var filesSpoolDir string

// errFilePartTooLarge marks the file-part cap hit at the spool boundary (the
// part carried more than MaxFileSizeBytes even though the request stayed
// under the route wire cap). Distinct from *http.MaxBytesError, which marks
// the wire-level body cap.
var errFilePartTooLarge = errors.New("file part exceeds the maximum size")

// errSpoolUnavailable marks the temp-file creation failure (disk full,
// unwritable TMPDIR): a server-side 500, not a client 400.
var errSpoolUnavailable = errors.New("create upload spool")

// Auth/labels/credit ride the shared inference middleware group; the org
// comes from the resolved key (X-Org-Id). Without a DB pool the handlers
// answer 503 — the surface is mounted but cannot serve.

func (gw *gateway) filesStoreOr503(w http.ResponseWriter, r *http.Request) (*batchstore.Store, string, bool) {
	if gw.batchStore == nil {
		apierrors.Write(w, http.StatusServiceUnavailable, apierrors.ErrorCodeServiceUnavailable,
			"files API requires a database-backed gateway")
		return nil, "", false
	}
	orgID := r.Header.Get("X-Org-Id")
	if orgID == "" {
		apierrors.Write(w, http.StatusUnauthorized, apierrors.ErrorCodeAuthentication, "org resolution failed")
		return nil, "", false
	}
	return gw.batchStore, orgID, true
}

// fileJSONObject is the OpenAI-shaped wire object of a stored file.
type fileJSONObject struct {
	ID        string `json:"id"`
	Object    string `json:"object"`
	Bytes     int64  `json:"bytes"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
	Filename  string `json:"filename"`
	Purpose   string `json:"purpose"`
	Status    string `json:"status"`
}

func fileObject(f *batchstore.File) fileJSONObject {
	return fileJSONObject{
		ID:        f.ID,
		Object:    "file",
		Bytes:     f.Bytes,
		CreatedAt: f.CreatedAt.Unix(),
		ExpiresAt: f.ExpiresAt.Unix(),
		Filename:  f.Filename,
		Purpose:   f.Purpose,
		Status:    "uploaded",
	}
}

func writeFileObject(w http.ResponseWriter, f *batchstore.File) {
	writeJSONOK(w, fileObject(f))
}

func writeJSONOK(w http.ResponseWriter, v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		apierrors.Write(w, http.StatusInternalServerError, apierrors.ErrorCodeAPI, "serialization failed")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(raw, '\n'))
}

// filesSpool is the on-disk spool of one in-flight upload's file part. The
// upload phase is client-paced and unbounded in duration: streaming the part
// to disk keeps gateway memory O(copy buffer) during that phase, where the
// previous io.ReadAll held the full payload in RAM from the first received
// byte until CreateFile returned. The bytes are read back only for the short,
// server-paced bytea insert (D2 ratified: batch_files.content is bytea, and
// the INSERT ... RETURNING parameter needs the full payload — so the insert
// window keeps its unavoidable 1×-size peak; only the client-controlled
// window is bounded).
type filesSpool struct {
	file *os.File
	size int64
}

// discard closes and removes the spool file: temp bytes never outlive the
// request, on ANY outcome (success, 413, malformed envelope, disconnect,
// panic — deferred handlers run during panic unwinding).
func (s *filesSpool) discard() {
	if s == nil || s.file == nil {
		return
	}
	_ = s.file.Close()
	_ = os.Remove(s.file.Name())
}

// readBack returns the spooled bytes (≤ MaxFileSizeBytes by construction).
func (s *filesSpool) readBack() ([]byte, error) {
	if _, err := s.file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewind upload spool: %w", err)
	}
	content, err := io.ReadAll(io.LimitReader(s.file, batchstore.MaxFileSizeBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read upload spool: %w", err)
	}
	return content, nil
}

// spoolFilePart streams one multipart file part to a temp file under the D3
// cap. Memory stays bounded to io.Copy's buffer regardless of part size; the
// cap is enforced by reading at most MaxFileSizeBytes+1 bytes and refusing
// when more arrived. The returned error is *http.MaxBytesError when the
// route-level wire cap tripped first (propagated unchanged from the wrapped
// request body through the multipart reader).
func spoolFilePart(part *multipart.Part) (*filesSpool, error) {
	tmp, err := os.CreateTemp(filesSpoolDir, "yabanin-upload-*")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errSpoolUnavailable, err)
	}
	s := &filesSpool{file: tmp}
	accepted := false
	defer func() {
		if !accepted {
			s.discard() // a rejected spool leaves no temp bytes behind
		}
	}()
	n, err := io.Copy(tmp, io.LimitReader(part, batchstore.MaxFileSizeBytes+1))
	if err != nil {
		return nil, err
	}
	if n > batchstore.MaxFileSizeBytes {
		return nil, errFilePartTooLarge
	}
	s.size = n
	accepted = true
	return s, nil
}

// filesUpload handles POST /v1/files: multipart/form-data with a "file" part
// and a "purpose" field (only "batch" is accepted for client uploads). The
// D3 100 MiB cap answers 413. The file part is SPOOLED TO DISK under the cap
// while the envelope streams (bounded memory: gateway RAM stays O(copy
// buffer) during the client-paced upload; the spool is read back only for
// the bytea insert and removed on every outcome), and the route-level body
// limit leaves slack for the envelope only.
func (gw *gateway) filesUpload(w http.ResponseWriter, r *http.Request) {
	store, orgID, ok := gw.filesStoreOr503(w, r)
	if !ok {
		return
	}
	reader, err := r.MultipartReader()
	if err != nil {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
			"multipart/form-data request required (fields: file, purpose)")
		return
	}
	var purpose, filename string
	var spool *filesSpool
	// Closure (not defer spool.discard()): a deferred method value evaluates
	// its receiver AT DEFER TIME — nil here — and would never discard.
	defer func() { spool.discard() }()
	for {
		part, perr := reader.NextPart()
		if perr == io.EOF {
			break
		}
		if perr != nil {
			apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
				"malformed multipart body: "+perr.Error())
			return
		}
		formName := part.FormName()
		if formName == "purpose" {
			raw, rerr := io.ReadAll(io.LimitReader(part, 256))
			if rerr != nil {
				apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "unreadable purpose field")
				return
			}
			purpose = strings.TrimSpace(string(raw))
			continue
		}
		if formName != "file" {
			continue // unknown fields are ignored, OpenAI-style
		}
		if spool != nil {
			apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "multiple file parts")
			return
		}
		filename = part.FileName()
		s, serr := spoolFilePart(part)
		if serr != nil {
			if httpmw.IsMaxBytesError(serr) || errors.Is(serr, errFilePartTooLarge) {
				apierrors.WriteWithCode(w, http.StatusRequestEntityTooLarge, apierrors.ErrorCodeInvalidRequest,
					"file exceeds the maximum size of 100 MiB", "file_too_large")
				return
			}
			if errors.Is(serr, errSpoolUnavailable) {
				apierrors.Write(w, http.StatusInternalServerError, apierrors.ErrorCodeAPI, "upload spool unavailable")
				return
			}
			apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "unreadable file part")
			return
		}
		spool = s
	}
	if spool == nil {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "missing file part")
		return
	}
	if purpose == "" {
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest, "missing purpose field")
		return
	}
	if purpose != batchstore.PurposeBatchInput {
		apierrors.WriteWithCode(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
			"unsupported purpose; only \"batch\" uploads are supported", "unsupported_purpose")
		return
	}
	// Validation is complete: only now are the spooled bytes read back into
	// memory for the bytea insert — rejected uploads never load RAM.
	content, rerr := spool.readBack()
	if rerr != nil {
		apierrors.Write(w, http.StatusInternalServerError, apierrors.ErrorCodeAPI, "upload processing failed")
		return
	}
	f, err := store.CreateFile(r.Context(), orgID, filename, purpose, content)
	if err != nil {
		writeFilesStoreError(w, err)
		return
	}
	writeFileObject(w, f)
}

func writeFilesStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, batchstore.ErrFileTooLarge):
		apierrors.WriteWithCode(w, http.StatusRequestEntityTooLarge, apierrors.ErrorCodeInvalidRequest,
			"file exceeds the maximum size of 100 MiB", "file_too_large")
	case errors.Is(err, batchstore.ErrNotFound):
		apierrors.Write(w, http.StatusNotFound, apierrors.ErrorCodeNotFound, "file not found")
	default:
		apierrors.Write(w, http.StatusInternalServerError, apierrors.ErrorCodeAPI, "files store unavailable")
	}
}

// filesList handles GET /v1/files.
func (gw *gateway) filesList(w http.ResponseWriter, r *http.Request) {
	store, orgID, ok := gw.filesStoreOr503(w, r)
	if !ok {
		return
	}
	files, err := store.ListFiles(r.Context(), orgID, listLimit(r))
	if err != nil {
		writeFilesStoreError(w, err)
		return
	}
	objs := make([]fileJSONObject, 0, len(files))
	for _, f := range files {
		objs = append(objs, fileObject(f))
	}
	writeJSONOK(w, map[string]any{"object": "list", "data": objs})
}

// filesGet handles GET /v1/files/{id}.
func (gw *gateway) filesGet(w http.ResponseWriter, r *http.Request) {
	store, orgID, ok := gw.filesStoreOr503(w, r)
	if !ok {
		return
	}
	f, err := store.GetFile(r.Context(), orgID, chi.URLParam(r, "id"))
	if err != nil {
		writeFilesStoreError(w, err)
		return
	}
	writeFileObject(w, f)
}

// filesContent handles GET /v1/files/{id}/content (authorized download;
// foreign org → 404, existence hidden).
func (gw *gateway) filesContent(w http.ResponseWriter, r *http.Request) {
	store, orgID, ok := gw.filesStoreOr503(w, r)
	if !ok {
		return
	}
	content, _, err := store.FileContent(r.Context(), orgID, chi.URLParam(r, "id"))
	if err != nil {
		writeFilesStoreError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

// filesDelete handles DELETE /v1/files/{id}.
func (gw *gateway) filesDelete(w http.ResponseWriter, r *http.Request) {
	store, orgID, ok := gw.filesStoreOr503(w, r)
	if !ok {
		return
	}
	id := chi.URLParam(r, "id")
	deleted, err := store.DeleteFile(r.Context(), orgID, id)
	if err != nil {
		writeFilesStoreError(w, err)
		return
	}
	if !deleted {
		apierrors.Write(w, http.StatusNotFound, apierrors.ErrorCodeNotFound, "file not found")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"id":"` + id + `","object":"file","deleted":true}` + "\n"))
}

func listLimit(r *http.Request) int {
	raw := strings.TrimSpace(r.URL.Query().Get("limit"))
	if raw == "" {
		return 100
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 100
	}
	if n > 1000 {
		return 1000
	}
	return n
}
