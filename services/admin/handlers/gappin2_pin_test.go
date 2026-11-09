package handlers

// Handler-level pins for RV-1 GAP-A6 and GAP-A7:
//
//   - GAP-A6: the export guards' wire shapes — the two 400 guards
//     (payload grant without a request_id filter; invalid scope value), the
//     pre-flight 413 row-cap message, and the X-Export-Error trailer contract
//     on a committed 200 (byte_limit / row_limit / write_error; the
//     store_error trailer is pinned by
//     TestFIX08MidStreamStoreFailureBurnsGrantAndIsJournalled).
//   - GAP-A7: the L1 RequireOrgPermission(PermRequestsRead) cell for the
//     export and archive-search routes specifically — a sessioned human
//     without any role on the target org is 403'd by the middleware before
//     the handler runs (rm42 pins this only for the LIST route).
//
// These tests PIN current deliberate behavior; a red run is a regression,
// not a license to change production.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/stretchr/testify/require"
)

// gapPinA6SinkStore serves the export stream from a script: one detail row,
// optionally oversized (byte_limit) or followed by the store-level row-cap
// error (row_limit trailer). The handler's emit callback stays the authority
// on byte accounting — the store only supplies rows.
type gapPinA6SinkStore struct {
	*mockStore
	oversize          bool
	tooLargeMidStream bool
}

func (s *gapPinA6SinkStore) StreamRequestExport(ctx context.Context, filters adminstore.RequestListFilters, access adminstore.RequestPayloadAccess, maxRows int, emit func(*adminstore.RequestDetail) error) (int, error) {
	d := &adminstore.RequestDetail{RequestID: "req-1", OrgID: filters.OrgID, HomeRegion: "us"}
	if s.oversize {
		d.Response = json.RawMessage(`{"blob":"` + strings.Repeat("x", maxRequestExportBytes) + `"}`)
		if err := emit(d); err != nil {
			return 1, err
		}
		return 1, nil
	}
	if err := emit(d); err != nil {
		return 1, err
	}
	if s.tooLargeMidStream {
		return 2, adminstore.ErrRequestExportTooLarge
	}
	return 1, nil
}

// gapPinA6FailWriter is an http.ResponseWriter whose body sink is closed:
// every Write fails after the header phase, so a stream committed with a 200
// still cannot deliver a single byte.
type gapPinA6FailWriter struct {
	header http.Header
	code   int
}

func newGapPinA6FailWriter() *gapPinA6FailWriter {
	return &gapPinA6FailWriter{header: make(http.Header)}
}

func (w *gapPinA6FailWriter) Header() http.Header        { return w.header }
func (w *gapPinA6FailWriter) Write([]byte) (int, error)  { return 0, errors.New("sink closed") }
func (w *gapPinA6FailWriter) WriteHeader(code int)       { w.code = code }
func (w *gapPinA6FailWriter) Flush()                     {}
func (w *gapPinA6FailWriter) trailer(name string) string { return w.header.Get(name) }

// GAP-A6: the export guards' wire shapes.
func TestGapPinExportGuardWireShapes(t *testing.T) {
	t.Run("400 grant without request_id filter", func(t *testing.T) {
		store := newMockStore()
		h := New(store, "", "", nil)
		t.Cleanup(h.Stop)
		token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)

		rec := runRootExport(h, "/api/organizations/org-1/requests/export?payload_grant="+token)

		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		require.JSONEq(t, `{"error":"payload grants require request_id filter"}`, rec.Body.String(),
			"a bearer grant must never widen to an org export: the 400 guard shape is part of the contract")
		require.NotContains(t, rec.Header().Get("Content-Type"), "x-ndjson", "no stream may start")
		require.True(t, grantAlive(store, token), "a 400 guard runs before the consume; the token stays redeemable")
	})

	t.Run("400 invalid scope value", func(t *testing.T) {
		store := newMockStore()
		h := New(store, "", "", nil)
		t.Cleanup(h.Stop)
		token := issueExportGrant(t, h, `{"ttl_seconds":60,"org_id":"org-1","request_id":"req-1"}`)

		rec := runRootExport(h, "/api/organizations/org-1/requests/export?request_id=req-1&payload_grant="+token+"&scope=payload.everything")

		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		require.JSONEq(t, `{"error":"invalid payload scope"}`, rec.Body.String(),
			"an unknown scope value is a client error, not a silent fallback")
		require.True(t, grantAlive(store, token), "the scope guard runs before the consume")
	})

	t.Run("413 pre-flight row cap message", func(t *testing.T) {
		store := &fix08SeamStore{mockStore: newMockStore(), overCap: true}
		h := New(store, "", "", nil)
		t.Cleanup(h.Stop)

		rec := runRootExport(h, "/api/organizations/org-1/requests/export")

		require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code, rec.Body.String())
		require.JSONEq(t, `{"error":"export exceeds 1000-row limit; narrow the time range or filters"}`, rec.Body.String(),
			"the 413 wire message tells the caller how to narrow the export")
	})

	t.Run("trailer byte_limit on a committed 200", func(t *testing.T) {
		store := &gapPinA6SinkStore{mockStore: newMockStore(), oversize: true}
		h := New(store, "", "", nil)
		t.Cleanup(h.Stop)

		rec := runRootExport(h, "/api/organizations/org-1/requests/export")

		require.Equal(t, http.StatusOK, rec.Code, "the 200 commits before the oversized row is seen")
		require.Empty(t, rec.Body.String(), "an over-cap row must not deliver a partial line")
		require.Equal(t, "byte_limit", rec.Header().Get("X-Export-Error"))
	})

	t.Run("trailer row_limit when the store walks past the cap", func(t *testing.T) {
		store := &gapPinA6SinkStore{mockStore: newMockStore(), tooLargeMidStream: true}
		h := New(store, "", "", nil)
		t.Cleanup(h.Stop)

		rec := runRootExport(h, "/api/organizations/org-1/requests/export")

		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.Equal(t, "row_limit", rec.Header().Get("X-Export-Error"))
		require.Equal(t, 1, strings.Count(rec.Body.String(), "\n"), "only rows streamed before the cap error are on the wire")
	})

	t.Run("trailer write_error when the client sink fails", func(t *testing.T) {
		store := &gapPinA6SinkStore{mockStore: newMockStore()}
		h := New(store, "", "", nil)
		t.Cleanup(h.Stop)

		w := newGapPinA6FailWriter()
		wrapWithParams(h.apiOrgRequestExport(), "/api/organizations/{id}/requests/export")(
			w, rootPayloadRequest(http.MethodGet, "/api/organizations/org-1/requests/export", ""))

		require.Equal(t, http.StatusOK, w.code, "the 200 commits before the first write fails")
		require.Equal(t, "write_error", w.trailer("X-Export-Error"))
	})
}

// GAP-A7: the L1 middleware cell for the export and archive-search routes.
// A sessioned human with NO role on the target org is 403'd by
// RequireOrgPermission(PermRequestsRead) before any handler logic runs —
// the same no-membership shape rm42 pins for the LIST route.
func TestGapPinL1DeniesExportAndArchiveSearchWithoutOrgRole(t *testing.T) {
	const secret = "test-secret-32-bytes-long-here!!" // #nosec G101 -- test-only HMAC key
	store := newMockStore()
	h := New(store, secret, "", []string{})
	t.Cleanup(h.Stop)
	router := h.SetupRouter()

	call := func(method, path string, root bool) (int, string) {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), method, path, nil)
		req.AddCookie(makeSessionCookie(root, secret))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}

	for _, path := range []string{
		"/api/organizations/org-1/requests/export",
		"/api/organizations/org-1/requests/archive-search?q=secret",
	} {
		code, body := call(http.MethodGet, path, false)
		require.Equal(t, http.StatusForbidden, code, body)
		require.JSONEq(t, `{"error":"insufficient permission for this organization"}`, body,
			"%s: the L1 middleware shape is the no-membership 403", path)
		require.NotContains(t, body, "req-1", "no row data may leak past the middleware")
	}

	// Contrast: the SAME routes pass L1 for a reader member and for root —
	// the 403 above is the permission cell, not a broken route.
	store.orgMembers["admin-1/org-1"] = &adminstore.OrgMembership{UserID: "admin-1", OrgID: "org-1", Role: adminstore.RoleReader}
	for _, path := range []string{
		"/api/organizations/org-1/requests/export",
		"/api/organizations/org-1/requests/archive-search?q=secret",
	} {
		code, body := call(http.MethodGet, path, false)
		require.Equal(t, http.StatusOK, code, body)
		code, body = call(http.MethodGet, path, true)
		require.Equal(t, http.StatusOK, code, body)
	}
}
