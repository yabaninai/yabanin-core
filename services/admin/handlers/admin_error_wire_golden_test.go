package handlers

// bytes, headers) via the consolidated respondError path. Written before the
// pkg/apierrors consolidation and must pass unchanged after it.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGoldenWire_AdminRespondError_4xxEchoesMessage(t *testing.T) {
	h := &AdminHandlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/admin/api/organizations", nil)

	h.respondError(rec, r, errors.New("boom"), http.StatusBadRequest)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, "{\"error\":\"boom\"}\n", rec.Body.String()) //nolint:testifylint // golden: exact wire bytes incl. trailing newline are the assertion
}

func TestGoldenWire_AdminRespondError_5xxMasked(t *testing.T) {
	h := &AdminHandlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/admin/api/organizations", nil)

	h.respondError(rec, r, errors.New("SQL: secrets"), http.StatusInternalServerError)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, "{\"error\":\"internal server error\"}\n", rec.Body.String()) //nolint:testifylint // golden: exact wire bytes incl. trailing newline are the assertion
}

func TestGoldenWire_AdminInvalidSort_ExactBytes(t *testing.T) {
	rec := httptest.NewRecorder()
	writeInvalidSort(rec)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, "{\"error\":\"invalid_sort\"}\n", rec.Body.String()) //nolint:testifylint // golden: exact wire bytes incl. trailing newline are the assertion
}
