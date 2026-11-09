package handlers

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateModelAlias_RejectsBadPattern(t *testing.T) {
	h := newTestAdminH(newMockStore())
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/model-aliases", bytes.NewReader([]byte(`{"alias":"has space","target_model":"qwen"}`)))
	rec := httptest.NewRecorder()
	h.CreateModelAlias().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}
