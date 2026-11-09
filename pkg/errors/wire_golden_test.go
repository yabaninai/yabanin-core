package errors

// body bytes, headers). These tests existed before the pkg/apierrors
// consolidation and must pass unchanged after it — they pin the wire.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGoldenWire_Write_BodyBytesAndHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	Write(rec, http.StatusBadRequest, ErrorCodeInvalidRequest, "messages is required")

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "application/json; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "{\"error\":{\"message\":\"messages is required\",\"type\":\"invalid_request_error\"}}\n", rec.Body.String()) //nolint:testifylint // golden: exact wire bytes incl. field order and trailing newline are the assertion
}

func TestGoldenWire_WriteWithCode_BodyBytes(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteWithCode(rec, http.StatusTooManyRequests, ErrorCodeRateLimitExceeded, "slow down", "rate_limit_hit")

	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Equal(t, "application/json; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	// param omitted (nil), code present, field order message,type,param,code.
	assert.Equal(t, "{\"error\":{\"message\":\"slow down\",\"type\":\"rate_limit_exceeded\",\"code\":\"rate_limit_hit\"}}\n", rec.Body.String()) //nolint:testifylint // golden: exact wire bytes are the assertion
}

func TestGoldenWire_WriteAPIError_BodyBytesWithParamAndCode(t *testing.T) {
	param := "messages[0].role"
	code := "invalid_role"
	apiErr := &APIError{Error: ErrorResponse{
		Message: `invalid role "wizard"`,
		Type:    ErrorCodeInvalidRequest,
		Param:   &param,
		Code:    &code,
	}}

	rec := httptest.NewRecorder()
	WriteAPIError(rec, http.StatusBadRequest, apiErr)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "application/json; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "{\"error\":{\"message\":\"invalid role \\\"wizard\\\"\",\"type\":\"invalid_request_error\",\"param\":\"messages[0].role\",\"code\":\"invalid_role\"}}\n", rec.Body.String()) //nolint:testifylint // golden: exact wire bytes are the assertion
}

func TestGoldenWire_Write_EmptyParamAndCodeAreOmitted(t *testing.T) {
	rec := httptest.NewRecorder()
	Write(rec, http.StatusUnauthorized, ErrorCodeAuthentication, "missing Authorization")

	body := rec.Body.String()
	require.NotContains(t, body, "param")
	require.NotContains(t, body, "code")
	assert.Equal(t, "{\"error\":{\"message\":\"missing Authorization\",\"type\":\"authentication_error\"}}\n", body) //nolint:testifylint // golden: exact wire bytes are the assertion
}
