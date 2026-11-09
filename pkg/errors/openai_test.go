package errors

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWrite_SetsHeadersAndBody(t *testing.T) {
	rec := httptest.NewRecorder()
	Write(rec, http.StatusBadRequest, ErrorCodeInvalidRequest, "messages is required")

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "application/json; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))

	var env APIError
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env))
	assert.Equal(t, "messages is required", env.Error.Message)
	assert.Equal(t, ErrorCodeInvalidRequest, env.Error.Type)
	assert.Nil(t, env.Error.Param)
	assert.Nil(t, env.Error.Code)
}

func TestWriteWithCode_IncludesCode(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteWithCode(rec, http.StatusTooManyRequests, ErrorCodeRateLimitExceeded, "slow down", "rate_limit_hit")

	assert.Equal(t, http.StatusTooManyRequests, rec.Code)

	var env APIError
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env))
	assert.Equal(t, "slow down", env.Error.Message)
	assert.Equal(t, ErrorCodeRateLimitExceeded, env.Error.Type)
	require.NotNil(t, env.Error.Code)
	assert.Equal(t, "rate_limit_hit", *env.Error.Code)
}

func TestWriteAPIError_RoundTrips(t *testing.T) {
	param := "messages[0].role"
	code := "invalid_role"
	apiErr := &APIError{
		Error: ErrorResponse{
			Message: `invalid role "wizard"`,
			Type:    ErrorCodeInvalidRequest,
			Param:   &param,
			Code:    &code,
		},
	}

	rec := httptest.NewRecorder()
	WriteAPIError(rec, http.StatusBadRequest, apiErr)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var env APIError
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env))
	assert.Equal(t, *apiErr, env)
}

func TestMapUpstreamStatus_AllClasses(t *testing.T) {
	cases := []struct {
		name        string
		upstream    int
		wantStatus  int
		wantErrType string
	}{
		{"upstream 401 masked to 502", 401, http.StatusBadGateway, ErrorCodeAPI},
		{"upstream 403 stays 403", 403, http.StatusForbidden, ErrorCodePermissionDenied},
		{"upstream 404 maps to 404", 404, http.StatusNotFound, ErrorCodeNotFound},
		{"upstream 429 throttled", 429, http.StatusTooManyRequests, ErrorCodeRateLimitExceeded},
		{"upstream 400 invalid_request", 400, http.StatusBadRequest, ErrorCodeInvalidRequest},
		{"upstream 405 invalid_request", 405, http.StatusBadRequest, ErrorCodeInvalidRequest},
		{"upstream 418 invalid_request (4xx)", 418, http.StatusBadRequest, ErrorCodeInvalidRequest},
		{"upstream 500 api_error", 500, http.StatusBadGateway, ErrorCodeAPI},
		{"upstream 502 api_error", 502, http.StatusBadGateway, ErrorCodeAPI},
		{"upstream 503 api_error", 503, http.StatusBadGateway, ErrorCodeAPI},
		{"upstream 200 falls through to 500 api_error", 200, http.StatusInternalServerError, ErrorCodeAPI},
		{"upstream 0 falls through", 0, http.StatusInternalServerError, ErrorCodeAPI},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, et := MapUpstreamStatus(tc.upstream)
			assert.Equal(t, tc.wantStatus, s)
			assert.Equal(t, tc.wantErrType, et)
		})
	}
}

func TestWrite_401AuthenticationErrorShape(t *testing.T) {
	rec := httptest.NewRecorder()
	Write(rec, http.StatusUnauthorized, ErrorCodeAuthentication, "missing Authorization")

	var env APIError
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env))
	assert.Equal(t, "missing Authorization", env.Error.Message)
	assert.Equal(t, ErrorCodeAuthentication, env.Error.Type)
}

func TestWrite_503ServiceUnavailableShape(t *testing.T) {
	rec := httptest.NewRecorder()
	Write(rec, http.StatusServiceUnavailable, ErrorCodeServiceUnavailable,
		"upstream provider temporarily unavailable, please retry later")

	var env APIError
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env))
	assert.Equal(t, ErrorCodeServiceUnavailable, env.Error.Type)
}
