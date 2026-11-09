package cli

// endpoint error body (status, body, headers). Written before the
// pkg/apierrors consolidation and must pass unchanged after it.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGoldenWire_SSEErrorFrame_ExactBytes(t *testing.T) {
	rec := httptest.NewRecorder()
	writeSSEError(rec, "upstream_error", "boom")

	assert.Equal(t, "data: {\"error\":{\"message\":\"boom\",\"type\":\"upstream_error\"}}\n\ndata: [DONE]\n\n", rec.Body.String())
}

func TestGoldenWire_ResponsesEndpointError_ShapeStatusHeaders(t *testing.T) {
	cases := []struct {
		name          string
		status        int
		errType       string
		code          string
		message       string
		wantStatus    int
		wantType      string
		wantParamNull bool
		wantCodeNull  bool
	}{
		{"explicit", http.StatusForbidden, "permission_denied_error", "guard_denied", "denied",
			http.StatusForbidden, "permission_denied_error", false, false},
		{"defaults applied", 0, "", "invalid_json", "bad body",
			http.StatusBadRequest, "invalid_request_error", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeResponsesError(rec, tc.status, tc.errType, tc.code, tc.message)

			assert.Equal(t, tc.wantStatus, rec.Code)
			assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

			var env struct {
				Error struct {
					Message string          `json:"message"`
					Type    string          `json:"type"`
					Param   json.RawMessage `json:"param"`
					Code    json.RawMessage `json:"code"`
				} `json:"error"`
			}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env), rec.Body.String())
			assert.Equal(t, tc.message, env.Error.Message)
			assert.Equal(t, tc.wantType, env.Error.Type)
			if tc.wantParamNull {
				assert.Equal(t, "null", string(env.Error.Param), "param key must exist even when null")
			} else {
				assert.Equal(t, "null", string(env.Error.Param))
			}
			if tc.wantCodeNull {
				assert.Equal(t, "null", string(env.Error.Code))
			} else {
				assert.Equal(t, "\""+tc.code+"\"", string(env.Error.Code))
			}
		})
	}
}
