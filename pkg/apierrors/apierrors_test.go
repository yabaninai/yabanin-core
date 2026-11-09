package apierrors

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestE_ErrorAndChaining(t *testing.T) {
	e := New(http.StatusBadRequest, TypeInvalidRequest, "bad").WithCode("invalid_json").WithParam("body")
	assert.Equal(t, "bad", e.Error())
	assert.Equal(t, http.StatusBadRequest, e.Status)
	assert.Equal(t, "invalid_json", e.Code)
	assert.Equal(t, "body", e.Param)

	var nilE *E
	assert.Empty(t, nilE.Error())
	assert.Empty(t, GatewayCode(nilE))
}

func TestGatewayCode_Classification(t *testing.T) {
	cases := []struct {
		name string
		e    *E
		want string
	}{
		{"code wins", &E{Type: TypeRateLimitExceeded, Code: "budget_exceeded"}, "budget_exceeded"},
		{"standard type is not a code", &E{Type: TypeInvalidRequest}, ""},
		{"non-standard type becomes code", &E{Type: "guard_denied"}, "guard_denied"},
		{"empty type", &E{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, GatewayCode(tc.e))
		})
	}
}

func TestWriteOpenAI_HeadersStatusAndBody(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteOpenAI(rec, http.StatusBadRequest, New(http.StatusBadRequest, TypeInvalidRequest, "messages is required"))

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "application/json; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "{\"error\":{\"message\":\"messages is required\",\"type\":\"invalid_request_error\"}}\n", rec.Body.String()) //nolint:testifylint // golden-parity: exact bytes incl. field order and trailing newline

	rec = httptest.NewRecorder()
	WriteOpenAI(rec, http.StatusTooManyRequests, New(0, TypeRateLimitExceeded, "slow").WithCode("rate_limit_hit"))
	assert.Equal(t, "{\"error\":{\"message\":\"slow\",\"type\":\"rate_limit_exceeded\",\"code\":\"rate_limit_hit\"}}\n", rec.Body.String()) //nolint:testifylint // golden-parity: exact bytes are the assertion
}

func TestMarshalOpenAI_ParamOmittedWhenEmpty(t *testing.T) {
	b, err := MarshalOpenAI(New(0, TypeAPI, "x").WithParam("model"))
	require.NoError(t, err)
	assert.JSONEq(t, `{"error":{"message":"x","type":"api_error","param":"model"}}`, string(b))
}

func TestSSEErrorFrame_ExactBytes(t *testing.T) {
	frame := SSEErrorFrame(&E{Type: "upstream_error", Message: "boom"})
	assert.Equal(t, "data: {\"error\":{\"message\":\"boom\",\"type\":\"upstream_error\"}}\n\n", string(frame))
}

func TestAnthropic_TypeMappingRetryAndPrefix(t *testing.T) {
	out, hdr := Anthropic(http.StatusServiceUnavailable, &E{Type: TypeAPI, Message: "down"})
	assert.Equal(t, `{"type":"error","error":{"type":"overloaded_error","message":"down"}}`, string(out)) //nolint:testifylint // golden-parity: exact bytes are the assertion
	assert.Equal(t, "true", hdr.Get("x-should-retry"))

	out, hdr = Anthropic(http.StatusForbidden, &E{Type: "guard_denied", Message: "blocked"})
	assert.Equal(t, `{"type":"error","error":{"type":"permission_error","message":"[guard_denied] blocked"}}`, string(out)) //nolint:testifylint // golden-parity: exact bytes are the assertion
	assert.Equal(t, "false", hdr.Get("x-should-retry"))

	// 404: not retryable, no gateway code → header absent.
	_, hdr = Anthropic(http.StatusNotFound, &E{Type: TypeNotFound, Message: "nope"})
	assert.Empty(t, hdr.Get("x-should-retry"))
}

func TestResponses_Nullability(t *testing.T) {
	out := Responses(&E{Type: TypeInvalidRequest, Message: "bad", Code: "invalid_json"})
	assert.Equal(t, `{"error":{"message":"bad","type":"invalid_request_error","param":null,"code":"invalid_json"}}`, string(out)) //nolint:testifylint // golden-parity: exact bytes are the assertion

	out = Responses(&E{Type: TypeInvalidRequest, Message: "bad", Param: "model"})
	assert.Equal(t, `{"error":{"message":"bad","type":"invalid_request_error","param":"model","code":null}}`, string(out)) //nolint:testifylint // golden-parity: exact bytes are the assertion

	var env struct {
		Error struct {
			Param json.RawMessage `json:"param"`
			Code  json.RawMessage `json:"code"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(Responses(nil), &env))
	assert.Equal(t, "null", string(env.Error.Param))
	assert.Equal(t, "null", string(env.Error.Code))
}

func TestAdmin_Envelope(t *testing.T) {
	assert.Equal(t, AdminError{Error: "boom"}, Admin(&E{Message: "boom"}))
	assert.Equal(t, AdminError{}, Admin(nil))
}
