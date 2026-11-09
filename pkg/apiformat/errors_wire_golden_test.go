package apiformat

// (exact body bytes, headers). Written before the pkg/apierrors consolidation
// and must pass unchanged after it — they pin the wire.

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGoldenWire_ToAnthropicError_BodyBytesAndHeaders(t *testing.T) {
	body := []byte(`{"error":{"message":"nope","type":"invalid_request_error"}}`)

	cases := []struct {
		name      string
		status    int
		wantBody  string
		wantRetry string // "" = header absent
	}{
		{"400", http.StatusBadRequest,
			`{"type":"error","error":{"type":"invalid_request_error","message":"nope"}}`, ""},
		{"401", http.StatusUnauthorized,
			`{"type":"error","error":{"type":"authentication_error","message":"nope"}}`, ""},
		{"403", http.StatusForbidden,
			`{"type":"error","error":{"type":"permission_error","message":"nope"}}`, ""},
		{"404", http.StatusNotFound,
			`{"type":"error","error":{"type":"not_found_error","message":"nope"}}`, ""},
		{"413", http.StatusRequestEntityTooLarge,
			`{"type":"error","error":{"type":"request_too_large","message":"nope"}}`, ""},
		{"429", http.StatusTooManyRequests,
			`{"type":"error","error":{"type":"rate_limit_error","message":"nope"}}`, ""},
		{"502 retry", http.StatusBadGateway,
			`{"type":"error","error":{"type":"api_error","message":"nope"}}`, "true"},
		{"503 overloaded retry", http.StatusServiceUnavailable,
			`{"type":"error","error":{"type":"overloaded_error","message":"nope"}}`, "true"},
		{"504 retry", http.StatusGatewayTimeout,
			`{"type":"error","error":{"type":"api_error","message":"nope"}}`, "true"},
		{"500", http.StatusInternalServerError,
			`{"type":"error","error":{"type":"api_error","message":"nope"}}`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, hdr := ToAnthropicError(tc.status, body)
			assert.Equal(t, tc.wantBody, string(out))
			assert.Equal(t, tc.wantRetry, hdr.Get("x-should-retry"))
			_, hasCT := hdr["Content-Type"]
			assert.False(t, hasCT, "adapter must not set Content-Type; the writer owns it")
		})
	}
}

func TestGoldenWire_ToAnthropicError_GatewayCodePrefixAndNoRetry(t *testing.T) {
	out, hdr := ToAnthropicError(http.StatusForbidden, []byte(`{"error":{"message":"blocked","type":"guard_denied"}}`))
	assert.Equal(t, `{"type":"error","error":{"type":"permission_error","message":"[guard_denied] blocked"}}`, string(out)) //nolint:testifylint // golden: exact wire bytes are the assertion
	assert.Equal(t, "false", hdr.Get("x-should-retry"))

	out, hdr = ToAnthropicError(http.StatusTooManyRequests,
		[]byte(`{"error":{"message":"slow","type":"rate_limit_exceeded","code":"budget_exceeded"}}`))
	assert.Equal(t, `{"type":"error","error":{"type":"rate_limit_error","message":"[budget_exceeded] slow"}}`, string(out)) //nolint:testifylint // golden: exact wire bytes are the assertion
	assert.Equal(t, "false", hdr.Get("x-should-retry"))
}

func TestGoldenWire_ToResponsesError_BodyBytes(t *testing.T) {
	out := ToResponsesError(http.StatusBadRequest,
		[]byte(`{"error":{"message":"bad","type":"invalid_request_error","code":"model_not_found"}}`))
	// param normalised to explicit null, code kept, field order message,type,param,code.
	assert.Equal(t, `{"error":{"message":"bad","type":"invalid_request_error","param":null,"code":"model_not_found"}}`, string(out)) //nolint:testifylint // golden: exact wire bytes are the assertion

	out = ToResponsesError(http.StatusBadRequest,
		[]byte(`{"error":{"message":"bad","type":"invalid_request_error","param":"model"}}`))
	assert.Equal(t, `{"error":{"message":"bad","type":"invalid_request_error","param":"model","code":null}}`, string(out)) //nolint:testifylint // golden: exact wire bytes are the assertion

	// Bare gateway message with no type/code round-trips with explicit nulls.
	out = ToResponsesError(http.StatusBadRequest, []byte(`{"error":{"message":"boom"}}`))
	assert.Equal(t, `{"error":{"message":"boom","type":"","param":null,"code":null}}`, string(out)) //nolint:testifylint // golden: exact wire bytes are the assertion

	require.NotPanics(t, func() {
		_ = ToResponsesError(http.StatusBadRequest, []byte(`not-json`))
	})
}
