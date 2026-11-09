package apierrors

import (
	"encoding/json"
	"net/http"
)

// Anthropic renders e as an Anthropic error document plus the headers A1 §8.1
// requires: {"type":"error","error":{"type","message"}} with the gateway code
// prefixed to the message ("[code] message") and x-should-retry set to
// "false" for no-retry gateway codes, "true" for retryable statuses, absent
// otherwise. The caller owns Content-Type and WriteHeader.
func Anthropic(status int, e *E) ([]byte, http.Header) {
	msg := e.Message
	code := GatewayCode(e)
	if code != "" {
		msg = "[" + code + "] " + msg
	}
	out, err := json.Marshal(struct {
		Type  string `json:"type"`
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}{
		Type: "error",
		Error: struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		}{
			Type:    anthropicErrorType(status),
			Message: msg,
		},
	})
	if err != nil {
		out = []byte(`{"type":"error","error":{"type":"api_error","message":"encode failed"}}`)
	}
	h := make(http.Header)
	if code != "" {
		if _, deny := noRetryCodes[code]; deny {
			h.Set("x-should-retry", "false")
		}
	}
	if h.Get("x-should-retry") == "" && retryableStatus(status) {
		h.Set("x-should-retry", "true")
	}
	return out, h
}

func retryableStatus(status int) bool {
	return status == http.StatusBadGateway ||
		status == http.StatusServiceUnavailable ||
		status == http.StatusGatewayTimeout
}

func anthropicErrorType(status int) string {
	switch status {
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		return "invalid_request_error"
	case http.StatusUnauthorized:
		return "authentication_error"
	case http.StatusForbidden:
		return "permission_error"
	case http.StatusNotFound:
		return "not_found_error"
	case http.StatusRequestEntityTooLarge:
		return "request_too_large"
	case http.StatusTooManyRequests:
		return "rate_limit_error"
	case http.StatusServiceUnavailable:
		return "overloaded_error"
	default:
		if status >= 500 {
			return "api_error"
		}
		return "invalid_request_error"
	}
}
