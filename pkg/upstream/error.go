package upstream

import (
	"fmt"
	"net/http"
)

// Error is the typed upstream HTTP failure returned by Client.Stream and the
// forward path on any non-200 upstream status. The gateway maps Status to a
// client-facing status without parsing error strings.
//
// The message deliberately keeps the historical "upstream error NNN: body"
// shape: logs, events and golden tests match on it.
type Error struct {
	// Status is the upstream HTTP status code.
	Status int
	// Body is the raw upstream response body (already fully read; the
	// original body is closed by the client).
	Body string
	// Header carries the failed response's headers, cloned so the value
	// stays valid after the response body/connection is released (e.g.
	// Retry-After on a 429 or the provider's request-id). Nil for failures
	// that never produced a readable response or on success paths.
	Header http.Header
}

// Error implements the error interface with the legacy wire/log text.
func (e *Error) Error() string {
	if e == nil {
		return "upstream error <nil>"
	}
	if e.Body != "" {
		return fmt.Sprintf("upstream error %d: %s", e.Status, e.Body)
	}
	return fmt.Sprintf("upstream error %d", e.Status)
}

// TranslateError reports a 200 response whose provider-native body could not
// be converted into the OpenAI response contract (e.g. a malformed Anthropic
// Messages payload). Returning the raw body would leak a foreign schema to an
// OpenAI client, so the caller receives a typed failure the gateway maps to
// 502 upstream_error.
type TranslateError struct {
	// Provider is the adapter name that failed the conversion.
	Provider string
	// Err is the underlying parse/translation failure.
	Err error
}

// Error implements the error interface.
func (e *TranslateError) Error() string {
	if e == nil {
		return "upstream: translate response: <nil>"
	}
	if e.Provider != "" {
		return fmt.Sprintf("upstream %s: translate response: %v", e.Provider, e.Err)
	}
	return fmt.Sprintf("upstream: translate response: %v", e.Err)
}

// Unwrap exposes the underlying translation failure to errors.Is/As.
func (e *TranslateError) Unwrap() error { return e.Err }
