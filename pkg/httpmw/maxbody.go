package httpmw

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// MaxBody returns a middleware that limits the request body size to maxBytes bytes.
// If the body exceeds the limit, the handler receives a *http.MaxBytesError when
// reading from r.Body (e.g. via json.NewDecoder.Decode or io.ReadAll), and the client
// gets a 413 Request Entity Too Large response with a clean JSON error message.
//
// The middleware works by wrapping r.Body in http.MaxBytesReader. It does NOT read
// the body itself — that is left to the handler (or any downstream middleware). This
// means it is fully compatible with json.Decoder, io.ReadAll, or any streaming reader.
func MaxBody(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}

// MaxBodyByPrefix is MaxBody with per-path-prefix overrides: requests whose
// URL path starts with one of the prefixes get prefixMaxBytes, everything
// ceiling while every other route keeps it).
func MaxBodyByPrefix(maxBytes, prefixMaxBytes int64, prefixes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			limit := maxBytes
			for _, p := range prefixes {
				if strings.HasPrefix(r.URL.Path, p) {
					limit = prefixMaxBytes
					break
				}
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
			next.ServeHTTP(w, r)
		})
	}
}

// MaxBytesError is the error returned when a request body exceeds the configured limit.
// It wraps the standard library's http.MaxBytesError sentinel and provides a clean
// human-readable message for logging.
type MaxBytesError struct {
	Limit int64
	Err   error
}

func (e *MaxBytesError) Error() string {
	return fmt.Sprintf("request body too large: limit=%d bytes", e.Limit)
}

func (e *MaxBytesError) Unwrap() error {
	return e.Err
}

// IsMaxBytesError reports whether err is a MaxBytesError wrapping the standard
// library's http.MaxBytesError sentinel. It matches both our custom wrapper type
// and raw *http.MaxBytesError values.
func IsMaxBytesError(err error) bool {
	if err == nil {
		return false
	}
	var maxErr *http.MaxBytesError
	return errors.As(err, &maxErr)
}
