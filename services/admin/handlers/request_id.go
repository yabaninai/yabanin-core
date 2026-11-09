package handlers

import (
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"
)

// requestIDParam returns the request_id path parameter DECODED.
//
// Regression (user finding 2026-09-15): gateway-generated request ids embed
// a slash ("host/counter-000244"). Clients correctly send them percent-
// encoded (%2F); net/http then keeps URL.RawPath set, and chi routes on the
// raw path — so chi.URLParam hands the handler the STILL-ENCODED value and
// every lookup 404s ("not found"), leaving the explorer detail and lineage
// views empty. PathUnescape is a no-op for ids that never needed encoding.
func requestIDParam(r *http.Request) string {
	raw := chi.URLParam(r, "request_id")
	if raw == "" {
		return ""
	}
	if decoded, err := url.PathUnescape(raw); err == nil {
		return decoded
	}
	return raw
}
