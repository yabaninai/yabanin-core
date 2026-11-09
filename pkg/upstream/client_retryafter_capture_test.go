package upstream

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// P1 (RATELIMIT-FALLBACK): a failed attempt's response headers must ride the
// typed *upstream.Error verbatim — the retry scheduler (pkg/retry delayFor)
// and the terminal render path both consume Retry-After hints from this
// carrier. Capture stays verbatim on purpose: parsing, validation and
// clamping live in one place (pkg/retry.After), so every wire form —
// seconds, HTTP-date, garbage — must survive unchanged.

func TestErrorCapturesResponseHeaders_Verbatim(t *testing.T) {
	const httpDate = "Wed, 21 Oct 2026 07:28:00 GMT"

	for _, tc := range []struct {
		name      string
		status    int
		hint      string
		wantHint  string // verbatim expectation; empty string = header omitted by upstream
		wantKnown bool   // false = upstream sent no Retry-After at all
	}{
		{"429 seconds form", http.StatusTooManyRequests, "12", "12", true},
		{"429 http-date form", http.StatusTooManyRequests, httpDate, httpDate, true},
		{"429 garbage form captured verbatim", http.StatusTooManyRequests, "soon", "soon", true},
		{"429 negative form captured verbatim", http.StatusTooManyRequests, "-5", "-5", true},
		{"429 absent", http.StatusTooManyRequests, "", "", false},
		{"502 with hint also captured", http.StatusBadGateway, "30", "30", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.hint != "" {
					w.Header().Set("Retry-After", tc.hint)
				}
				w.Header().Set("X-Request-Id", "req-1")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte("busy"))
			}))
			defer srv.Close()

			client := newTestClient(t, srv)
			_, _, _, err := client.forward(t.Context(), []byte(`{}`), "gpt-4", "test-key", 0, false)
			require.Error(t, err)

			var uerr *Error
			require.ErrorAs(t, err, &uerr)
			require.NotNil(t, uerr.Header, "failed response headers must be captured")
			assert.Equal(t, tc.wantHint, uerr.Header.Get("Retry-After"))
			if !tc.wantKnown {
				assert.Empty(t, uerr.Header.Get("Retry-After"))
			}
			assert.Equal(t, "req-1", uerr.Header.Get("X-Request-Id"))
			assert.Equal(t, tc.status, uerr.Status)
			assert.Equal(t, "busy", uerr.Body)
		})
	}
}

// TestErrorCapturesHeaders_MessageTextUnchanged pins the legacy wire/log
// text: adding the Header field must not perturb the golden-pinned
// "upstream error NNN: body" message shape.
func TestErrorCapturesHeaders_MessageTextUnchanged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("busy"))
	}))
	defer srv.Close()

	client := newTestClient(t, srv)
	_, _, _, err := client.forward(t.Context(), []byte(`{}`), "gpt-4", "test-key", 0, false)
	require.Error(t, err)
	assert.Equal(t, "upstream error 429: busy", err.Error())

	var uerr *Error
	require.ErrorAs(t, err, &uerr)
	assert.Equal(t, "7", uerr.Header.Get("Retry-After"))
}

// TestErrorCapturesHeaders_ThroughWrapping: the fallback chain wraps the
// upstream failure; errors.As must reach the captured headers through the
// wrapping.
func TestErrorCapturesHeaders_ThroughWrapping(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "9")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("busy"))
	}))
	defer srv.Close()

	client := newTestClient(t, srv)
	_, _, _, err := client.forward(t.Context(), []byte(`{}`), "gpt-4", "test-key", 0, false)
	require.Error(t, err)
	wrapped := fmt.Errorf("hop m2: %w", err)

	var uerr *Error
	require.ErrorAs(t, wrapped, &uerr)
	require.NotNil(t, uerr.Header)
	assert.Equal(t, "9", uerr.Header.Get("Retry-After"))
}

// TestStreamCapturesResponseHeaders pins the same capture on the streaming
// path: a stream request answered with a non-200 (here 429 + Retry-After)
// surfaces the typed Error carrying the cloned response headers.
func TestStreamCapturesResponseHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "3")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("rate limited"))
	}))
	defer srv.Close()

	client := newTestClient(t, srv)
	resp, err := client.Stream(t.Context(), []byte(`{"model":"gpt-4","stream":true}`), "test-key")
	require.Error(t, err)
	if resp != nil {
		defer resp.Body.Close()
	}
	assert.Nil(t, resp)

	var uerr *Error
	require.ErrorAs(t, err, &uerr)
	assert.Equal(t, http.StatusTooManyRequests, uerr.Status)
	require.NotNil(t, uerr.Header)
	assert.Equal(t, "3", uerr.Header.Get("Retry-After"))
}

// TestErrorCapturesHeaders_ImmutableAfterClone: the captured header map is a
// clone — mutating it must not race or alias the live response transport
// state, and the gateway may hold it for the remainder of the request.
func TestErrorCapturesHeaders_ImmutableAfterClone(t *testing.T) {
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("busy"))
	}))
	defer srv.Close()

	client := newTestClient(t, srv)
	_, _, _, err := client.forward(t.Context(), []byte(`{}`), "gpt-4", "test-key", 0, false)
	require.Error(t, err)

	var uerr *Error
	require.ErrorAs(t, err, &uerr)
	require.NotNil(t, uerr.Header)
	uerr.Header.Set("Retry-After", "999")
	assert.Equal(t, "999", uerr.Header.Get("Retry-After"),
		"the gateway owns its clone; the transport state is unaffected")
}
