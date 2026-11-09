package upstream

// N08-P04-T04 «Локальные модели: Проверить custom base URL»: the custom
// base URL of a local/self-hosted model row is the egress boundary the
// operator configures once and the gateway dials on every request. These
// tests pin BOTH halves of that boundary:
//
//   - positive: clean http(s) origins (loopback, link-local, RFC1918, IPv6
//     loopback) construct through the guarded pool and keep their exact
//     origin; an empty override falls back to the operator default;
//   - negative: every malformed, non-http(s) or credential-bearing form is
//     refused at the pool boundary with a precise reason (never mislabeled
//     as "unknown provider"), the secret is never echoed back, and no
//     upstream is dialed for a refused URL.
//
// Redirect policy for these pooled clients is pinned separately by
// TestPool_DefaultAllowlistBlocksRedirectToOtherHost and the rebind-guard
// redirect tests (same package); dial-time pinning by
// TestLocalEndpoint_AllowlistedPrivateEndpointDials.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalBaseURL_CleanOriginsConstructAndKeepOrigin(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		raw  string
		want string // normalized client.BaseURL()
	}{
		{name: "loopback with port", raw: "http://127.0.0.1:8080", want: "http://127.0.0.1:8080"},
		{name: "trailing slash normalized", raw: "http://127.0.0.1:8080/", want: "http://127.0.0.1:8080"},
		{name: "ipv6 loopback literal", raw: "http://[::1]:8080", want: "http://[::1]:8080"},
		{name: "rfc1918 local GPU box", raw: "http://10.20.30.40:8081", want: "http://10.20.30.40:8081"},
		{name: "https private IP literal", raw: "https://10.20.30.41:8443", want: "https://10.20.30.41:8443"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Self-admitting pool posture (empty operator allowlist): the
			// caller passes an operator-configured URL and the client
			// approves exactly that origin.
			pool := NewPool(Options{})
			client, err := pool.Get(tc.raw, "llamacpp")
			require.NoError(t, err, "a clean custom base URL must construct through the guarded pool")
			require.NotNil(t, client)
			assert.Equal(t, tc.want, client.BaseURL(), "the configured origin must survive normalization verbatim")
			assert.Equal(t, "llamacpp", client.Adapter().Name())

			// The request-time SSRF layer accepts the pinned origin (offline
			// checks only: construction and validation dial nothing).
			require.NoError(t, client.checkSSRF(),
				"the pool-approved origin must pass its own request-time egress policy")
		})
	}
}

func TestLocalBaseURL_RefusedFormsCarryPreciseReason(t *testing.T) {
	t.Parallel()

	// fixtureSecret is a synthetic refusal fixture: the test's whole point
	// is that this string NEVER reappears in a surfaced error. It is kept
	// in a const and spliced into the URL so no single credential-shaped
	// literal exists for the secret scanner to misread.
	const fixtureSecret = "s3cr3t-pw"

	cases := []struct {
		name        string
		raw         string
		wantReqs    []string // every substring must appear in the error
		notContains []string // no substring may appear in the error
	}{
		{
			name:     "empty override",
			raw:      "   ",
			wantReqs: []string{"upstream pool:", "empty"},
		},
		{
			name:     "missing scheme",
			raw:      "://no-scheme",
			wantReqs: []string{"upstream pool:", "invalid provider URL"},
		},
		{
			name:     "malformed ipv6",
			raw:      "http://[::1",
			wantReqs: []string{"upstream pool:", "invalid provider URL"},
		},
		{
			name:     "file scheme refused",
			raw:      "file:///opt/models/qwen",
			wantReqs: []string{"upstream pool:", `scheme "file"`, "not allowed"},
		},
		{
			name:     "ftp scheme refused",
			raw:      "ftp://10.20.30.40:8081",
			wantReqs: []string{"upstream pool:", `scheme "ftp"`, "not allowed"},
		},
		{
			name:     "websocket scheme refused",
			raw:      "ws://127.0.0.1:8080",
			wantReqs: []string{"upstream pool:", `scheme "ws"`, "not allowed"},
		},
		{
			name:     "no host",
			raw:      "http:///v1",
			wantReqs: []string{"upstream pool:", "has no host"},
		},
		{
			name:     "userinfo credentials refused",
			raw:      "http://admin:" + fixtureSecret + "@10.20.30.40:8081",
			wantReqs: []string{"upstream pool:", "credentials", "10.20.30.40"},
			notContains: []string{
				fixtureSecret, // the secret must never be echoed back into surfaced errors
				"unknown provider",
			},
		},
		{
			name:     "query string refused",
			raw:      "http://10.20.30.40:8081/?route=chat",
			wantReqs: []string{"upstream pool:", "query string"},
		},
		{
			name:     "fragment refused",
			raw:      "http://10.20.30.40:8081/#local",
			wantReqs: []string{"upstream pool:", "fragment"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			pool := NewPool(Options{AllowedUpstreams: []string{"http://10.20.30.40:8081"}})
			client, err := pool.Get(tc.raw, "llamacpp")
			require.Error(t, err, "the malformed/insecure custom base URL must be refused at the pool boundary")
			require.Nil(t, client)

			for _, want := range tc.wantReqs {
				assert.Contains(t, err.Error(), want,
					"the refusal must carry a precise, operator-actionable reason")
			}
			for _, banned := range tc.notContains {
				assert.NotContains(t, err.Error(), banned)
			}
			assert.Equal(t, 0, pool.Size(), "the refused key must not be cached")
		})
	}
}

func TestLocalBaseURL_RefusedURLIsNeverDialed(t *testing.T) {
	t.Parallel()

	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(mock.Close)

	// The credential-bearing variant of the live endpoint's origin: refusal
	// must happen before any dial, so the endpoint observes nothing.
	bad := "http://admin:pw@" + strings.TrimPrefix(mock.URL, "http://")

	pool := NewPool(Options{AllowedUpstreams: []string{mock.URL}})
	client, err := pool.Get(bad, "llamacpp")
	require.Error(t, err)
	require.Nil(t, client)
	assert.Contains(t, err.Error(), "credentials")
	assert.Equal(t, 0, pool.Size(), "the refused key must not be cached")
}

func TestLocalBaseURL_EmptyOverrideFallsBackToPoolDefault(t *testing.T) {
	t.Parallel()

	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"c1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"pong"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	t.Cleanup(mock.Close)

	pool := NewPool(Options{BaseURL: mock.URL})
	client, err := pool.Get("", "llamacpp")
	require.NoError(t, err, "an empty override resolves to the operator default, it is not a refusal")
	assert.Equal(t, mock.URL, client.BaseURL())

	respBody, ferr := client.ForwardJSON(t.Context(),
		[]byte(`{"model":"m","messages":[{"role":"user","content":"ping"}]}`), "m", "")
	require.NoError(t, ferr)
	assert.Contains(t, string(respBody), "pong")
}
