package mcpagg

import (
	"net/http"
	"time"

	"github.com/reireirei/yabanin/pkg/ssrf"
)

// Config holds the aggregator proxy settings for one gateway process.
// Zero values mean defaults (see WithDefaults usage in the gateway wiring).
type Config struct {
	// Enabled gates the whole proxy route group. The gateway sets it from
	// YABANIN_MCP_GATEWAY=1; false (default) = route not mounted.
	Enabled bool

	// AllowedUpstreams is the SSRF domain allow-list for MCP server URLs
	// (exact or *.suffix). Empty disables the allow-list check in
	// ValidateServerURL/ValidateURLAtInvoke — the reserved-IP check still
	// runs, but an empty allow-list means "any public domain", so operators
	// are expected to configure it. The gateway merges it with the existing
	// gateway AllowedUpstreams (provider URLs) so one list covers both.
	AllowedUpstreams []string

	// ConnectTimeout bounds the TCP+TLS handshake to an upstream MCP server.
	ConnectTimeout time.Duration

	// ReadTimeout bounds the full upstream response (SSE body included).
	ReadTimeout time.Duration

	// MaxResponseBytes caps the upstream response body. A tool result is
	// request/response-sized; a larger body is abuse or a misconfigured
	// server (docs/mcp-gateway.md §6 R8).
	MaxResponseBytes int64

	// HTTP is the client used for invokes. When nil the proxy builds one
	// from the timeout settings (with redirects disabled — R1: a redirect to
	// a reserved host must not bypass the guard).
	HTTP *http.Client

	// testAllowHTTP is a unit-test seam: it lets httptest (http://) upstreams
	// pass the https-only rule. The production gateway NEVER sets it — it is
	// unexported, so only tests in this package can. The https-only invariant
	// itself is pinned in validate_test.go.
	testAllowHTTP bool
}

// NewDefaultConfig returns a Config with safe defaults and Enabled=false.
func NewDefaultConfig() Config {
	return Config{
		ConnectTimeout:   10 * time.Second,
		ReadTimeout:      60 * time.Second,
		MaxResponseBytes: 8 * 1024 * 1024,
	}
}

// Client returns the HTTP client to use for invokes, building one from the
// timeout settings when HTTP is nil. Redirects are disabled: following a
// Location header to a host that was never SSRF-checked would be a guard
// bypass (docs/mcp-gateway.md §6 R1).
//
// with the dial-time reserved-IP guard enabled: a DNS rebinding between
// ValidateURLAtInvoke and the connect is rejected at dial time. The
// testAllowHTTP seam disables the guard together with the https-only rule,
// so httptest loopback upstreams keep working (production never sets it).
func (c Config) Client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	transport := ssrf.NewTransport(ssrf.TransportOptions{
		Proxy:                 http.ProxyFromEnvironment,
		DialTimeout:           c.ConnectTimeout,
		TLSHandshakeTimeout:   c.ConnectTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConns:          16,
		IdleConnTimeout:       30 * time.Second,
		GuardDialedIP:         !c.testAllowHTTP,
	})
	return &http.Client{
		Transport: transport,
		Timeout:   c.ReadTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
