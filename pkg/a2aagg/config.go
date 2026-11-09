package a2aagg

import (
	"net/http"
	"time"

	"github.com/reireirei/yabanin/pkg/ssrf"
)

// Config holds the A2A proxy settings for one gateway process. Zero values
// mean defaults; the gateway sets Enabled from YABANIN_A2A_GATEWAY=1 and the
// allow-list from YABANIN_A2A_ALLOWED_UPSTREAMS (mirroring the MCP wiring).
type Config struct {
	Enabled          bool
	AllowedUpstreams []string

	ConnectTimeout   time.Duration
	ReadTimeout      time.Duration
	MaxResponseBytes int64

	HTTP *http.Client

	// testAllowHTTP is a unit-test seam: it lets httptest (http://) upstreams
	// pass the https-only rule. The production gateway NEVER sets it — it is
	// unexported, so only tests in this package can. The https-only invariant
	// itself is pinned in validate_test.go.
	testAllowHTTP bool
}

// NewDefaultConfig returns a Config with safe defaults and Enabled=false.
// A2A message/send round-trips are agent-work sized; the read timeout is a
// little tighter than MCP's (agents should answer, not stream).
func NewDefaultConfig() Config {
	return Config{
		ConnectTimeout:   10 * time.Second,
		ReadTimeout:      30 * time.Second,
		MaxResponseBytes: 8 * 1024 * 1024,
	}
}

// Client returns the HTTP client for sends, building one from the timeout
// settings when HTTP is nil. Redirects are disabled: following a Location
// header to a host that was never SSRF-checked would be a guard bypass
// (same invariant as pkg/mcpagg).
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
