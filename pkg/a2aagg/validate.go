// Package a2aagg implements the A2A (Agent2Agent protocol) agent registry
// and gateway-side proxy — the agent-to-agent counterpart of pkg/mcpagg.
// An org registers external A2A agents (https:// base URLs); the org's
// agent principals (yag_ keys) then send them messages through the gateway
// with the same discipline as MCP tool calls: SSRF guarding, pre-egress
// param guards, bounded timeouts and an audit trail.
//
// v1 scope (docs/a2a-gateway.md): the JSON-RPC message/send method
// (request/response). Streaming (message/stream) and push notifications are
// a later increment. The feature is OFF by default: the gateway mounts the
// proxy route only when YABANIN_A2A_GATEWAY=1, and every agent row is inert
// until enabled.
package a2aagg

import (
	"fmt"
	"net/url"
	"regexp"

	"github.com/reireirei/yabanin/pkg/ssrf"
)

// AgentNameRe bounds the registry name: short, lowercase, URL-safe. The DB
// CHECK (0015) enforces the same rule at the schema level; this is the
// API-level check with a better error message.
var AgentNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// MaxAgentNameLen caps the name length (the DB text type does not).
const MaxAgentNameLen = 64

// ValidateAgentName checks the registry name rules.
func ValidateAgentName(name string) error {
	if name == "" {
		return fmt.Errorf("a2aagg: name is required")
	}
	if len(name) > MaxAgentNameLen {
		return fmt.Errorf("a2aagg: name must be at most %d characters", MaxAgentNameLen)
	}
	if !AgentNameRe.MatchString(name) {
		return fmt.Errorf("a2aagg: name must match %s (lowercase letters, digits, '-', '_'; must start with a letter or digit)", AgentNameRe)
	}
	return nil
}

// validateAgentURL is the SSRF/transport guard core. testMode is the
// unit-test seam (Config.testAllowHTTP): it relaxes BOTH the https-only
// rule and the reserved-IP check so httptest loopback upstreams can be
// exercised. Production always runs with testMode=false; the full guard is
// pinned in validate_test.go.
func validateAgentURL(urlStr string, allow ssrf.AllowList, testMode bool) error {
	u, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("a2aagg: invalid url: %w", err)
	}
	if !testMode && u.Scheme != "https" {
		return fmt.Errorf("a2aagg: url must be https (got %q)", u.Scheme)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("a2aagg: unsupported url scheme %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("a2aagg: url has no host")
	}
	if u.User != nil {
		return fmt.Errorf("a2aagg: url must not contain credentials")
	}
	if testMode {
		// Test seam: the httptest upstream is loopback by design; the
		// reserved-IP vector is covered in validate_test.go.
		return nil
	}
	if err := allow.ValidateUpstream(host); err != nil {
		return fmt.Errorf("a2aagg: %w", err)
	}
	return nil
}

// ValidateAgentURL is the registration-time SSRF/transport guard (first
// layer): https-only, no credentials in the URL, allow-list + reserved-IP
// resolution. It does NOT cache the DNS answer — the proxy re-validates at
// every send (ValidateURLAtSend) because a DNS-rebinding window between
// registration and send would otherwise be exploitable.
func ValidateAgentURL(urlStr string, allow ssrf.AllowList) error {
	return validateAgentURL(urlStr, allow, false)
}

// ValidateURLAtSend is the second-layer SSRF guard, run on every message
// send. allowTestHTTP is the unit-test seam (Config.testAllowHTTP).
func ValidateURLAtSend(urlStr string, allow ssrf.AllowList, allowTestHTTP bool) error {
	return validateAgentURL(urlStr, allow, allowTestHTTP)
}
