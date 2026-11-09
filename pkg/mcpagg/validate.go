package mcpagg

import (
	"fmt"
	"net/url"
	"regexp"

	"github.com/reireirei/yabanin/pkg/ssrf"
)

// TransportHTTP is the spec label (docs/mcp-gateway.md §4) for the proxied
// MCP-over-HTTP transport. stdio upstream servers are an explicit non-goal.
const TransportHTTP = "http-sse"

// ServerNameRe bounds the registry name: short, lowercase, URL-safe. The DB
// CHECK (0004) enforces the same rule at the schema level; this is the
// API-level check with a better error message.
var ServerNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// MaxServerNameLen caps the name length (the DB text type does not).
const MaxServerNameLen = 64

// MaxAllowedTools caps the per-server tool allow-list length. A longer list
// is a sign of misuse (the allow-list is for narrowing, not mirroring an
// upstream catalog).
const MaxAllowedTools = 256

// ValidateServerName checks the registry name rules.
func ValidateServerName(name string) error {
	if name == "" {
		return fmt.Errorf("mcpagg: name is required")
	}
	if len(name) > MaxServerNameLen {
		return fmt.Errorf("mcpagg: name must be at most %d characters", MaxServerNameLen)
	}
	if !ServerNameRe.MatchString(name) {
		return fmt.Errorf("mcpagg: name must match %s (lowercase letters, digits, '-', '_'; must start with a letter or digit)", ServerNameRe)
	}
	return nil
}

// ValidateTransport accepts only the supported transport label.
func ValidateTransport(transport string) error {
	if transport != TransportHTTP {
		return fmt.Errorf("mcpagg: unsupported transport %q (only %q is supported; stdio upstreams are not proxied)", transport, TransportHTTP)
	}
	return nil
}

// ValidateAllowedTools checks the per-server tool allow-list shape.
func ValidateAllowedTools(tools []string) error {
	if len(tools) > MaxAllowedTools {
		return fmt.Errorf("mcpagg: allowed_tools must have at most %d entries", MaxAllowedTools)
	}
	seen := make(map[string]struct{}, len(tools))
	for _, t := range tools {
		if t == "" {
			return fmt.Errorf("mcpagg: allowed_tools entries must be non-empty")
		}
		if len(t) > 128 {
			return fmt.Errorf("mcpagg: tool name %q is too long (max 128)", t)
		}
		if _, dup := seen[t]; dup {
			return fmt.Errorf("mcpagg: duplicate tool name %q in allowed_tools", t)
		}
		seen[t] = struct{}{}
	}
	return nil
}

// validateServerURL is the SSRF/transport guard core. testMode is the unit-
// test seam (Config.testAllowHTTP): it relaxes BOTH the https-only rule and
// the reserved-IP check so httptest loopback upstreams can be exercised.
// Production always runs with testMode=false. The full guard (https-only +
// allow-list + reserved-IP) is pinned in validate_test.go.
func validateServerURL(urlStr string, allow ssrf.AllowList, testMode bool) error {
	u, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("mcpagg: invalid url: %w", err)
	}
	if !testMode && u.Scheme != "https" {
		return fmt.Errorf("mcpagg: url must be https (got %q)", u.Scheme)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("mcpagg: unsupported url scheme %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("mcpagg: url has no host")
	}
	if u.User != nil {
		return fmt.Errorf("mcpagg: url must not contain credentials")
	}
	if testMode {
		// Test seam: the httptest upstream is loopback by design; the
		// reserved-IP vector is covered in validate_test.go.
		return nil
	}
	if err := allow.ValidateUpstream(host); err != nil {
		return fmt.Errorf("mcpagg: %w", err)
	}
	return nil
}

// ValidateServerURL is the registration-time SSRF/transport guard
// (docs/mcp-gateway.md §6 R1, §7 invariant 1 — first layer). It:
//  1. requires an https:// URL (no cleartext proxying);
//  2. requires a non-empty host without credentials (userinfo would let an
//     attacker smuggle a token into the URL);
//  3. checks the host against the SSRF domain allow-list AND resolves the
//     host, rejecting any reserved-IP answer (metadata endpoints, RFC1918,
//     loopback, link-local, CGNAT).
//
// It does NOT cache the DNS answer: the proxy re-validates at every invoke
// (ValidateURLAtInvoke) because a DNS-rebinding window between registration
// and invoke would otherwise be exploitable.
func ValidateServerURL(urlStr string, allow ssrf.AllowList) error {
	return validateServerURL(urlStr, allow, false)
}

// ValidateURLAtInvoke is the second-layer SSRF guard, run on every tool
// invoke (docs/mcp-gateway.md §6 R1: the rebind window). Same checks as
// ValidateServerURL; the URL comes from the registry row, not from the
// client. allowTestHTTP is the unit-test seam (Config.testAllowHTTP).
func ValidateURLAtInvoke(urlStr string, allow ssrf.AllowList, allowTestHTTP bool) error {
	return validateServerURL(urlStr, allow, allowTestHTTP)
}
