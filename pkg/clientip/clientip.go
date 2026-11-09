package clientip

import (
	"net"
	"strings"
)

// Extract returns the real client IP from the request.
// If trustedProxies is non-empty and the remote address matches one of them
// (IP or CIDR), X-Forwarded-For is walked right to left: every address inside
// trustedProxies is skipped as a proxy hop and the first non-trusted address
// is returned as the client. This prevents a client behind a trusted proxy
// from spoofing its IP by prepending entries to XFF. When every entry is
// trusted, the remote address is used. X-Real-IP is honored as a fallback
// under the same trust rules. Otherwise, headers are ignored and RemoteAddr
// is returned directly.
func Extract(remoteAddr string, xffHeader string, xRealIPHeader string, trustedProxies []string) string {
	if len(trustedProxies) > 0 && isTrustedProxy(remoteAddr, trustedProxies) {
		if xffHeader != "" {
			if client := rightmostUntrustedHop(xffHeader, trustedProxies); client != "" {
				return client
			}
		}
		if xRealIPHeader != "" {
			return strings.TrimSpace(xRealIPHeader)
		}
	}
	return remoteAddr
}

func rightmostUntrustedHop(xff string, trustedProxies []string) string {
	entries := strings.Split(xff, ",")
	for i := len(entries) - 1; i >= 0; i-- {
		entry := strings.TrimSpace(entries[i])
		if entry == "" {
			continue
		}
		if !isTrustedIP(entry, trustedProxies) {
			return entry
		}
	}
	return ""
}

// ParseCIDRs parses a slice of CIDR/IP strings into a list of *net.IPNet and net.IP.
func ParseCIDRs(cidrs []string) ([]*net.IPNet, []net.IP) {
	var networks []*net.IPNet
	var ips []net.IP
	for _, c := range cidrs {
		if _, ipnet, err := net.ParseCIDR(c); err == nil {
			networks = append(networks, ipnet)
		} else if ip := net.ParseIP(c); ip != nil {
			ips = append(ips, ip)
		}
	}
	return networks, ips
}

func isTrustedProxy(remoteAddr string, trustedProxies []string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	return isTrustedIP(host, trustedProxies)
}

func isTrustedIP(addr string, trustedProxies []string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}

	networks, ips := ParseCIDRs(trustedProxies)

	for _, trusted := range ips {
		if trusted.Equal(ip) {
			return true
		}
	}

	for _, n := range networks {
		if n.Contains(ip) {
			return true
		}
	}

	return false
}
