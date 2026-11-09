package provider

import (
	"net"
	"net/url"
	"strings"
)

// trustedExactHostPin returns the D-4 TrustedExactHosts predicate for a
// token-exchange transport (ssrf.TransportOptions.TrustedExactHosts). The
// reserved-range dial verdict is waived ONLY for the exact IP-literal form
// of an operator-configured authority host. Hostnames are never waived:
// their DNS answers are not operator-controlled, so the DNS-rebinding
// window stays closed (same semantics as ssrf.AllowList.TrustsExactPin).
//
// A nil-return equivalent (no literal pins configured) yields a predicate
// that always refuses, i.e. the guarded dialer keeps its unconditional
// reserved-range refusal.
func trustedExactHostPin(authorities ...string) func(host string) bool {
	pins := make(map[string]struct{}, len(authorities))
	for _, authority := range authorities {
		parsed, err := url.Parse(authority)
		if err != nil {
			continue
		}
		host := strings.ToLower(parsed.Hostname())
		if host == "" || net.ParseIP(host) == nil {
			continue
		}
		pins[host] = struct{}{}
	}
	return func(host string) bool {
		_, ok := pins[strings.ToLower(host)]
		return ok
	}
}
