package ssrf

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// ReservedCIDRs are IP ranges that should never be reachable as upstream targets.
// Includes RFC 1918 private, link-local, loopback, benchmark, and IANA reserved ranges.
var ReservedCIDRs = []*net.IPNet{
	// Loopback
	mustParseCIDR("127.0.0.0/8"),
	mustParseCIDR("::1/128"),
	// RFC 1918 private networks
	mustParseCIDR("10.0.0.0/8"),
	mustParseCIDR("172.16.0.0/12"),
	mustParseCIDR("192.168.0.0/16"),
	// "This network" (RFC 791 / RFC 1122): 0.0.0.0 as a dial target and the
	mustParseCIDR("0.0.0.0/8"),
	// Link-local
	mustParseCIDR("169.254.0.0/16"),
	mustParseCIDR("fe80::/10"),
	mustParseCIDR("fc00::/7"),
	// Multicast
	mustParseCIDR("224.0.0.0/4"),
	mustParseCIDR("ff00::/8"),
	// Unspecified
	mustParseCIDR("::/128"),
	// IANA reserved / benchmarking
	mustParseCIDR("198.18.0.0/15"),
	mustParseCIDR("100.64.0.0/10"), // CGNAT
	// Cloud provider metadata endpoints (common SSRF targets)
	// AWS/GCP/Azure: 169.254.169.254 covered by link-local 169.254.0.0/16
	// Aliyun: 100.100.0.0/16 covered by CGNAT 100.64.0.0/10
}

// MustParseCIDR is a helper that panics on invalid CIDR (only used at init time).
func mustParseCIDR(s string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		panic(fmt.Sprintf("ssrf: invalid reserved CIDR %q: %v", s, err))
	}
	return ipnet
}

// IsReserved returns true if the given IP falls within any reserved/private range.
func IsReserved(ip net.IP) bool {
	for _, cidr := range ReservedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// InternalCIDRs is the subset of ReservedCIDRs that routinely hosts legitimate
// services inside a deployment's own network: RFC 1918, IPv6 ULA (fc00::/7),
// and CGNAT (100.64.0.0/10). On-prem deployments may allow these as internal
// delivery targets; every other reserved range (loopback, link-local/metadata,
// multicast, unspecified, 0.0.0.0/8, benchmarking) stays forbidden in all modes.
var InternalCIDRs = []*net.IPNet{
	mustParseCIDR("10.0.0.0/8"),
	mustParseCIDR("172.16.0.0/12"),
	mustParseCIDR("192.168.0.0/16"),
	mustParseCIDR("fc00::/7"),
	mustParseCIDR("100.64.0.0/10"),
}

// IsInternalNetwork reports whether ip falls within InternalCIDRs.
func IsInternalNetwork(ip net.IP) bool {
	for _, cidr := range InternalCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// Domain contains an allow-listed domain pattern for upstream verification.
type Domain struct {
	pattern string // exact or *.suffix
	isWild  bool
	suffix  string // the suffix part (e.g., "openai.com")
}

// ParseDomain parses a domain entry which can be:
//   - An exact domain like "api.openai.com"
//   - A wildcard pattern like "*.openai.com" (matches subdomains)
func ParseDomain(entry string) (Domain, error) {
	entry = strings.TrimSpace(strings.ToLower(entry))
	if entry == "" {
		return Domain{}, fmt.Errorf("ssrf: empty domain entry")
	}

	if strings.HasPrefix(entry, "*.") {
		suffix := strings.TrimPrefix(entry, "*.")
		if suffix == "" || !strings.Contains(suffix, ".") {
			return Domain{}, fmt.Errorf("ssrf: invalid wildcard domain %q", entry)
		}
		return Domain{pattern: entry, isWild: true, suffix: suffix}, nil
	}

	if strings.Contains(entry, "*") {
		return Domain{}, fmt.Errorf("ssrf: invalid wildcard domain %q", entry)
	}

	return Domain{pattern: entry, isWild: false, suffix: entry}, nil
}

// Matches checks if a hostname matches this domain pattern.
func (d Domain) Matches(hostname string) bool {
	hostname = strings.TrimSpace(strings.ToLower(hostname))
	if d.isWild {
		return strings.HasSuffix(hostname, "."+d.suffix)
	}
	return hostname == d.pattern
}

// AllowList holds a validated set of allowed upstream domains.
type AllowList struct {
	domains []Domain
	// lookup overrides DNS resolution for ValidateUpstream. It exists so
	// the SSRF guard's DNS-dependent invariants (public-domain allow,
	// rebind-to-reserved reject) are testable hermetically; production
	// lists are always built by NewAllowList and use the bounded default
	// resolver. A nil lookup means the default path.
	lookup func(ctx context.Context, host string) ([]net.IP, error)
	// trustExactPins implements the D-4 posture (owner decision 2026-10-13),
	// scoped to IP-lITERAL pins: an allow-list entry that IS a literal IP
	// (127.0.0.1, 10.20.30.40 — the local-provider case) is an explicit
	// operator pin for that exact ADDRESS, so the reserved-range refusal is
	// waived for it at both guard layers. DNS-NAME entries are never
	// trusted: a name's answer can change between validate and dial (the
	// rebinding window), so waiving the reserved verdict for a name
	// would let a rebind reach loopback/metadata through an allow-listed
	// (false) keeps the historical invariant — reserved ranges are refused
	// regardless of the domain list — which the MCP/A2A registration guards
	// pin (pkg/mcpagg/validate_test.go DNSRebindToReserved).
	trustExactPins bool
}

// NewAllowList creates an allow-list from domain entries. Resolution goes
// through the default resolver with a bounded timeout. Reserved-range
// refusals stay independent of the domain list: a listed host that resolves
// into loopback/RFC1918/metadata ranges is still refused.
func NewAllowList(entries []string) (AllowList, error) {
	return buildAllowList(entries, nil, false)
}

// NewAllowListTrustingExactPins builds an allow-list with the D-4 posture
// (owner decision 2026-10-13): an allow-list entry that is an IP LITERAL
// ("127.0.0.1", "10.20.30.40" — the local-provider case) is an explicit
// operator pin for that exact address, so ValidateUpstream admits it even
// though it lives in a reserved range. DNS-name entries — including exact
// ones — are never trusted: a name's answer can change between validate and
// dial (the rebinding window), so reserved-range refusals stay in
// force for every hostname, and wildcard entries keep them everywhere. The
// dial-time GuardDialedIP transport pin (pkg/upstream rebind guard) remains
// the second layer with the same literal-pin predicate. Use only where an
// entry is a deliberate per-address pin by construction (the upstream
// client allow-list); registration-style guards (MCP/A2A) must keep
// NewAllowList.
func NewAllowListTrustingExactPins(entries []string) (AllowList, error) {
	return buildAllowList(entries, nil, true)
}

// NewAllowListWithResolver creates an allow-list whose ValidateUpstream
// resolves through the provided function instead of the network resolver.
// It exists for deterministic tests of the guard's DNS-dependent behavior
// (QG2-D3); production code must use NewAllowList. A nil resolver is
// rejected so an empty seam can never silently disable the IP checks.
func NewAllowListWithResolver(entries []string, lookup func(ctx context.Context, host string) ([]net.IP, error)) (AllowList, error) {
	if lookup == nil {
		return AllowList{}, fmt.Errorf("ssrf: nil resolver in NewAllowListWithResolver")
	}
	return buildAllowList(entries, lookup, false)
}

// NewAllowListWithResolverAndExactPins is NewAllowListWithResolver plus the
// D-4 exact-pin trust posture (NewAllowListTrustingExactPins). Test seam for
// the trusting mode; production code uses NewAllowListTrustingExactPins.
func NewAllowListWithResolverAndExactPins(entries []string, lookup func(ctx context.Context, host string) ([]net.IP, error)) (AllowList, error) {
	if lookup == nil {
		return AllowList{}, fmt.Errorf("ssrf: nil resolver in NewAllowListWithResolverAndExactPins")
	}
	return buildAllowList(entries, lookup, true)
}

func buildAllowList(entries []string, lookup func(ctx context.Context, host string) ([]net.IP, error), trustExactPins bool) (AllowList, error) {
	var ls AllowList
	for _, entry := range entries {
		d, err := ParseDomain(entry)
		if err != nil {
			return AllowList{}, fmt.Errorf("ssrf: %w", err)
		}
		ls.domains = append(ls.domains, d)
	}
	ls.lookup = lookup
	ls.trustExactPins = trustExactPins
	return ls, nil
}

// literalIPPin reports whether hostname matches an entry that is itself an
// IP literal: the operator pinned this exact ADDRESS (D-4 trusting posture).
// A hostname — even exactly listed — is not a literal pin, because its DNS
// answer is not under the allow-list's control (rebinding window).
func (al AllowList) literalIPPin(hostname string) bool {
	hostname = strings.TrimSpace(strings.ToLower(hostname))
	if net.ParseIP(hostname) == nil {
		return false
	}
	for _, d := range al.domains {
		if !d.isWild && d.Matches(hostname) {
			return true
		}
	}
	return false
}

// TrustsExactPin is the D-4 dial-time predicate (owner decision
// 2026-10-13): true when hostname is an IP-literal entry of a trusting
// allow-list — an explicit operator pin for that exact address, whose
// reserved-range verdict is waived at both the validate and dial guard
// rebinding protection stays intact. Wire it into
// TransportOptions.TrustedExactHosts so both layers decide identically.
func (al AllowList) TrustsExactPin(hostname string) bool {
	return al.trustExactPins && al.literalIPPin(hostname)
}

// defaultResolverLookup resolves a hostname through the system resolver with
// a bounded timeout: an unbounded resolver stall must not hold the request
// path (noctx). ctx is the SSRF guard context — already detached from caller
// cancellation by ValidateUpstreamWithContext — so the 5s bound stays the
// only deadline. Package-level var = test seam for the default-resolution
// error/empty branches (the allow-list seam covers the injected path).
var defaultResolverLookup = func(ctx context.Context, hostname string) ([]net.IP, error) {
	resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(resolveCtx, hostname)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		ips = append(ips, addr.IP)
	}
	return ips, nil
}

// Contains checks if a hostname is in the allow-list.
func (al AllowList) Contains(hostname string) bool {
	for _, d := range al.domains {
		if d.Matches(hostname) {
			return true
		}
	}
	return false
}

// ValidateUpstream resolves a hostname and checks both DNS allow-list membership
// and IP reservation status to prevent SSRF attacks. The no-context form runs
// the guard on the detached background context (QG2-D3).
func (al AllowList) ValidateUpstream(hostname string) error {
	return al.ValidateUpstreamWithContext(context.Background(), hostname)
}

// ValidateUpstreamWithContext is the context-aware form of ValidateUpstream:
// the guard resolves on a context detached from caller cancellation
// (context.WithoutCancel), so a client disconnect never aborts the SSRF
// decision, while the caller's ctx values still reach the resolver (QG2-D3).
// The resolver keeps its own bounded timeout on top of the detached context.
func (al AllowList) ValidateUpstreamWithContext(ctx context.Context, hostname string) error {
	guardCtx := context.WithoutCancel(ctx)
	hostname = strings.TrimSpace(strings.ToLower(hostname))
	if hostname == "" {
		return fmt.Errorf("ssrf: empty hostname")
	}

	// Check domain allow-list
	if !al.Contains(hostname) {
		return fmt.Errorf("ssrf: host %q is not in the allowed domains list", hostname)
	}

	var ips []net.IP
	if al.lookup != nil {
		// Test seam (NewAllowListWithResolver): deterministic answers.
		resolved, err := al.lookup(guardCtx, hostname)
		if err != nil {
			return fmt.Errorf("ssrf: failed to resolve %q: %w", hostname, err)
		}
		ips = resolved
	} else {
		var lookupErr error
		ips, lookupErr = defaultResolverLookup(guardCtx, hostname)
		if lookupErr != nil {
			return fmt.Errorf("ssrf: failed to resolve %q: %w", hostname, lookupErr)
		}
	}
	if len(ips) == 0 {
		return fmt.Errorf("ssrf: no IPs resolved for %q", hostname)
	}

	// Check every resolved IP against reserved ranges — unless the hostname
	// is an IP-literal operator pin in the D-4 trusting posture (see
	// trustExactPins/literalIPPin): allow-listing `127.0.0.1` IS the
	// statement "dial this exact address", reserved range included. DNS-name
	// entries keep the refusal at this layer — their answers are not under
	// keep it everywhere (metadata/loopback/RFC1918 vectors stay blocked).
	if !al.trustExactPins || !al.literalIPPin(hostname) {
		if badIPs := reservedAnswers(ips); len(badIPs) > 0 {
			return fmt.Errorf("ssrf: %q resolved to reserved IP(s): %v", hostname, badIPs)
		}
	}

	return nil
}

// reservedAnswers collects the string form of every resolved IP that falls
// into a reserved range — the D-4 reserved-verdict evidence.
func reservedAnswers(ips []net.IP) []string {
	var badIPs []string
	for _, ip := range ips {
		if IsReserved(ip) {
			badIPs = append(badIPs, ip.String())
		}
	}
	return badIPs
}
