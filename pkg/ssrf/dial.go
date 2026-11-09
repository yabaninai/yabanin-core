package ssrf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// ErrReservedTarget is the sentinel behind every policy rejection of this
// package's dial-time guard. Callers can use errors.Is to tell a policy
// rejection (misconfigured or rebinding upstream) apart from a network
// failure. The error text never contains the forbidden address: dial errors
// reach clients and logs, and echoing the resolved internal address would
// leak topology to the party the guard protects against.
var ErrReservedTarget = errors.New("ssrf: target address is forbidden")

// LookupFunc resolves a hostname to its IP addresses.
type LookupFunc func(ctx context.Context, host string) ([]net.IP, error)

func defaultLookup(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
}

// DialerOptions configures NewGuardedDialer.
type DialerOptions struct {
	// Timeout bounds the TCP connect (and, via the same net.Dialer, the
	// pinned-dial phase). Zero means no explicit timeout.
	Timeout time.Duration
	// KeepAlive is passed to the underlying net.Dialer.
	KeepAlive time.Duration
	// Lookup overrides DNS resolution. nil means net.DefaultResolver
	// (production). A non-nil value is a test seam only — the same contract
	// as NewAllowListWithResolver: a nil-failing empty seam must never
	// silently disable the IP checks, so production wiring must leave it
	// unset.
	Lookup LookupFunc
	// Dial overrides the underlying connection dial. nil means a plain
	// net.Dialer (production). Test seam only.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
	// TrustedExactHosts implements the D-4 posture (owner decision
	// 2026-10-13): when the predicate says the dial target is an IP-literal
	// operator pin (an allow-list entry that IS that address), the
	// reserved-range refusal is waived for it — loopback/RFC1918 local
	// providers stay dialable with the guard on. Hostname targets never get
	// the waiver (a name's answer can rebind — the window this
	// dialer exists to close), and the resolve-and-pin structure is kept so
	// the verified address is exactly the connected one. nil (default)
	// refuses every reserved target — the invariant the MCP/A2A guards pin.
	TrustedExactHosts func(host string) bool
}

// NewGuardedDialer returns a DialContext that closes the DNS-rebinding
// TOCTOU window left open by validate-then-dial designs: the two lookups
// (validate time and dial time) can return different answers, so checking
// the answer of the first lookup does not constrain the address the
//
// The returned dialer resolves the hostname ITSELF, rejects the dial when
// any resolved answer is in ReservedCIDRs, and dials the pinned literal IP
// — the address verified is exactly the address connected to, with no
// second lookup in between. Literal IP targets are checked directly.
//
// Error texts identify the policy violation and, for hostname targets, the
// caller-supplied hostname; they never include the resolved address.
func NewGuardedDialer(opts DialerOptions) func(ctx context.Context, network, addr string) (net.Conn, error) {
	lookup := opts.Lookup
	if lookup == nil {
		lookup = defaultLookup
	}
	dial := opts.Dial
	if dial == nil {
		d := &net.Dialer{Timeout: opts.Timeout, KeepAlive: opts.KeepAlive}
		dial = d.DialContext
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("ssrf: split dial address: %w", err)
		}

		// D-4: an IP-literal operator pin waives the reserved-range verdict
		// for that address only (see DialerOptions.TrustedExactHosts);
		// hostname targets always keep the check (rebinding window).
		trusted := opts.TrustedExactHosts != nil && opts.TrustedExactHosts(host)

		if ip := net.ParseIP(host); ip != nil {
			if !trusted && IsReserved(ip) {
				return nil, ErrReservedTarget
			}
			return dial(ctx, network, addr)
		}

		ips, err := lookup(ctx, host)
		if err != nil {
			// The hostname was supplied by the dialer's caller, echoing it
			// leaks nothing; resolver errors do not carry resolved IPs.
			return nil, fmt.Errorf("ssrf: resolve %q: %w", host, err)
		}
		if !trusted {
			for _, ip := range ips {
				if ip != nil && IsReserved(ip) {
					return nil, fmt.Errorf("%w (host %q)", ErrReservedTarget, host)
				}
			}
		}
		pick := firstDialable(ips, network)
		if pick == nil {
			return nil, fmt.Errorf("ssrf: no usable address for host %q", host)
		}
		return dial(ctx, network, net.JoinHostPort(pick.String(), port))
	}
}

// firstDialable returns the first IP that matches the dial network's family
// ("tcp4"/"udp4" = IPv4, "tcp6"/"udp6" = IPv6, anything else = any family).
func firstDialable(ips []net.IP, network string) net.IP {
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		switch network {
		case "tcp4", "udp4":
			if ip.To4() != nil {
				return ip
			}
		case "tcp6", "udp6":
			if ip.To4() == nil && ip.To16() != nil {
				return ip
			}
		default:
			return ip
		}
	}
	return nil
}

// TransportOptions configures NewTransport, the shared upstream HTTP
// transport constructor. Every gateway egress transport (provider upstream,
// MCP aggregator, A2A aggregator) must be built through it so dial
// behaviour — timeouts, pooling, and the optional dial-time SSRF guard —
type TransportOptions struct {
	// Proxy is http.Transport.Proxy; nil means no proxy.
	Proxy func(*http.Request) (*url.URL, error)

	DialTimeout time.Duration
	KeepAlive   time.Duration

	TLSHandshakeTimeout   time.Duration
	ResponseHeaderTimeout time.Duration
	ExpectContinueTimeout time.Duration
	IdleConnTimeout       time.Duration

	MaxIdleConns        int
	MaxIdleConnsPerHost int

	ForceAttemptHTTP2 bool

	// GuardDialedIP enables the dial-time reserved-IP verification (anti
	// DNS-rebinding, see NewGuardedDialer). When false the dialer behaves
	// exactly like a plain net.Dialer — this is the legacy/dev mode for
	// deployments without an allow-list, where loopback upstreams (e.g.
	// llama.cpp on localhost:8081) are expected to keep working.
	GuardDialedIP bool

	// TrustedExactHosts forwards the D-4 exact-pin waiver to the guarded
	// dialer (see DialerOptions.TrustedExactHosts). Wire it from the same
	// allow-list that fed ValidateUpstream so both guard layers make one
	// decision. nil keeps the unconditional reserved-range refusal.
	TrustedExactHosts func(host string) bool

	// Lookup and Dial are test seams forwarded to NewGuardedDialer;
	// production wiring must leave them nil.
	Lookup LookupFunc
	Dial   func(ctx context.Context, network, address string) (net.Conn, error)
}

// NewTransport builds the shared upstream HTTP transport. With
// GuardDialedIP set, connection targets are resolved and pinned here and
// every answer is verified with IsReserved at dial time.
//
// A caller that configures Proxy must explicitly validate its proxy URL
// against the applicable egress allow-list. The guarded DialContext resolves
// and checks the proxy host when net/http connects to it; environment proxy
// settings must not be enabled as a substitute for an allow-list-checked URL.
func NewTransport(opts TransportOptions) *http.Transport {
	var dialCtx func(ctx context.Context, network, address string) (net.Conn, error)
	if opts.GuardDialedIP {
		dialCtx = NewGuardedDialer(DialerOptions{
			Timeout:           opts.DialTimeout,
			KeepAlive:         opts.KeepAlive,
			Lookup:            opts.Lookup,
			Dial:              opts.Dial,
			TrustedExactHosts: opts.TrustedExactHosts,
		})
	} else {
		d := &net.Dialer{Timeout: opts.DialTimeout, KeepAlive: opts.KeepAlive}
		dialCtx = d.DialContext
	}
	return &http.Transport{
		Proxy:                 opts.Proxy,
		DialContext:           dialCtx,
		ForceAttemptHTTP2:     opts.ForceAttemptHTTP2,
		MaxIdleConns:          opts.MaxIdleConns,
		MaxIdleConnsPerHost:   opts.MaxIdleConnsPerHost,
		IdleConnTimeout:       opts.IdleConnTimeout,
		TLSHandshakeTimeout:   opts.TLSHandshakeTimeout,
		ResponseHeaderTimeout: opts.ResponseHeaderTimeout,
		ExpectContinueTimeout: opts.ExpectContinueTimeout,
	}
}
