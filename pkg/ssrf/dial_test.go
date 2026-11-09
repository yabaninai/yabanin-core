package ssrf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func guardedTestDialer(lookup LookupFunc, dial func(ctx context.Context, network, address string) (net.Conn, error)) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return NewGuardedDialer(DialerOptions{Lookup: lookup, Dial: dial})
}

// TestGuardedDialerRejectsReservedLiterals pins that literal reserved
// targets are rejected before any dial, and that the rejection does not
// echo the forbidden address (dial errors reach clients and logs).
func TestGuardedDialerRejectsReservedLiterals(t *testing.T) {
	dialCalled := false
	dial := func(_ context.Context, _, _ string) (net.Conn, error) {
		dialCalled = true
		return nil, errors.New("dial must not be reached")
	}
	d := guardedTestDialer(nil, dial)

	for _, target := range []string{
		"169.254.169.254:80", "127.0.0.1:8081", "10.1.2.3:443",
		"172.16.0.9:443", "192.168.1.1:80", "100.64.0.1:443",
		"100.100.0.5:80", "0.0.0.0:80", "[::1]:8081", "[fc00::1]:443",
		"[fd12:3456::1]:80", "[fe80::1]:443",
	} {
		t.Run(target, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := d(ctx, "tcp", target)
			if err == nil {
				_ = conn.Close()
				t.Fatal("reserved literal dial was not rejected")
			}
			if !errors.Is(err, ErrReservedTarget) {
				t.Fatalf("want ErrReservedTarget, got: %v", err)
			}
			if strings.Contains(err.Error(), target) {
				t.Fatalf("error leaks the forbidden address: %v", err)
			}
		})
	}
	if dialCalled {
		t.Fatal("underlying dial was reached for a reserved target")
	}
}

// TestGuardedDialerResolvesOnceAndPins pins the core anti-rebinding
// invariant: exactly one lookup per dial, and the dialed address is the
// pinned literal IP — no second resolution in between.
func TestGuardedDialerResolvesOnceAndPins(t *testing.T) {
	lookups := 0
	lookup := func(_ context.Context, host string) ([]net.IP, error) {
		lookups++
		if host != "api.example.test" {
			t.Errorf("lookup for unexpected host %q", host)
		}
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	}
	var dialed []string
	dial := func(_ context.Context, network, address string) (net.Conn, error) {
		dialed = append(dialed, network+"|"+address)
		return nil, errors.New("stop-here")
	}

	d := guardedTestDialer(lookup, dial)
	_, err := d(context.Background(), "tcp", "api.example.test:443")
	if err == nil || !strings.Contains(err.Error(), "stop-here") {
		t.Fatalf("dial should pass the guard and reach the underlying dial: %v", err)
	}
	if lookups != 1 {
		t.Fatalf("lookups = %d, want exactly 1", lookups)
	}
	if len(dialed) != 1 || dialed[0] != "tcp|93.184.216.34:443" {
		t.Fatalf("dialed = %v, want the pinned literal 93.184.216.34:443", dialed)
	}
}

// TestGuardedDialerRejectsRebindingAnswer pins that a dial-time lookup
// returning a reserved answer is rejected — the exact DNS-rebinding
// window the guard exists for.
func TestGuardedDialerRejectsRebindingAnswer(t *testing.T) {
	dialCalled := false
	lookup := func(_ context.Context, _ string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.216.34"), net.ParseIP("169.254.169.254")}, nil
	}
	d := guardedTestDialer(lookup, func(_ context.Context, _, _ string) (net.Conn, error) {
		dialCalled = true
		return nil, errors.New("dial must not be reached")
	})

	_, err := d(context.Background(), "tcp", "rebind.example.test:81")
	if !errors.Is(err, ErrReservedTarget) {
		t.Fatalf("want ErrReservedTarget, got: %v", err)
	}
	if strings.Contains(err.Error(), "169.254.169.254") {
		t.Fatalf("error leaks the forbidden address: %v", err)
	}
	if dialCalled {
		t.Fatal("underlying dial was reached despite the rebinding answer")
	}
}

// TestGuardedDialerResolverError is the DNS-failure path: a wrapped error
// naming the caller-supplied host (never a resolved address).
func TestGuardedDialerResolverError(t *testing.T) {
	lookup := func(_ context.Context, _ string) ([]net.IP, error) {
		return nil, fmt.Errorf("nameserver dead")
	}
	d := guardedTestDialer(lookup, nil)
	_, err := d(context.Background(), "tcp", "dead.example.test:443")
	if err == nil || !strings.Contains(err.Error(), "dead.example.test") || !strings.Contains(err.Error(), "ssrf") {
		t.Fatalf("want wrapped resolve error naming the host, got: %v", err)
	}
}

// TestGuardedDialerNoDialableAddress covers an answer set with no IP for
// the requested family (tcp4 against an IPv6-only answer).
func TestGuardedDialerNoDialableAddress(t *testing.T) {
	lookup := func(_ context.Context, _ string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("2606:4700:4700::1111")}, nil
	}
	dialCalled := false
	d := guardedTestDialer(lookup, func(_ context.Context, _, _ string) (net.Conn, error) {
		dialCalled = true
		return nil, errors.New("dial must not be reached")
	})
	_, err := d(context.Background(), "tcp4", "v6only.example.test:443")
	if err == nil || !strings.Contains(err.Error(), "no usable address") {
		t.Fatalf("want no-usable-address error, got: %v", err)
	}
	if dialCalled {
		t.Fatal("underlying dial was reached with no dialable address")
	}

	// Same answer, tcp6: dials the pinned literal.
	var dialed string
	d2 := guardedTestDialer(lookup, func(_ context.Context, _, address string) (net.Conn, error) {
		dialed = address
		return nil, errors.New("stop")
	})
	_, _ = d2(context.Background(), "tcp6", "v6only.example.test:443")
	if dialed != "[2606:4700:4700::1111]:443" {
		t.Fatalf("dialed = %q, want [2606:4700:4700::1111]:443", dialed)
	}
}

// TestNewTransportGuardWiring pins that NewTransport wires the guard
// exactly when GuardDialedIP is set, and leaves a plain dialer otherwise.
func TestNewTransportGuardWiring(t *testing.T) {
	guarded := NewTransport(TransportOptions{GuardDialedIP: true})
	_, err := guarded.DialContext(context.Background(), "tcp", "169.254.169.254:80")
	if !errors.Is(err, ErrReservedTarget) {
		t.Fatalf("guarded transport must reject reserved literal, got: %v", err)
	}

	plain := NewTransport(TransportOptions{})
	// Dialing a refused loopback port proves the plain path performs no
	// policy check (the error is the OS connection error, not the guard's).
	_, err = plain.DialContext(context.Background(), "tcp", "127.0.0.1:1")
	if err == nil {
		t.Fatal("expected the OS dial error for a refused loopback port")
	}
	if errors.Is(err, ErrReservedTarget) {
		t.Fatalf("plain transport applied the guard: %v", err)
	}
}

// TestTransportOptionsApplied pins that the transport knobs are forwarded.
func TestTransportOptionsApplied(t *testing.T) {
	tr := NewTransport(TransportOptions{
		DialTimeout:           3 * time.Second,
		KeepAlive:             15 * time.Second,
		TLSHandshakeTimeout:   4 * time.Second,
		ResponseHeaderTimeout: 7 * time.Second,
		ExpectContinueTimeout: 2 * time.Second,
		IdleConnTimeout:       60 * time.Second,
		MaxIdleConns:          42,
		MaxIdleConnsPerHost:   9,
		ForceAttemptHTTP2:     true,
	})
	if tr.TLSHandshakeTimeout != 4*time.Second ||
		tr.ResponseHeaderTimeout != 7*time.Second ||
		tr.ExpectContinueTimeout != 2*time.Second ||
		tr.IdleConnTimeout != 60*time.Second ||
		tr.MaxIdleConns != 42 ||
		tr.MaxIdleConnsPerHost != 9 ||
		!tr.ForceAttemptHTTP2 {
		t.Fatalf("transport options not applied: %+v", tr)
	}
}

// TestGuardedDialerDefaultLookupLocalhost covers the production lookup path
// (Lookup nil → net.DefaultResolver): "localhost" resolves from /etc/hosts
// on every supported platform without network, to a loopback address the
// guard must reject.
func TestGuardedDialerDefaultLookupLocalhost(t *testing.T) {
	d := NewGuardedDialer(DialerOptions{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := d(ctx, "tcp", "localhost:80")
	if err == nil {
		_ = conn.Close()
		t.Fatal("localhost dial was not rejected")
	}
	if strings.Contains(err.Error(), "resolve") {
		t.Skipf("localhost not resolvable on this host: %v", err)
	}
	if !errors.Is(err, ErrReservedTarget) {
		t.Fatalf("want ErrReservedTarget, got: %v", err)
	}
	if strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("error leaks the resolved loopback address: %v", err)
	}
}

// TestGuardedDialerDefaultLookupError covers the resolver-error wrap of the
// default lookup path. The .invalid TLD is guaranteed not to resolve; any
// resolver failure (offline included) satisfies the branch.
func TestGuardedDialerDefaultLookupError(t *testing.T) {
	d := NewGuardedDialer(DialerOptions{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := d(ctx, "tcp", "imp86-unreachable.invalid:443")
	if err == nil || !strings.Contains(err.Error(), "ssrf: resolve") {
		t.Fatalf("want wrapped resolve error, got: %v", err)
	}
}

// TestGuardedDialerInvalidAddress covers the malformed dial address path.
func TestGuardedDialerInvalidAddress(t *testing.T) {
	d := guardedTestDialer(nil, func(_ context.Context, _, _ string) (net.Conn, error) {
		t.Fatal("dial must not be reached")
		return nil, errors.New("unreachable")
	})
	_, err := d(context.Background(), "tcp", "no-port-here")
	if err == nil || !strings.Contains(err.Error(), "ssrf: split dial address") {
		t.Fatalf("want split-address error, got: %v", err)
	}
}

// TestGuardedDialerLiteralPublicPasses covers the not-reserved literal
// branch: the dial proceeds with the address unchanged (no lookup).
func TestGuardedDialerLiteralPublicPasses(t *testing.T) {
	var dialed string
	d := guardedTestDialer(func(_ context.Context, _ string) ([]net.IP, error) {
		t.Fatal("literal IP must not be looked up")
		return nil, errors.New("unreachable")
	}, func(_ context.Context, _, address string) (net.Conn, error) {
		dialed = address
		return nil, errors.New("stop")
	})
	_, _ = d(context.Background(), "tcp", "93.184.216.34:443")
	if dialed != "93.184.216.34:443" {
		t.Fatalf("dialed = %q, want unchanged literal", dialed)
	}
}

// TestFirstDialable pins the family matching, including the nil-entry skip
// and the udp4/udp6 selectors.
func TestFirstDialable(t *testing.T) {
	v4 := net.ParseIP("93.184.216.34")
	v6 := net.ParseIP("2606:4700:4700::1111")

	cases := []struct {
		name    string
		ips     []net.IP
		network string
		want    net.IP
	}{
		{"nil-entry-skipped", []net.IP{nil, v4}, "tcp", v4},
		{"any-family-first", []net.IP{v6, v4}, "tcp", v6},
		{"tcp4-picks-v4", []net.IP{v6, v4}, "tcp4", v4},
		{"udp4-picks-v4", []net.IP{v6, v4}, "udp4", v4},
		{"tcp6-picks-v6", []net.IP{v4, v6}, "tcp6", v6},
		{"udp6-picks-v6", []net.IP{v4, v6}, "udp6", v6},
		{"tcp4-empty", []net.IP{v6}, "tcp4", nil},
		{"tcp6-empty", []net.IP{v4}, "tcp6", nil},
		{"all-nil", []net.IP{nil, nil}, "tcp", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := firstDialable(tc.ips, tc.network); !got.Equal(tc.want) {
				t.Fatalf("firstDialable = %v, want %v", got, tc.want)
			}
		})
	}
}
