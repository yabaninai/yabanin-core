package upstream

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/ssrf"
	"golang.org/x/net/dns/dnsmessage"
)

// fakeDNSResolver answers A queries from a scripted list (one IP per A
// query, in order; the last answer repeats) and returns no AAAA records.
// It exists so the DNS-rebinding TOCTOU scenario (validate-time lookup
// returns a public IP, dial-time lookup returns a metadata IP) can be
// exercised hermetically through the production net.DefaultResolver path.
type fakeDNSResolver struct {
	mu      sync.Mutex
	answers []string
	next    int
}

func newFakeDNS(answers ...string) *net.Resolver {
	f := &fakeDNSResolver{answers: answers}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			client, server := net.Pipe()
			// The Go resolver (1.27, custom Dial) speaks DNS with the
			// 2-byte TCP length prefix on the dialed connection even when
			// it reports network "udp", so always read/write framed.
			go f.serve(server, true)
			return client, nil
		},
	}
}

func (f *fakeDNSResolver) nextAnswer() (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.answers) == 0 {
		return "", false
	}
	if f.next >= len(f.answers) {
		f.next = len(f.answers) - 1
	}
	s := f.answers[f.next]
	f.next++
	return s, true
}

// serve handles one DNS exchange over c. The Go resolver speaks DNS with a
// 2-byte TCP length prefix when network is tcp, and raw datagrams otherwise
// (the pipe preserves message boundaries).
func (f *fakeDNSResolver) serve(c net.Conn, framed bool) {
	defer func() { _ = c.Close() }()

	var payload []byte
	if framed {
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		payload = make([]byte, binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(c, payload); err != nil {
			return
		}
	} else {
		payload = make([]byte, 512)
		n, err := c.Read(payload)
		if err != nil {
			return
		}
		payload = payload[:n]
	}

	var q dnsmessage.Message
	if err := q.Unpack(payload); err != nil {
		return
	}

	resp := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 q.ID,
			Response:           true,
			Authoritative:      true,
			RecursionDesired:   q.RecursionDesired,
			RecursionAvailable: true,
			RCode:              dnsmessage.RCodeSuccess,
		},
		Questions: q.Questions,
	}
	if len(q.Questions) == 1 && q.Questions[0].Type == dnsmessage.TypeA {
		if answer, ok := f.nextAnswer(); ok {
			if ip4 := net.ParseIP(answer).To4(); ip4 != nil {
				var a [4]byte
				copy(a[:], ip4)
				resp.Answers = append(resp.Answers, dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{
						Name:  q.Questions[0].Name,
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
					},
					Body: &dnsmessage.AResource{A: a},
				})
			}
		}
	}
	out, err := resp.Pack()
	if err != nil {
		return
	}
	if len(out) > math.MaxUint16 {
		return
	}
	if framed {
		buf := make([]byte, 2+len(out))
		// Mask is a no-op here: len(out) <= math.MaxUint16 is checked above
		// (gosec G115 cannot see the guard).
		binary.BigEndian.PutUint16(buf[:2], uint16(len(out)&math.MaxUint16))
		copy(buf[2:], out)
		_, _ = c.Write(buf)
	} else {
		_, _ = c.Write(out)
	}
}

func swapDefaultResolver(t *testing.T, r *net.Resolver) {
	t.Helper()
	old := net.DefaultResolver
	net.DefaultResolver = r
	t.Cleanup(func() { net.DefaultResolver = old })
}

// validation resolves the host once (legal public IP), and the transport
// dial resolves again — when that dial-time resolution returns a metadata
// address (DNS rebinding), the connection must be rejected by policy,
// quickly, without leaking the forbidden address in the error text.
func TestRebindingMetadataRejectedAtDial(t *testing.T) {
	swapDefaultResolver(t, newFakeDNS("93.184.216.34", "169.254.169.254"))

	c, err := NewClientWithAdapter(Options{
		BaseURL:          "http://rebind.example.test/v1",
		AllowedUpstreams: []string{"http://rebind.example.test"},
		DialTimeout:      300 * time.Millisecond,
		ProviderName:     "openai",
	})
	if err != nil {
		t.Fatalf("NewClientWithAdapter: %v", err)
	}

	// Lookup #1 — validate time: the legal answer must pass the allow-list.
	if err := c.checkSSRF(); err != nil {
		t.Fatalf("validate-time resolution rejected: %v", err)
	}

	tr, ok := c.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", c.client.Transport)
	}

	// Lookup #2 — dial time: the rebinding answer (metadata IP) must be
	// rejected. On the vulnerable (pre-fix) transport this is a real
	// connect attempt to the metadata address.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	conn, err := tr.DialContext(ctx, "tcp", "rebind.example.test:81")
	if err == nil {
		_ = conn.Close()
		t.Fatal("dial after rebind to metadata address was not rejected")
	}
	if !strings.Contains(err.Error(), "ssrf") {
		t.Fatalf("dial error is not an SSRF policy rejection: %v", err)
	}
	if !errors.Is(err, ssrf.ErrReservedTarget) {
		t.Fatalf("dial error is not ErrReservedTarget: %v", err)
	}
	if strings.Contains(err.Error(), "169.254.169.254") {
		t.Fatalf("dial error leaks the forbidden address: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("rebind rejection took %v — looks like a real connect attempt, not a policy reject", elapsed)
	}
}

// TestDialGuardOffWithoutAllowlistKeepsLoopbackWorking pins the dev-mode
// decision: with no allow-list configured (legacy/dev deployments, e.g.
// llama.cpp on localhost:8081 via YABANIN_PROVIDER_ADDR) the transport must
// keep dialing loopback targets — the dial-time guard is only active when
// SSRF protection is enabled.
func TestEmptyAllowlistFailsClosed(t *testing.T) {
	c, err := NewClientWithAdapter(Options{BaseURL: "http://127.0.0.1:8081", ProviderName: "openai"})
	if err == nil || c != nil {
		t.Fatalf("empty allowlist must fail client construction, client=%v err=%v", c, err)
	}
	if !strings.Contains(err.Error(), "AllowedUpstreams must contain") {
		t.Fatalf("configuration error should explain the required allowlist: %v", err)
	}
}

func TestRedirectToReservedIPIsRejectedBeforeSecondHop(t *testing.T) {
	swapDefaultResolver(t, newFakeDNS("169.254.169.254"))
	var secondHop int
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		secondHop++
	}))
	defer target.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "http://metadata.example.test/latest/meta-data/")
		w.WriteHeader(http.StatusFound)
	}))
	defer first.Close()

	c, err := NewClientWithAdapter(Options{
		BaseURL:          first.URL,
		AllowedUpstreams: []string{first.URL, "http://metadata.example.test"},
		ProviderName:     "openai",
	})
	if err != nil {
		t.Fatalf("NewClientWithAdapter: %v", err)
	}
	resp, err := c.Do(context.Background(), "/redirect", nil, "", false, nil)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, ssrf.ErrReservedTarget) {
		t.Fatalf("redirect to reserved address must be rejected, err=%v", err)
	}
	if secondHop != 0 {
		t.Fatalf("redirect target received %d requests", secondHop)
	}
}

func TestRedirectToUnlistedHostnameIsRejectedBeforeSecondHop(t *testing.T) {
	var secondHop int
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		secondHop++
	}))
	defer target.Close()
	otherHostnameURL := strings.Replace(target.URL, "127.0.0.1", "localhost", 1)
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", otherHostnameURL)
		w.WriteHeader(http.StatusFound)
	}))
	defer first.Close()

	c, err := NewClientWithAdapter(Options{
		BaseURL:          first.URL,
		AllowedUpstreams: []string{first.URL},
		ProviderName:     "openai",
	})
	if err != nil {
		t.Fatalf("NewClientWithAdapter: %v", err)
	}
	resp, err := c.Do(context.Background(), "/redirect", nil, "", false, nil)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "not in the allowed domains list") {
		t.Fatalf("redirect to unlisted hostname must be rejected, err=%v", err)
	}
	if secondHop != 0 {
		t.Fatalf("redirect target received %d requests", secondHop)
	}
}

func TestRedirectHTTPSDowngradeToSameHostIsRejected(t *testing.T) {
	var secondHop int
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		secondHop++
	}))
	defer target.Close()
	first := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusFound)
	}))
	defer first.Close()

	firstURL, err := url.Parse(first.URL)
	if err != nil {
		t.Fatal(err)
	}
	targetURL, err := url.Parse(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	if firstURL.Hostname() != targetURL.Hostname() {
		t.Fatalf("test requires same hostname: TLS=%q HTTP=%q", firstURL.Hostname(), targetURL.Hostname())
	}
	c, err := NewClientWithAdapter(Options{
		BaseURL:          first.URL,
		AllowedUpstreams: []string{first.URL},
		ProviderName:     "openai",
	})
	if err != nil {
		t.Fatalf("NewClientWithAdapter: %v", err)
	}
	// Trust the hermetic httptest certificate while retaining the production
	// transport and redirect policy under test.
	clientTLS := first.Client().Transport.(*http.Transport).TLSClientConfig
	transport := c.client.Transport.(*http.Transport)
	transport.TLSClientConfig = clientTLS.Clone()

	resp, err := c.Do(context.Background(), "/redirect", nil, "", false, nil)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "scheme") {
		t.Fatalf("HTTPS-to-HTTP downgrade must be rejected, err=%v", err)
	}
	if secondHop != 0 {
		t.Fatalf("downgrade target received %d requests", secondHop)
	}
}

func TestGuardedClientIgnoresProxyEnvironment(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://192.0.2.10:8080")
	t.Setenv("http_proxy", "http://192.0.2.11:8080")
	t.Setenv("HTTPS_PROXY", "http://192.0.2.12:8080")
	t.Setenv("https_proxy", "http://192.0.2.13:8080")
	t.Setenv("ALL_PROXY", "http://192.0.2.14:8080")
	t.Setenv("all_proxy", "http://192.0.2.15:8080")
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")

	c, err := NewClientWithAdapter(Options{
		BaseURL:          "http://api.example.test",
		AllowedUpstreams: []string{"http://api.example.test"},
		ProviderName:     "openai",
	})
	if err != nil {
		t.Fatalf("NewClientWithAdapter: %v", err)
	}
	tr, ok := c.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", c.client.Transport)
	}
	if tr.Proxy != nil {
		t.Fatal("guarded upstream client must not install an environment proxy")
	}
	if _, err := tr.DialContext(context.Background(), "tcp", "169.254.169.254:80"); !errors.Is(err, ssrf.ErrReservedTarget) {
		t.Fatalf("direct guarded dial must still reject reserved IPs, got: %v", err)
	}
}

func TestExactIPAllowlistPinStillAllowsLocalProvider(t *testing.T) {
	var called int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called++
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	hostPort := strings.TrimPrefix(srv.URL, "http://")
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		t.Fatal(err)
	}
	baseURL := "http://" + net.JoinHostPort(host, port)
	c, err := NewClientWithAdapter(Options{
		BaseURL:          baseURL,
		AllowedUpstreams: []string{"http://" + host},
		ProviderName:     "openai",
	})
	if err != nil {
		t.Fatalf("NewClientWithAdapter: %v", err)
	}
	resp, err := c.Do(context.Background(), "/health", nil, "", false, nil)
	if err != nil {
		t.Fatalf("explicit IP-literal pin should permit local provider: %v", err)
	}
	_ = resp.Body.Close()
	if called != 1 {
		t.Fatalf("local provider calls = %d, want 1", called)
	}
}

// TestDialGuardActiveWithAllowlistRejectsReservedLiteral pins that the
// shared transport actually wires the dial-time guard when an allow-list
// is configured — not just that the helper exists.
func TestDialGuardActiveWithAllowlistRejectsReservedLiteral(t *testing.T) {
	c, err := NewClientWithAdapter(Options{
		BaseURL:          "http://api.example.test/v1",
		AllowedUpstreams: []string{"http://api.example.test"},
		DialTimeout:      300 * time.Millisecond,
		ProviderName:     "openai",
	})
	if err != nil {
		t.Fatalf("NewClientWithAdapter: %v", err)
	}
	tr, ok := c.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", c.client.Transport)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := tr.DialContext(ctx, "tcp", "169.254.169.254:80")
	if err == nil {
		_ = conn.Close()
		t.Fatal("literal metadata dial was not rejected")
	}
	if !errors.Is(err, ssrf.ErrReservedTarget) {
		t.Fatalf("want ErrReservedTarget, got: %v", err)
	}
	if strings.Contains(err.Error(), "169.254.169.254") {
		t.Fatalf("error leaks the forbidden address: %v", err)
	}
}
