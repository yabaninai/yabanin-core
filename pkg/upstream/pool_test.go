package upstream

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestPool() *Pool {
	return NewPool(Options{AllowedUpstreams: []string{
		"https://api.openai.com", "https://api.anthropic.com", "https://api.example.com",
		"https://default.local", "https://u.local", "https://a.local", "https://b.local", "https://c.local",
		"https://u0.local", "https://u1.local", "https://u2.local", "https://u3.local", "https://u4.local",
	}})
}

func TestPool_Get_SameURL_ReturnsSameClient(t *testing.T) {
	p := newTestPool()
	a, err := p.Get("https://api.openai.com", "")
	require.NoError(t, err)
	b, err := p.Get("https://api.openai.com", "")
	require.NoError(t, err)
	if a != b {
		t.Fatal("expected same client instance for the same URL")
	}
	assert.Equal(t, 1, p.Size())
}

func TestPool_Get_DifferentURL_ReturnsDifferentClients(t *testing.T) {
	p := newTestPool()
	a, err := p.Get("https://api.openai.com", "")
	require.NoError(t, err)
	b, err := p.Get("https://api.anthropic.com", "")
	require.NoError(t, err)
	if a == b {
		t.Fatal("expected different client instances for different URLs")
	}
	assert.Equal(t, 2, p.Size())
}

func TestPool_Get_DifferentProvider_DifferentClients(t *testing.T) {
	p := newTestPool()
	a, err := p.Get("https://api.example.com", "openai")
	require.NoError(t, err)
	b, err := p.Get("https://api.example.com", "anthropic")
	require.NoError(t, err)
	if a == b {
		t.Fatal("expected different client instances for different providers")
	}
	assert.Equal(t, "openai", a.Adapter().Name())
	assert.Equal(t, "anthropic", b.Adapter().Name())
}

func TestPool_Get_EmptyURL_FallsBackToDefault(t *testing.T) {
	p := NewPool(Options{BaseURL: "https://default.local", AllowedUpstreams: []string{"https://default.local"}})
	c, err := p.Get("", "")
	require.NoError(t, err)
	require.NotNil(t, c)
	if !strings.HasSuffix(c.BaseURL(), "default.local") {
		t.Fatalf("expected default URL, got %q", c.BaseURL())
	}
	// The empty-key lookup must reuse the same slot as a subsequent explicit
	// default-URL lookup.
	c2, err := p.Get("https://default.local", "")
	require.NoError(t, err)
	if c != c2 {
		t.Fatal("expected identical instance for empty and explicit default URL")
	}
}

func TestPool_Get_AppliesDefaultsTimeout(t *testing.T) {
	p := newTestPool()
	c, err := p.Get("https://api.openai.com", "")
	require.NoError(t, err)
	if c.defaultTimeout != DefaultNonStreamTimeout {
		t.Fatalf("expected default timeout %v, got %v", DefaultNonStreamTimeout, c.defaultTimeout)
	}
}

func TestPool_Get_CustomDefaultsPropagated(t *testing.T) {
	p := NewPool(Options{Timeout: 7, AllowedUpstreams: []string{"https://api.openai.com"}})
	c, err := p.Get("https://api.openai.com", "")
	require.NoError(t, err)
	if c.defaultTimeout != 7 {
		t.Fatalf("expected propagated timeout 7, got %v", c.defaultTimeout)
	}
}

func TestPool_Concurrent_Get_NoRace(t *testing.T) {
	p := newTestPool()
	const goroutines = 100
	const distinctURLs = 5

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			_, _ = p.Get(fmt.Sprintf("https://u%d.local", i%distinctURLs), "")
		}(i)
	}
	wg.Wait()

	if p.Size() != distinctURLs {
		t.Fatalf("expected %d clients, got %d", distinctURLs, p.Size())
	}
}

func TestPool_Eviction_AtMaxSize(t *testing.T) {
	p := newTestPool().WithMaxSize(2)
	_, _ = p.Get("https://a.local", "")
	_, _ = p.Get("https://b.local", "")
	_, _ = p.Get("https://c.local", "")
	if p.Size() > 2 {
		t.Fatalf("size %d exceeds configured max 2", p.Size())
	}
}

func TestPool_WithMaxSize_ZeroOrNegativeIgnored(t *testing.T) {
	p := NewPool(Options{}).WithMaxSize(0)
	if p.maxSize != DefaultPoolMaxSize {
		t.Fatalf("WithMaxSize(0) should keep default, got %d", p.maxSize)
	}
	p.WithMaxSize(-5)
	if p.maxSize != DefaultPoolMaxSize {
		t.Fatalf("WithMaxSize(-5) should keep default, got %d", p.maxSize)
	}
}

func TestPool_Close_DropsAllClients(t *testing.T) {
	p := newTestPool()
	_, _ = p.Get("https://a.local", "")
	_, _ = p.Get("https://b.local", "")
	require.Equal(t, 2, p.Size())

	p.Close()
	assert.Equal(t, 0, p.Size())

	// Pool must remain usable after Close — new clients get recreated.
	c, err := p.Get("https://a.local", "")
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.Equal(t, 1, p.Size())
}

func TestPool_Get_SSRFDefaultsPropagated(t *testing.T) {
	// Defaults carry an SSRF allowlist; every lazily-created client must
	// inherit it. The default BaseURL host must be in the allowlist.
	p := NewPool(Options{
		BaseURL:          "https://api.openai.com",
		AllowedUpstreams: []string{"https://api.openai.com"},
	})
	c, err := p.Get("https://api.openai.com", "")
	require.NoError(t, err)
	require.NotNil(t, c)
	if !c.ssrfAllowList.Contains("api.openai.com") {
		t.Fatal("expected pooled client to retain the configured egress allowlist")
	}
}

func TestPool_DefaultAllowlistBlocksRedirectToOtherHost(t *testing.T) {
	var secondHop int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/target" {
			secondHop++
			return
		}
		_, port, err := net.SplitHostPort(r.Host)
		if err != nil {
			t.Errorf("SplitHostPort(%q): %v", r.Host, err)
			return
		}
		w.Header().Set("Location", "http://localhost:"+port+"/target")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	// With no explicit allowlist, Pool.Get approves only this trusted default
	// operator URL. Its redirect to another host must still be refused.
	p := NewPool(Options{BaseURL: srv.URL})
	c, err := p.Get("", "")
	if err != nil {
		t.Fatalf("Pool.Get: %v", err)
	}
	resp, err := c.Do(context.Background(), "/redirect", nil, "", false, nil)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "not in the allowed domains list") {
		t.Fatalf("redirect to a different host must be rejected, err=%v", err)
	}
	if secondHop != 0 {
		t.Fatalf("redirect target received %d requests", secondHop)
	}
}

func TestPool_Get_UnknownProvider_ReturnsError(t *testing.T) {
	p := newTestPool()
	c, err := p.Get("https://u.local", "grok")
	require.Error(t, err, "unknown provider must return an error, not panic (IMP-92)")
	assert.Nil(t, c)
	assert.Contains(t, err.Error(), "grok")

	// The failed key must not be cached and the pool must stay usable.
	assert.Equal(t, 0, p.Size())
	good, err := p.Get("https://u.local", "openai")
	require.NoError(t, err)
	require.NotNil(t, good)
	assert.Equal(t, 1, p.Size())
}

func TestPool_Get_Error_IsNotCached_AcrossCalls(t *testing.T) {
	p := newTestPool()
	for i := 0; i < 3; i++ {
		c, err := p.Get("https://u.local", "does-not-exist")
		require.Error(t, err)
		assert.Nil(t, c)
	}
	assert.Equal(t, 0, p.Size())
}

func TestPool_Get_AnthropicProviderCreatesAdapter(t *testing.T) {
	p := newTestPool()
	c, err := p.Get("https://api.anthropic.com", "anthropic")
	require.NoError(t, err)
	if c.Adapter().Name() != "anthropic" {
		t.Fatalf("expected anthropic adapter, got %s", c.Adapter().Name())
	}
}

func TestProviderNameFromKey(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want string
	}{
		{name: "provider prefix", key: "anthropic::https://api.example.com", want: "anthropic"},
		{name: "missing delimiter", key: "https://api.example.com", want: ""},
		{name: "single colon", key: "anthropic:https://api.example.com", want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, providerNameFromKey(tc.key))
		})
	}
}
