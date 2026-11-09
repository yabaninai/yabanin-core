package upstream

import (
	"net/http"
	"testing"
	"time"
)

func TestTransportDefaults_H2AndIdlePools(t *testing.T) {
	c, err := newTestClientWithAdapter(Options{BaseURL: "https://api.example.test", ProviderName: "openai"})
	if err != nil {
		t.Fatalf("NewClientWithAdapter: %v", err)
	}
	tr, ok := c.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", c.client.Transport)
	}
	if !tr.ForceAttemptHTTP2 {
		t.Fatal("ForceAttemptHTTP2 must be true (custom Transport does not enable h2 by default)")
	}
	if tr.MaxIdleConns != 100 {
		t.Fatalf("MaxIdleConns = %d, want 100", tr.MaxIdleConns)
	}
	if tr.MaxIdleConnsPerHost != 100 {
		t.Fatalf("MaxIdleConnsPerHost = %d, want 100", tr.MaxIdleConnsPerHost)
	}
	if tr.IdleConnTimeout != 90*time.Second {
		t.Fatalf("IdleConnTimeout = %v, want 90s", tr.IdleConnTimeout)
	}
}
