package cli

// a2aSend handler unit tests: the pre-proxy paths (nil proxy, org
// resolution, agent-only, malformed body). The proxied happy path runs in
// services/gateway/integration against a real gateway.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/a2aagg"
	"github.com/reireirei/yabanin/pkg/ssrf"
)

func mustTestAllowList(t *testing.T) ssrf.AllowList {
	t.Helper()
	al, err := ssrf.NewAllowList([]string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("allowlist: %v", err)
	}
	return al
}

func TestA2ASend_NilProxy_404(t *testing.T) {
	gw := &gateway{}
	w := httptest.NewRecorder()
	gw.a2aSend(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/a2a/send", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("nil proxy: got %d, want 404", w.Code)
	}
}

func TestA2ASend_NoOrg_401(t *testing.T) {
	gw := &gateway{a2aProxy: a2aagg.NewProxy(nil, a2aagg.NewDefaultConfig(), mustTestAllowList(t), nil, nil)}
	w := httptest.NewRecorder()
	gw.a2aSend(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/a2a/send", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no org: got %d, want 401", w.Code)
	}
}

func TestA2ASend_OrgKeyForbidden(t *testing.T) {
	gw := &gateway{a2aProxy: a2aagg.NewProxy(nil, a2aagg.NewDefaultConfig(), mustTestAllowList(t), nil, nil)}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/a2a/send", nil)
	req.Header.Set("X-Org-Id", "org-1")
	// No X-Agent-Id (set by the auth middleware for yag_ principals only).
	w := httptest.NewRecorder()
	gw.a2aSend(w, req)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "agent") {
		t.Fatalf("org key: got %d %s, want 403 agent_only", w.Code, w.Body.String())
	}
	// A client-forged X-Agent-Id is stripped at ingress — the handler must
	// not see it either way; here we verify the handler trusts the header it
	// receives, because the stripping happens in the middleware (pinned by
	// the integration trust-boundary rows).
}

func TestA2ASend_MalformedBody_400(t *testing.T) {
	gw := &gateway{a2aProxy: a2aagg.NewProxy(nil, a2aagg.NewDefaultConfig(), mustTestAllowList(t), nil, nil)}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/a2a/send",
		strings.NewReader("not json"))
	req.Header.Set("X-Org-Id", "org-1")
	req.Header.Set("X-Agent-Id", "agent-1")
	w := httptest.NewRecorder()
	gw.a2aSend(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("malformed body: got %d, want 400", w.Code)
	}
}
