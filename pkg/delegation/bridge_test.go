package delegation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestBridgeExecutor_LoopbackOnly(t *testing.T) {
	b := NewBridgeExecutor("codex", "https://evil.example")
	if b.Available(context.Background()) {
		t.Fatal("non-loopback must be unavailable")
	}
	_, err := b.Run(context.Background(), Request{Task: "x", Mode: ModeAnalyze})
	if err == nil {
		t.Fatal("expected loopback error")
	}
}

func TestBridgeExecutor_FakeSidecar(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.Path != "/v1/delegate" {
			http.NotFound(w, r)
			return
		}
		var in map[string]any
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Errorf("decode: %v", err)
		}
		if in["provider"] != "codex" || in["task"] == "" {
			t.Errorf("bad payload %+v", in)
		}
		_ = json.NewEncoder(w).Encode(Result{Status: "ok", Executor: "codex", Summary: "done", ChangedFiles: []string{"a.go"}})
	}))
	defer srv.Close()

	b := NewBridgeExecutor("codex", srv.URL)
	if !b.Available(context.Background()) {
		t.Fatal("expected available")
	}
	out, err := b.Run(context.Background(), Request{Task: "add tests", Mode: ModeImplement, Workspace: "/tmp/ws"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "ok" || out.Executor != "codex" || len(out.ChangedFiles) != 1 {
		t.Fatalf("got %+v", out)
	}
}

// TP-19: the bridge never follows redirects — a 3xx from the sidecar must
// fail the request with zero payloads delivered to the destination, whether
// the Location points at another loopback port or somewhere external. The
// capture server records every hit; only the redirecting source may see
// traffic (exactly one request). Fully local: no external network.
func TestTP19_BridgeRefusesRedirects(t *testing.T) {
	var destHits int32
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&destHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer dest.Close()

	for _, code := range []int{
		http.StatusMovedPermanently,  // 301
		http.StatusFound,             // 302
		http.StatusTemporaryRedirect, // 307 (replays the POST body)
		http.StatusPermanentRedirect, // 308 (replays the POST body)
	} {
		for name, location := range map[string]string{
			"other-loopback": dest.URL + "/catch",
			"external-look":  "http://external.invalid/catch",
		} {
			t.Run(fmt.Sprintf("%d_%s", code, name), func(t *testing.T) {
				var sourceHits int32
				src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					atomic.AddInt32(&sourceHits, 1)
					http.Redirect(w, r, location, code)
				}))
				defer src.Close()

				b := NewBridgeExecutor("codex", src.URL)
				out, err := b.Run(context.Background(), Request{Task: "secret-task", Mode: ModeAnalyze, Workspace: "/tmp/ws"})
				if err == nil || !strings.Contains(err.Error(), "refused") {
					t.Fatalf("redirect must be refused explicitly, got err=%v out=%+v", err, out)
				}
				if out.Status != "error" {
					t.Fatalf("redirected run must be an error result: %+v", out)
				}
				if got := atomic.LoadInt32(&sourceHits); got != 1 {
					t.Fatalf("source must see exactly one request, got %d", got)
				}
				if got := atomic.LoadInt32(&destHits); got != 0 {
					t.Fatalf("destination must receive zero payloads, got %d hits", got)
				}
				if b.Available(context.Background()) {
					t.Fatal("a redirecting healthz must not count as available")
				}
			})
		}
	}
	if got := atomic.LoadInt32(&destHits); got != 0 {
		t.Fatalf("capture server must stay untouched across all cases, got %d hits", got)
	}
}
