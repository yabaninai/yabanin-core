package cli

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/pkg/shadow"
)

func newShadowTestGateway(t *testing.T, cfgKey string, withDispatcher bool) *gateway {
	t.Helper()
	gw := &gateway{
		cfg: config.Gateway{MetricsBearerKey: cfgKey},
		log: slog.Default(),
	}
	if withDispatcher {
		vc, err := shadow.Config{
			Enabled:       true,
			Model:         "gpt-4o",
			SampleRate:    1.0,
			Timeout:       30 * time.Second,
			MaxConcurrent: 4,
		}.Validate()
		if err != nil {
			t.Fatalf("shadow config: %v", err)
		}
		gw.shadow = shadow.NewDispatcher(vc, slog.Default())
	}
	return gw
}

func mountShadowAdmin(t *testing.T, gw *gateway) chi.Router {
	t.Helper()
	r := chi.NewRouter()
	gw.registerShadowAdmin(r, slog.Default())
	return r
}

// --- status --------------------------------------------------------------------

func TestShadowAdmin_Status_RequiresKey(t *testing.T) {
	r := mountShadowAdmin(t, newShadowTestGateway(t, "", true)) // no key configured
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/admin/shadow/status", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("no-key status = %d, want 403 (fail-closed)", w.Code)
	}
}

func TestShadowAdmin_Status_WithKey(t *testing.T) {
	r := mountShadowAdmin(t, newShadowTestGateway(t, "admin-secret", true))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/admin/shadow/status", nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var st map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatalf("status not JSON: %v", err)
	}
	if st["model"] != "gpt-4o" {
		t.Errorf("model = %v, want gpt-4o", st["model"])
	}
	if st["enabled"] != true {
		t.Errorf("enabled = %v, want true", st["enabled"])
	}
	// The bearer key must never appear in the status payload.
	if strings.Contains(w.Body.String(), "admin-secret") {
		t.Errorf("status leaked the bearer key: %s", w.Body.String())
	}
}

func TestShadowAdmin_Status_WrongKey(t *testing.T) {
	r := mountShadowAdmin(t, newShadowTestGateway(t, "admin-secret", true))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/admin/shadow/status", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("wrong-key status = %d, want 403", w.Code)
	}
}

// --- toggle --------------------------------------------------------------------

func TestShadowAdmin_Toggle_FlipsState(t *testing.T) {
	gw := newShadowTestGateway(t, "k", true)
	ch := mountShadowAdmin(t, gw)

	if !gw.shadow.Enabled() {
		t.Fatal("expected enabled initially")
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/admin/shadow/toggle", strings.NewReader(`{"enabled": false}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer k")
	w := httptest.NewRecorder()
	ch.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("toggle = %d, want 200", w.Code)
	}
	if gw.shadow.Enabled() {
		t.Error("still enabled after toggle off")
	}
	req2 := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/admin/shadow/toggle", strings.NewReader(`{"enabled": true}`))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer k")
	w2 := httptest.NewRecorder()
	ch.ServeHTTP(w2, req2)
	if !gw.shadow.Enabled() {
		t.Error("not enabled after toggle on")
	}
}

func TestShadowAdmin_Toggle_RequiresKey(t *testing.T) {
	r := mountShadowAdmin(t, newShadowTestGateway(t, "", true))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/admin/shadow/toggle", strings.NewReader(`{"enabled": false}`))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("no-key toggle = %d, want 403", w.Code)
	}
}

func TestShadowAdmin_Toggle_BadBody(t *testing.T) {
	ch := mountShadowAdmin(t, newShadowTestGateway(t, "k", true))
	for _, body := range []string{`{}`, `not json`, `{"enabled":"yes"}`} {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/admin/shadow/toggle", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer k")
		w := httptest.NewRecorder()
		ch.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("body %q → %d, want 400", body, w.Code)
		}
	}
}

func TestShadowAdmin_NotConfigured_409(t *testing.T) {
	ch := mountShadowAdmin(t, newShadowTestGateway(t, "k", false)) // no dispatcher
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/admin/shadow/status", nil)
	req.Header.Set("Authorization", "Bearer k")
	w := httptest.NewRecorder()
	ch.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Errorf("unconfigured status = %d, want 409", w.Code)
	}
}

// --- concurrency: toggles and status reads race-clean ----------------------------

func TestShadowAdmin_ConcurrentToggleAndStatus(t *testing.T) {
	gw := newShadowTestGateway(t, "k", true)
	ch := mountShadowAdmin(t, gw)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		enable := i%2 == 0
		go func() {
			defer wg.Done()
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/admin/shadow/toggle",
				strings.NewReader(`{"enabled":`+boolStr(enable)+`}`))
			req.Header.Set("Authorization", "Bearer k")
			w := httptest.NewRecorder()
			ch.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Errorf("concurrent toggle = %d", w.Code)
			}
		}()
		go func() {
			defer wg.Done()
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/admin/shadow/status", nil)
			req.Header.Set("Authorization", "Bearer k")
			w := httptest.NewRecorder()
			ch.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Errorf("concurrent status = %d", w.Code)
			}
		}()
	}
	wg.Wait()
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
