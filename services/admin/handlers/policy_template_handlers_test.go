package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/pkg/policy"
	"github.com/reireirei/yabanin/services/admin/handlers"
)

// TestPolicyTemplateHandlers_Export_NoOrgID verifies 400 when org_id is missing.
func TestPolicyTemplateHandlers_Export_NoOrgID(t *testing.T) {
	h := handlers.NewPolicyTemplateHandlers(nil, nil)
	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/organizations/export", strings.NewReader(`{}`))
	h.Export(rw, req)

	if rw.Code != http.StatusBadRequest {
		t.Errorf("Export without org_id returned %d, want 400", rw.Code)
	}
}

// TestPolicyTemplateHandlers_Export_Success verifies successful export.
func TestPolicyTemplateHandlers_Export_Success(t *testing.T) {
	mp := policy.NewTemplateMarketplace(nil)
	h := handlers.NewPolicyTemplateHandlers(mp, nil)
	router := chi.NewRouter()
	router.Post("/api/organizations/{id}/export", h.Export)

	body := `{"region":"sg","pack_id":"rbi-finance","name":"RBI Pack","description":"Indian RBI compliance"}`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/organizations/org-123/export", strings.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Export returned %d, want 200: %s", w.Code, w.Body.String())
	}

	var result map[string]any
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode error: %v", err)
	}

	tmpl := result["template"].(map[string]any)
	if tmpl["id"] != "tpl-sg-rbi-finance" {
		t.Errorf("template id = %v, want tpl-sg-rbi-finance", tmpl["id"])
	}
}

// TestPolicyTemplateHandlers_ListAvailable_WithNilMarketplace verifies that nil marketplace panics.
// In production, ListAvailable is only called when pool != nil (guarded in main.go).
func TestPolicyTemplateHandlers_ListAvailable_WithNilMarketplace(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic from nil marketplace")
		}
	}()

	h := handlers.NewPolicyTemplateHandlers(nil, nil)
	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/templates", nil)
	h.ListAvailable(rw, req)
}

// TestPolicyTemplateHandlers_Subscribe_Success verifies subscription.
func TestPolicyTemplateHandlers_Subscribe_Success(t *testing.T) {
	mp := policy.NewTemplateMarketplace(nil)
	h := handlers.NewPolicyTemplateHandlers(mp, nil)
	router := chi.NewRouter()
	router.Post("/api/organizations/{id}/subscribe/{template_id}", h.Subscribe)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/organizations/org-123/subscribe/tpl-sg-test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Subscribe returned %d, want 200: %s", w.Code, w.Body.String())
	}

	var result map[string]any
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if result["subscribed"] != true {
		t.Error("expected subscribed=true")
	}
}

// TestPolicyTemplateHandlers_Subscribe_MissingParams verifies 400 when template_id is empty.
func TestPolicyTemplateHandlers_Subscribe_MissingParams(t *testing.T) {
	mp := policy.NewTemplateMarketplace(nil)
	h := handlers.NewPolicyTemplateHandlers(mp, nil)

	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/organizations/org-123/subscribe", nil)
	// chi.URLParam returns "" when param is absent.
	h.Subscribe(rw, req)

	if rw.Code != http.StatusBadRequest {
		t.Errorf("Subscribe with missing template_id returned %d, want 400", rw.Code)
	}
}
