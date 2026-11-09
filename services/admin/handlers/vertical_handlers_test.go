package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/reireirei/yabanin/services/admin/handlers"
)

// TestVerticalHandlers_List_NoOrgID verifies 400 when org_id is missing.
func TestVerticalHandlers_List_NoOrgID(t *testing.T) {
	vh := handlers.NewVerticalHandlers(nil, nil)
	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req = req.WithContext(req.Context()) // chi needs route context for URLParam

	// Without URL param (empty), List returns 400.
	vh.List(rw, req)
	if rw.Code != http.StatusBadRequest {
		t.Errorf("List without org_id returned %d, want 400", rw.Code)
	}
}

// TestVerticalHandlers_List_WithOrgID verifies 200 with valid org.
func TestVerticalHandlers_List_WithOrgID(t *testing.T) {
	vh := handlers.NewVerticalHandlers(nil, nil)
	_ = vh // ensure handler is constructed

	router := chi.NewRouter()
	router.Get("/api/organizations/{id}/verticals", vh.List)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/organizations/org-123/verticals", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("List returned %d, want 200", w.Code)
	}

	var result map[string]any
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if result["org_id"] != "org-123" {
		t.Errorf("org_id = %v, want org-123", result["org_id"])
	}
	if verticals, ok := result["verticals"].([]any); !ok || len(verticals) != 0 {
		t.Error("expected empty verticals list")
	}
}

// TestVerticalHandlers_Enable_InvalidVertical verifies 400 for unknown vertical.
func TestVerticalHandlers_Enable_InvalidVertical(t *testing.T) {
	vh := handlers.NewVerticalHandlers(nil, nil)
	router := chi.NewRouter()
	router.Post("/api/organizations/{id}/verticals/{vertical}", vh.Enable)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/organizations/org-123/verticals/unknown", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Enable invalid vertical returned %d, want 400", w.Code)
	}
}

// TestVerticalHandlers_Enable_Valid verifies 200 for valid vertical.
func TestVerticalHandlers_Enable_Valid(t *testing.T) {
	vh := handlers.NewVerticalHandlers(nil, nil)
	router := chi.NewRouter()
	router.Post("/api/organizations/{id}/verticals/{vertical}", vh.Enable)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/organizations/org-123/verticals/halal", strings.NewReader(`{"config":{}}`))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Enable returned %d, want 200", w.Code)
	}

	var result map[string]any
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if result["vertical"] != "halal" {
		t.Errorf("vertical = %v, want halal", result["vertical"])
	}
	if enabled, ok := result["enabled"].(bool); !ok || !enabled {
		t.Error("expected enabled=true")
	}
}

// TestVerticalHandlers_Disable verifies 200 with valid response.
func TestVerticalHandlers_Disable(t *testing.T) {
	vh := handlers.NewVerticalHandlers(nil, nil)
	router := chi.NewRouter()
	router.Delete("/api/organizations/{id}/verticals/{vertical}", vh.Disable)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/api/organizations/org-123/verticals/carbon", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Disable returned %d, want 200", w.Code)
	}

	var result map[string]any
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if result["vertical"] != "carbon" {
		t.Errorf("vertical = %v, want carbon", result["vertical"])
	}
	if enabled, ok := result["enabled"].(bool); !ok || enabled {
		t.Error("expected enabled=false")
	}
}

// TestVerticalHandlers_ListMarketplace verifies 200 and pack count.
func TestVerticalHandlers_ListMarketplace(t *testing.T) {
	vh := handlers.NewVerticalHandlers(nil, nil)
	router := chi.NewRouter()
	router.Get("/api/verticals/marketplace", vh.ListMarketplace)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/verticals/marketplace", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("ListMarketplace returned %d, want 200", w.Code)
	}

	var result map[string]any
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode error: %v", err)
	}

	verticals := result["verticals"].([]any)
	if len(verticals) != 5 {
		t.Errorf("got %d verticals, want 5", len(verticals))
	}
}
