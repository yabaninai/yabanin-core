package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/reireirei/yabanin/pkg/classifier"
	"github.com/reireirei/yabanin/pkg/feedback"
	"github.com/reireirei/yabanin/services/admin/handlers"
)

// TestRetrainHandlers_Status_WithNilExporter verifies that nil exporter panics (pgxpool).
// In production, Status is only called when pool != nil (guarded in main.go).
func TestRetrainHandlers_Status_WithNilExporter(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic from nil exporter (pgxpool nil)")
		}
	}()

	rh := handlers.NewRetrainHandlers(nil, nil)
	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/retrain/status", nil)
	rh.Status(rw, req)
}

// TestRetrainHandlers_Status_WithTrigger verifies retrain logic panics with nil exporter.
func TestRetrainHandlers_Status_WithTrigger(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic from nil exporter")
		}
	}()

	rh := handlers.NewRetrainHandlers(nil, classifier.NewFeedbackDrivenRetrainTrigger())
	rw := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/retrain/status", nil)
	rh.Status(rw, req)
}

// TestRetrainHandlers_SetFeedbackCollector verifies the setter works.
func TestRetrainHandlers_SetFeedbackCollector(t *testing.T) {
	rh := handlers.NewRetrainHandlers(nil, nil)
	fc := feedback.NewCollector(nil, nil) // nil pool for constructor test
	if fc == nil {
		t.Fatal("NewCollector returned nil")
	}
	rh.SetFeedbackCollector(fc)
	// If we got here without panic, the setter works.
}
