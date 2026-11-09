package feedback_test

import (
	"context"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/feedback"
)

// TestExporter_New verifies constructor.
func TestExporter_New(t *testing.T) {
	e := feedback.NewExporter(nil) // nil pool for constructor test
	if e == nil {
		t.Fatal("expected non-nil exporter")
	}
}

// TestExporter_ExportProblematicSamples_PanicNilPool verifies that nil pool panics — callers must guard.
func TestExporter_ExportProblematicSamples_PanicNilPool(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic from nil pool")
		}
	}()

	e := feedback.NewExporter(nil)
	_, _ = e.ExportProblematicSamples(context.Background(), 24*time.Hour)
}

// TestExporter_ExportAllRecent_PanicNilPool verifies that nil pool panics — callers must guard.
func TestExporter_ExportAllRecent_PanicNilPool(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic from nil pool")
		}
	}()

	e := feedback.NewExporter(nil)
	_, _ = e.ExportAllRecent(context.Background(), 24*time.Hour)
}

// TestExporter_GetProblematicSamples_PanicNilPool verifies that nil pool panics — callers must guard.
func TestExporter_GetProblematicSamples_PanicNilPool(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic from nil pool")
		}
	}()

	e := feedback.NewExporter(nil)
	_, _ = e.GetProblematicSamples(context.Background(), "easy", 24*time.Hour)
}
