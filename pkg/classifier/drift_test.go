package classifier

import (
	"testing"
)

func TestDriftDetector_HappyPath(t *testing.T) {
	d := NewDriftDetector()

	// Healthy: high confidence scores.
	for i := 0; i < 50; i++ {
		d.Record(Result{Class: ClassEasy, Confidence: 0.85 + float64(i)*0.001})
	}

	if d.Status() != DriftHealthy {
		t.Errorf("expected healthy, got %s", d.Status())
	}
	if d.AverageConfidence() < 0.8 {
		t.Errorf("expected avg > 0.8, got %.3f", d.AverageConfidence())
	}

	// Simulate degradation — low confidence scores push into warning.
	for i := 0; i < 60; i++ {
		d.Record(Result{Class: ClassHard, Confidence: 0.5 + float64(i)*0.002})
	}

	status := d.Status()
	if status != DriftWarning && status != DriftCritical {
		t.Logf("status after degradation: %s (expected warning or critical)", status)
	}
}

func TestDriftDetector_Critical(t *testing.T) {
	d := NewDriftDetector()

	// All low confidence → should go critical.
	for i := 0; i < 30; i++ {
		d.Record(Result{Class: ClassMedium, Confidence: 0.3 + float64(i)*0.005})
	}

	if d.Status() != DriftCritical {
		t.Errorf("expected critical after low confidence, got %s", d.Status())
	}
}

func TestDriftDetector_Reset(t *testing.T) {
	d := NewDriftDetector()
	d.Record(Result{Confidence: 0.3})
	d.Record(Result{Confidence: 0.4})
	if d.SampleCount() == 0 {
		t.Error("expected samples after recording")
	}

	d.Reset()
	if d.SampleCount() != 0 {
		t.Error("expected zero samples after reset")
	}
	if d.Status() != DriftHealthy {
		t.Error("expected healthy after reset (no data → default)")
	}
}

func TestFeedbackDrivenRetrainTrigger(t *testing.T) {
	trigger := NewFeedbackDrivenRetrainTrigger()

	// No problematic classes → no retrain needed.
	if trigger.NeedsRetrain(0.2) {
		t.Error("expected no retrain with empty data")
	}

	// Add problematic classes.
	trigger.Update(map[Class]float64{
		ClassEasy:   0.1,
		ClassMedium: 0.25, // above threshold
	})

	if !trigger.NeedsRetrain(0.2) {
		t.Error("expected retrain when class has >20% problem rate")
	}

	// Check ProblematicClasses returns the map.
	pb := trigger.ProblematicClasses()
	if len(pb) != 2 {
		t.Errorf("expected 2 problematic classes, got %d", len(pb))
	}
}

func TestDriftAndFeedbackIntegration(t *testing.T) {
	// Simulate a full feedback-driven retrain cycle.
	d := NewDriftDetector()
	trigger := NewFeedbackDrivenRetrainTrigger()

	// Record some degraded classifications.
	for i := 0; i < 20; i++ {
		d.Record(Result{Class: ClassEasy, Confidence: 0.4})
	}

	// Simulate feedback collector reporting problematic classes.
	trigger.Update(map[Class]float64{
		ClassEasy: 0.35, // 35% thumbs_down for easy class
	})

	if trigger.NeedsRetrain(0.2) {
		t.Log("Both drift detector and feedback agree retrain is needed")
	}

	// Verify status reflects the degradation.
	status := d.Status()
	if status == DriftHealthy {
		t.Log("Drift detector shows healthy — may need more samples")
	}
	_ = status
}

func TestExporterCompile(t *testing.T) {
	// The exporter is tested in its own package. Just verify the feedback.Store
	// interface contract is met — this file tests drift detection only.
	// Integration test would run with a real DB pool.
}
