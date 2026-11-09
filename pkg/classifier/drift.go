// Package classifier provides task complexity classification for smart model routing.
package classifier

import (
	"context"
	"sync"
	"time"
)

// DriftDetector monitors classifier confidence distribution shifts and alerts
// when the model's accuracy degrades beyond acceptable thresholds.
type DriftDetector struct {
	mu      sync.RWMutex
	history windowedConfidence // sliding window of past confidence scores
	alerted bool               // avoid repeated alerts for same drift event

	// Thresholds — configurable via config or env.
	WarningThreshold  float64 // avg confidence below this → warning
	CriticalThreshold float64 // avg confidence below this → critical alert
	HistorySize       int     // number of samples to keep in window
}

// NewDriftDetector creates a drift detector with default thresholds.
func NewDriftDetector() *DriftDetector {
	return &DriftDetector{
		history:           windowedConfidence{},
		WarningThreshold:  0.65, // avg confidence < 65% → warning
		CriticalThreshold: 0.45, // avg confidence < 45% → critical
		HistorySize:       100,  // track last 100 classifications
	}
}

// windowedConfidence is a ring buffer of recent confidence scores.
type windowedConfidence struct {
	buf []float64
	idx int
	n   int
}

func (w *windowedConfidence) push(v float64) {
	if len(w.buf) == 0 {
		w.buf = make([]float64, 100)
	}
	w.idx = w.idx % len(w.buf)
	w.buf[w.idx] = v
	w.idx++
	if w.n < len(w.buf) {
		w.n++
	}
}

func (w *windowedConfidence) avg() float64 {
	if w.n == 0 {
		return 1.0 // no data yet — assume healthy
	}
	sum := 0.0
	for i := 0; i < w.n; i++ {
		sum += w.buf[i]
	}
	return sum / float64(w.n)
}

// Record adds a classification result to the drift history.
func (d *DriftDetector) Record(result Result) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.history.push(result.Confidence)
	if d.history.n >= 10 {
		avg := d.history.avg()
		if avg < d.CriticalThreshold && !d.alerted {
			d.alerted = true
		}
		if avg > d.WarningThreshold+0.1 {
			d.alerted = false // recovered
		}
	}
}

// Status returns the current drift status.
func (d *DriftDetector) Status() DriftStatus {
	d.mu.RLock()
	defer d.mu.RUnlock()

	avg := d.history.avg()
	if avg < d.CriticalThreshold {
		return DriftCritical
	}
	if avg < d.WarningThreshold {
		return DriftWarning
	}
	return DriftHealthy
}

// AverageConfidence returns the rolling average confidence over the window.
func (d *DriftDetector) AverageConfidence() float64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.history.avg()
}

// SampleCount returns the number of samples recorded.
func (d *DriftDetector) SampleCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.history.n
}

// Reset clears the detector state (useful for testing).
func (d *DriftDetector) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.history = windowedConfidence{}
	d.alerted = false
}

// DriftStatus indicates the current health of classifier confidence.
type DriftStatus int

const (
	// DriftHealthy means confidence is within normal bounds.
	DriftHealthy DriftStatus = iota
	// DriftWarning means confidence has degraded but not critically.
	DriftWarning
	// DriftCritical means confidence has dropped significantly — retrain recommended.
	DriftCritical
)

func (s DriftStatus) String() string {
	switch s {
	case DriftHealthy:
		return "healthy"
	case DriftWarning:
		return "warning"
	case DriftCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// FeedbackDrivenRetrainTrigger uses feedback data to determine if a retrain is needed.
type FeedbackDrivenRetrainTrigger struct {
	mu          sync.RWMutex
	problematic map[Class]float64 // class → problem_rate from feedback
	window      time.Duration     // lookback window for feedback
}

// NewFeedbackDrivenRetrainTrigger creates a trigger that watches feedback data.
func NewFeedbackDrivenRetrainTrigger() *FeedbackDrivenRetrainTrigger {
	return &FeedbackDrivenRetrainTrigger{
		problematic: make(map[Class]float64),
		window:      7 * 24 * time.Hour, // last 7 days
	}
}

// Update sets the problematic class rates from the feedback collector.
func (t *FeedbackDrivenRetrainTrigger) Update(problematic map[Class]float64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.problematic = problematic
}

// NeedsRetrain returns true if any class has a problem rate above threshold.
func (t *FeedbackDrivenRetrainTrigger) NeedsRetrain(threshold float64) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	for _, rate := range t.problematic {
		if rate > threshold {
			return true
		}
	}
	return false
}

// ProblematicClasses returns the current problematic class map.
func (t *FeedbackDrivenRetrainTrigger) ProblematicClasses() map[Class]float64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	result := make(map[Class]float64, len(t.problematic))
	for k, v := range t.problematic {
		result[k] = v
	}
	return result
}

// TrainingSample represents one labeled example for classifier training.
type TrainingSample struct {
	Prompt     string  `json:"prompt"`
	Class      Class   `json:"class"`
	Confidence float64 `json:"confidence"`
	Feedback   string  `json:"feedback,omitempty"` // thumbs_up / thumbs_down / regenerate
}

// FeedbackStore is the interface for querying feedback data needed for retraining.
type FeedbackStore interface {
	GetProblematicSamples(ctx context.Context, cls Class, window time.Duration) ([]TrainingSample, error)
}
