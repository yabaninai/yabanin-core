package classifier

import (
	"math"
	"sync"
)

// Calibrator performs Platt scaling to calibrate classifier confidence scores.
// It maps raw confidence → calibrated confidence using logistic regression
// fitted on (raw_confidence, actual_correct) pairs from eval-gate data.
type Calibrator struct {
	mu      sync.RWMutex
	enabled bool
	a       float64 // slope coefficient
	b       float64 // intercept coefficient
	minConf float64
	maxConf float64
}

// NewCalibrator creates an uncalibrated calibrator (identity mapping).
func NewCalibrator() *Calibrator {
	return &Calibrator{
		a:       1.0,
		b:       0.0,
		minConf: 0.0,
		maxConf: 1.0,
	}
}

// Scale applies Platt scaling to a raw confidence score.
// scale(x) = sigmoid(a * logit(x) + b) where logit(x) = ln(x/(1-x)).
func (c *Calibrator) Scale(rawConfidence float64, class Class) float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.enabled {
		return rawConfidence // identity — no calibration
	}

	// Clamp to avoid log(0).
	clamped := math.Max(c.minConf+1e-10, math.Min(rawConfidence, c.maxConf-1e-10))
	logit := math.Log(clamped / (1 - clamped))
	scaled := sigmoid(c.a*logit + c.b)

	// Clamp result back to [0, 1].
	return math.Max(0.0, math.Min(scaled, 1.0))
}

func sigmoid(x float64) float64 {
	if x > 500 {
		return 1.0
	}
	if x < -500 {
		return 0.0
	}
	return 1.0 / (1.0 + math.Exp(-x))
}

// Fit trains the calibrator on raw confidence and actual correctness pairs.
// Each pair is (rawConfidence, wasCorrect) where wasCorrect is 0 or 1.
func (c *Calibrator) Fit(pairs [][2]float64) {
	if len(pairs) < 3 {
		return // not enough data
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.enabled = true

	// Simple logistic regression via gradient descent on (rawConfidence, label).
	a, b := 1.0, 0.0
	learningRate := 0.1
	for _, pair := range pairs {
		rawConf, label := pair[0], pair[1]
		clamped := math.Max(1e-10, math.Min(rawConf, 1-1e-10))
		logit := math.Log(clamped / (1 - clamped))
		pred := sigmoid(a*logit + b)
		err := pred - label
		a -= learningRate * err * logit
		b -= learningRate * err
	}

	c.a = a
	c.b = b
}

// IsEnabled returns whether calibration is active.
func (c *Calibrator) IsEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.enabled
}
