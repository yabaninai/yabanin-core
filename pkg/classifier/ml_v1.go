package classifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// MLClassifier is an HTTP client for the self-hosted ML classifier service (P5.7).
// It sends prompts to a FastAPI server running bge-small-en-v1.5 with a 3-class head.
type MLClassifier struct {
	baseURL       string
	httpClient    *http.Client
	timeout       time.Duration
	log           *slog.Logger
	calibrator    *Calibrator
	driftDetector *DriftDetector
}

// NewMLClassifier creates an ML classifier pointing at the self-hosted service.
func NewMLClassifier(baseURL string, log *slog.Logger) *MLClassifier {
	return &MLClassifier{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 100 * time.Millisecond, // tight timeout — ML must be fast
		},
		timeout:    100 * time.Millisecond,
		log:        log.With("component", "ml-classifier"),
		calibrator: NewCalibrator(),
	}
}

// WithCalibrator sets the calibrator for confidence calibration.
func (m *MLClassifier) WithCalibrator(c *Calibrator) {
	m.calibrator = c
}

// WithDriftDetector sets the drift detector for confidence monitoring.
func (m *MLClassifier) WithDriftDetector(d *DriftDetector) {
	if d != nil {
		m.driftDetector = d
	}
}

// Name returns the classifier name for Registry fallback chain.
func (m *MLClassifier) Name() string { return "ml_v1" }

// Classify sends a prompt to the ML service and parses the 3-class response.
func (m *MLClassifier) Classify(ctx context.Context, in Input) (Result, error) {
	start := time.Now()

	body, _ := json.Marshal(map[string]interface{}{
		"text":   in.Prompt,
		"org_id": in.OrgID,
	})

	req, err := http.NewRequestWithContext(ctx, "POST", m.baseURL+"/v1/classify", bytes.NewReader(body))
	if err != nil {
		return Result{}, fmt.Errorf("ml request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("ml service unavailable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("ml service returned %d", resp.StatusCode)
	}

	var out struct {
		ClassName  string  `json:"class_name"`
		Confidence float64 `json:"confidence"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Result{}, fmt.Errorf("ml decode: %w", err)
	}

	confidence := m.calibrator.Scale(out.Confidence, Class(out.ClassName))

	r := Result{
		Class:      Class(out.ClassName),
		Confidence: confidence,
		Source:     string(SourceMLV1),
		Latency:    time.Since(start).Nanoseconds(),
	}

	// Feed result into drift detector for confidence monitoring.
	if m.driftDetector != nil {
		m.driftDetector.Record(r)
	}

	return r, nil
}

// HealthCheck pings the ML service health endpoint.
func (m *MLClassifier) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", m.baseURL+"/health", nil)
	if err != nil {
		return err
	}
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check returned %d", resp.StatusCode)
	}
	return nil
}
