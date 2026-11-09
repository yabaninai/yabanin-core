package evalgate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// Judge evaluates whether a cheap-model response is sufficient or if a premium model
// should have been used. Used on sampled requests to gather quality feedback for classifier tuning.
type Judge struct {
	evaluatorURL string
	apiKey       string // optional API key for judge endpoint auth
	client       *http.Client
	timeout      time.Duration
	log          *slog.Logger
	model        string // model to use as judge (default gpt-4o-mini)
}

// SetAPIKey configures the Authorization header for judge requests.
func (j *Judge) SetAPIKey(key string) {
	j.apiKey = key
}

// SetModel configures the judge model name.
func (j *Judge) SetModel(model string) {
	j.model = model
}

// Verdict represents the judge's evaluation of two responses.
type Verdict struct {
	CheapQuality   float64 `json:"cheap_quality"`   // 0..1 quality score for cheap model response
	PremiumQuality float64 `json:"premium_quality"` // 0..1 quality score for premium model response
	ShouldUpgrade  bool    `json:"should_upgrade"`  // true if premium model would have been better
	Reason         string  `json:"reason"`          // human-readable explanation
}

// NewJudge creates a new LLM-as-judge instance.
// evaluatorURL should be an OpenAI-compatible endpoint for the judge model.
func NewJudge(evaluatorURL string, log *slog.Logger) *Judge {
	if log == nil {
		log = slog.Default()
	}
	return &Judge{
		evaluatorURL: evaluatorURL,
		model:        "gpt-4o-mini",
		client:       &http.Client{Timeout: 10 * time.Second},
		timeout:      10 * time.Second,
		log:          log.With("component", "evalgate"),
	}
}

// Evaluate compares a cheap and premium model response to the same prompt.
// Returns a verdict indicating whether the cheap model was sufficient.
func (j *Judge) Evaluate(ctx context.Context, prompt, cheapResponse, premiumResponse string) (*Verdict, error) {
	start := time.Now()

	judgePrompt := fmt.Sprintf(`You are evaluating two AI responses to the same user prompt.

User prompt: %s

Response A (from a cheaper/faster model):
%s

Response B (from a premium/higher-quality model):
%s

Score each response 0.0 to 1.0 on correctness, completeness, and clarity.
Return ONLY valid JSON with these exact fields:
{"cheap_quality": 0.X, "premium_quality": 0.Y, "should_upgrade": true/false, "reason": "brief explanation"}`, prompt, cheapResponse[:min(len(cheapResponse), 2000)], premiumResponse[:min(len(premiumResponse), 2000)])

	body, _ := json.Marshal(map[string]interface{}{
		"model":    j.model,
		"messages": []map[string]string{{"role": "user", "content": judgePrompt}},
	})

	req, err := http.NewRequestWithContext(ctx, "POST", j.evaluatorURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create judge request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if j.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+j.apiKey)
	}

	resp, err := j.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("judge request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("judge returned status %d", resp.StatusCode)
	}

	var judgeOut struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&judgeOut); err != nil {
		return nil, fmt.Errorf("parse judge response: %w", err)
	}
	if len(judgeOut.Choices) == 0 {
		return nil, fmt.Errorf("judge returned empty choices")
	}

	// TP-03: the verdict feeds the calibration refresher, so a malformed or
	// incomplete verdict must surface as an explicit error instead of being
	// persisted as a defaulted measurement. The map pass enforces a single
	// JSON document (trailing garbage is rejected); the typed pass enforces
	// field types; unknown extra keys stay tolerated.
	content := []byte(judgeOut.Choices[0].Message.Content)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(content, &fields); err != nil {
		return nil, fmt.Errorf("judge returned invalid JSON: %w", err)
	}
	for _, field := range [...]string{"cheap_quality", "premium_quality", "should_upgrade", "reason"} {
		if _, ok := fields[field]; !ok {
			return nil, fmt.Errorf("judge verdict missing field %q", field)
		}
	}
	var verdict Verdict
	if err := json.Unmarshal(content, &verdict); err != nil {
		return nil, fmt.Errorf("judge verdict field types invalid: %w", err)
	}
	// Non-finite scores (1e999, NaN) cannot survive the typed decode above —
	// json.Unmarshal rejects them — so only the [0,1] range remains to enforce.
	for _, score := range []struct {
		name  string
		value float64
	}{
		{"cheap_quality", verdict.CheapQuality},
		{"premium_quality", verdict.PremiumQuality},
	} {
		if score.value < 0 || score.value > 1 {
			return nil, fmt.Errorf("judge verdict %s=%v out of range [0,1]", score.name, score.value)
		}
	}

	j.log.Debug("judge verdict",
		"cheap_quality", verdict.CheapQuality,
		"premium_quality", verdict.PremiumQuality,
		"should_upgrade", verdict.ShouldUpgrade,
		"latency_ms", time.Since(start).Milliseconds())

	return &verdict, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
