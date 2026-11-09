//go:build quality

package classifier_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/reireirei/yabanin/pkg/classifier"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// datasetDir is the directory containing dataset.jsonl, resolved relative
// to this test file's location so tests pass regardless of CWD.
var datasetDir = func() string {
	dir, err := os.Getwd()
	if err != nil {
		return "tests/quality"
	}
	// If running from module root, dataset is at tests/quality/dataset.jsonl
	// If running from tests/quality/, dataset is at ./dataset.jsonl
	if _, err := os.Stat(filepath.Join(dir, "dataset.jsonl")); err == nil {
		return dir
	}
	parent := filepath.Dir(dir)
	if _, err := os.Stat(filepath.Join(parent, "tests", "quality", "dataset.jsonl")); err == nil {
		return filepath.Join(parent, "tests", "quality")
	}
	return "tests/quality"
}()

// TestQualityRegressionSuite loads dataset.jsonl and verifies each prompt
// is classified correctly by the RuleTier classifier. This file is gated
// behind the "quality" build tag so it runs only when explicitly requested.
//
// Measured baseline: ~65% accuracy on synthetic dataset (RuleTier V0).
func TestQualityRegressionSuite(t *testing.T) {
	datasetPath := filepath.Join(datasetDir, "dataset.jsonl")

	f, err := os.Open(datasetPath)
	require.NoError(t, err, "dataset.jsonl must exist at %s", datasetPath)
	defer f.Close()

	entries := loadDataset(t, f)

	r := classifier.NewRuleTier()
	ctx := context.Background()

	total := 0
	passed := 0
	failed := make(map[string]int) // expected_class -> count of mismatches

	for _, entry := range entries {
		res, err := r.Classify(ctx, classifier.Input{Prompt: entry.Prompt})
		require.NoError(t, err, "classify should not error for: %q", entry.Prompt)

		total++
		if string(res.Class) == entry.ExpectedClass {
			passed++
		} else {
			failed[entry.ExpectedClass]++
			t.Logf("MISMATCH: expected=%s got=%s prompt=%q",
				entry.ExpectedClass, res.Class, truncate(entry.Prompt, 80))
		}
	}

	accuracy := float64(passed) / float64(total)
	t.Logf("Quality regression: %d/%d passed (%.1f%%)", passed, total, accuracy*100)

	// RuleTier V0 baseline: must maintain >=55% accuracy
	// (measured ~65% on synthetic dataset — margin for template changes)
	assert.GreaterOrEqual(t, accuracy, 0.55,
		"RuleTier accuracy dropped below 55%% baseline threshold")
}

// TestMLClassifierAccuracy runs the ML classifier V1 against the quality
// dataset and verifies accuracy >=90%. Requires CLASSIFIER_URL env var
// pointing to a running classifier service. Skips if not set.
func TestMLClassifierAccuracy(t *testing.T) {
	classifierURL := os.Getenv("CLASSIFIER_URL")
	if classifierURL == "" {
		t.Skip("CLASSIFIER_URL not set — skipping ML accuracy test")
	}

	datasetPath := filepath.Join(datasetDir, "dataset.jsonl")
	f, err := os.Open(datasetPath)
	require.NoError(t, err)
	defer f.Close()

	entries := loadDataset(t, f)

	ml := classifier.NewMLClassifier(classifierURL,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := context.Background()

	// Health check first
	if err := ml.HealthCheck(ctx); err != nil {
		t.Skipf("ML classifier service not available at %s: %v", classifierURL, err)
	}

	total := 0
	passed := 0
	perClass := map[string]struct{ correct, total int }{}

	for _, entry := range entries {
		res, err := ml.Classify(ctx, classifier.Input{Prompt: entry.Prompt})
		if err != nil {
			t.Logf("classify error (skipping): %v — prompt=%q", err, truncate(entry.Prompt, 60))
			continue
		}

		total++
		stats := perClass[entry.ExpectedClass]
		stats.total++
		if string(res.Class) == entry.ExpectedClass {
			passed++
			stats.correct++
		} else {
			t.Logf("MISMATCH: expected=%s got=%s prompt=%q",
				entry.ExpectedClass, res.Class, truncate(entry.Prompt, 80))
		}
		perClass[entry.ExpectedClass] = stats
	}

	require.Positive(t, total, "no prompts were classified — service may be down")
	accuracy := float64(passed) / float64(total)
	t.Logf("ML classifier V1 accuracy: %d/%d (%.1f%%)", passed, total, accuracy*100)

	for cls, stats := range perClass {
		clsAcc := float64(stats.correct) / float64(stats.total)
		t.Logf("  %s: %d/%d (%.1f%%)", cls, stats.correct, stats.total, clsAcc*100)
	}

	// ML V1 must achieve >=90% accuracy (measured 99.4% on synthetic test set)
	assert.GreaterOrEqual(t, accuracy, 0.90,
		"ML classifier V1 accuracy below 90%% threshold")
}

// TestQualityRegressionEachClass verifies that each class has at least one match.
func TestQualityRegressionEachClass(t *testing.T) {
	datasetPath := filepath.Join(datasetDir, "dataset.jsonl")

	f, err := os.Open(datasetPath)
	require.NoError(t, err)
	defer f.Close()

	entries := loadDataset(t, f)
	r := classifier.NewRuleTier()
	ctx := context.Background()

	classResults := map[classifier.Class]int{
		classifier.ClassEasy:   0,
		classifier.ClassMedium: 0,
		classifier.ClassHard:   0,
	}

	for _, entry := range entries {
		res, err := r.Classify(ctx, classifier.Input{Prompt: entry.Prompt})
		require.NoError(t, err)

		if string(res.Class) == entry.ExpectedClass {
			classResults[res.Class]++
		}
	}

	for cls, count := range classResults {
		assert.Greater(t, count, 0, "expected at least one correct classification for class %s", cls)
	}
}

// TestQualityRegressionConfidenceRanges verifies confidence values are in expected ranges.
func TestQualityRegressionConfidenceRanges(t *testing.T) {
	datasetPath := filepath.Join(datasetDir, "dataset.jsonl")

	f, err := os.Open(datasetPath)
	require.NoError(t, err)
	defer f.Close()

	entries := loadDataset(t, f)
	r := classifier.NewRuleTier()
	ctx := context.Background()

	for _, entry := range entries {
		res, err := r.Classify(ctx, classifier.Input{Prompt: entry.Prompt})
		require.NoError(t, err)

		switch entry.ExpectedClass {
		case "easy":
			assert.InDelta(t, 0.90, res.Confidence, 0.12,
				"easy prompt confidence should be ~0.90-0.98, got %.4f: %s",
				res.Confidence, truncate(entry.Prompt, 60))
		case "medium":
			assert.InDelta(t, 0.60, res.Confidence, 0.01,
				"medium prompt confidence should be ~0.60, got %.4f: %s",
				res.Confidence, truncate(entry.Prompt, 60))
		case "hard":
			assert.GreaterOrEqual(t, res.Confidence, 0.70,
				"hard prompt confidence should be >= 0.70, got %.4f: %s",
				res.Confidence, truncate(entry.Prompt, 60))
		}
	}
}

// TestQualityRegressionSource verifies all results come from rule_tier source.
func TestQualityRegressionSource(t *testing.T) {
	datasetPath := filepath.Join(datasetDir, "dataset.jsonl")

	f, err := os.Open(datasetPath)
	require.NoError(t, err)
	defer f.Close()

	entries := loadDataset(t, f)
	r := classifier.NewRuleTier()
	ctx := context.Background()

	for _, entry := range entries {
		res, err := r.Classify(ctx, classifier.Input{Prompt: entry.Prompt})
		require.NoError(t, err)
		assert.Equal(t, string(classifier.SourceRuleTier), res.Source,
			"unexpected source for: %s", truncate(entry.Prompt, 40))
	}
}

// TestQualityRegressionLatencyPositive verifies latency is always positive.
func TestQualityRegressionLatencyPositive(t *testing.T) {
	datasetPath := filepath.Join(datasetDir, "dataset.jsonl")

	f, err := os.Open(datasetPath)
	require.NoError(t, err)
	defer f.Close()

	entries := loadDataset(t, f)
	r := classifier.NewRuleTier()
	ctx := context.Background()

	for _, entry := range entries {
		res, err := r.Classify(ctx, classifier.Input{Prompt: entry.Prompt})
		require.NoError(t, err)
		assert.Positive(t, res.Latency,
			"latency should be positive for: %s", truncate(entry.Prompt, 40))
	}
}

// ---------- helpers ----------

type datasetEntry struct {
	Prompt        string `json:"prompt"`
	ExpectedClass string `json:"expected_class"`
}

func loadDataset(t *testing.T, r *os.File) []datasetEntry {
	t.Helper()

	var entries []datasetEntry
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if line == "" {
			continue
		}
		var entry datasetEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("line %d: invalid JSON: %v", lineNum, err)
		}
		if entry.Prompt == "" {
			t.Fatalf("line %d: empty prompt", lineNum)
		}
		if entry.ExpectedClass == "" {
			t.Fatalf("line %d: empty expected_class", lineNum)
		}
		entries = append(entries, entry)
	}

	require.NoError(t, scanner.Err())
	assert.NotEmpty(t, entries, "dataset must not be empty")
	return entries
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen < 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
