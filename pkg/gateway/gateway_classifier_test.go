package cli

import (
	"context"
	"testing"

	"github.com/reireirei/yabanin/pkg/classifier"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClassifierRouting_ClassifierIntegration verifies the classifier registry
// correctly classifies prompts into tier classes and that the result fields
// match what get hoisted in gateway.go's chatCompletions handler.
func TestClassifierRouting_ClassifierIntegration(t *testing.T) {
	reg := classifier.NewRegistry(classifier.NewRuleTier())

	tests := []struct {
		name      string
		prompt    string
		wantClass classifier.Class
	}{
		{"short_translate", "Translate to French", classifier.ClassEasy},
		{"summarize", "Summarize this document", classifier.ClassEasy},
		{"step_by_step", "Reason step by step and explain the architecture", classifier.ClassHard},
		{"debug_code", "Debug this: ```go\nfunc foo() {}\n```", classifier.ClassHard},
		{"general_q", "Tell me about AI", classifier.ClassMedium},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := reg.Classify(context.Background(), classifier.Input{
				Prompt: tt.prompt,
			})
			assert.Equal(t, tt.wantClass, res.Class, "classification mismatch for %q", tt.prompt)
			assert.Greater(t, res.Confidence, 0.0, "confidence should be positive")
			assert.NotEmpty(t, res.Source, "source should be set")

			// Verify the fields match what gateway.go hoists into outer scope:
			// classifierClass = string(classResult.Class)
			// classifierConfidence = classResult.Confidence
			// classifierSource = classResult.Source
			classStr := string(res.Class)
			assert.NotEmpty(t, classStr)
			assert.True(t, res.Confidence >= 0.0 && res.Confidence <= 1.0,
				"confidence should be in [0, 1], got %f", res.Confidence)
			assert.NotEmpty(t, res.Source)
		})
	}
}

// TestClassifierRouting_AllTiersReturned verifies each tier (easy/medium/hard)
// is reachable through the registry with proper source attribution.
func TestClassifierRouting_AllTiersReturned(t *testing.T) {
	reg := classifier.NewRegistry(classifier.NewRuleTier())

	easyInputs := []string{"Translate", "Summarize this", "What is Go?"}
	mediumInputs := []string{"Write a paragraph about computing history", "Tell me about machine learning"}
	hardInputs := []string{
		"Debug this:\n```go\nfunc foo() {}\n```",
		"Reason step by step and explain the architecture",
	}

	for _, in := range easyInputs {
		res := reg.Classify(context.Background(), classifier.Input{Prompt: in})
		assert.Equal(t, classifier.ClassEasy, res.Class, "expected easy for %q", in)
		assert.Equal(t, string(classifier.SourceRuleTier), res.Source)
	}

	for _, in := range mediumInputs {
		res := reg.Classify(context.Background(), classifier.Input{Prompt: in})
		assert.Equal(t, classifier.ClassMedium, res.Class, "expected medium for %q", in)
	}

	for _, in := range hardInputs {
		res := reg.Classify(context.Background(), classifier.Input{Prompt: in})
		assert.Equal(t, classifier.ClassHard, res.Class, "expected hard for %q", in)
	}
}

// TestClassifierRouting_SourceFields validates that classifier source strings
// match the constants used in gateway.go publishEvent classifier_source field.
func TestClassifierRouting_SourceFields(t *testing.T) {
	reg := classifier.NewRegistry(classifier.NewRuleTier())
	res := reg.Classify(context.Background(), classifier.Input{Prompt: "hello"})

	// Source must be one of the recognized values that gateway.go writes to
	// eventpub.Event.ClassifierSource.
	supportedSources := map[string]bool{
		string(classifier.SourceRuleTier): true,
		string(classifier.SourceMLV1):     true,
		string(classifier.SourceCacheHit): true,
		string(classifier.SourceDefault):  true,
		string(classifier.SourceFallback): true,
	}
	assert.True(t, supportedSources[res.Source], "unexpected classifier source: %q", res.Source)
}

// TestClassifierRouting_EventPayloadFieldsValid verifies that the classifier
// result fields produce valid values for the event payload struct.
func TestClassifierRouting_EventPayloadFieldsValid(t *testing.T) {
	reg := classifier.NewRegistry(classifier.NewRuleTier())
	res := reg.Classify(context.Background(), classifier.Input{Prompt: "Explain quantum physics"})

	// These are the exact assignments from gateway.go hoisting logic:
	classifierClass := string(res.Class)
	classifierConfidence := res.Confidence
	classifierSource := res.Source

	// Validate they're suitable for event fields.
	require.NotEmpty(t, classifierClass, "classifier class must not be empty")
	require.True(t, classifierConfidence >= 0 && classifierConfidence <= 1,
		"confidence must be in [0, 1]")
	require.NotEmpty(t, classifierSource, "classifier source must not be empty")

	// Verify the class is one of the three expected values.
	switch classifier.Class(classifierClass) {
	case classifier.ClassEasy, classifier.ClassMedium, classifier.ClassHard:
		// valid
	default:
		t.Fatalf("invalid class %q", classifierClass)
	}
}
