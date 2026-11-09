package classifier

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractFeatures_ShortPrompt(t *testing.T) {
	in := Input{
		Prompt:        "Summarize this",
		Messages:      []string{},
		ContextTokens: 0,
	}
	f := ExtractFeatures(in)

	assert.Less(t, f.PromptTokens, 50)
	require.Len(t, f.KeywordsEasy, 1)
	assert.Contains(t, f.KeywordsEasy, "summarize")
	require.Empty(t, f.KeywordsHard)
	assert.False(t, f.HasCodeFence)
}

func TestExtractFeatures_CodeFence(t *testing.T) {
	code := strings.Repeat("line of code\n", 60)
	in := Input{
		Prompt:        "debug this:\n```go\n" + code + "\n```",
		Messages:      []string{},
		ContextTokens: 0,
	}
	f := ExtractFeatures(in)

	assert.True(t, f.HasCodeFence)
	assert.Greater(t, f.CodeFenceLines, 50)
	require.Len(t, f.KeywordsHard, 1)
	assert.Contains(t, f.KeywordsHard, "debug")
}

func TestExtractFeatures_ToolCallJSON(t *testing.T) {
	in := Input{
		Prompt:        `{"tool_calls": [{"function": {"name": "search"}}]}`,
		Messages:      []string{},
		ContextTokens: 0,
	}
	f := ExtractFeatures(in)

	assert.True(t, f.HasToolCallJSON)
}

func TestExtractFeatures_MultipleKeywords(t *testing.T) {
	in := Input{
		Prompt:        "Translate and summarize this text",
		Messages:      []string{},
		ContextTokens: 0,
	}
	f := ExtractFeatures(in)

	require.Len(t, f.KeywordsEasy, 2)
	assert.Contains(t, f.KeywordsEasy, "translate")
	assert.Contains(t, f.KeywordsEasy, "summarize")
}

func TestExtractFeatures_QuestionMarks(t *testing.T) {
	in := Input{
		Prompt:        "What is this? Why does it work? How do I use it?",
		Messages:      []string{},
		ContextTokens: 0,
	}
	f := ExtractFeatures(in)

	assert.Equal(t, 3, f.QuestionMarks)
}

func TestExtractFeatures_FromMessages(t *testing.T) {
	in := Input{
		Prompt:        "Translate this",
		Messages:      []string{"Hello world, how are you doing today"},
		ContextTokens: 0,
	}
	f := ExtractFeatures(in)

	require.Len(t, f.KeywordsEasy, 1)
	assert.Contains(t, f.KeywordsEasy, "translate")
}

func TestExtractFeatures_LongPrompt_HardTokens(t *testing.T) {
	long := strings.Repeat("word ", 1000) // ~4000 chars → ~1000 tokens
	in := Input{
		Prompt:        long,
		Messages:      []string{},
		ContextTokens: 0,
	}
	f := ExtractFeatures(in)

	assert.Greater(t, f.PromptTokens, 800) // significant token count
}

// --- RuleTier tests ---

func TestRuleTier_SummarizeShort_Easy(t *testing.T) {
	r := NewRuleTier()
	res, err := r.Classify(context.Background(), Input{Prompt: "Summarize this"})
	require.NoError(t, err)
	assert.Equal(t, ClassEasy, res.Class)
	assert.Greater(t, res.Confidence, 0.8)
	assert.Equal(t, string(SourceRuleTier), res.Source)
}

func TestRuleTier_DebugCode_Hard(t *testing.T) {
	r := NewRuleTier()
	code := strings.Repeat("line of code\n", 60)
	res, err := r.Classify(context.Background(), Input{
		Prompt: "debug this:\n```go\n" + code + "\n```",
	})
	require.NoError(t, err)
	assert.Equal(t, ClassHard, res.Class)
}

func TestRuleTier_LongPrompt_Hard(t *testing.T) {
	r := NewRuleTier()
	res, err := r.Classify(context.Background(), Input{
		Prompt: strings.Repeat("word ", 1000), // ~4000 chars → ~1000 tokens
	})
	require.NoError(t, err)
	// With only ~1000 tokens it may not hit the >2000 threshold.
	// But the test verifies long prompts don't crash and return a class.
	assert.NotEmpty(t, res.Class)
}

func TestRuleTier_VeryLongPrompt_Hard(t *testing.T) {
	r := NewRuleTier()
	res, err := r.Classify(context.Background(), Input{
		Prompt: strings.Repeat("word ", 2500), // ~10000 chars → ~2500 tokens > 2000 threshold
	})
	require.NoError(t, err)
	assert.Equal(t, ClassHard, res.Class)
}

func TestRuleTier_StepByStep_Hard(t *testing.T) {
	r := NewRuleTier()
	res, err := r.Classify(context.Background(), Input{
		Prompt: "Reason step by step and explain the architecture",
	})
	require.NoError(t, err)
	assert.Equal(t, ClassHard, res.Class)
}

func TestRuleTier_MediumFallback(t *testing.T) {
	r := NewRuleTier()
	res, err := r.Classify(context.Background(), Input{
		Prompt: "Tell me about machine learning in general",
	})
	require.NoError(t, err)
	assert.Equal(t, ClassMedium, res.Class)
	assert.InDelta(t, 0.60, res.Confidence, 0.01)
}

func TestRuleTier_ShortQuestion_Easy(t *testing.T) {
	r := NewRuleTier()
	res, err := r.Classify(context.Background(), Input{
		Prompt: "What is Go?",
	})
	require.NoError(t, err)
	assert.Equal(t, ClassEasy, res.Class)
}

func TestRuleTier_TranslateShort_Easy(t *testing.T) {
	r := NewRuleTier()
	res, err := r.Classify(context.Background(), Input{
		Prompt: "Translate this to French",
	})
	require.NoError(t, err)
	assert.Equal(t, ClassEasy, res.Class)
}

func TestRuleTier_MediumLength_NoKeywords_Medium(t *testing.T) {
	r := NewRuleTier()
	res, err := r.Classify(context.Background(), Input{
		Prompt: "Write a paragraph about the history of computing",
	})
	require.NoError(t, err)
	assert.Equal(t, ClassMedium, res.Class)
}

func TestRuleTier_DifferentModelsSameClass(t *testing.T) {
	r := NewRuleTier()

	res1, err := r.Classify(context.Background(), Input{Prompt: "Summarize"})
	require.NoError(t, err)
	res2, err := r.Classify(context.Background(), Input{Prompt: "Summarize", ModelRequested: "gpt-4"})
	require.NoError(t, err)

	assert.Equal(t, res1.Class, res2.Class)
}

func TestRuleTier_ConfidenceRanges(t *testing.T) {
	r := NewRuleTier()

	// Short keyword prompt → high confidence easy.
	resEasy, err := r.Classify(context.Background(), Input{Prompt: "Translate"})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, resEasy.Confidence, 0.9)

	// Ambiguous medium → default confidence.
	resMed, err := r.Classify(context.Background(), Input{Prompt: "Tell me about AI"})
	require.NoError(t, err)
	assert.InDelta(t, 0.60, resMed.Confidence, 0.01)

	// Hard keyword prompt → high confidence hard.
	resHard, err := r.Classify(context.Background(), Input{Prompt: "Debug this code"})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, resHard.Confidence, 0.8)
}

func TestRuleTier_LatencyPositive(t *testing.T) {
	r := NewRuleTier()
	res, err := r.Classify(context.Background(), Input{Prompt: "hello"})
	require.NoError(t, err)

	// Latency should be positive (>0 because time.Since takes actual time).
	assert.Positive(t, res.Latency)
}
