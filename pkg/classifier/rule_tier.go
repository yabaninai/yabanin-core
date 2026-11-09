package classifier

import (
	"context"
	"time"
)

// RuleTier is a deterministic rule-based classifier V0.
// It classifies prompts as easy/medium/hard based on heuristics:
// prompt length, code fences, tool calls, and keyword matching.
type RuleTier struct{}

// NewRuleTier creates a new rule-tier classifier.
func NewRuleTier() *RuleTier { return &RuleTier{} }

// Name returns the classifier identifier.
func (r *RuleTier) Name() string { return "rule_tier" }

// Classify analyzes the input prompt and returns a complexity classification.
// The rules are checked in priority order: HARD first, then EASY, default MEDIUM.
func (r *RuleTier) Classify(_ context.Context, in Input) (Result, error) {
	start := time.Now()
	f := ExtractFeatures(in)

	// --- HARD rules (checked first — any match → hard) ---
	if f.PromptTokens > 2000 {
		return r.result(ClassHard, 0.85, start)
	}
	if len(f.KeywordsHard) > 0 {
		return r.result(ClassHard, 0.80+float64(len(f.KeywordsHard))*0.02, start)
	}
	if f.HasCodeFence && f.CodeFenceLines > 50 {
		return r.result(ClassHard, 0.75, start)
	}
	if f.HasToolCallJSON && f.PromptTokens > 800 {
		return r.result(ClassHard, 0.70, start)
	}

	// --- EASY rules (all conditions must hold for strong confidence) ---
	if f.PromptTokens < 200 && len(f.KeywordsEasy) > 0 && !f.HasCodeFence {
		conf := 0.90 + float64(len(f.KeywordsEasy))*0.02
		if conf > 0.98 {
			conf = 0.98
		}
		return r.result(ClassEasy, conf, start)
	}
	if f.PromptTokens < 500 && len(f.KeywordsEasy) >= 2 {
		return r.result(ClassEasy, 0.80, start)
	}
	if f.PromptTokens < 100 && !f.HasCodeFence && f.QuestionMarks > 0 {
		return r.result(ClassEasy, 0.75, start)
	}

	// --- Default: MEDIUM (safe fallback for ambiguous prompts) ---
	return r.result(ClassMedium, 0.60, start)
}

func (r *RuleTier) result(c Class, conf float64, start time.Time) (Result, error) {
	return Result{
		Class:      c,
		Confidence: conf,
		Source:     string(SourceRuleTier),
		Latency:    time.Since(start).Nanoseconds(),
	}, nil
}
