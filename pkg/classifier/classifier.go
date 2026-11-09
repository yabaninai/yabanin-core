// Package classifier provides task complexity classification for smart model routing.
package classifier

import "context"

// Class represents the complexity level of a prompt.
type Class string

const (
	// ClassEasy — simple prompts: summarize, translate, extract, short questions. Mapped to cheap pool.
	ClassEasy Class = "easy"
	// ClassMedium — moderate prompts: general questions, medium-length text. Mapped to mid-tier pool.
	ClassMedium Class = "medium"
	// ClassHard — complex prompts: debug, architect, step-by-step reasoning, long code fences. Mapped to premium pool.
	ClassHard Class = "hard"
)

// Source identifies which classifier produced the result.
type Source string

const (
	// SourceRuleTier indicates the result came from the deterministic rule-tier classifier.
	SourceRuleTier Source = "rule_tier"
	// SourceMLV1 indicates the result came from the ML model classifier.
	SourceMLV1 Source = "ml_v1"
	// SourceCacheHit indicates a cached classification was reused.
	SourceCacheHit Source = "cache_hit"
	// SourceDefault indicates no classifier could run, default Medium was returned.
	SourceDefault Source = "default"
	// SourceFallback indicates a fallback classifier was used after the primary failed.
	SourceFallback Source = "fallback"
)

// Result is the output of a classification decision.
type Result struct {
	Class      Class   // easy / medium / hard
	Confidence float64 // [0, 1] — how sure the classifier is about the class
	Source     string  // which classifier produced this result
	Latency    int64   // duration in nanoseconds
}

// Input is what gets passed to a classifier for analysis.
type Input struct {
	Prompt         string   // the last user message (the actionable request)
	Messages       []string // normalized conversation history
	ContextTokens  int      // estimated total tokens in the context window
	ModelRequested string   // model the client originally asked for
	OrgID          string   // organization making the request
}

// Classifier is the interface that all classifiers must implement.
type Classifier interface {
	// Classify analyzes the input and returns a complexity classification.
	Classify(ctx context.Context, in Input) (Result, error)
	// Name returns a human-readable identifier for this classifier.
	Name() string
}

// RegistryClassifier wraps a Registry to implement the Classifier interface.
// This is needed because Registry.Classify returns just Result while the
// Classifier interface requires (Result, error).
type RegistryClassifier struct {
	reg *Registry
}

// Classify implements the Classifier interface by delegating to the wrapped Registry.
func (w *RegistryClassifier) Classify(ctx context.Context, in Input) (Result, error) {
	return w.reg.Classify(ctx, in), nil
}

// Name implements the Classifier interface.
func (w *RegistryClassifier) Name() string {
	return "registry_wrapper"
}

// NewRegistryClassifier creates a Classifier from a Registry.
func NewRegistryClassifier(reg *Registry) *RegistryClassifier {
	return &RegistryClassifier{reg: reg}
}
