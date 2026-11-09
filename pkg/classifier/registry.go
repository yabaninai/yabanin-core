package classifier

import (
	"context"
	"log/slog"
)

// Registry manages a primary classifier with optional fallbacks.
// If the primary classifier fails, the registry tries each fallback in order.
// If all classifiers fail, it returns a safe default (ClassMedium).
type Registry struct {
	primary   Classifier
	fallbacks []Classifier
	log       *slog.Logger
}

// NewRegistry creates a new classifier registry.
// The primary classifier is tried first; if it fails, fallbacks are tried in order.
func NewRegistry(primary Classifier, fallbacks ...Classifier) *Registry {
	return &Registry{
		primary:   primary,
		fallbacks: fallbacks,
		log:       slog.Default(),
	}
}

// WithLogger sets a custom logger for the registry.
func (r *Registry) WithLogger(l *slog.Logger) *Registry {
	r.log = l
	return r
}

// Classify attempts classification using the primary classifier, then fallbacks.
// It never returns an error — if all classifiers fail, it returns a safe default.
func (r *Registry) Classify(ctx context.Context, in Input) Result {
	// Try primary classifier.
	if r.primary != nil {
		res, err := r.primary.Classify(ctx, in)
		if err == nil {
			return res
		}
		r.log.Warn("primary classifier failed", "classifier", r.primary.Name(), "error", err)
	}

	// Try fallbacks in order.
	for _, fb := range r.fallbacks {
		res, err := fb.Classify(ctx, in)
		if err == nil {
			res.Source = fb.Name() + "_fallback"
			return res
		}
		r.log.Warn("fallback classifier failed", "classifier", fb.Name(), "error", err)
	}

	// All classifiers failed — return safe default (medium).
	r.log.Error("all classifiers failed, returning default medium")
	return Result{
		Class:      ClassMedium,
		Confidence: 0.0,
		Source:     string(SourceDefault),
		Latency:    0,
	}
}
