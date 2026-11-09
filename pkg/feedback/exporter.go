package feedback

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/reireirei/yabanin/pkg/classifier"
)

// Exporter exports classifier feedback data into training-ready datasets.
type Exporter struct {
	pool *pgxpool.Pool
}

// NewExporter creates a new feedback exporter.
func NewExporter(pool *pgxpool.Pool) *Exporter {
	return &Exporter{pool: pool}
}

// ExportProblematicSamples returns samples from classes with high problem rates.
func (e *Exporter) ExportProblematicSamples(ctx context.Context, window time.Duration) ([]classifier.TrainingSample, error) {
	since := time.Now().Add(-window)

	rows, err := e.pool.Query(ctx, `
		SELECT cf.prompt_hash, cf.original_class, cf.action,
		       rl.request_id, rl.classifier_confidence, rl.model_used
		FROM classifier_feedback cf
		JOIN request_logs rl ON cf.request_id = rl.request_id
		WHERE cf.created_at > $1
		  AND cf.action IN ('thumbs_down', 'regenerate')
		ORDER BY cf.created_at DESC
		LIMIT 500
	`, since)
	if err != nil {
		return nil, fmt.Errorf("export problematic samples: %w", err)
	}
	defer rows.Close()

	var samples []classifier.TrainingSample
	for rows.Next() {
		var hash, class, action, reqID string
		var confidence float64
		var modelUsed *string
		if err := rows.Scan(&hash, &class, &action, &reqID, &confidence, &modelUsed); err != nil {
			break
		}
		samples = append(samples, classifier.TrainingSample{
			Prompt:     hash, // In production, join back to prompts table for full text
			Class:      classifier.Class(class),
			Confidence: confidence,
			Feedback:   action,
		})
	}

	return samples, nil
}

// ExportAllRecent returns all feedback from the given window.
func (e *Exporter) ExportAllRecent(ctx context.Context, window time.Duration) ([]classifier.TrainingSample, error) {
	since := time.Now().Add(-window)

	rows, err := e.pool.Query(ctx, `
		SELECT cf.prompt_hash, cf.original_class, cf.action,
		       rl.classifier_confidence
		FROM classifier_feedback cf
		JOIN request_logs rl ON cf.request_id = rl.request_id
		WHERE cf.created_at > $1
		ORDER BY cf.created_at DESC
		LIMIT 1000
	`, since)
	if err != nil {
		return nil, fmt.Errorf("export all recent: %w", err)
	}
	defer rows.Close()

	var samples []classifier.TrainingSample
	for rows.Next() {
		var hash, class, action string
		var confidence float64
		if err := rows.Scan(&hash, &class, &action, &confidence); err != nil {
			break
		}
		samples = append(samples, classifier.TrainingSample{
			Prompt:     hash,
			Class:      classifier.Class(class),
			Confidence: confidence,
			Feedback:   action,
		})
	}

	return samples, nil
}

// GetProblematicSamples returns samples from a specific class with negative feedback.
func (e *Exporter) GetProblematicSamples(ctx context.Context, cls classifier.Class, window time.Duration) ([]classifier.TrainingSample, error) {
	since := time.Now().Add(-window)

	rows, err := e.pool.Query(ctx, `
		SELECT cf.prompt_hash, cf.action, rl.classifier_confidence
		FROM classifier_feedback cf
		JOIN request_logs rl ON cf.request_id = rl.request_id
		WHERE cf.created_at > $1
		  AND cf.original_class = $2
		  AND cf.action IN ('thumbs_down', 'regenerate')
		ORDER BY cf.created_at DESC
		LIMIT 200
	`, since, string(cls))
	if err != nil {
		return nil, fmt.Errorf("get problematic samples for class %s: %w", cls, err)
	}
	defer rows.Close()

	var samples []classifier.TrainingSample
	for rows.Next() {
		var hash, action string
		var confidence float64
		if err := rows.Scan(&hash, &action, &confidence); err != nil {
			break
		}
		samples = append(samples, classifier.TrainingSample{
			Prompt:     hash,
			Class:      cls,
			Confidence: confidence,
			Feedback:   action,
		})
	}

	return samples, nil
}

// Ensure Exporter implements classifier.FeedbackStore.
var _ classifier.FeedbackStore = (*Exporter)(nil)
