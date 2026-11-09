package feedback

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/reireirei/yabanin/pkg/classifier"
)

// Action represents a user feedback action on a classification.
type Action string

// Feedback actions users can submit on a classification result.
const (
	// ActionThumbsUp indicates the user approved the classification.
	ActionThumbsUp Action = "thumbs_up"
	// ActionThumbsDown indicates the user disapproved of the classification.
	ActionThumbsDown Action = "thumbs_down"
	// ActionRegenerate indicates the user requested a regenerated response.
	ActionRegenerate Action = "regenerate"
)

// Collector records and analyzes classifier feedback signals.
type Collector struct {
	pool *pgxpool.Pool
	log  *slog.Logger
}

// NewCollector creates a new Collector backed by the given database pool and logger.
func NewCollector(pool *pgxpool.Pool, log *slog.Logger) *Collector {
	return &Collector{pool: pool, log: log}
}

// Record saves a feedback signal.
func (c *Collector) Record(ctx context.Context, orgID, requestID, promptHash string, originalClass classifier.Class, action Action) error {
	_, err := c.pool.Exec(ctx, `
		INSERT INTO classifier_feedback (org_id, request_id, prompt_hash, original_class, action)
		VALUES ($1, $2, $3, $4, $5)
	`, orgID, requestID, promptHash, string(originalClass), string(action))
	if err != nil {
		return fmt.Errorf("feedback record: %w", err)
	}
	c.log.Debug("feedback recorded", "org_id", orgID, "action", action, "class", originalClass)
	return nil
}

// GetProblematicClasses returns the percentage of thumbs_down / regenerate signals per class.
func (c *Collector) GetProblematicClasses(ctx context.Context, orgID string) (map[classifier.Class]float64, error) {
	rows, err := c.pool.Query(ctx, `
		SELECT original_class, 
		       COUNT(*) FILTER (WHERE action IN ('thumbs_down', 'regenerate'))::float / COUNT(*) as problem_rate
		FROM classifier_feedback
		WHERE org_id = $1
		GROUP BY original_class
	`, orgID)
	if err != nil {
		return nil, fmt.Errorf("get problematic classes: %w", err)
	}
	defer rows.Close()

	result := map[classifier.Class]float64{}
	for rows.Next() {
		var class string
		var rate float64
		if err := rows.Scan(&class, &rate); err != nil {
			break
		}
		result[classifier.Class(class)] = rate
	}
	return result, nil
}

// Request is the API request body for POST /v1/feedback.
type Request struct {
	RequestID     string  `json:"request_id"`
	Action        Action  `json:"action"`
	OverrideClass *string `json:"override_class,omitempty"`
}

// Validate checks that the feedback request is well-formed.
func (f *Request) Validate() error {
	switch f.Action {
	case ActionThumbsUp, ActionThumbsDown, ActionRegenerate:
		return nil
	}
	return fmt.Errorf("invalid action: %s", f.Action)
}

// ValidActions returns all recognized action values.
func ValidActions() []string {
	return []string{"thumbs_up", "thumbs_down", "regenerate"}
}
