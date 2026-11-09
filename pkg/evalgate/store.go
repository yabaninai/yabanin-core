package evalgate

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Store handles persistence of LLM-as-judge verdicts.
type Store struct {
	pool *pgxpool.Pool
	log  *slog.Logger
}

// NewStore creates a new Store backed by the given pgxpool and logger.
func NewStore(pool *pgxpool.Pool, log *slog.Logger) *Store {
	return &Store{pool: pool, log: log.With("component", "evalgate_store")}
}

// InsertVerdict records a judge verdict into evalgate_results.
func (s *Store) InsertVerdict(ctx context.Context, orgID, requestID, prompt, cheapModel, premiumModel string, v *Verdict, rawConfidence float64) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO evalgate_results (org_id, request_id, prompt, cheap_model, premium_model,
			cheap_quality, premium_quality, should_upgrade, reason, raw_confidence)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, orgID, requestID, prompt, cheapModel, premiumModel, v.CheapQuality, v.PremiumQuality, v.ShouldUpgrade, v.Reason, rawConfidence)
	if err != nil {
		return fmt.Errorf("evalgate store: %w", err)
	}
	s.log.Debug("evalgate verdict stored", "org_id", orgID, "should_upgrade", v.ShouldUpgrade)
	return nil
}

// LoadCalibrationPairs returns (raw_confidence, actual_correct) pairs from recent evalgate results.
// actual_correct = 1 if should_upgrade=false (judge said cheap was fine), 0 otherwise.
func (s *Store) LoadCalibrationPairs(ctx context.Context, sinceTime time.Time) ([][2]float64, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT raw_confidence, CASE WHEN should_upgrade THEN 0.0 ELSE 1.0 END as actual_correct
		FROM evalgate_results
		WHERE created_at > $1 AND raw_confidence IS NOT NULL
		ORDER BY created_at DESC LIMIT 500
	`, sinceTime)
	if err != nil {
		return nil, fmt.Errorf("load calibration pairs: %w", err)
	}
	defer rows.Close()

	var pairs [][2]float64
	for rows.Next() {
		var rawConf, actualCorrect float64
		if err := rows.Scan(&rawConf, &actualCorrect); err != nil {
			break
		}
		pairs = append(pairs, [2]float64{rawConf, actualCorrect})
	}
	return pairs, nil
}
