// Package regionrepl produces federated daily rollups of request activity
// and ships them to a central analytics region. No PII is emitted: org_id is
// SHA-256 hashed to an 8-char prefix (k-anonymity); message content is never
// included.
package regionrepl

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RollupRow is one aggregated (region, day, model, org-prefix) bucket.
type RollupRow struct {
	Region         string  `json:"region"`
	Day            string  `json:"day"` // YYYY-MM-DD
	ModelUsed      string  `json:"model_used"`
	RequestCount   int64   `json:"request_count"`
	TotalCostUSD   float64 `json:"total_cost_usd"`
	TotalTokensIn  int64   `json:"total_tokens_in"`
	TotalTokensOut int64   `json:"total_tokens_out"`
	OrgHashPrefix  string  `json:"org_hash_prefix"`
}

// hashOrg returns the first 8 hex chars of SHA-256(org_id). Non-reversible.
func hashOrg(orgID string) string {
	if orgID == "" {
		return ""
	}
	h := sha256.Sum256([]byte(orgID))
	return hex.EncodeToString(h[:])[:8]
}

// RollupForDay aggregates request_logs for a given (region, day) into rows.
func RollupForDay(ctx context.Context, pool *pgxpool.Pool, region string, day time.Time) ([]RollupRow, error) {
	q := `
		SELECT
			COALESCE(NULLIF(org_id, ''), '__none__') AS org_bucket,
			COALESCE(model_used, 'unknown')         AS model_bucket,
			COUNT(*)                                 AS request_count,
			COALESCE(SUM(tokens_in), 0)              AS tokens_in,
			COALESCE(SUM(tokens_out), 0)             AS tokens_out
		FROM request_logs
		WHERE created_at >= $1 AND created_at < $2
		GROUP BY org_bucket, model_bucket`
	dayStart := time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, day.Location())
	dayEnd := dayStart.Add(24 * time.Hour)
	rows, err := pool.Query(ctx, q, dayStart, dayEnd)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []RollupRow
	for rows.Next() {
		var orgBucket, modelBucket string
		var count, tokIn, tokOut int64
		if err := rows.Scan(&orgBucket, &modelBucket, &count, &tokIn, &tokOut); err != nil {
			return nil, err
		}
		orgPrefix := ""
		if orgBucket != "__none__" {
			orgPrefix = hashOrg(orgBucket)
		}
		out = append(out, RollupRow{
			Region:         region,
			Day:            dayStart.Format("2006-01-02"),
			ModelUsed:      modelBucket,
			RequestCount:   count,
			TotalTokensIn:  tokIn,
			TotalTokensOut: tokOut,
			OrgHashPrefix:  orgPrefix,
		})
	}
	return out, rows.Err()
}
