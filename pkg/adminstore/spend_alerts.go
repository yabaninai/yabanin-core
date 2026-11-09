package adminstore

import (
	"context"
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// P6.9: Per-org spend alerts — fires webhook when daily spend exceeds threshold.
// ---------------------------------------------------------------------------

// OrgSpendAlertSettings holds the per-organization spend alert configuration.
type OrgSpendAlertSettings struct {
	ThresholdUSD *float64   `json:"threshold_usd"` // nil = disabled
	WebhookURL   *string    `json:"webhook_url"`   // nil = no webhook
	LastAlertAt  *time.Time `json:"last_alert_at"` // last time alert fired
	SpendToday   float64    `json:"spend_today"`   // computed, not stored
}

// SpendAlertOrg holds org info for the background alert checker.
type SpendAlertOrg struct {
	ID           string
	Name         string
	ThresholdUSD float64
	WebhookURL   string
	LastAlertAt  *time.Time
	// Currency/Timezone are the org's presentation settings (I18N-11). The
	// stored threshold/spend remain USD; currency is the code echoed in the
	// webhook so the receiving system knows how to label the amount.
	Currency string
	Timezone string
}

// GetOrgSpendAlertSettings returns the spend alert settings for an organization.
func (s *Store) GetOrgSpendAlertSettings(ctx context.Context, orgID string) (*OrgSpendAlertSettings, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}

	var rs OrgSpendAlertSettings
	var threshold *float64
	var webhookURL *string
	var lastAlertAt *time.Time

	err := s.db.QueryRow(ctx,
		`SELECT spend_alert_threshold_usd, spend_alert_webhook_url, last_alert_at FROM organizations WHERE id = $1`,
		orgID,
	).Scan(&threshold, &webhookURL, &lastAlertAt)
	if err != nil {
		return nil, fmt.Errorf("get org spend alert settings: %w", err)
	}

	rs.ThresholdUSD = threshold
	rs.WebhookURL = webhookURL
	rs.LastAlertAt = lastAlertAt

	// Compute today's spend
	now := time.Now().UTC()
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	var spendToday float64
	_ = s.db.QueryRow(ctx,
		`SELECT COALESCE(SUM(cost_in_usd), 0) FROM request_logs WHERE org_id::text = $1 AND created_at >= $2
		   AND COALESCE(ab_group, '') <> 'shadow'`,
		orgID, startOfDay,
	).Scan(&spendToday)
	rs.SpendToday = spendToday

	return &rs, nil
}

// UpdateOrgSpendAlertSettings updates the spend alert threshold and webhook for an organization.
func (s *Store) UpdateOrgSpendAlertSettings(ctx context.Context, orgID string, threshold *float64, webhookURL *string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	_, err := s.db.Exec(ctx,
		`UPDATE organizations SET spend_alert_threshold_usd = $2, spend_alert_webhook_url = $3 WHERE id = $1`,
		orgID, threshold, webhookURL,
	)
	if err != nil {
		return fmt.Errorf("update org spend alert settings: %w", err)
	}
	return nil
}

// ListOrgsWithSpendAlerts returns all orgs that have a spend alert threshold configured.
func (s *Store) ListOrgsWithSpendAlerts(ctx context.Context) ([]SpendAlertOrg, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}

	rows, err := s.db.Query(ctx,
		`SELECT id::text, name, COALESCE(spend_alert_threshold_usd, 0), COALESCE(spend_alert_webhook_url, ''), last_alert_at,
		        COALESCE(currency, 'USD'), COALESCE(timezone, 'UTC')
		 FROM organizations
		 WHERE spend_alert_threshold_usd IS NOT NULL AND spend_alert_threshold_usd > 0`,
	)
	if err != nil {
		return nil, fmt.Errorf("list orgs with spend alerts: %w", err)
	}
	defer rows.Close()

	var orgs []SpendAlertOrg
	for rows.Next() {
		var o SpendAlertOrg
		if err := rows.Scan(&o.ID, &o.Name, &o.ThresholdUSD, &o.WebhookURL, &o.LastAlertAt, &o.Currency, &o.Timezone); err != nil {
			return nil, fmt.Errorf("scan spend alert org: %w", err)
		}
		orgs = append(orgs, o)
	}
	return orgs, rows.Err()
}

// SpendToday returns the total spend for an org since the start of today (UTC).
func (s *Store) SpendToday(ctx context.Context, orgID string) (float64, error) {
	if s.db == nil {
		return 0, fmt.Errorf("database not available")
	}

	now := time.Now().UTC()
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	var total float64
	err := s.db.QueryRow(ctx,
		`SELECT COALESCE(SUM(cost_in_usd), 0) FROM request_logs WHERE org_id::text = $1 AND created_at >= $2
		   AND COALESCE(ab_group, '') <> 'shadow'`,
		orgID, startOfDay,
	).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("spend today: %w", err)
	}
	return total, nil
}

// UpdateLastAlertAt records when the last alert was fired for throttling.
func (s *Store) UpdateLastAlertAt(ctx context.Context, orgID string, at time.Time) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	_, err := s.db.Exec(ctx,
		`UPDATE organizations SET last_alert_at = $2 WHERE id = $1`,
		orgID, at,
	)
	if err != nil {
		return fmt.Errorf("update last alert at: %w", err)
	}
	return nil
}
