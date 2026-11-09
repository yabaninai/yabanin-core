package adminstore

// services/admin/handlers/sovereign_handlers.go. Every statement below is
// the byte-equivalent of the handler query it replaces.

import (
	"context"
	"fmt"
)

// SovereignModel is one sovereign-model row of the admin marketplace list
// (tags identical to the former in-handler modelRow).
type SovereignModel struct {
	Name     string `json:"model_name"`
	Display  string `json:"display_name"`
	Tier     string `json:"tier"`
	Provider string `json:"provider"`
	Country  string `json:"country"`
	Juris    string `json:"jurisdiction"`
	SoTier   string `json:"sovereignty_tier"`
	VendorHQ string `json:"vendor_hq"`
	CNFlag   bool   `json:"cn_flagged"`
	Enabled  bool   `json:"enabled"`
}

// OrgSovereigntyPolicy is the per-org sovereignty routing policy (tags
// identical to the former in-handler policy struct).
type OrgSovereigntyPolicy struct {
	RequiredTier      string   `json:"required_tier"`
	ExcludedCountries []string `json:"excluded_countries"`
	BuyerJurisdiction string   `json:"buyer_jurisdiction"`
	CNAllowed         bool     `json:"cn_allowed"`
}

// ListSovereignModels returns the sovereign model rows: models with a known
// country or a CN flag, ordered by country then name.
func (s *Store) ListSovereignModels(ctx context.Context) ([]SovereignModel, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not configured")
	}
	rows, err := s.db.Query(ctx, `
		SELECT model_name, display_name, tier, provider, country, jurisdiction,
		       sovereignty_tier, vendor_hq, cn_flagged, enabled
		FROM models_registry
		WHERE country IS NOT NULL OR cn_flagged = true
		ORDER BY country, model_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SovereignModel
	for rows.Next() {
		var m SovereignModel
		if err := rows.Scan(&m.Name, &m.Display, &m.Tier, &m.Provider, &m.Country,
			&m.Juris, &m.SoTier, &m.VendorHQ, &m.CNFlag, &m.Enabled); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// SetSovereignModelEnabled enables or disables a sovereign model by name.
func (s *Store) SetSovereignModelEnabled(ctx context.Context, name string, enabled bool) error {
	if s.db == nil {
		return fmt.Errorf("database not configured")
	}
	_, err := s.db.Exec(ctx,
		`UPDATE models_registry SET enabled=$1 WHERE model_name=$2`, enabled, name)
	return err
}

// GetOrgSovereigntyPolicy retrieves the per-org sovereignty routing policy.
// A missing row surfaces as pgx.ErrNoRows — the handler keeps its
// default-policy fallback on any error, exactly as before.
func (s *Store) GetOrgSovereigntyPolicy(ctx context.Context, orgID string) (*OrgSovereigntyPolicy, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not configured")
	}
	var p OrgSovereigntyPolicy
	err := s.db.QueryRow(ctx,
		`SELECT required_tier, excluded_countries, buyer_jurisdiction, cn_allowed
		 FROM org_sovereignty_policy WHERE org_id=$1`, orgID,
	).Scan(&p.RequiredTier, &p.ExcludedCountries, &p.BuyerJurisdiction, &p.CNAllowed)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// UpsertOrgSovereigntyPolicy upserts the per-org sovereignty routing policy.
func (s *Store) UpsertOrgSovereigntyPolicy(ctx context.Context, orgID string, p *OrgSovereigntyPolicy) error {
	if s.db == nil {
		return fmt.Errorf("database not configured")
	}
	_, err := s.db.Exec(ctx, `
		INSERT INTO org_sovereignty_policy (org_id, required_tier, excluded_countries, buyer_jurisdiction, cn_allowed, updated_at)
		VALUES ($1,$2,$3,$4,$5,now())
		ON CONFLICT (org_id) DO UPDATE SET
			required_tier=EXCLUDED.required_tier,
			excluded_countries=EXCLUDED.excluded_countries,
			buyer_jurisdiction=EXCLUDED.buyer_jurisdiction,
			cn_allowed=EXCLUDED.cn_allowed,
			updated_at=now()`,
		orgID, p.RequiredTier, p.ExcludedCountries, p.BuyerJurisdiction, p.CNAllowed)
	return err
}
