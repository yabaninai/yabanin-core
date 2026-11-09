// Package policystore provides policy-pack CRUD operations backed by Postgres.
package policystore

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/reireirei/yabanin/pkg/policy"
)

// Store provides access to policy-pack and residency-region data.
type Store struct {
	pool *pgxpool.Pool
}

// New creates a new policy store.
func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Upsert creates or updates a policy pack override for an org.
func (s *Store) Upsert(ctx context.Context, c PackConfig) (PackConfig, error) {
	if s.pool == nil {
		return PackConfig{}, ErrNoDB
	}
	if !IsValidRegion(c.Region) {
		return PackConfig{}, fmt.Errorf("invalid region %q: must be SG, IN, or ID", c.Region)
	}

	id := uuid.New()
	_, err := s.pool.Exec(ctx, `
		INSERT INTO policy_packs (id, org_id, region, pack_id, config)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (org_id, region) WHERE enabled = true DO UPDATE
			SET pack_id = EXCLUDED.pack_id,
			    config = EXCLUDED.config,
			    updated_at = now()
	`, id, c.OrgID.String(), c.Region, c.PackID, c.Config)
	if err != nil {
		return PackConfig{}, fmt.Errorf("upsert policy pack: %w", err)
	}

	return PackConfig{
		ID:        id,
		OrgID:     c.OrgID,
		Region:    c.Region,
		PackID:    c.PackID,
		Config:    c.Config,
		Version:   1,
		Enabled:   true,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}, nil
}

// GetByOrgRegion retrieves a single policy pack for an org.
func (s *Store) GetByOrgRegion(ctx context.Context, orgID, region string) (*PackConfig, error) {
	if s.pool == nil {
		return nil, ErrNoDB
	}
	var id uuid.UUID
	var packID string
	var cfg json.RawMessage
	err := s.pool.QueryRow(ctx, `
		SELECT id, pack_id, config FROM policy_packs
		WHERE org_id::text = $1 AND region = $2 AND enabled = true
	`, orgID, region).Scan(&id, &packID, &cfg)
	if err != nil {
		return nil, fmt.Errorf("get policy pack: %w", err)
	}

	return &PackConfig{
		ID:        id,
		Region:    region,
		PackID:    packID,
		Config:    cfg,
		Version:   1,
		Enabled:   true,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}, nil
}

// List retrieves all enabled policy packs for an org.
func (s *Store) List(ctx context.Context, orgID string) ([]PackConfig, error) {
	if s.pool == nil {
		return nil, ErrNoDB
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, region, pack_id, config::text, version, enabled, created_at, updated_at
		FROM policy_packs
		WHERE org_id::text = $1 AND enabled = true
		ORDER BY region
	`, orgID)
	if err != nil {
		return nil, fmt.Errorf("list policy packs: %w", err)
	}
	defer rows.Close()

	var records []PackConfig
	for rows.Next() {
		var id uuid.UUID
		var region, packID string
		var cfg json.RawMessage
		var version int
		var enabled bool
		var createdAt, updatedAt time.Time
		if err := rows.Scan(&id, &region, &packID, &cfg, &version, &enabled, &createdAt, &updatedAt); err != nil {
			continue
		}
		records = append(records, PackConfig{
			ID: id, Region: region, PackID: packID, Config: cfg,
			Version: version, Enabled: enabled, CreatedAt: createdAt, UpdatedAt: updatedAt,
		})
	}
	return records, nil
}

// Delete disables a policy pack by its record ID.
func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE policy_packs SET enabled = false, updated_at = now()
		WHERE id = $1
	`, id)
	if err != nil {
		return fmt.Errorf("delete policy pack: %w", err)
	}
	return nil
}

// PackConfig is the API-facing config for a policy pack override.
type PackConfig struct {
	ID        uuid.UUID       `json:"id,omitempty"`
	OrgID     *uuid.UUID      `json:"org_id,omitempty"` // passed in from handler
	Region    string          `json:"region"`
	PackID    string          `json:"pack_id"`
	Config    json.RawMessage `json:"config"`
	Version   int             `json:"version"`
	Enabled   bool            `json:"enabled"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// ErrNoDB is returned when the store has no database pool.
var ErrNoDB = fmt.Errorf("policystore: no database pool configured")

// IsValidRegion checks if a region string is a recognized Asia region (SG/IN/ID).
func IsValidRegion(r string) bool {
	return r == "SG" || r == "IN" || r == "ID"
}

// PolicyPackRecord represents a row from the policy_packs table.
type PolicyPackRecord struct {
	ID        uuid.UUID      `db:"id"`
	OrgID     uuid.UUID      `db:"org_id"`
	Region    string         `db:"region"`
	PackID    string         `db:"pack_id"`
	Config    map[string]any `db:"config"`
	Version   int            `db:"version"`
	Enabled   bool           `db:"enabled"`
	CreatedAt time.Time      `db:"created_at"`
	UpdatedAt time.Time      `db:"updated_at"`
}

// GetPolicyPacks retrieves all enabled policy packs for an org.
func (s *Store) GetPolicyPacks(ctx context.Context, orgID string) ([]PolicyPackRecord, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, org_id, region, pack_id, config, version, enabled, created_at, updated_at
		FROM policy_packs
		WHERE org_id::text = $1 AND enabled = true
		ORDER BY region
	`, orgID)
	if err != nil {
		return nil, fmt.Errorf("get policy packs: %w", err)
	}
	defer rows.Close()

	var records []PolicyPackRecord
	for rows.Next() {
		var r PolicyPackRecord
		if err := rows.Scan(&r.ID, &r.OrgID, &r.Region, &r.PackID,
			&r.Config, &r.Version, &r.Enabled, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan policy pack: %w", err)
		}
		if r.Config == nil {
			r.Config = make(map[string]any)
		}
		records = append(records, r)
	}
	return records, nil
}

// UpsertPolicyPack creates or updates a policy pack for an org.
func (s *Store) UpsertPolicyPack(ctx context.Context, orgID, region, packID string, rules policy.ResidencyRule) error {
	configJSON := map[string]any{
		"allowed_jurisdictions":  rules.AllowedJurisdictions,
		"allowed_model_families": rules.AllowedModelFamilies,
		"data_residency":         string(rules.DataResidency),
		"cross_border_allowed":   rules.CrossBorderAllowed,
		"blacklisted_countries":  rules.BlacklistedCountries,
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO policy_packs (org_id, region, pack_id, config)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (org_id, region) WHERE enabled = true DO UPDATE
			SET pack_id = EXCLUDED.pack_id,
			    config = EXCLUDED.config,
			    updated_at = now()
	`, orgID, region, packID, configJSON)
	if err != nil {
		return fmt.Errorf("upsert policy pack: %w", err)
	}
	return nil
}

// DeletePolicyPack disables a policy pack for an org.
func (s *Store) DeletePolicyPack(ctx context.Context, orgID string, region string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE policy_packs SET enabled = false, updated_at = now()
		WHERE org_id::text = $1 AND region = $2
	`, orgID, region)
	if err != nil {
		return fmt.Errorf("delete policy pack: %w", err)
	}
	return nil
}

// GetOrgResidencyRegion returns the residency region for an org.
func (s *Store) GetOrgResidencyRegion(ctx context.Context, orgID string) (*string, error) {
	var region *string
	err := s.pool.QueryRow(ctx, `
		SELECT residency_region FROM organizations WHERE id::text = $1
	`, orgID).Scan(&region)
	if err != nil {
		return nil, fmt.Errorf("get org residency: %w", err)
	}
	return region, nil
}

// UpdateOrgResidencyRegion sets the residency region for an org.
func (s *Store) UpdateOrgResidencyRegion(ctx context.Context, orgID string, newRegion string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE organizations SET residency_region = $1, updated_at = now()
		WHERE id::text = $2
	`, newRegion, orgID)
	if err != nil {
		return fmt.Errorf("update org residency: %w", err)
	}
	return nil
}
