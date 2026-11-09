package adminstore

import (
	"context"
	"fmt"
)

// CreateOrganization creates a new organization and its credit wallet.
func (s *Store) CreateOrganization(ctx context.Context, name, slug string) (*Organization, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}

	// Execute org creation + wallet initialization in a single transaction.
	var o Organization
	err := s.db.QueryRow(ctx, `
		WITH org_insert AS (
			INSERT INTO organizations (name, slug, cache_enabled, cache_mode, routing_mode)
			VALUES ($1, $2, true, 'semantic', 'auto')
			RETURNING id::text, name, slug, created_at, cache_enabled, cache_mode, routing_mode, currency, timezone, COALESCE(issue_url_template, '') AS issue_url_template
		),
		wallet_insert AS (
			INSERT INTO org_credits (org_id, balance_cents, updated_at)
			SELECT oi.id, 0, now() FROM org_insert oi
			ON CONFLICT (org_id) DO NOTHING
		)
		SELECT oi.id, oi.name, oi.slug, oi.created_at, oi.cache_enabled, oi.cache_mode, oi.routing_mode, oi.currency, oi.timezone, oi.issue_url_template
		FROM org_insert oi
	`, name, slug).Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt, &o.CacheEnabled, &o.CacheMode, &o.RoutingMode, &o.Currency, &o.Timezone, &o.IssueURLTemplate)
	if err != nil {
		return nil, fmt.Errorf("create organization: %w", err)
	}
	return &o, nil
}

// GetOrganizationByID returns an organization by ID.
func (s *Store) GetOrganizationByID(ctx context.Context, id string) (*Organization, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	var o Organization
	err := s.db.QueryRow(ctx,
		`SELECT id::text, name, slug, created_at, cache_enabled, cache_mode, routing_mode, currency, timezone, COALESCE(issue_url_template, ''), oc.grace_floor_cents
		 FROM organizations o LEFT JOIN org_credits oc ON oc.org_id = o.id::text WHERE o.id = $1`,
		id,
	).Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt, &o.CacheEnabled, &o.CacheMode, &o.RoutingMode, &o.Currency, &o.Timezone, &o.IssueURLTemplate, &o.GraceFloorCents)
	if err != nil {
		return nil, fmt.Errorf("get organization: %w", err)
	}
	return &o, nil
}

// GetOrganizationBySlug returns an organization by slug.
func (s *Store) GetOrganizationBySlug(ctx context.Context, slug string) (*Organization, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	var o Organization
	err := s.db.QueryRow(ctx,
		`SELECT o.id::text, o.name, o.slug, o.created_at, o.cache_enabled, o.cache_mode, o.routing_mode, o.currency, o.timezone, COALESCE(o.issue_url_template, ''), oc.grace_floor_cents
		 FROM organizations o LEFT JOIN org_credits oc ON oc.org_id = o.id::text WHERE o.slug = $1`,
		slug,
	).Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt, &o.CacheEnabled, &o.CacheMode, &o.RoutingMode, &o.Currency, &o.Timezone, &o.IssueURLTemplate, &o.GraceFloorCents)
	if err != nil {
		return nil, fmt.Errorf("get organization by slug: %w", err)
	}
	return &o, nil
}

// ListOrganizations returns a page of organizations.
// Pass PageFilter to control LIMIT/OFFSET; returns (rows, total, error).
func (s *Store) ListOrganizations(ctx context.Context, f PageFilter) ([]*Organization, int64, error) {
	if s.db == nil {
		return nil, 0, fmt.Errorf("database not available")
	}
	if f.PageSize <= 0 {
		f = NewPageFilter(f.Page, f.PageSize)
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM organizations`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count organizations: %w", err)
	}
	rows, err := s.db.Query(ctx,
		`SELECT o.id::text, o.name, o.slug, o.created_at, o.cache_enabled, o.cache_mode, o.routing_mode, o.currency, o.timezone, COALESCE(o.issue_url_template, ''), oc.grace_floor_cents
		 FROM organizations o LEFT JOIN org_credits oc ON oc.org_id = o.id::text`+
			f.OrderBy(OrganizationSortColumns, "created_at", true)+
			` LIMIT $1 OFFSET $2`,
		f.PageSize, f.Offset(),
	)
	if err != nil {
		return nil, 0, fmt.Errorf("list organizations: %w", err)
	}
	defer rows.Close()

	var orgs []*Organization
	for rows.Next() {
		var o Organization
		if err := rows.Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt, &o.CacheEnabled, &o.CacheMode, &o.RoutingMode, &o.Currency, &o.Timezone, &o.IssueURLTemplate, &o.GraceFloorCents); err != nil {
			return nil, 0, fmt.Errorf("scan organization: %w", err)
		}
		orgs = append(orgs, &o)
	}
	return orgs, total, rows.Err()
}

// DeleteOrganization deletes an organization by ID (cascades to keys/rules).
func (s *Store) DeleteOrganization(ctx context.Context, id string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	result, err := s.db.Exec(ctx,
		`DELETE FROM organizations WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("delete organization: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("organization not found")
	}
	return nil
}

// --- Teams ---

// UpdateOrganization updates name, slug, presentation currency and billing
// timezone for an organization. Empty currency/timezone fall back to the
// safe defaults (USD / UTC) so a partial update never blanks the setting.
func (s *Store) UpdateOrganization(ctx context.Context, id, name, slug, currency, timezone string, issueURL *string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	if currency == "" {
		currency = "USD"
	}
	if timezone == "" {
		timezone = "UTC"
	}
	var err error
	if issueURL == nil {
		_, err = s.db.Exec(ctx,
			`UPDATE organizations SET name = $1, slug = $2, currency = $3, timezone = $4, updated_at = now() WHERE id = $5`,
			name, slug, currency, timezone, id,
		)
	} else {
		_, err = s.db.Exec(ctx,
			`UPDATE organizations SET name = $1, slug = $2, currency = $3, timezone = $4, issue_url_template = $6, updated_at = now() WHERE id = $5`,
			name, slug, currency, timezone, id, *issueURL,
		)
	}
	if err != nil {
		return fmt.Errorf("update organization: %w", err)
	}
	return nil
}

// GetOrgResidencyRegion returns the residency region for an organization.
// Returns "" (global, no enforcement) when the column is NULL or the org is
// missing. Errors are returned only for transport problems.
func (s *Store) GetOrgResidencyRegion(ctx context.Context, orgID string) (string, error) {
	if s.db == nil {
		return "", nil
	}
	var region *string
	err := s.db.QueryRow(ctx,
		`SELECT residency_region FROM organizations WHERE id = $1`,
		orgID,
	).Scan(&region)
	if IsNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("get org residency region: %w", err)
	}
	if region == nil {
		return "", nil
	}
	return *region, nil
}

// UpdateOrgResidencyRegion sets the residency region for an organization.
// Pass "" (empty) to clear residency enforcement (global free-pass).
func (s *Store) UpdateOrgResidencyRegion(ctx context.Context, orgID string, region string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	var arg interface{}
	if region == "" {
		arg = nil
	} else {
		arg = region
	}
	_, err := s.db.Exec(ctx,
		`UPDATE organizations SET residency_region = $2 WHERE id = $1`,
		orgID, arg,
	)
	if err != nil {
		return fmt.Errorf("update org residency region: %w", err)
	}
	return nil
}
