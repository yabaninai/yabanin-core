package adminstore

import (
	"context"
	"fmt"
)

// GetOrgCacheSettings returns the cache settings for an organization.
func (s *Store) GetOrgCacheSettings(ctx context.Context, orgID string) (*OrgCacheSettings, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	var cs OrgCacheSettings
	err := s.db.QueryRow(ctx,
		`SELECT cache_enabled, COALESCE(cache_mode, 'semantic') FROM organizations WHERE id = $1`,
		orgID,
	).Scan(&cs.CacheEnabled, &cs.CacheMode)
	if IsNotFound(err) {
		return nil, fmt.Errorf("organization not found: %s", orgID)
	}
	if err != nil {
		return nil, fmt.Errorf("get org cache settings: %w", err)
	}
	return &cs, nil
}

// UpdateOrgCacheSettings updates the cache settings for an organization.
// An unknown organization is ErrNotFound: a 0-row UPDATE must not be
// reported as success (the root settings write would otherwise ack a no-op
// and audit it). The two fields are one statement — they commit together or
// not at all.
func (s *Store) UpdateOrgCacheSettings(ctx context.Context, orgID string, enabled bool, mode string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	tag, err := s.db.Exec(ctx,
		`UPDATE organizations SET cache_enabled = $2, cache_mode = $3 WHERE id = $1`,
		orgID, enabled, mode,
	)
	if err != nil {
		return fmt.Errorf("update org cache settings: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("organization not found: %s: %w", orgID, ErrNotFound)
	}
	return nil
}

// ---------------------------------------------------------------------------
// P5.5: Per-org routing mode + threshold — controls classifier-based tier routing.
// ---------------------------------------------------------------------------

// DefaultRoutingThreshold returns the default confidence threshold based on routing mode.
func (rs *OrgRoutingSettings) DefaultRoutingThreshold() float64 {
	switch rs.RoutingMode {
	case RoutingModeAggressiveCost:
		return 0.4
	case RoutingModeClassifierOnly:
		return 0.9
	default: // auto, always_premium, always_cheap — use config or DB value
		if rs.RoutingThresholdConfidence > 0 {
			return rs.RoutingThresholdConfidence
		}
		return 0.6
	}
}

// EffectiveRoutingMode returns the effective routing behavior for this org.
// Returns "route_by_class", "always_premium", "always_cheap", or "disabled".
func (rs *OrgRoutingSettings) EffectiveRoutingMode() string {
	switch rs.RoutingMode {
	case RoutingModeAlwaysPremium:
		return "always_premium"
	case RoutingModeAlwaysCheap:
		return "always_cheap"
	case RoutingModeAggressiveCost, RoutingModeClassifierOnly, RoutingModeAuto:
		return "route_by_class"
	default: // disabled or unknown — treat as disabled
		return "disabled"
	}
}

// GetOrgRoutingSettings returns the routing settings for an organization.
func (s *Store) GetOrgRoutingSettings(ctx context.Context, orgID string) (*OrgRoutingSettings, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	var rs OrgRoutingSettings
	err := s.db.QueryRow(ctx,
		`SELECT COALESCE(routing_mode, 'auto'), COALESCE(routing_threshold_confidence, 0.6) FROM organizations WHERE id = $1`,
		orgID,
	).Scan(&rs.RoutingMode, &rs.RoutingThresholdConfidence)
	if IsNotFound(err) {
		return nil, fmt.Errorf("organization not found: %s", orgID)
	}
	if err != nil {
		return nil, fmt.Errorf("get org routing settings: %w", err)
	}
	return &rs, nil
}

// UpdateOrgRoutingSettings updates the routing mode for an organization.
// An unknown organization is ErrNotFound (same 0-row UPDATE rule as the
// other root settings writers).
func (s *Store) UpdateOrgRoutingSettings(ctx context.Context, orgID string, mode string, threshold float64) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	tag, err := s.db.Exec(ctx,
		`UPDATE organizations SET routing_mode = $2, routing_threshold_confidence = $3 WHERE id = $1`,
		orgID, mode, threshold,
	)
	if err != nil {
		return fmt.Errorf("update org routing settings: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("organization not found: %s: %w", orgID, ErrNotFound)
	}
	return nil
}

// ---------------------------------------------------------------------------
// P4.10: Model version management for cache invalidation.
// ---------------------------------------------------------------------------
