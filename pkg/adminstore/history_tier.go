package adminstore

import (
	"context"
	"fmt"

	"github.com/reireirei/yabanin/pkg/historyarchive"
)

// N10-P02-T02: the per-org history-archive tier read model. It resolves the
// one org-dependent input of the archive contract (the original-text opt-in,
// I63) and joins it with the pinned package-level constants (90-day hot
// threshold, metadata-only media policy) into the single struct the transfer
// writer (T05/T06) persists with every archive batch — so the archive
// carries the media/original policy it was written under, hot and cold
// alike.
//
// Everything here is a read model: no policy can be CHANGED through it. The
// 90-day threshold is intentionally not per-org configuration — the contract
// fixes it (see historyarchive.HotRetentionDays); per-team deletion windows
// (team_retention_policies) are a separate, opt-in mechanism and are
// deliberately not mixed into this tier boundary.

// HistoryTierPolicy is the effective archive tier policy for one
// organization: what the hot→cold transfer must preserve and after which
// boundary the org's history becomes tier-eligible.
type HistoryTierPolicy struct {
	OrgID string `json:"org_id"`
	// HotRetentionDays is the fixed hot tier boundary in days (always 90 —
	// a tier boundary, never an age-based deletion deadline).
	HotRetentionDays int `json:"hot_retention_days"`
	// MediaPolicy is the pinned archive media policy (I62).
	MediaPolicy string `json:"media_policy"`
	// RedactionPolicy is the chosen originals redaction policy (I63).
	RedactionPolicy string `json:"redaction_policy"`
	// OriginalsOptIn reports the org's effective original-text retention
	// (fail-closed: unset/unresolved orgs inherit processed-only, so the
	// archive keeps originals out unless the org explicitly opted in).
	OriginalsOptIn bool `json:"originals_opt_in"`
}

// EffectiveHistoryTier resolves the archive tier policy for orgID. Unknown
// orgs return ErrNotFound; a wired-but-failing original-retention store
// resolves fail-closed (OriginalsOptIn=false) via GetOrgOriginalRetention —
// the same matrix the hot capture path uses, so the archive never widens
// what the hot tier lawfully persisted.
func (s *Store) EffectiveHistoryTier(ctx context.Context, orgID string) (*HistoryTierPolicy, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	retention, err := s.GetOrgOriginalRetention(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("effective history tier: %w", err)
	}
	return &HistoryTierPolicy{
		OrgID:            retention.OrgID,
		HotRetentionDays: historyarchive.HotRetentionDays,
		MediaPolicy:      historyarchive.MediaPolicyMetadataOnly,
		RedactionPolicy:  historyarchive.RedactionPolicyOriginalsOrgOptIn,
		OriginalsOptIn:   retention.Effective,
	}, nil
}
