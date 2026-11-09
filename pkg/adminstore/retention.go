package adminstore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// NEXT-21: per-team retention policies — hot-storage windows per table
// family, the redaction flag and the cold-storage export destination.
// Migration 0026 owns the schema; this file owns the admin API surface and
// the effective-resolution rules the retention worker consumes.
// ---------------------------------------------------------------------------

// Retention window bounds. A window below one day is refused (a policy must
// never delete data faster than it can be exported); the upper bound is a
// sanity cap (10 years) so a fat-fingered value cannot disable retention
// effectively forever.
const (
	MinRetentionDays = 1
	MaxRetentionDays = 3650
)

// ValidRetentionDays reports whether v is a settable hot-storage window.
// nil (no policy for that table family) is decided by the caller.
func ValidRetentionDays(v int) bool {
	return v >= MinRetentionDays && v <= MaxRetentionDays
}

// Cold-storage destination schemes. ” means "no destination": the retention
// worker must then never delete (export-before-delete contract). The
// file scheme stores JSONL+manifest archives under an absolute local path
// (also the deployment shape for S3-compatible object stores mounted via
// FUSE/NFS). The s3 scheme is reserved; the worker rejects it explicitly
// until a native S3 writer lands (no new dependencies in NEXT-21).
const (
	ColdSchemeFile = "file"
	ColdSchemeS3   = "s3"
)

// ValidColdDestination reports whether dest is a storable destination URI:
// ” (none) or file:///abs/path or s3://bucket[/prefix]. Mirrors the DB
// CHECK in migration 0026 ('file:///%' / 's3://%' need at least one more
// character), which stays the last line of defense.
func ValidColdDestination(dest string) bool {
	switch {
	case dest == "":
		return true
	case strings.HasPrefix(dest, "file:///"):
		return len(dest) > len("file:///")
	case strings.HasPrefix(dest, "s3://"):
		return len(dest) > len("s3://")
	}
	return false
}

// TeamRetentionPolicy is the per-team retention configuration (migration
// 0026). Every *Days nil = no window for that table family.
type TeamRetentionPolicy struct {
	TeamID string `json:"team_id"`
	// Hot-storage windows in days per table family.
	RequestLogsDays     *int `json:"request_logs_days"`
	CacheEntriesDays    *int `json:"cache_entries_days"`
	LineageDays         *int `json:"lineage_days"`
	BackupSnapshotsDays *int `json:"backup_snapshots_days"`
	// RedactContent exports raw content payloads (responses, upstream
	// request/response captures, cache payloads) as null; hashes, metadata
	// and the lineage hash chain always go verbatim.
	RedactContent bool `json:"redact_content"`
	// ColdDestination is '' or file:///… or s3://… (see ValidColdDestination).
	ColdDestination string `json:"cold_destination"`
	// Enabled=false keeps the policy stored but inert (worker skips it).
	Enabled bool `json:"enabled"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// OrgRetention is the effective retention for an organization: the MIN
// (strictest) enabled window per table family across the org's teams, and
// redact=OR (any enabled policy redacting wins). Destination is the
// lexicographically-smallest non-empty destination among the org's enabled
// policies — deterministic, so org-scoped exports (cache_entries,
// request_lineage) land in exactly one place even when several teams
// configure retention. nil destination = nothing exportable: the worker
// skips org-scoped cleanup instead of deleting without an archive.
type OrgRetention struct {
	RequestLogsDays     *int    `json:"request_logs_days"`
	CacheEntriesDays    *int    `json:"cache_entries_days"`
	LineageDays         *int    `json:"lineage_days"`
	BackupSnapshotsDays *int    `json:"backup_snapshots_days"`
	RedactContent       bool    `json:"redact_content"`
	Destination         *string `json:"destination"`
}

// TeamRetentionAssignment joins an enabled policy with its team's org; the
// retention worker consumes these flat rows (team-scoped work keys on
// TeamID, org-scoped work groups by OrgID).
type TeamRetentionAssignment struct {
	TeamRetentionPolicy
	OrgID string `json:"org_id"`
}

// ValidateRetentionDays checks one policy's windows in memory (the DB CHECK
// re-checks); used by Upsert so admin callers get a plain error instead of a
// constraint violation.
func ValidateRetentionDays(p *TeamRetentionPolicy) error {
	for _, d := range []*int{p.RequestLogsDays, p.CacheEntriesDays, p.LineageDays, p.BackupSnapshotsDays} {
		if d != nil && !ValidRetentionDays(*d) {
			return fmt.Errorf("retention days must be between %d and %d, got %d", MinRetentionDays, MaxRetentionDays, *d)
		}
	}
	if !ValidColdDestination(p.ColdDestination) {
		return fmt.Errorf("cold_destination must be '' or file:///<abs-path> or s3://<bucket>, got %q", p.ColdDestination)
	}
	return nil
}

// GetTeamRetentionPolicy returns the policy for a team; a team without a
// policy row is ErrNotFound (distinct from a stored, disabled policy).
func (s *Store) GetTeamRetentionPolicy(ctx context.Context, teamID string) (*TeamRetentionPolicy, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	tid, err := uuid.Parse(teamID)
	if err != nil {
		return nil, fmt.Errorf("team not found: %s: %w", teamID, ErrNotFound)
	}
	var p TeamRetentionPolicy
	err = s.db.QueryRow(ctx, `
		SELECT team_id::text, request_logs_days, cache_entries_days, lineage_days,
		       backup_snapshots_days, redact_content, cold_destination, enabled,
		       created_at, updated_at
		FROM team_retention_policies WHERE team_id = $1`, tid,
	).Scan(&p.TeamID, &p.RequestLogsDays, &p.CacheEntriesDays, &p.LineageDays,
		&p.BackupSnapshotsDays, &p.RedactContent, &p.ColdDestination, &p.Enabled,
		&p.CreatedAt, &p.UpdatedAt)
	if IsNotFound(err) {
		return nil, fmt.Errorf("team retention policy not found: %s: %w", teamID, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("get team retention policy: %w", err)
	}
	return &p, nil
}

// UpsertTeamRetentionPolicy creates or replaces the policy for an existing
// team. An unknown team is ErrNotFound (the INSERT ... SELECT only fires for
// a real organizations_teams row); invalid windows/destinations are plain
// errors before the DB is touched.
func (s *Store) UpsertTeamRetentionPolicy(ctx context.Context, p *TeamRetentionPolicy) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	if p == nil {
		return fmt.Errorf("upsert team retention policy: nil policy")
	}
	if err := ValidateRetentionDays(p); err != nil {
		return fmt.Errorf("upsert team retention policy: %w", err)
	}
	tid, err := uuid.Parse(p.TeamID)
	if err != nil {
		return fmt.Errorf("team not found: %s: %w", p.TeamID, ErrNotFound)
	}
	tag, err := s.db.Exec(ctx, `
		INSERT INTO team_retention_policies
			(team_id, request_logs_days, cache_entries_days, lineage_days,
			 backup_snapshots_days, redact_content, cold_destination, enabled)
		SELECT ot.id, $2, $3, $4, $5, $6, $7, $8
		FROM organizations_teams ot WHERE ot.id = $1
		ON CONFLICT (team_id) DO UPDATE SET
			request_logs_days = EXCLUDED.request_logs_days,
			cache_entries_days = EXCLUDED.cache_entries_days,
			lineage_days = EXCLUDED.lineage_days,
			backup_snapshots_days = EXCLUDED.backup_snapshots_days,
			redact_content = EXCLUDED.redact_content,
			cold_destination = EXCLUDED.cold_destination,
			enabled = EXCLUDED.enabled,
			updated_at = now()`,
		tid, p.RequestLogsDays, p.CacheEntriesDays, p.LineageDays,
		p.BackupSnapshotsDays, p.RedactContent, p.ColdDestination, p.Enabled,
	)
	if err != nil {
		return fmt.Errorf("upsert team retention policy: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("team not found: %s: %w", p.TeamID, ErrNotFound)
	}
	return nil
}

// DeleteTeamRetentionPolicy removes the policy (the team itself is untouched;
// rows for the team's data are not deleted by this call).
func (s *Store) DeleteTeamRetentionPolicy(ctx context.Context, teamID string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	tid, err := uuid.Parse(teamID)
	if err != nil {
		return fmt.Errorf("team retention policy not found: %s: %w", teamID, ErrNotFound)
	}
	tag, err := s.db.Exec(ctx, `DELETE FROM team_retention_policies WHERE team_id = $1`, tid)
	if err != nil {
		return fmt.Errorf("delete team retention policy: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("team retention policy not found: %s: %w", teamID, ErrNotFound)
	}
	return nil
}

// ListEnabledTeamRetentionAssignments returns every enabled policy joined
// with its team's org — the retention worker's policy source.
func (s *Store) ListEnabledTeamRetentionAssignments(ctx context.Context) ([]TeamRetentionAssignment, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	rows, err := s.db.Query(ctx, `
		SELECT p.team_id::text, ot.org_id::text, p.request_logs_days, p.cache_entries_days,
		       p.lineage_days, p.backup_snapshots_days, p.redact_content,
		       p.cold_destination, p.enabled, p.created_at, p.updated_at
		FROM team_retention_policies p
		JOIN organizations_teams ot ON ot.id = p.team_id
		WHERE p.enabled`)
	if err != nil {
		return nil, fmt.Errorf("list enabled retention policies: %w", err)
	}
	defer rows.Close()

	var out []TeamRetentionAssignment
	for rows.Next() {
		var a TeamRetentionAssignment
		if err := rows.Scan(&a.TeamID, &a.OrgID, &a.RequestLogsDays, &a.CacheEntriesDays,
			&a.LineageDays, &a.BackupSnapshotsDays, &a.RedactContent,
			&a.ColdDestination, &a.Enabled, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan retention assignment: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ErrNoRetention marks an org with no enabled retention policies: retention
// is opt-in per team, never implicit.
var ErrNoRetention = errors.New("no enabled retention policies")

// EffectiveOrgRetention resolves the org-wide MIN/OR aggregation documented
// on OrgRetention. An org with no enabled policies returns ErrNoRetention.
func (s *Store) EffectiveOrgRetention(ctx context.Context, orgID string) (*OrgRetention, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	oid, err := uuid.Parse(orgID)
	if err != nil {
		return nil, fmt.Errorf("organization not found: %s: %w", orgID, ErrNotFound)
	}
	var out OrgRetention
	err = s.db.QueryRow(ctx, `
		SELECT MIN(p.request_logs_days), MIN(p.cache_entries_days),
		       MIN(p.lineage_days), MIN(p.backup_snapshots_days),
		       COALESCE(BOOL_OR(p.redact_content), true),
		       (SELECT MIN(NULLIF(p2.cold_destination, ''))
		        FROM team_retention_policies p2
		        JOIN organizations_teams ot2 ON ot2.id = p2.team_id
		        WHERE ot2.org_id = $1 AND p2.enabled)
		FROM team_retention_policies p
		JOIN organizations_teams ot ON ot.id = p.team_id
		WHERE ot.org_id = $1 AND p.enabled`,
		oid, // $1 is referenced twice (subquery + outer filter)
	).Scan(&out.RequestLogsDays, &out.CacheEntriesDays, &out.LineageDays,
		&out.BackupSnapshotsDays, &out.RedactContent, &out.Destination)
	if IsNotFound(err) {
		return nil, fmt.Errorf("organization not found: %s: %w", orgID, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("effective org retention: %w", err)
	}
	if out.RequestLogsDays == nil && out.CacheEntriesDays == nil &&
		out.LineageDays == nil && out.BackupSnapshotsDays == nil {
		return nil, ErrNoRetention
	}
	return &out, nil
}
