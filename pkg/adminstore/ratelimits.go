package adminstore

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// CRUD surface over migration 0027's key_rate_limits table. Enforcement
// lives in the gateway (pkg/gateway/ratelimit.go) behind
// YABANIN_KEY_RATE_LIMITS (default OFF); this file owns storage, validation
// and the per-scope effective resolution the gateway enforcer consumes.
// ---------------------------------------------------------------------------

// Rate limit scopes. The subject_id column references a different table per
// scope: 'key' → api_keys.id, 'team' → organizations_teams.id,
// 'org' → organizations.id.
const (
	RateLimitScopeKey  = "key"
	RateLimitScopeTeam = "team"
	RateLimitScopeOrg  = "org"
)

// Settable limit bounds. A value below one is refused (a zero limit would be
// indistinguishable from "disabled" and blocks the 0027 CHECK too); the upper
// bound is a sanity cap so a fat-fingered value cannot disable the limiter
// effectively forever.
const (
	MinRateLimitValue = 1
	MaxRateLimitValue = 10_000_000
)

// KeyRateLimit is one stored rate-limit row (migration 0027). RPM counts
// requests per minute, TPM counts model tokens per minute; nil = unlimited
// for that dimension. At least one of RPM/TPM must be set.
type KeyRateLimit struct {
	Scope     string `json:"scope"`
	SubjectID string `json:"subject_id"`
	// RPM is requests per minute (nil = unlimited for this scope).
	RPM *int64 `json:"rpm"`
	// TPM is model tokens per minute (nil = unlimited for this scope).
	TPM *int64 `json:"tpm"`
	// Enabled=false keeps the row stored but inert (the gateway skips it).
	Enabled bool `json:"enabled"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// KeyRateScopeLimits is the per-scope slice of an identity triple the gateway
// resolves per request: every enabled row that matches the key, team or org
// of the request, each enforced against its own Redis window with the
// strictest remaining value binding.
type KeyRateScopeLimits struct {
	Scope     string `json:"scope"`
	SubjectID string `json:"subject_id"`
	RPM       *int64 `json:"rpm"`
	TPM       *int64 `json:"tpm"`
}

// ValidRateLimitScope reports whether scope names a supported subject table.
func ValidRateLimitScope(scope string) bool {
	switch scope {
	case RateLimitScopeKey, RateLimitScopeTeam, RateLimitScopeOrg:
		return true
	}
	return false
}

// ValidRateLimitValue reports whether v is a settable rpm/tpm value.
func ValidRateLimitValue(v int64) bool {
	return v >= MinRateLimitValue && v <= MaxRateLimitValue
}

// ValidateKeyRateLimit checks one row in memory (the DB CHECKs re-check);
// used by Upsert so admin callers get a plain error instead of a constraint
// violation.
func ValidateKeyRateLimit(l *KeyRateLimit) error {
	if l == nil {
		return fmt.Errorf("nil rate limit")
	}
	if !ValidRateLimitScope(l.Scope) {
		return fmt.Errorf("scope must be %q, %q or %q, got %q",
			RateLimitScopeKey, RateLimitScopeTeam, RateLimitScopeOrg, l.Scope)
	}
	if _, err := uuid.Parse(l.SubjectID); err != nil {
		return fmt.Errorf("subject_id must be a UUID, got %q", l.SubjectID)
	}
	for name, v := range map[string]*int64{"rpm": l.RPM, "tpm": l.TPM} {
		if v != nil && !ValidRateLimitValue(*v) {
			return fmt.Errorf("%s must be between %d and %d, got %d",
				name, MinRateLimitValue, MaxRateLimitValue, *v)
		}
	}
	if l.RPM == nil && l.TPM == nil {
		return fmt.Errorf("at least one of rpm/tpm must be set")
	}
	return nil
}

// keyRateLimitUpsertSQL maps a scope to its Upsert query against the scope's
// subject table (all three own a uuid id). Fixed query constants, never
// interpolation: the scope is validated before lookup, and the INSERT only
// fires when the subject row exists, so no orphan limit can be stored.
var keyRateLimitUpsertSQL = map[string]string{
	RateLimitScopeKey: `
		INSERT INTO key_rate_limits (scope, subject_id, rpm, tpm, enabled)
		SELECT $1, $2, $3, $4, $5
		FROM api_keys s WHERE s.id::text = $2
		ON CONFLICT (scope, subject_id) DO UPDATE SET
			rpm = EXCLUDED.rpm,
			tpm = EXCLUDED.tpm,
			enabled = EXCLUDED.enabled,
			updated_at = now()`,
	RateLimitScopeTeam: `
		INSERT INTO key_rate_limits (scope, subject_id, rpm, tpm, enabled)
		SELECT $1, $2, $3, $4, $5
		FROM organizations_teams s WHERE s.id::text = $2
		ON CONFLICT (scope, subject_id) DO UPDATE SET
			rpm = EXCLUDED.rpm,
			tpm = EXCLUDED.tpm,
			enabled = EXCLUDED.enabled,
			updated_at = now()`,
	RateLimitScopeOrg: `
		INSERT INTO key_rate_limits (scope, subject_id, rpm, tpm, enabled)
		SELECT $1, $2, $3, $4, $5
		FROM organizations s WHERE s.id::text = $2
		ON CONFLICT (scope, subject_id) DO UPDATE SET
			rpm = EXCLUDED.rpm,
			tpm = EXCLUDED.tpm,
			enabled = EXCLUDED.enabled,
			updated_at = now()`,
}

// GetKeyRateLimit returns the stored row for (scope, subjectID); no row is
// ErrNotFound (distinct from a stored, disabled row).
func (s *Store) GetKeyRateLimit(ctx context.Context, scope, subjectID string) (*KeyRateLimit, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	if !ValidRateLimitScope(scope) {
		return nil, fmt.Errorf("rate limit scope must be %q, %q or %q, got %q",
			RateLimitScopeKey, RateLimitScopeTeam, RateLimitScopeOrg, scope)
	}
	var l KeyRateLimit
	err := s.db.QueryRow(ctx, `
		SELECT scope, subject_id, rpm, tpm, enabled, created_at, updated_at
		FROM key_rate_limits WHERE scope = $1 AND subject_id = $2`,
		scope, subjectID,
	).Scan(&l.Scope, &l.SubjectID, &l.RPM, &l.TPM, &l.Enabled, &l.CreatedAt, &l.UpdatedAt)
	if IsNotFound(err) {
		return nil, fmt.Errorf("rate limit not found: %s/%s: %w", scope, subjectID, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("get key rate limit: %w", err)
	}
	return &l, nil
}

// UpsertKeyRateLimit creates or replaces the row for its (scope, subject).
// An unknown subject (key/team/org does not exist) is ErrNotFound — the
// INSERT only fires when the subject row exists, so no orphan limit can be
// stored.
func (s *Store) UpsertKeyRateLimit(ctx context.Context, l *KeyRateLimit) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	if err := ValidateKeyRateLimit(l); err != nil {
		return fmt.Errorf("upsert key rate limit: %w", err)
	}
	query, ok := keyRateLimitUpsertSQL[l.Scope]
	if !ok {
		return fmt.Errorf("upsert key rate limit: unknown scope %q", l.Scope)
	}
	tag, err := s.db.Exec(ctx, query,
		l.Scope, l.SubjectID, l.RPM, l.TPM, l.Enabled,
	)
	if err != nil {
		return fmt.Errorf("upsert key rate limit: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("subject not found: %s/%s: %w", l.Scope, l.SubjectID, ErrNotFound)
	}
	return nil
}

// DeleteKeyRateLimit removes the row (the key/team/org itself is untouched).
func (s *Store) DeleteKeyRateLimit(ctx context.Context, scope, subjectID string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	if !ValidRateLimitScope(scope) {
		return fmt.Errorf("rate limit scope must be %q, %q or %q, got %q",
			RateLimitScopeKey, RateLimitScopeTeam, RateLimitScopeOrg, scope)
	}
	tag, err := s.db.Exec(ctx,
		`DELETE FROM key_rate_limits WHERE scope = $1 AND subject_id = $2`,
		scope, subjectID)
	if err != nil {
		return fmt.Errorf("delete key rate limit: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("rate limit not found: %s/%s: %w", scope, subjectID, ErrNotFound)
	}
	return nil
}

// ListKeyRateLimits returns every stored row (enabled and disabled), oldest
// first.
func (s *Store) ListKeyRateLimits(ctx context.Context) ([]KeyRateLimit, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	rows, err := s.db.Query(ctx, `
		SELECT scope, subject_id, rpm, tpm, enabled, created_at, updated_at
		FROM key_rate_limits ORDER BY created_at, scope, subject_id`)
	if err != nil {
		return nil, fmt.Errorf("list key rate limits: %w", err)
	}
	defer rows.Close()

	var out []KeyRateLimit
	for rows.Next() {
		var l KeyRateLimit
		if err := rows.Scan(&l.Scope, &l.SubjectID, &l.RPM, &l.TPM, &l.Enabled,
			&l.CreatedAt, &l.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan key rate limit: %w", err)
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// EffectiveKeyRateLimits resolves the per-scope limits that apply to a
// request's identity triple: every ENABLED row matching the key, the team or
// the org, each with its own rpm/tpm. Empty key/team/org ids simply never
// match their scope. The gateway enforces all returned rows and lets the
// strictest remaining value bind. No rows = no limits (the caller must treat
// that as "pass through without Redis").
func (s *Store) EffectiveKeyRateLimits(ctx context.Context, apiKeyID, teamID, orgID string) ([]KeyRateScopeLimits, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	rows, err := s.db.Query(ctx, `
		SELECT scope, subject_id, rpm, tpm
		FROM key_rate_limits
		WHERE enabled
		  AND (
		    (scope = 'key'  AND subject_id = $1)
		 OR (scope = 'team' AND subject_id = $2 AND $2 <> '')
		 OR (scope = 'org'  AND subject_id = $3 AND $3 <> '')
		  )`,
		apiKeyID, teamID, orgID,
	)
	if err != nil {
		return nil, fmt.Errorf("resolve key rate limits: %w", err)
	}
	defer rows.Close()

	var out []KeyRateScopeLimits
	for rows.Next() {
		var l KeyRateScopeLimits
		if err := rows.Scan(&l.Scope, &l.SubjectID, &l.RPM, &l.TPM); err != nil {
			return nil, fmt.Errorf("scan effective key rate limit: %w", err)
		}
		out = append(out, l)
	}
	return out, rows.Err()
}
