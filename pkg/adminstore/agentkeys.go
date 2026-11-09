package adminstore

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// AgentKey represents an agent-principal key (G1). Distinct from APIKey: it
// identifies an agent within an org and resolves to an AgentID. Only the
// sha256 hash is stored; the plaintext yag_ key is returned once at creation.
//
// ADL-03 delegation fields (all nullable): ParentID is set when this key was
// issued as a CHILD of another agent key; ExpiresAt is the delegation TTL
// (the auth resolver rejects the key once past this instant); DailyLimitCents
// is the delegation budget cap (mirrored into agent_budgets for enforcement).
// W-SECADM: KeyHash is internal-only (`json:"-"`); HTTP callers report HasHash.
type AgentKey struct {
	ID        string     `json:"id"`
	KeyHash   string     `json:"-"`
	HasHash   bool       `json:"has_hash"`
	OrgID     string     `json:"org_id"`
	Name      string     `json:"name"`
	Active    bool       `json:"active"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	// ADL-03 delegation.
	ParentID        *string    `json:"parent_id,omitempty"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	DailyLimitCents *int64     `json:"daily_limit_cents,omitempty"`
}

// agentKeyCols is the canonical column list used to read an agent_keys row
// (incl. the ADL-03 delegation columns). Kept as one constant so the read and
// the scan stay in sync.
const agentKeyCols = `id::text, key_hash, org_id::text, name, active, created_at, revoked_at,
	parent_id::text, expires_at, daily_limit_cents`

// scanAgentKey maps an agentKeyCols row onto an AgentKey.
func scanAgentKey(row pgx.Row) (*AgentKey, error) {
	k := &AgentKey{}
	if err := row.Scan(&k.ID, &k.KeyHash, &k.OrgID, &k.Name, &k.Active, &k.CreatedAt, &k.RevokedAt,
		&k.ParentID, &k.ExpiresAt, &k.DailyLimitCents); err != nil {
		if IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	// W-SECADM: the hash is internal-only; has_hash tells HTTP clients a key
	// exists without exposing the material.
	k.HasHash = k.KeyHash != ""
	return k, nil
}

// CreateAgentKey inserts a new ROOT agent key (hash-only) and returns the row.
// A root has no delegation fields (parent_id/expires_at/daily_limit_cents NULL).
func (s *Store) CreateAgentKey(ctx context.Context, keyHash, name, orgID string) (*AgentKey, error) {
	return s.CreateAgentKeyDelegated(ctx, AgentKeyCreateParams{
		KeyHash: keyHash,
		Name:    name,
		OrgID:   orgID,
	})
}

// AgentKeyCreateParams is the input for CreateAgentKeyDelegated. The
// delegation fields are optional: zero/nil produces a root key.
type AgentKeyCreateParams struct {
	KeyHash         string
	Name            string
	OrgID           string
	ParentID        *string
	ExpiresAt       *time.Time
	DailyLimitCents *int64
}

// CreateAgentKeyDelegated inserts an agent key, optionally as a CHILD of a
// parent (ADL-03). The caller is responsible for enforcing the delegation
// invariants (parent exists + is a root; grants ⊆ parent; budget ≤ parent
// residual) — this method only persists the row with the delegation fields.
func (s *Store) CreateAgentKeyDelegated(ctx context.Context, p AgentKeyCreateParams) (*AgentKey, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	row := s.db.QueryRow(ctx,
		`INSERT INTO agent_keys (key_hash, org_id, name, active, parent_id, expires_at, daily_limit_cents)
		 VALUES ($1, $2, $3, true, $4, $5, $6)
		 RETURNING `+agentKeyCols,
		p.KeyHash, p.OrgID, p.Name, p.ParentID, p.ExpiresAt, p.DailyLimitCents)
	k, err := scanAgentKey(row)
	if err != nil {
		return nil, fmt.Errorf("create agent key: %w", err)
	}
	return k, nil
}

// GetAgentKeyByID returns an agent key by ID.
func (s *Store) GetAgentKeyByID(ctx context.Context, id string) (*AgentKey, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	k, err := scanAgentKey(s.db.QueryRow(ctx,
		`SELECT `+agentKeyCols+` FROM agent_keys WHERE id = $1`, id))
	if err != nil {
		return nil, fmt.Errorf("get agent key: %w", err)
	}
	return k, nil
}

// ListAgentKeys returns agent keys for an org (newest first).
func (s *Store) ListAgentKeys(ctx context.Context, orgID string) ([]*AgentKey, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	rows, err := s.db.Query(ctx,
		`SELECT `+agentKeyCols+` FROM agent_keys WHERE org_id = $1 ORDER BY created_at DESC`,
		orgID,
	)
	if err != nil {
		return nil, fmt.Errorf("list agent keys: %w", err)
	}
	defer rows.Close()

	var keys []*AgentKey
	for rows.Next() {
		k := &AgentKey{}
		if err := rows.Scan(&k.ID, &k.KeyHash, &k.OrgID, &k.Name, &k.Active, &k.CreatedAt, &k.RevokedAt,
			&k.ParentID, &k.ExpiresAt, &k.DailyLimitCents); err != nil {
			return nil, fmt.Errorf("scan agent key: %w", err)
		}
		k.HasHash = k.KeyHash != ""
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// RevokeAgentKey sets active=false and stamps revoked_at for an agent key.
func (s *Store) RevokeAgentKey(ctx context.Context, id string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	result, err := s.db.Exec(ctx,
		`UPDATE agent_keys SET active = false, revoked_at = now() WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("revoke agent key: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
