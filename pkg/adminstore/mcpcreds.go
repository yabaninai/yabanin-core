package adminstore

// MC-1 (MCP-CREDENTIALS-PLAN-2026-10-05): persistence for MCP upstream
// credentials — the server-level credential (one per registered server,
// admin-managed) and the per-user credential (lazy per-(server, agent)
// authorization), both encrypted at rest with the enc:-prefixed envelope of
// pkg/encryption (org_provider_credentials parity, migration 0002).
//
// Invariants (fixed contract for the whole feature):
//   - Plaintext secret material exists only as a call argument into
//     Upsert/resolve methods. Every read returns the masked row only
//     (secret_last4, has_secret) — no struct field could carry the
//     plaintext or the ciphertext out of the store.
//   - Writes are fail-closed: without a configured encryptor (and outside
//     the dev/test plaintext escape hatch) the write is refused, so a
//     missing encryption config can never silently downgrade to plaintext
//     at rest (orgcredentials.go parity).
//   - Every operation runs inside one transaction whose app.current_org GUC
//     is pinned via withOrgTx — the org_isolation RLS contract of migration
//     0007 (ENABLE + FORCE, least-privilege yabanin_app role). A foreign
//     org's rows are invisible and unwritable; an unset GUC sees nothing.
//   - `version` increments on every secret rotation or status transition so
//     the gateway resolver cache (MC-2) can invalidate by version.
//   - A per-user upsert requires an ENABLED grant on the server (the grant
//     stays the ceiling); grant revocation orphans the row (Orphan/
//     RestoreMCPUserCredentials are the grant-CRUD hooks, MC-3).

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/reireirei/yabanin/pkg/encryption"
)

// Credential kinds (migration 0007 CHECK).
const (
	MCPCredKindHeaders = "headers"
	MCPCredKindOAuth   = "oauth"
)

// Per-user credential statuses (migration 0007 CHECK).
const (
	MCPUserCredStatusPending     = "pending"
	MCPUserCredStatusActive      = "active"
	MCPUserCredStatusOrphaned    = "orphaned"
	MCPUserCredStatusNeedsReauth = "needs_reauth" //nolint:gosec // G101 false positive: status vocabulary label, not a credential
	MCPUserCredStatusNeedsUpdate = "needs_update"
)

// mcpSecretMaxBytes bounds one plaintext secret payload (headers JSON or
// oauth token JSON). A larger payload is misuse, not a credential.
const mcpSecretMaxBytes = 8 * 1024

// MCPServerCredential is one org-scoped server-level MCP credential as read
// back from the store. SecretLast4/HasSecret are display facts; neither the
// plaintext nor the ciphertext is representable in this type.
type MCPServerCredential struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"org_id"`
	ServerID    string    `json:"server_id"`
	ServerName  string    `json:"server_name"`
	Kind        string    `json:"kind"`
	SecretLast4 string    `json:"secret_last4"`
	HasSecret   bool      `json:"has_secret"`
	Enabled     bool      `json:"enabled"`
	Version     int64     `json:"version"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// MCPUserCredential is one per-(server, agent) MCP credential as read back
// from the store (masked). ExpiresAt nil = the secret never expires.
type MCPUserCredential struct {
	ID          string     `json:"id"`
	OrgID       string     `json:"org_id"`
	ServerID    string     `json:"server_id"`
	ServerName  string     `json:"server_name"`
	AgentKeyID  string     `json:"agent_key_id"`
	Kind        string     `json:"kind"`
	SecretLast4 string     `json:"secret_last4"`
	HasSecret   bool       `json:"has_secret"`
	Status      string     `json:"status"`
	Version     int64      `json:"version"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// mcpServerCredColumns is the canonical masked SELECT list for the
// server-level table. It never includes secret_ct.
const mcpServerCredColumns = `c.id::text, c.org_id::text, c.server_id::text, s.name, c.kind, c.secret_last4, c.enabled, c.version, c.created_at, c.updated_at, (c.secret_ct <> '') AS has_secret` //nolint:gosec // SQL column list; "secret" names a column, not a value

// mcpUserCredColumns is the canonical masked SELECT list for the per-user
// table. It never includes secret_ct.
const mcpUserCredColumns = `u.id::text, u.org_id::text, u.server_id::text, s.name, u.agent_key_id::text, u.kind, u.secret_last4, u.status, u.version, u.expires_at, u.created_at, u.updated_at, (u.secret_ct <> '') AS has_secret` //nolint:gosec // SQL column list; "secret" names a column, not a value

// scanMCPServerCredential scans one row of mcpServerCredColumns.
func scanMCPServerCredential(row scanner, c *MCPServerCredential) error {
	return row.Scan(&c.ID, &c.OrgID, &c.ServerID, &c.ServerName, &c.Kind,
		&c.SecretLast4, &c.Enabled, &c.Version, &c.CreatedAt, &c.UpdatedAt, &c.HasSecret)
}

// scanMCPUserCredential scans one row of mcpUserCredColumns.
func scanMCPUserCredential(row scanner, u *MCPUserCredential) error {
	return row.Scan(&u.ID, &u.OrgID, &u.ServerID, &u.ServerName, &u.AgentKeyID, &u.Kind,
		&u.SecretLast4, &u.Status, &u.Version, &u.ExpiresAt, &u.CreatedAt, &u.UpdatedAt, &u.HasSecret)
}

// resolveMCPServerID returns the id of the org's (enabled-state agnostic)
// server by name inside the caller's org-pinned transaction. A missing
// server is ErrNotFound.
func resolveMCPServerID(ctx context.Context, tx auditTx, orgID, serverName string) (string, error) {
	var id string
	err := tx.QueryRow(ctx,
		`SELECT id::text FROM mcp_servers WHERE org_id = $1::uuid AND name = $2`,
		orgID, serverName).Scan(&id)
	if err != nil {
		if IsNotFound(err) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("resolve mcp server %q: %w", serverName, err)
	}
	return id, nil
}

// requireEnabledMCPGrant verifies the agent holds an ENABLED grant on the
// named server (the grant is the ceiling for per-user credentials). Missing
// server or missing/disabled grant is the same ErrNotFound — a caller cannot
// distinguish grant-blocked from server-blocked (mcpagg parity).
func requireEnabledMCPGrant(ctx context.Context, tx auditTx, orgID, serverName, agentKeyID string) error {
	var one int
	err := tx.QueryRow(ctx,
		`SELECT 1 FROM mcp_server_grants
		 WHERE org_id = $1::uuid AND agent_id = $2::uuid AND server_name = $3 AND enabled`,
		orgID, agentKeyID, serverName).Scan(&one)
	if err != nil {
		if IsNotFound(err) {
			return ErrNotFound
		}
		return fmt.Errorf("resolve mcp grant: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Server-level credentials (admin-managed, one per server)
// ---------------------------------------------------------------------------

// UpsertMCPServerCredential creates or rotates the org's server-level
// credential. A non-empty existing row is replaced atomically and its
// version increments (rotation marker for the resolver cache). The server
// must exist for the org (ErrNotFound otherwise). After a rotation, per-user
// credentials on the same server whose kind no longer matches move to
// needs_update (the server's auth contract changed — the user must
// re-submit/re-auth).
func (s *Store) UpsertMCPServerCredential(ctx context.Context, orgID, serverName, kind, plaintextSecret string) (MCPServerCredential, error) {
	var out MCPServerCredential
	if err := validateMCPCredKind(kind); err != nil {
		return out, err
	}
	ct, last4, err := s.encryptMCPCredSecret(kind, plaintextSecret)
	if err != nil {
		return out, err
	}
	err = s.withOrgTx(ctx, orgID, func(tx auditTx) error {
		serverID, err := resolveMCPServerID(ctx, tx, orgID, serverName)
		if err != nil {
			return err
		}
		// RETURNING cannot reference the scan list's join aliases; the
		// server name is an input of this call, so it is filled in Go.
		err = tx.QueryRow(ctx,
			`INSERT INTO mcp_server_credentials (org_id, server_id, kind, secret_ct, secret_last4)
			 VALUES ($1::uuid, $2::uuid, $3, $4, $5)
			 ON CONFLICT (server_id) DO UPDATE SET
			     kind = EXCLUDED.kind,
			     secret_ct = EXCLUDED.secret_ct,
			     secret_last4 = EXCLUDED.secret_last4,
			     enabled = true,
			     version = mcp_server_credentials.version + 1,
			     updated_at = now()
			 RETURNING id::text, org_id::text, server_id::text, kind,
			     secret_last4, enabled, version, created_at, updated_at, (secret_ct <> '')`,
			orgID, serverID, kind, ct, last4,
		).Scan(&out.ID, &out.OrgID, &out.ServerID, &out.Kind,
			&out.SecretLast4, &out.Enabled, &out.Version, &out.CreatedAt, &out.UpdatedAt, &out.HasSecret)
		if err != nil {
			return fmt.Errorf("upsert mcp server credential: %w", err)
		}
		out.ServerName = serverName
		// Kind change invalidates matching-kind user credentials: their
		// secret authorizes the OLD auth contract (sticky until re-submit).
		if _, err := tx.Exec(ctx,
			`UPDATE mcp_user_credentials SET status = $3, version = version + 1, updated_at = now()
			 WHERE server_id = $1::uuid AND status = $4 AND kind <> $2`,
			serverID, kind, MCPUserCredStatusNeedsUpdate, MCPUserCredStatusActive,
		); err != nil {
			return fmt.Errorf("mark mcp user credentials needs_update: %w", err)
		}
		return nil
	})
	if err != nil {
		return MCPServerCredential{}, err
	}
	return out, nil
}

// SetMCPServerCredentialEnabled toggles the org's server-level credential.
// A disabled credential stops resolving (routing miss, not an error).
func (s *Store) SetMCPServerCredentialEnabled(ctx context.Context, orgID, serverName string, enabled bool) (MCPServerCredential, error) {
	var out MCPServerCredential
	err := s.withOrgTx(ctx, orgID, func(tx auditTx) error {
		serverID, err := resolveMCPServerID(ctx, tx, orgID, serverName)
		if err != nil {
			return err
		}
		err = tx.QueryRow(ctx,
			`UPDATE mcp_server_credentials SET enabled = $3, updated_at = now()
			 WHERE server_id = $2::uuid AND org_id = $1::uuid
			 RETURNING id::text, org_id::text, server_id::text, kind,
			     secret_last4, enabled, version, created_at, updated_at, (secret_ct <> '')`,
			orgID, serverID, enabled,
		).Scan(&out.ID, &out.OrgID, &out.ServerID, &out.Kind,
			&out.SecretLast4, &out.Enabled, &out.Version, &out.CreatedAt, &out.UpdatedAt, &out.HasSecret)
		if err != nil {
			if IsNotFound(err) {
				return ErrNotFound
			}
			return fmt.Errorf("set mcp server credential enabled: %w", err)
		}
		out.ServerName = serverName
		return nil
	})
	if err != nil {
		return MCPServerCredential{}, err
	}
	return out, nil
}

// GetMCPServerCredential returns the org's masked server-level credential.
func (s *Store) GetMCPServerCredential(ctx context.Context, orgID, serverName string) (MCPServerCredential, error) {
	var out MCPServerCredential
	err := s.withOrgTx(ctx, orgID, func(tx auditTx) error {
		err := tx.QueryRow(ctx,
			`SELECT `+mcpServerCredColumns+` FROM mcp_server_credentials c
			 JOIN mcp_servers s ON s.id = c.server_id
			 WHERE c.org_id = $1::uuid AND s.name = $2`,
			orgID, serverName,
		).Scan(&out.ID, &out.OrgID, &out.ServerID, &out.ServerName, &out.Kind,
			&out.SecretLast4, &out.Enabled, &out.Version, &out.CreatedAt, &out.UpdatedAt, &out.HasSecret)
		if err != nil {
			if IsNotFound(err) {
				return ErrNotFound
			}
			return fmt.Errorf("get mcp server credential: %w", err)
		}
		return nil
	})
	if err != nil {
		return MCPServerCredential{}, err
	}
	return out, nil
}

// ListMCPServerCredentials returns all of the org's masked server-level
// credentials, newest first.
func (s *Store) ListMCPServerCredentials(ctx context.Context, orgID string) ([]MCPServerCredential, error) {
	var out []MCPServerCredential
	err := s.withOrgTx(ctx, orgID, func(tx auditTx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+mcpServerCredColumns+` FROM mcp_server_credentials c
			 JOIN mcp_servers s ON s.id = c.server_id
			 WHERE c.org_id = $1::uuid ORDER BY c.created_at DESC, c.id`,
			orgID,
		)
		if err != nil {
			return fmt.Errorf("list mcp server credentials: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var c MCPServerCredential
			if err := scanMCPServerCredential(rows, &c); err != nil {
				return fmt.Errorf("scan mcp server credential: %w", err)
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteMCPServerCredential removes the org's server-level credential.
// Deleting a missing credential is ErrNotFound.
func (s *Store) DeleteMCPServerCredential(ctx context.Context, orgID, serverName string) error {
	var deleted int64
	err := s.withOrgTx(ctx, orgID, func(tx auditTx) error {
		serverID, err := resolveMCPServerID(ctx, tx, orgID, serverName)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx,
			`DELETE FROM mcp_server_credentials WHERE org_id = $1::uuid AND server_id = $2::uuid`,
			orgID, serverID)
		if err != nil {
			return fmt.Errorf("delete mcp server credential: %w", err)
		}
		deleted = tag.RowsAffected()
		return nil
	})
	if err != nil {
		return err
	}
	if deleted == 0 {
		return ErrNotFound
	}
	return nil
}

// ResolveMCPServerSecret returns the decrypted plaintext secret of the org's
// ENABLED server-level credential, plus its kind and version. ok=false (nil
// error) when the org has no enabled credential for the server. This is the
// only plaintext egress for server-level creds: in-process only, never
// logged, never serialized by callers.
func (s *Store) ResolveMCPServerSecret(ctx context.Context, orgID, serverName string) (secret, kind string, version int64, ok bool, err error) {
	if s.db == nil {
		return "", "", 0, false, fmt.Errorf("database not available")
	}
	var ct string
	err = s.withOrgTx(ctx, orgID, func(tx auditTx) error {
		err := tx.QueryRow(ctx,
			`SELECT c.secret_ct, c.kind, c.version FROM mcp_server_credentials c
			 JOIN mcp_servers s ON s.id = c.server_id
			 WHERE c.org_id = $1::uuid AND s.name = $2 AND c.enabled = true`,
			orgID, serverName,
		).Scan(&ct, &kind, &version)
		if err != nil {
			if IsNotFound(err) {
				return nil // ok=false below
			}
			return fmt.Errorf("resolve mcp server credential: %w", err)
		}
		return nil
	})
	if err != nil || ct == "" {
		return "", "", 0, false, err
	}
	plain, err := s.decryptMCPCredSecret(ct)
	if err != nil {
		return "", "", 0, false, err
	}
	return plain, kind, version, true, nil
}

// MCPServerCredentialMode returns the server's credential mode and
// configuration version (migration 0016, I54): the gateway consults it on
// every probe resolve so the delegated mode can refuse the silent fallback
// to the service credential. ok=false when the server row is absent.
func (s *Store) MCPServerCredentialMode(ctx context.Context, orgID, serverName string) (mode string, configVersion int64, ok bool, err error) {
	if s.db == nil {
		return "", 0, false, fmt.Errorf("database not available")
	}
	err = s.withOrgTx(ctx, orgID, func(tx auditTx) error {
		err := tx.QueryRow(ctx,
			`SELECT credential_mode, config_version FROM mcp_servers
			 WHERE org_id = $1::uuid AND name = $2`,
			orgID, serverName,
		).Scan(&mode, &configVersion)
		if err != nil {
			if IsNotFound(err) {
				return nil // ok=false below
			}
			return fmt.Errorf("read mcp server credential mode: %w", err)
		}
		ok = true
		return nil
	})
	if err != nil {
		return "", 0, false, err
	}
	return mode, configVersion, ok, nil
}

// StoreMCPUserCredVerifier persists the encrypted PKCE code_verifier (RFC
// 7636, migration 0017) on the agent's credential row. The gateway is the
// confidential client: the verifier never leaves the server except as the
// S256 challenge inside the authorize URL. Requires the row to exist
// (the flow creates it before the verifier is planted) — ErrNotFound otherwise.
func (s *Store) StoreMCPUserCredVerifier(ctx context.Context, orgID, serverName, agentKeyID, verifier string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	ct, _, err := s.encryptMCPCredSecret("", verifier)
	if err != nil {
		return fmt.Errorf("encrypt mcp pkce verifier: %w", err)
	}
	return s.withOrgTx(ctx, orgID, func(tx auditTx) error {
		serverID, err := resolveMCPServerID(ctx, tx, orgID, serverName)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx,
			`UPDATE mcp_user_credentials SET code_verifier_ct = $3
			 WHERE org_id = $1::uuid AND server_id = $2::uuid AND agent_key_id = $4`,
			orgID, serverID, ct, agentKeyID,
		)
		if err != nil {
			return fmt.Errorf("store mcp pkce verifier: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// ConsumeMCPUserCredVerifier reads and clears the pending PKCE code_verifier
// in one statement (single use per RFC 7636). ok=false when the row carries
// no verifier (pre-0017 row, already consumed, or downgraded schema) — the
// exchange then runs without code_verifier. The plaintext never leaves the
// store unencrypted: the ct is decrypted here and the column is cleared
// even if the caller aborts afterwards.
func (s *Store) ConsumeMCPUserCredVerifier(ctx context.Context, orgID, serverName, agentKeyID string) (verifier string, ok bool, err error) {
	if s.db == nil {
		return "", false, fmt.Errorf("database not available")
	}
	var ct string
	err = s.withOrgTx(ctx, orgID, func(tx auditTx) error {
		serverID, err := resolveMCPServerID(ctx, tx, orgID, serverName)
		if err != nil {
			return err
		}
		// The pending CTE snapshots the pre-statement value (a plain
		// UPDATE..SET col=NULL RETURNING col would return the NEW null) and
		// FOR UPDATE makes concurrent consumes single-winner: the loser
		// re-evaluates IS NOT NULL after the winner commits and finds the
		// row already consumed.
		err = tx.QueryRow(ctx,
			`WITH pending AS (
			     SELECT id, code_verifier_ct FROM mcp_user_credentials
			      WHERE org_id = $1::uuid AND server_id = $2::uuid AND agent_key_id = $3 AND code_verifier_ct IS NOT NULL
			      FOR UPDATE
			 )
			 UPDATE mcp_user_credentials u SET code_verifier_ct = NULL
			  FROM pending p
			  WHERE u.id = p.id
			  RETURNING p.code_verifier_ct`,
			orgID, serverID, agentKeyID,
		).Scan(&ct)
		if err != nil {
			if IsNotFound(err) {
				return nil // no pending verifier: ok=false
			}
			return fmt.Errorf("consume mcp pkce verifier: %w", err)
		}
		ok = true
		return nil
	})
	if err != nil {
		return "", false, err
	}
	if !ok {
		return "", false, nil
	}
	plain, err := s.decryptMCPCredSecret(ct)
	if err != nil {
		return "", false, err
	}
	return plain, true, nil
}

// ---------------------------------------------------------------------------
// Per-user credentials (lazy authorization, one row per (server, agent))
// ---------------------------------------------------------------------------

// UpsertMCPUserCredential creates or rotates the agent's credential on the
// server, setting the status to active (the submit/re-auth path). Requires
// an ENABLED grant for (org, agent, server): ErrNotFound otherwise — the
// grant stays the ceiling even against direct store callers. expiresAt nil
// means the secret never expires.
func (s *Store) UpsertMCPUserCredential(ctx context.Context, orgID, serverName, agentKeyID, kind, plaintextSecret string, expiresAt *time.Time) (MCPUserCredential, error) {
	return s.upsertMCPUserCredential(ctx, orgID, serverName, agentKeyID, kind, plaintextSecret, expiresAt, MCPUserCredStatusActive, "")
}

// CreatePendingMCPUserCredential plants the agent's pending OAuth row for
// the begin step: state (a random nonce) becomes the lookup key (flow_state)
// and the stored payload until the callback replaces it with tokens.
// Requires an ENABLED grant.
func (s *Store) CreatePendingMCPUserCredential(ctx context.Context, orgID, serverName, agentKeyID, state string) (MCPUserCredential, error) {
	if state == "" {
		return MCPUserCredential{}, fmt.Errorf("flow state is required")
	}
	if err := validateMCPFlowState(state); err != nil {
		return MCPUserCredential{}, err
	}
	return s.upsertMCPUserCredential(ctx, orgID, serverName, agentKeyID, MCPCredKindOAuth,
		fmt.Sprintf(`{"state":%q}`, state), nil, MCPUserCredStatusPending, state)
}

// UpdateMCPUserOAuthTokens rotates the agent's OAuth token material (the
// callback and the force-refresh path), sets the row active and bumps the
// version. Requires an ENABLED grant (a callback whose grant died mid-flow
// must not resurrect access).
func (s *Store) UpdateMCPUserOAuthTokens(ctx context.Context, orgID, serverName, agentKeyID, tokenJSON string, expiresAt *time.Time) (MCPUserCredential, error) {
	return s.upsertMCPUserCredential(ctx, orgID, serverName, agentKeyID, MCPCredKindOAuth, tokenJSON, expiresAt, MCPUserCredStatusActive, "")
}

// upsertMCPUserCredential is the single INSERT..ON CONFLICT path for the
// per-user table. status is the post-write status.
func (s *Store) upsertMCPUserCredential(ctx context.Context, orgID, serverName, agentKeyID, kind, plaintextSecret string, expiresAt *time.Time, status, flowState string) (MCPUserCredential, error) {
	var out MCPUserCredential
	if err := validateMCPCredKind(kind); err != nil {
		return out, err
	}
	if agentKeyID == "" {
		return out, fmt.Errorf("agent key id is required")
	}
	ct, last4, err := s.encryptMCPCredSecret(kind, plaintextSecret)
	if err != nil {
		return out, err
	}
	err = s.withOrgTx(ctx, orgID, func(tx auditTx) error {
		if err := requireEnabledMCPGrant(ctx, tx, orgID, serverName, agentKeyID); err != nil {
			return err
		}
		serverID, err := resolveMCPServerID(ctx, tx, orgID, serverName)
		if err != nil {
			return err
		}
		// RETURNING cannot reference the scan list's join aliases; the
		// server name is an input of this call, so it is filled in Go.
		err = tx.QueryRow(ctx,
			`INSERT INTO mcp_user_credentials
			     (org_id, server_id, agent_key_id, kind, secret_ct, secret_last4, status, expires_at, flow_state)
			 VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, $8, $9)
			 ON CONFLICT (server_id, agent_key_id) DO UPDATE SET
			     kind = EXCLUDED.kind,
			     secret_ct = EXCLUDED.secret_ct,
			     secret_last4 = EXCLUDED.secret_last4,
			     status = EXCLUDED.status,
			     expires_at = EXCLUDED.expires_at,
			     flow_state = EXCLUDED.flow_state,
			     version = mcp_user_credentials.version + 1,
			     updated_at = now()
			 RETURNING id::text, org_id::text, server_id::text, kind,
			     secret_last4, status, version, expires_at, created_at, updated_at, (secret_ct <> '')`,
			orgID, serverID, agentKeyID, kind, ct, last4, status, expiresAt, flowState,
		).Scan(&out.ID, &out.OrgID, &out.ServerID, &out.Kind,
			&out.SecretLast4, &out.Status, &out.Version, &out.ExpiresAt, &out.CreatedAt, &out.UpdatedAt, &out.HasSecret)
		if err != nil {
			return fmt.Errorf("upsert mcp user credential: %w", err)
		}
		out.ServerName = serverName
		out.AgentKeyID = agentKeyID
		return nil
	})
	if err != nil {
		return MCPUserCredential{}, err
	}
	return out, nil
}

// GetMCPUserCredential returns the agent's masked credential on the server.
func (s *Store) GetMCPUserCredential(ctx context.Context, orgID, serverName, agentKeyID string) (MCPUserCredential, error) {
	var out MCPUserCredential
	err := s.withOrgTx(ctx, orgID, func(tx auditTx) error {
		err := tx.QueryRow(ctx,
			`SELECT `+mcpUserCredColumns+` FROM mcp_user_credentials u
			 JOIN mcp_servers s ON s.id = u.server_id
			 WHERE u.org_id = $1::uuid AND s.name = $2 AND u.agent_key_id = $3::uuid`,
			orgID, serverName, agentKeyID,
		).Scan(&out.ID, &out.OrgID, &out.ServerID, &out.ServerName, &out.AgentKeyID, &out.Kind,
			&out.SecretLast4, &out.Status, &out.Version, &out.ExpiresAt, &out.CreatedAt, &out.UpdatedAt, &out.HasSecret)
		if err != nil {
			if IsNotFound(err) {
				return ErrNotFound
			}
			return fmt.Errorf("get mcp user credential: %w", err)
		}
		return nil
	})
	if err != nil {
		return MCPUserCredential{}, err
	}
	return out, nil
}

// ListMCPUserCredentials returns the org's masked per-user credentials,
// newest first. serverName nil lists every server.
func (s *Store) ListMCPUserCredentials(ctx context.Context, orgID string, serverName *string) ([]MCPUserCredential, error) {
	var out []MCPUserCredential
	err := s.withOrgTx(ctx, orgID, func(tx auditTx) error {
		query := `SELECT ` + mcpUserCredColumns + ` FROM mcp_user_credentials u
			 JOIN mcp_servers s ON s.id = u.server_id
			 WHERE u.org_id = $1::uuid`
		args := []any{orgID}
		if serverName != nil && *serverName != "" {
			query += ` AND s.name = $2`
			args = append(args, *serverName)
		}
		query += ` ORDER BY u.created_at DESC, u.id`
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("list mcp user credentials: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var u MCPUserCredential
			if err := scanMCPUserCredential(rows, &u); err != nil {
				return fmt.Errorf("scan mcp user credential: %w", err)
			}
			out = append(out, u)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteMCPUserCredential removes the agent's credential on the server
// (revoke). Deleting a missing credential is ErrNotFound.
func (s *Store) DeleteMCPUserCredential(ctx context.Context, orgID, serverName, agentKeyID string) error {
	var deleted int64
	err := s.withOrgTx(ctx, orgID, func(tx auditTx) error {
		serverID, err := resolveMCPServerID(ctx, tx, orgID, serverName)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx,
			`DELETE FROM mcp_user_credentials WHERE org_id = $1::uuid AND server_id = $2::uuid AND agent_key_id = $3::uuid`,
			orgID, serverID, agentKeyID)
		if err != nil {
			return fmt.Errorf("delete mcp user credential: %w", err)
		}
		deleted = tag.RowsAffected()
		return nil
	})
	if err != nil {
		return err
	}
	if deleted == 0 {
		return ErrNotFound
	}
	return nil
}

// SetMCPUserCredentialStatus moves the agent's credential to the given
// status (lifecycle transitions). Missing row is ErrNotFound.
func (s *Store) SetMCPUserCredentialStatus(ctx context.Context, orgID, serverName, agentKeyID, status string) error {
	switch status {
	case MCPUserCredStatusPending, MCPUserCredStatusActive, MCPUserCredStatusOrphaned,
		MCPUserCredStatusNeedsReauth, MCPUserCredStatusNeedsUpdate:
	default:
		return fmt.Errorf("unknown mcp user credential status %q", status)
	}
	var updated int64
	err := s.withOrgTx(ctx, orgID, func(tx auditTx) error {
		serverID, err := resolveMCPServerID(ctx, tx, orgID, serverName)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx,
			`UPDATE mcp_user_credentials SET status = $4, version = version + 1, updated_at = now()
			 WHERE org_id = $1::uuid AND server_id = $2::uuid AND agent_key_id = $3::uuid`,
			orgID, serverID, agentKeyID, status)
		if err != nil {
			return fmt.Errorf("set mcp user credential status: %w", err)
		}
		updated = tag.RowsAffected()
		return nil
	})
	if err != nil {
		return err
	}
	if updated == 0 {
		return ErrNotFound
	}
	return nil
}

// OrphanMCPUserCredentials is the grant-revocation hook (MC-3): every live
// credential of the (server, agent) pair becomes orphaned — runtime no
// longer sees it, and the row is preserved for the restore path.
func (s *Store) OrphanMCPUserCredentials(ctx context.Context, orgID, serverName, agentKeyID string) error {
	return s.transitionMCPUserCredentials(ctx, orgID, serverName, agentKeyID,
		`UPDATE mcp_user_credentials SET status = $4, version = version + 1, updated_at = now()
		 WHERE org_id = $1::uuid AND server_id = $2::uuid AND agent_key_id = $3::uuid AND status <> $4`,
		MCPUserCredStatusOrphaned)
}

// RestoreMCPUserCredentials is the grant-return hook (MC-3): orphaned
// credentials of the (server, agent) pair reactivate. A headers credential
// returns to active; an oauth credential returns to active only when token
// material is present, otherwise back to pending (the flow never finished).
// The payload inspection happens in Go inside the same transaction (the
// stored value is an enc: envelope, not SQL-castable JSON).
func (s *Store) RestoreMCPUserCredentials(ctx context.Context, orgID, serverName, agentKeyID string) error {
	return s.withOrgTx(ctx, orgID, func(tx auditTx) error {
		serverID, err := resolveMCPServerID(ctx, tx, orgID, serverName)
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx,
			`SELECT id::text, kind, secret_ct FROM mcp_user_credentials
			 WHERE org_id = $1::uuid AND server_id = $2::uuid AND agent_key_id = $3::uuid AND status = 'orphaned'`,
			orgID, serverID, agentKeyID)
		if err != nil {
			return fmt.Errorf("list orphaned mcp user credentials: %w", err)
		}
		type orphanRow struct {
			id, kind, ct string
		}
		var orphans []orphanRow
		for rows.Next() {
			var r orphanRow
			if err := rows.Scan(&r.id, &r.kind, &r.ct); err != nil {
				rows.Close()
				return fmt.Errorf("scan orphaned mcp user credential: %w", err)
			}
			orphans = append(orphans, r)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("list orphaned mcp user credentials: %w", err)
		}
		rows.Close()
		for _, r := range orphans {
			if _, err := tx.Exec(ctx,
				`UPDATE mcp_user_credentials SET status = $2, version = version + 1, updated_at = now()
				 WHERE id = $1::uuid`,
				r.id, s.restoredMCPUserCredStatus(r.kind, r.ct)); err != nil {
				return fmt.Errorf("restore mcp user credential: %w", err)
			}
		}
		return nil
	})
}

// restoredMCPUserCredStatus decides the post-restore status: headers is
// immediately usable; oauth is active only with token material, else it goes
// back to pending; an undecryptable payload never comes back as active.
func (s *Store) restoredMCPUserCredStatus(kind, ct string) string {
	if kind != MCPCredKindOAuth {
		return MCPUserCredStatusActive
	}
	plain, err := s.decryptMCPCredSecret(ct)
	if err != nil {
		return MCPUserCredStatusNeedsReauth
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal([]byte(plain), &tok); err == nil && tok.AccessToken != "" {
		return MCPUserCredStatusActive
	}
	return MCPUserCredStatusPending
}

// transitionMCPUserCredentials runs one status-transition UPDATE (the SQL
// pins org + server + agent; $4 carries the target status).
func (s *Store) transitionMCPUserCredentials(ctx context.Context, orgID, serverName, agentKeyID, query, status string) error {
	return s.withOrgTx(ctx, orgID, func(tx auditTx) error {
		serverID, err := resolveMCPServerID(ctx, tx, orgID, serverName)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, query, orgID, serverID, agentKeyID, status); err != nil {
			return fmt.Errorf("transition mcp user credentials: %w", err)
		}
		return nil
	})
}

// ResolveMCPUserSecret returns the decrypted plaintext secret of the agent's
// ACTIVE, unexpired credential on the server, plus kind and version.
// ok=false (nil error) when no usable credential exists — pending, orphaned,
// needs_reauth, needs_update and expired rows all miss. This is the only
// plaintext egress for per-user creds: in-process only.
func (s *Store) ResolveMCPUserSecret(ctx context.Context, orgID, serverName, agentKeyID string) (secret, kind string, version int64, ok bool, err error) {
	if s.db == nil {
		return "", "", 0, false, fmt.Errorf("database not available")
	}
	var ct string
	err = s.withOrgTx(ctx, orgID, func(tx auditTx) error {
		err := tx.QueryRow(ctx,
			`SELECT u.secret_ct, u.kind, u.version FROM mcp_user_credentials u
			 JOIN mcp_servers s ON s.id = u.server_id
			 WHERE u.org_id = $1::uuid AND s.name = $2 AND u.agent_key_id = $3::uuid
			   AND u.status = 'active' AND (u.expires_at IS NULL OR u.expires_at > now())`,
			orgID, serverName, agentKeyID,
		).Scan(&ct, &kind, &version)
		if err != nil {
			if IsNotFound(err) {
				return nil // ok=false below
			}
			return fmt.Errorf("resolve mcp user credential: %w", err)
		}
		return nil
	})
	if err != nil || ct == "" {
		return "", "", 0, false, err
	}
	plain, err := s.decryptMCPCredSecret(ct)
	if err != nil {
		return "", "", 0, false, err
	}
	return plain, kind, version, true, nil
}

// FindMCPUserCredentialByState locates the org's pending OAuth row by flow
// state (the callback path). Missing or non-pending is ErrNotFound.
func (s *Store) FindMCPUserCredentialByState(ctx context.Context, orgID, state string) (MCPUserCredential, error) {
	var out MCPUserCredential
	if state == "" {
		return out, ErrNotFound
	}
	err := s.withOrgTx(ctx, orgID, func(tx auditTx) error {
		err := tx.QueryRow(ctx,
			`SELECT `+mcpUserCredColumns+` FROM mcp_user_credentials u
			 JOIN mcp_servers s ON s.id = u.server_id
			 WHERE u.org_id = $1::uuid AND u.status = 'pending' AND u.flow_state = $2`,
			orgID, state,
		).Scan(&out.ID, &out.OrgID, &out.ServerID, &out.ServerName, &out.AgentKeyID, &out.Kind,
			&out.SecretLast4, &out.Status, &out.Version, &out.ExpiresAt, &out.CreatedAt, &out.UpdatedAt, &out.HasSecret)
		if err != nil {
			if IsNotFound(err) {
				return ErrNotFound
			}
			return fmt.Errorf("find mcp user credential by state: %w", err)
		}
		return nil
	})
	if err != nil {
		return MCPUserCredential{}, err
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Secret encoding helpers (fail-closed, orgcredentials.go parity)
// ---------------------------------------------------------------------------

// encryptMCPCredSecret returns the at-rest value plus the display mask for a
// plaintext MCP credential payload. Fail-closed: without an encryptor (and
// outside the dev/test plaintext escape hatch) it refuses, so a missing
// encryption config can never silently downgrade to plaintext at rest.
func (s *Store) encryptMCPCredSecret(kind, plaintext string) (string, string, error) {
	if plaintext == "" {
		return "", "", fmt.Errorf("secret is required: an mcp credential without a secret cannot authorize")
	}
	if len(plaintext) > mcpSecretMaxBytes {
		return "", "", fmt.Errorf("secret is too large (%d bytes; max %d)", len(plaintext), mcpSecretMaxBytes)
	}
	if kind == MCPCredKindHeaders {
		if err := ValidateMCPSecretHeaders(plaintext); err != nil {
			return "", "", err
		}
	}
	last4 := mcpSecretLast4(kind, plaintext)
	if s.enc == nil {
		if encryption.PlaintextWritesAllowed() {
			if s.log != nil {
				s.log.Warn("mcp credential secret stored as PLAINTEXT: no encryption_key configured (dev/test fallback; production refuses this)")
			}
			return plaintext, last4, nil
		}
		return "", "", fmt.Errorf("refusing to store the mcp credential secret as plaintext: encryption_key is not configured; set encryption_key (YABANIN_ENCRYPTION_KEY) before writing mcp credentials")
	}
	ct, err := s.enc.Encrypt(plaintext)
	if err != nil {
		return "", "", fmt.Errorf("failed to encrypt mcp credential secret: %w", err)
	}
	return ct, last4, nil
}

// decryptMCPCredSecret inverts encryptMCPCredSecret on the read path. An
// enc:-prefixed value without a configured encryptor is a hard error (fail
// closed): serving nothing silently would misroute traffic without auth.
func (s *Store) decryptMCPCredSecret(stored string) (string, error) {
	if encryption.IsEncrypted(stored) {
		if s.enc == nil {
			return "", fmt.Errorf("mcp credential secret is encrypted but no encryption_key is configured; refusing to serve")
		}
		plain, err := s.enc.Decrypt(stored)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt mcp credential secret: %w", err)
		}
		return plain, nil
	}
	// Legacy/dev plaintext row (only reachable via the dev write fallback).
	if s.log != nil {
		s.log.Warn("mcp credential secret_ct is stored as PLAINTEXT (dev fallback row); configure encryption_key and re-save the credential")
	}
	return stored, nil
}

// validateMCPCredKind accepts only the migration's kind vocabulary.
func validateMCPCredKind(kind string) error {
	if kind != MCPCredKindHeaders && kind != MCPCredKindOAuth {
		return fmt.Errorf("unknown mcp credential kind %q (want %q or %q)", kind, MCPCredKindHeaders, MCPCredKindOAuth)
	}
	return nil
}

// validateMCPFlowState bounds the pending-flow nonce: URL-safe, 16..128
// chars (the callback round-trips it as a query parameter).
func validateMCPFlowState(state string) error {
	if len(state) < 16 || len(state) > 128 {
		return fmt.Errorf("flow state must be 16..128 characters")
	}
	for _, r := range state {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return fmt.Errorf("flow state must be URL-safe (letters, digits, '-', '_')")
		}
	}
	return nil
}

// ValidateMCPSecretHeaders validates the plaintext JSON payload of a
// headers-kind credential: an object mapping header names to string or
// []string values. Header names must be HTTP tokens and values must not
// carry CR/LF/NUL — both would be header injection on the upstream request.
// At least one non-empty entry is required.
func ValidateMCPSecretHeaders(plaintext string) error {
	var headers map[string]any
	if err := json.Unmarshal([]byte(plaintext), &headers); err != nil {
		return fmt.Errorf("headers secret must be a JSON object of header names to values: %w", err)
	}
	if len(headers) == 0 {
		return fmt.Errorf("headers secret must set at least one header")
	}
	hasValue := false
	for name, raw := range headers {
		if !isHTTPHeaderValue(name) {
			return fmt.Errorf("invalid header name %q (must be an HTTP token)", name)
		}
		switch v := raw.(type) {
		case string:
			if err := validateMCPHeaderValue(v); err != nil {
				return err
			}
			if v != "" {
				hasValue = true
			}
		case []any:
			if len(v) == 0 {
				return fmt.Errorf("header %q has an empty value list", name)
			}
			for _, item := range v {
				s, ok := item.(string)
				if !ok {
					return fmt.Errorf("header %q values must be strings", name)
				}
				if err := validateMCPHeaderValue(s); err != nil {
					return err
				}
				if s != "" {
					hasValue = true
				}
			}
		default:
			return fmt.Errorf("header %q value must be a string or a list of strings", name)
		}
	}
	if !hasValue {
		return fmt.Errorf("headers secret must carry at least one non-empty value")
	}
	return nil
}

// validateMCPHeaderValue rejects control characters that would break the
// upstream request framing (header injection).
func validateMCPHeaderValue(v string) error {
	if strings.ContainsAny(v, "\r\n\x00") {
		return fmt.Errorf("header value must not contain CR, LF or NUL")
	}
	return nil
}

// isHTTPHeaderValue reports whether s is a valid HTTP token (RFC 7230
// tchar set) for use as a header name.
func isHTTPHeaderValue(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r > unicode.MaxASCII {
			return false
		}
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("!#$%&'*+-.^_`|~", r):
		default:
			return false
		}
	}
	return true
}

// mcpSecretLast4 derives the display mask for a secret payload. The mask is
// the last 4 characters of the payload's primary secret value: the longest
// header value for headers kind, access_token (else refresh_token) for oauth.
// Payloads too short to mask safely (or not parseable) mask to "".
func mcpSecretLast4(kind, plaintext string) string {
	primary := ""
	switch kind {
	case MCPCredKindOAuth:
		var tok struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.Unmarshal([]byte(plaintext), &tok); err == nil {
			primary = tok.AccessToken
			if primary == "" {
				primary = tok.RefreshToken
			}
		}
	default: // headers (and any future kind): longest string value
		var headers map[string]any
		if err := json.Unmarshal([]byte(plaintext), &headers); err == nil {
			for _, raw := range headers {
				collectSecretValues(raw, &primary)
			}
		}
	}
	if primary == "" {
		return ""
	}
	return orgCredentialKeyLast4(primary)
}

// collectSecretValues tracks the longest string value found in a headers
// payload value (string or nested list).
func collectSecretValues(raw any, longest *string) {
	switch v := raw.(type) {
	case string:
		if len(v) > len(*longest) {
			*longest = v
		}
	case []any:
		for _, item := range v {
			collectSecretValues(item, longest)
		}
	}
}
