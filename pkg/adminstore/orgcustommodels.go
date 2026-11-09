package adminstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/reireirei/yabanin/pkg/encryption"
)

// OrgCustomModel is one per-org custom model (W-BYOK-CORE, migration 0003):
// the essential models_registry routing columns scoped to an org. Org models
// are beta — they never enter tier pools or failover chains — and their
// upstream API keys are stored encrypted with the same enc:-prefixed envelope
// as models_registry (fail-closed writes: no encryptor configured refuses the
// write; plaintext at rest is never produced silently).
type OrgCustomModel struct {
	ID          string `json:"id"`
	OrgID       string `json:"org_id"`
	ModelName   string `json:"model_name"`
	DisplayName string `json:"display_name"`
	Tier        string `json:"tier"`
	// UpstreamURL is the endpoint the model is served from; empty falls back
	// to the gateway's global provider URL at routing time.
	UpstreamURL string `json:"upstream_url,omitempty"`
	// UpstreamAPIKey is the DECRYPTED plaintext key. Populated only by the
	// single-model read (GetOrgCustomModel) and never by List; callers must
	// treat it as a secret end to end and never log it.
	UpstreamAPIKey string `json:"-"`
	// KeyLast4 masks the key for admin display (never the secret itself).
	// It is persisted alongside the ciphertext at every key write, so lists
	// can surface it without ever decrypting.
	KeyLast4          string    `json:"key_last4,omitempty"`
	Provider          string    `json:"provider"`
	UpstreamTimeoutMs int       `json:"upstream_timeout_ms,omitempty"`
	Region            string    `json:"region"`
	Enabled           bool      `json:"enabled"`
	KeyVersion        int       `json:"key_version"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// OrgCustomModelParams is the mutable surface of an org custom model. Nil
// fields are skipped by UpdateOrgCustomModel; Create applies the non-nil
// values over the column defaults.
type OrgCustomModelParams struct {
	DisplayName       *string
	Tier              *string
	UpstreamURL       *string
	UpstreamAPIKey    *string
	Provider          *string
	UpstreamTimeoutMs *int
	Region            *string
	Enabled           *bool
}

// withOrgTx runs fn inside one transaction whose app.current_org GUC is
// pinned to orgID — the org-isolation contract of the org_custom_models RLS
// policy (migration 0003). Every org-scoped read/write must go through this
// helper so the store stays correct under the least-privilege application
// role (yabanin_app, NOBYPASSRLS).
func (s *Store) withOrgTx(ctx context.Context, orgID string, fn func(tx auditTx) error) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	tx, err := s.db.BeginAuditTx(ctx)
	if err != nil {
		return fmt.Errorf("begin org tx: %w", err)
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('app.current_org', $1, true)", orgID); err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("set org isolation GUC: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit org tx: %w", err)
	}
	return nil
}

// CreateOrgCustomModel inserts a per-org custom model. The upstream API key
// is encrypted before storage (fail-closed: a missing encryptor is an error,
// except the explicit dev plaintext allowance shared with models_registry).
// key_version starts at 1.
func (s *Store) CreateOrgCustomModel(ctx context.Context, orgID, modelName string, p OrgCustomModelParams) (OrgCustomModel, error) {
	var m OrgCustomModel
	if orgID == "" {
		return m, fmt.Errorf("org id is required")
	}
	if modelName == "" {
		return m, fmt.Errorf("model name is required")
	}
	encryptedKey, err := s.prepareUpstreamKey(p.UpstreamAPIKey)
	if err != nil {
		return m, err
	}

	displayName := ""
	if p.DisplayName != nil {
		displayName = *p.DisplayName
	}
	tier := "smart"
	if p.Tier != nil && *p.Tier != "" {
		tier = *p.Tier
	}
	provider := "openai-compat"
	if p.Provider != nil && *p.Provider != "" {
		provider = *p.Provider
	}
	region := "GLOBAL"
	if p.Region != nil && *p.Region != "" {
		region = *p.Region
	}

	err = s.withOrgTx(ctx, orgID, func(tx auditTx) error {
		row := tx.QueryRow(ctx, `
			INSERT INTO org_custom_models
			    (org_id, model_name, display_name, tier, upstream_url,
			     upstream_api_key, key_last4, provider, upstream_timeout_ms, region, enabled)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, COALESCE($11, true))
			RETURNING id::text, org_id::text, model_name, display_name, tier,
			       COALESCE(upstream_url, ''), provider,
			       COALESCE(upstream_timeout_ms, 0), region, enabled,
			       key_version, created_at, updated_at`,
			orgID, modelName, displayName, tier, p.UpstreamURL,
			encryptedKey, last4(p.UpstreamAPIKey), provider, p.UpstreamTimeoutMs, region, p.Enabled,
		)
		return row.Scan(&m.ID, &m.OrgID, &m.ModelName, &m.DisplayName, &m.Tier,
			&m.UpstreamURL, &m.Provider, &m.UpstreamTimeoutMs, &m.Region, &m.Enabled,
			&m.KeyVersion, &m.CreatedAt, &m.UpdatedAt)
	})
	if err != nil {
		return OrgCustomModel{}, fmt.Errorf("create org custom model: %w", err)
	}
	m.KeyLast4 = last4(p.UpstreamAPIKey)
	return m, nil
}

// GetOrgCustomModel reads one org model by name, decrypting the stored key
// fail-closed (enc:-prefixed ciphertext must decrypt or the read errors —
// serving raw ciphertext or an empty key silently would be worse).
func (s *Store) GetOrgCustomModel(ctx context.Context, orgID, modelName string) (*OrgCustomModel, error) {
	var m OrgCustomModel
	err := s.withOrgTx(ctx, orgID, func(tx auditTx) error {
		return scanOrgCustomModel(tx.QueryRow(ctx,
			`SELECT id::text, org_id::text, model_name, display_name, tier,
			       COALESCE(upstream_url, ''), COALESCE(upstream_api_key, ''),
			       COALESCE(key_last4, ''), provider, COALESCE(upstream_timeout_ms, 0), region, enabled,
			       key_version, created_at, updated_at
			 FROM org_custom_models WHERE org_id = $1::uuid AND model_name = $2`, orgID, modelName,
		), &m)
	})
	if err != nil {
		return nil, fmt.Errorf("get org custom model: %w", err)
	}
	plain, last, err := s.decryptOrgKey(m.UpstreamAPIKey, modelName)
	if err != nil {
		return nil, err
	}
	m.UpstreamAPIKey = plain
	m.KeyLast4 = last
	return &m, nil
}

// ListOrgCustomModels returns the org's models WITHOUT plaintext keys (the
// key field stays empty; KeyLast4 carries the display mask recorded at the
// last write). Bulk key reads are the kind of payload a compromised admin
// session must never yield, so the list never decrypts.
func (s *Store) ListOrgCustomModels(ctx context.Context, orgID string) ([]OrgCustomModel, error) {
	var raw []byte
	err := s.withOrgTx(ctx, orgID, func(tx auditTx) error {
		// The explicit org_id predicate is the primary isolation layer
		// (correct under any role, including RLS-bypassing owners); the
		// app.current_org GUC pinned by withOrgTx is defense in depth under
		// the least-privilege application role.
		return tx.QueryRow(ctx, `
			SELECT COALESCE(json_agg(t), '[]'::json)
			FROM (
			    SELECT id::text, org_id::text, model_name, display_name, tier,
			           COALESCE(upstream_url, '') AS upstream_url,
			           COALESCE(key_last4, '') AS key_last4,
			           provider, COALESCE(upstream_timeout_ms, 0) AS upstream_timeout_ms,
			           region, enabled, key_version, created_at, updated_at
			    FROM org_custom_models
			    WHERE org_id = $1::uuid
			    ORDER BY model_name
			) t`, orgID).Scan(&raw)
	})
	if err != nil {
		return nil, fmt.Errorf("list org custom models: %w", err)
	}
	var models []OrgCustomModel
	if err := json.Unmarshal(raw, &models); err != nil {
		return nil, fmt.Errorf("decode org custom models: %w", err)
	}
	return models, nil
}

// UpdateOrgCustomModel applies the non-nil params to one org model. Setting a
// new UpstreamAPIKey re-encrypts and bumps key_version; the key is otherwise
// left untouched. Unknown model names are a not-found error.
func (s *Store) UpdateOrgCustomModel(ctx context.Context, orgID, modelName string, p OrgCustomModelParams) (OrgCustomModel, error) {
	var m OrgCustomModel
	if orgID == "" || modelName == "" {
		return m, fmt.Errorf("org id and model name are required")
	}
	encryptedKey, err := s.prepareUpstreamKey(p.UpstreamAPIKey)
	if err != nil {
		return m, err
	}

	err = s.withOrgTx(ctx, orgID, func(tx auditTx) error {
		var set []string
		var args []interface{}
		n := 1
		// add registers one SET clause. The placeholder number is only
		// formatted into clauses that carry a verb (%d); verb-less clauses
		// (e.g. "key_version = key_version + 1") must pass through verbatim —
		// Sprintf would otherwise append "%!(EXTRA int=N)" to the SQL.
		add := func(clause string, vals ...interface{}) {
			if strings.Contains(clause, "%") {
				clause = fmt.Sprintf(clause, n)
			}
			set = append(set, clause)
			args = append(args, vals...)
			n += len(vals)
		}
		if p.DisplayName != nil {
			add("display_name = $%d", *p.DisplayName)
		}
		if p.Tier != nil {
			add("tier = $%d", *p.Tier)
		}
		if p.UpstreamURL != nil {
			add("upstream_url = $%d", *p.UpstreamURL)
		}
		if p.UpstreamAPIKey != nil {
			add("upstream_api_key = $%d", *encryptedKey)
			add("key_last4 = $%d", last4(p.UpstreamAPIKey))
			add("key_version = key_version + 1")
		}
		if p.Provider != nil {
			add("provider = $%d", *p.Provider)
		}
		if p.UpstreamTimeoutMs != nil {
			add("upstream_timeout_ms = $%d", *p.UpstreamTimeoutMs)
		}
		if p.Region != nil {
			add("region = $%d", *p.Region)
		}
		if p.Enabled != nil {
			add("enabled = $%d", *p.Enabled)
		}
		if len(set) == 0 {
			return errors.New("no fields to update")
		}
		row := tx.QueryRow(ctx, fmt.Sprintf(`
			UPDATE org_custom_models SET %s
			WHERE org_id = $%d::uuid AND model_name = $%d
			RETURNING id::text, org_id::text, model_name, display_name, tier,
			       COALESCE(upstream_url, ''), provider,
			       COALESCE(upstream_timeout_ms, 0), region, enabled,
			       COALESCE(key_last4, ''), key_version, created_at, updated_at`, joinSetClauses(set), n, n+1),
			append(args, orgID, modelName)...,
		)
		return row.Scan(&m.ID, &m.OrgID, &m.ModelName, &m.DisplayName, &m.Tier,
			&m.UpstreamURL, &m.Provider, &m.UpstreamTimeoutMs, &m.Region, &m.Enabled,
			&m.KeyLast4, &m.KeyVersion, &m.CreatedAt, &m.UpdatedAt)
	})
	if err != nil {
		return OrgCustomModel{}, fmt.Errorf("update org custom model: %w", err)
	}
	// m.KeyLast4 comes from RETURNING: the new mask after a key rotation,
	// the untouched previous mask otherwise.
	return m, nil
}

// DeleteOrgCustomModel removes one org model. Unknown names are a not-found
// error.
func (s *Store) DeleteOrgCustomModel(ctx context.Context, orgID, modelName string) error {
	return s.withOrgTx(ctx, orgID, func(tx auditTx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM org_custom_models WHERE org_id = $1::uuid AND model_name = $2`, orgID, modelName)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("org custom model not found: %s", modelName)
		}
		return nil
	})
}

// scanOrgCustomModel scans a full org_custom_models row (key column last
// read as text; decryptOrgKey applies the fail-closed policy).
func scanOrgCustomModel(row scanner, m *OrgCustomModel) error {
	return row.Scan(&m.ID, &m.OrgID, &m.ModelName, &m.DisplayName, &m.Tier,
		&m.UpstreamURL, &m.UpstreamAPIKey, &m.KeyLast4,
		&m.Provider, &m.UpstreamTimeoutMs, &m.Region, &m.Enabled,
		&m.KeyVersion, &m.CreatedAt, &m.UpdatedAt)
}

// decryptOrgKey decrypts an enc:-prefixed stored key, returning the plaintext
// and the display mask. A legacy plaintext row (dev/test written before an
// encryptor existed) stays readable-only, exactly like models_registry.
func (s *Store) decryptOrgKey(stored, modelName string) (plain, lastFour string, err error) {
	if stored == "" {
		return "", "", nil
	}
	if s.enc != nil && encryption.IsEncrypted(stored) {
		decrypted, decErr := s.enc.Decrypt(stored)
		if decErr != nil {
			return "", "", fmt.Errorf("decrypt org custom model key for %s: %w", modelName, decErr)
		}
		return decrypted, last4(&decrypted), nil
	}
	if s.log != nil {
		s.log.Warn("org custom model upstream_api_key is stored as PLAINTEXT (legacy row); run secret migration to encrypt it",
			"model", modelName)
	}
	return stored, last4(&stored), nil
}

// last4 returns the display mask of a plaintext key ("" when unset, else its
// last four characters; short keys mask trivially).
func last4(key *string) string {
	if key == nil || *key == "" {
		return ""
	}
	if len(*key) <= 4 {
		return *key
	}
	return (*key)[len(*key)-4:]
}
