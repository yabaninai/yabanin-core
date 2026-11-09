package adminstore

import (
	"context"
	"fmt"

	"github.com/reireirei/yabanin/pkg/encryption"
)

// prepareUpstreamKey returns the DB value for a provider API key.
//
// encryptor is an error — silent plaintext at rest is rejected. Dev/test
// runs (and an explicit YABANIN_ENCRYPTION_ALLOW_PLAINTEXT=1) keep the
// historical plaintext behavior with a loud warning.
func (s *Store) prepareUpstreamKey(key *string) (*string, error) {
	if key == nil {
		// No key supplied is a legitimate no-op, not a nil error pair:
		// the caller keeps its nil field unchanged.
		return nil, nil //nolint:nilnil // documented no-op contract
	}
	if s.enc == nil {
		if encryption.PlaintextWritesAllowed() {
			if s.log != nil {
				s.log.Warn("provider API key stored as PLAINTEXT: no encryption_key configured (dev/test fallback; production refuses this)")
			}
			return key, nil
		}
		return nil, fmt.Errorf("refusing to store provider API key as plaintext: encryption_key is not configured; set encryption_key (YABANIN_ENCRYPTION_KEY) before writing provider credentials")
	}
	ct, err := s.enc.Encrypt(*key)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt API key: %w", err)
	}
	return &ct, nil
}

// CreateModel creates a new model entry.
//
// Backward-compatible wrapper around CreateModelWithParams for callers that
// only need the legacy (name, display, tier, url, key) tuple.
func (s *Store) CreateModel(ctx context.Context, modelName, displayName, tier string, upstreamURL, upstreamAPIKey *string) (*ModelRegistry, error) {
	return s.CreateModelWithParams(ctx, CreateModelParams{
		ModelName:      modelName,
		DisplayName:    displayName,
		Tier:           tier,
		UpstreamURL:    upstreamURL,
		UpstreamAPIKey: upstreamAPIKey,
	})
}

// CreateModelWithParams creates a model with the full P3.3 parameter set
// (provider, fallback chain, tier pool, per-model timeout). DB-side defaults
// apply when optional fields are nil/empty.
func (s *Store) CreateModelWithParams(ctx context.Context, p CreateModelParams) (*ModelRegistry, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}

	encryptedKey, err := s.prepareUpstreamKey(p.UpstreamAPIKey)
	if err != nil {
		return nil, err
	}

	if p.Provider == "" {
		p.Provider = "openai-compat"
	}
	if p.FailoverModels == nil {
		p.FailoverModels = []string{}
	}
	if p.TierPool == nil {
		p.TierPool = []string{}
	}

	var m ModelRegistry
	err = s.db.QueryRow(ctx,
		`INSERT INTO models_registry
		     (model_name, display_name, tier, upstream_url, upstream_api_key,
		      provider, fallback_model, failover_models, tier_pool, upstream_timeout_ms)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 RETURNING id::text, model_name, display_name, tier,
		           upstream_url::text, upstream_api_key::text,
		           provider, fallback_model, failover_models, tier_pool, upstream_timeout_ms,
		           enabled, created_at`,
		p.ModelName, p.DisplayName, p.Tier, p.UpstreamURL, encryptedKey,
		p.Provider, p.FallbackModel, p.FailoverModels, p.TierPool, p.UpstreamTimeoutMs,
	).Scan(&m.ID, &m.ModelName, &m.DisplayName, &m.Tier,
		&m.UpstreamURL, &m.UpstreamAPIKey,
		&m.Provider, &m.FallbackModel, &m.FailoverModels, &m.TierPool, &m.UpstreamTimeoutMs,
		&m.Enabled, &m.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create model: %w", err)
	}
	return &m, nil
}

// scanModel scans a full ModelRegistry row using the P3.3 column set.
//
// Reads never fail on legacy plaintext values (read-only until the one-time
// migration re-encrypts them); enc:-prefixed ciphertext must decrypt or the
// read errors — serving raw ciphertext or an empty key silently would be
// worse than failing.
func (s *Store) scanModel(row scanner) (*ModelRegistry, error) {
	var m ModelRegistry
	err := row.Scan(&m.ID, &m.ModelName, &m.DisplayName, &m.Tier,
		&m.UpstreamURL, &m.UpstreamAPIKey,
		&m.Provider, &m.FallbackModel, &m.FailoverModels, &m.TierPool, &m.UpstreamTimeoutMs,
		&m.Enabled, &m.CreatedAt)
	if err != nil {
		return nil, err
	}
	if s.enc != nil && m.UpstreamAPIKey != nil && encryption.IsEncrypted(*m.UpstreamAPIKey) {
		decrypted, err := s.enc.Decrypt(*m.UpstreamAPIKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt API key: %w", err)
		}
		m.UpstreamAPIKey = stringPtr(string(decrypted))
	} else if m.UpstreamAPIKey != nil && *m.UpstreamAPIKey != "" && s.log != nil {
		// Legacy plaintext row: readable-only. Warn so ops run the migration.
		s.log.Warn("model upstream_api_key is stored as PLAINTEXT (legacy row); run secret migration to encrypt it",
			"model", m.ModelName)
	}
	return &m, nil
}

// modelColumns is the canonical SELECT column list for models_registry.
const modelColumns = `id::text, model_name, display_name, tier,
       upstream_url::text, upstream_api_key::text,
       provider, fallback_model, failover_models, tier_pool, upstream_timeout_ms,
       enabled, created_at`

// GetModelByName returns a model by name.
func (s *Store) GetModelByName(ctx context.Context, modelName string) (*ModelRegistry, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	row := s.db.QueryRow(ctx,
		`SELECT `+modelColumns+` FROM models_registry WHERE model_name = $1`,
		modelName,
	)
	m, err := s.scanModel(row)
	if err != nil {
		return nil, fmt.Errorf("get model: %w", err)
	}
	return m, nil
}

// ListModels returns a page of models.
func (s *Store) ListModels(ctx context.Context, f PageFilter) ([]*ModelRegistry, int64, error) {
	if s.db == nil {
		return nil, 0, fmt.Errorf("database not available")
	}
	if f.PageSize <= 0 {
		f = NewPageFilter(f.Page, f.PageSize)
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM models_registry`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count models: %w", err)
	}
	rows, err := s.db.Query(ctx,
		`SELECT `+modelColumns+`
		 FROM models_registry`+
			f.OrderBy(ModelSortColumns, "created_at", false)+
			` LIMIT $1 OFFSET $2`,
		f.PageSize, f.Offset(),
	)
	if err != nil {
		return nil, 0, fmt.Errorf("list models: %w", err)
	}
	defer rows.Close()

	var models []*ModelRegistry
	for rows.Next() {
		m, err := s.scanModel(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan model: %w", err)
		}
		models = append(models, m)
	}
	return models, total, rows.Err()
}

// UpdateModelEnabled toggles the enabled status of a model.
func (s *Store) UpdateModelEnabled(ctx context.Context, modelName string, enabled bool) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	_, err := s.db.Exec(ctx,
		`UPDATE models_registry SET enabled = $1 WHERE model_name = $2`,
		enabled, modelName,
	)
	if err != nil {
		return fmt.Errorf("update model enabled: %w", err)
	}
	return nil
}

// DeleteModel deletes a model by name.
func (s *Store) DeleteModel(ctx context.Context, modelName string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	result, err := s.db.Exec(ctx,
		`DELETE FROM models_registry WHERE model_name = $1`,
		modelName,
	)
	if err != nil {
		return fmt.Errorf("delete model: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("model not found")
	}
	return nil
}

// --- Routing Rules ---

// UpdateModel updates display_name, tier, upstream_url, upstream_api_key, and/or enabled for a model.
func (s *Store) UpdateModel(ctx context.Context, modelName, displayName string, tier *string, upstreamURL *string, upstreamAPIKey *string, enabled *bool) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	var set []string
	var args []interface{}
	n := 1
	set = append(set, fmt.Sprintf("display_name = $%d", n))
	args = append(args, displayName)
	n++
	if tier != nil {
		set = append(set, fmt.Sprintf("tier = $%d", n))
		args = append(args, *tier)
		n++
	}
	if upstreamURL != nil {
		set = append(set, fmt.Sprintf("upstream_url = $%d", n))
		args = append(args, *upstreamURL)
		n++
	}
	if upstreamAPIKey != nil {
		keyVal, err := s.prepareUpstreamKey(upstreamAPIKey)
		if err != nil {
			return err
		}
		if keyVal != nil {
			set = append(set, fmt.Sprintf("upstream_api_key = $%d", n))
			args = append(args, *keyVal)
			n++
		}
	}
	if enabled != nil {
		set = append(set, fmt.Sprintf("enabled = $%d", n))
		args = append(args, *enabled)
		n++
	}
	set = append(set, "updated_at = now()")
	args = append(args, modelName)
	query := fmt.Sprintf(`UPDATE models_registry SET %s WHERE model_name = $%d`, joinSetClauses(set), n)
	if _, err := s.db.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("update model: %w", err)
	}
	return nil
}

// UpdateModelWithParams performs a partial update on a model using the full
// P3.3 parameter set. Nil fields are skipped; non-nil fields are applied.
func (s *Store) UpdateModelWithParams(ctx context.Context, p UpdateModelParams) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	var set []string
	var args []interface{}
	n := 1

	if p.DisplayName != nil {
		set = append(set, fmt.Sprintf("display_name = $%d", n))
		args = append(args, *p.DisplayName)
		n++
	}
	if p.Tier != nil {
		set = append(set, fmt.Sprintf("tier = $%d", n))
		args = append(args, *p.Tier)
		n++
	}
	if p.UpstreamURL != nil {
		set = append(set, fmt.Sprintf("upstream_url = $%d", n))
		args = append(args, *p.UpstreamURL)
		n++
	}
	// in one call is ambiguous — refuse instead of silently picking one.
	if p.ClearUpstreamKey {
		if p.UpstreamAPIKey != nil {
			return fmt.Errorf("clear_upstream_key and upstream_api_key are mutually exclusive")
		}
		set = append(set, "upstream_api_key = NULL")
	}
	if p.UpstreamAPIKey != nil {
		keyVal, err := s.prepareUpstreamKey(p.UpstreamAPIKey)
		if err != nil {
			return err
		}
		if keyVal != nil {
			set = append(set, fmt.Sprintf("upstream_api_key = $%d", n))
			args = append(args, *keyVal)
			n++
		}
	}
	if p.Provider != nil {
		set = append(set, fmt.Sprintf("provider = $%d", n))
		args = append(args, *p.Provider)
		n++
	}
	if p.FallbackModel != nil {
		set = append(set, fmt.Sprintf("fallback_model = $%d", n))
		args = append(args, *p.FallbackModel)
		n++
	}
	if p.FailoverModels != nil {
		set = append(set, fmt.Sprintf("failover_models = $%d", n))
		args = append(args, p.FailoverModels)
		n++
	}
	if p.TierPool != nil {
		set = append(set, fmt.Sprintf("tier_pool = $%d", n))
		args = append(args, p.TierPool)
		n++
	}
	if p.UpstreamTimeoutMs != nil {
		set = append(set, fmt.Sprintf("upstream_timeout_ms = $%d", n))
		args = append(args, *p.UpstreamTimeoutMs)
		n++
	}
	if p.Enabled != nil {
		set = append(set, fmt.Sprintf("enabled = $%d", n))
		args = append(args, *p.Enabled)
		n++
	}

	if len(set) == 0 {
		// Nothing to update — just verify the model exists.
		var exists bool
		err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM models_registry WHERE model_name = $1)`, p.ModelName).Scan(&exists)
		if err != nil {
			return fmt.Errorf("check model existence: %w", err)
		}
		if !exists {
			return fmt.Errorf("model not found: %s", p.ModelName)
		}
		return nil
	}

	set = append(set, "updated_at = now()")
	args = append(args, p.ModelName)

	if len(set) == 0 {
		// Nothing to update — just verify the model exists.
		var exists bool
		err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM models_registry WHERE model_name = $1)`, p.ModelName).Scan(&exists)
		if err != nil {
			return fmt.Errorf("check model existence: %w", err)
		}
		if !exists {
			return fmt.Errorf("model not found: %s", p.ModelName)
		}
		return nil
	}

	query := fmt.Sprintf(`UPDATE models_registry SET %s WHERE model_name = $%d`, joinSetClauses(set), n)
	if _, err := s.db.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("update model: %w", err)
	}
	return nil
}

// BumpModelVersion bumps the version column on a models_registry entry,
// which triggers the DB trigger to cascade model_version updates into
// cache_entries (invalidating stale cached responses).
func (s *Store) BumpModelVersion(ctx context.Context, modelName string) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	res, err := s.db.Exec(ctx,
		`UPDATE models_registry SET version = version + 1 WHERE model_name = $1`,
		modelName,
	)
	if err != nil {
		return fmt.Errorf("bump model version: %w", err)
	}
	if res.RowsAffected() == 0 {
		return fmt.Errorf("model not found: %s", modelName)
	}
	return nil
}

// MigratePlaintextSecrets re-encrypts legacy plaintext upstream_api_key rows
// encryption key). Idempotent: enc:-prefixed rows are skipped, and each row
// is updated only while its stored value still matches what was read.
// Without an encryptor it is a no-op (0, nil) — plaintext stays read-only.
// Returns the number of rows migrated.
func (s *Store) MigratePlaintextSecrets(ctx context.Context) (int, error) {
	if s.db == nil {
		return 0, fmt.Errorf("database not available")
	}
	if s.enc == nil {
		return 0, nil
	}
	rows, err := s.db.Query(ctx,
		`SELECT id::text, upstream_api_key::text FROM models_registry
		 WHERE upstream_api_key IS NOT NULL AND upstream_api_key <> ''
		   AND upstream_api_key NOT LIKE 'enc:%'`)
	if err != nil {
		return 0, fmt.Errorf("scan plaintext api keys: %w", err)
	}
	defer rows.Close()

	migrated := 0
	for rows.Next() {
		var id, plain string
		if err := rows.Scan(&id, &plain); err != nil {
			return migrated, fmt.Errorf("scan plaintext api key row: %w", err)
		}
		ct, err := s.enc.Encrypt(plain)
		if err != nil {
			return migrated, fmt.Errorf("encrypt api key for model %s: %w", id, err)
		}
		tag, err := s.db.Exec(ctx,
			`UPDATE models_registry SET upstream_api_key = $1
			 WHERE id::text = $2 AND upstream_api_key = $3`,
			ct, id, plain)
		if err != nil {
			return migrated, fmt.Errorf("migrate api key for model %s: %w", id, err)
		}
		if tag.RowsAffected() > 0 {
			migrated++
			if s.log != nil {
				s.log.Info("migrated plaintext upstream_api_key to encrypted storage", "model_id", id)
			}
		}
	}
	return migrated, rows.Err()
}
