package adminstore

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/reireirei/yabanin/pkg/encryption"
	"github.com/reireirei/yabanin/pkg/kms"
)

// OrgCredential is one organization-scoped BYOK provider credential.
//
// W-BYOK-CORE. KeyLast4 is a display mask only: plaintext key material never
// leaves the store (no struct field could carry it, and the store refuses to
// return it on any read path).
type OrgCredential struct {
	ID       string `json:"id"`
	OrgID    string `json:"org_id"`
	Name     string `json:"name"`
	Provider string `json:"provider"`
	BaseURL  string `json:"base_url"`
	// KeyLast4 is the masked last-4 of the stored key ("" when the stored
	// key is too short to mask safely). Never the key itself.
	KeyLast4   string    `json:"key_last4"`
	Enabled    bool      `json:"enabled"`
	KeyVersion int       `json:"key_version"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// OrgCredentialStore is the persistence contract for org BYOK credentials.
//
// Semantics (fixed):
//   - List returns all credentials of one org, newest first.
//   - Create stores a new credential with the key encrypted at rest
//     (enc:-prefix); plaintext is never persisted unencrypted.
//   - Update applies the mutable fields carried by updated (name, provider,
//     base_url, enabled; org_id is immutable). newPlaintextKey "" keeps the
//     existing key; a non-empty value rotates the key AND increments
//     key_version.
//   - Delete removes the credential.
//   - ResolveKey returns the decrypted plaintext key for the org's enabled
//     credential matching (provider, baseURL); ok=false when none matches.
//     This is the only surface that yields plaintext, and only to the
//     in-process caller (gateway routing).
type OrgCredentialStore interface {
	List(ctx context.Context, orgID string) ([]OrgCredential, error)
	Create(ctx context.Context, orgID, name, provider, baseURL, plaintextKey string) (OrgCredential, error)
	// Update: newPlaintextKey "" = keep existing key (key_version unchanged).
	// orgID is required: every operation is scoped by the org-isolation GUC
	// (FORCE RLS on org_provider_credentials), so callers must supply the org
	// they are allowed to act on; a credential from another org is ErrNotFound.
	Update(ctx context.Context, orgID, id string, updated OrgCredential, newPlaintextKey string) (OrgCredential, error)
	Delete(ctx context.Context, orgID, id string) error
	ResolveKey(ctx context.Context, orgID, provider, baseURL string) (plaintext string, ok bool, err error)
}

var _ OrgCredentialStore = (*Store)(nil)

// orgCredentialColumns is the canonical SELECT list for reads. It never
// includes api_key_ct: the ciphertext has no business in read results, so a
// scan cannot leak it even by accident.
const orgCredentialColumns = `id::text, org_id::text, name, provider, base_url, key_last4, enabled, key_version, created_at, updated_at` //nolint:gosec // SQL column list; "credential" names the table, not a secret

// orgCredentialTable is the backing table (migration 0002).
const orgCredentialTable = `org_provider_credentials` //nolint:gosec // SQL table name, not a credential value

// versionedCredPrefix frames a text-safe versioned envelope in api_key_ct:
// "ykm1:" + hex(kms envelope). The raw VersionedKMS envelope is binary
// (magic + key version + nonce + ciphertext), so the column carries a hex
// encoding; the prefix keeps rows greppable and mirrors the legacy "enc:"
// convention. Everything after the prefix is opaque ciphertext material.
const versionedCredPrefix = "ykm1:" // envelope framing marker, not a credential value

// encodeVersionedCredentialEnvelope renders a raw kms envelope as the
// text-safe at-rest value.
func encodeVersionedCredentialEnvelope(env []byte) string {
	return versionedCredPrefix + hex.EncodeToString(env)
}

// decodeVersionedCredentialEnvelope parses a versioned at-rest value back to
// the raw kms envelope. ok=false for anything that does not carry the
// framing (legacy enc: rows and plaintext dev rows dispatch elsewhere) and
// for a value that carries the framing but whose hex payload does not parse.
// The prefix itself is the claim: callers that must fail closed on a
// corrupt framing value (decryptOrgCredentialKey) check the prefix
// separately so a parse failure can never fall through to a plaintext
// dispatch.
func decodeVersionedCredentialEnvelope(stored string) ([]byte, bool) {
	if !strings.HasPrefix(stored, versionedCredPrefix) {
		return nil, false
	}
	raw, err := hex.DecodeString(stored[len(versionedCredPrefix):])
	if err != nil {
		return nil, false
	}
	return raw, true
}

// withOrgTx runs fn inside one transaction whose app.current_org GUC is
// pinned to orgID — the org_isolation contract of the org_provider_credentials
// RLS policy (migration 0002, ENABLE+FORCE). Every operation MUST go through
// this helper so the store stays correct under the least-privilege application
// role (yabanin_app, NOBYPASSRLS): without the GUC the FORCE policy denies
// every row (fail-closed).
func (s *Store) withCredentialTx(ctx context.Context, orgID string, fn func(tx auditTx) error) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	tx, err := s.db.BeginAuditTx(ctx)
	if err != nil {
		return fmt.Errorf("begin org credential tx: %w", err)
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('app.current_org', $1, true)", orgID); err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("set org credential isolation GUC: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit org credential tx: %w", err)
	}
	return nil
}

// List returns all credentials of one org, newest first.
func (s *Store) List(ctx context.Context, orgID string) ([]OrgCredential, error) {
	var out []OrgCredential
	err := s.withCredentialTx(ctx, orgID, func(tx auditTx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+orgCredentialColumns+` FROM `+orgCredentialTable+
				` WHERE org_id = $1::uuid ORDER BY created_at DESC, id DESC`,
			orgID,
		)
		if err != nil {
			return fmt.Errorf("list org credentials: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var c OrgCredential
			if err := scanOrgCredential(rows, &c); err != nil {
				return fmt.Errorf("scan org credential: %w", err)
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

// Create stores a new credential with the key encrypted at rest. plaintextKey
// is required: a credential without a key cannot resolve, and writing an
// empty ct would silently break serving later.
//
// refused unless the dev/test plaintext escape hatch is active — exactly like
// models_registry upstream keys.
func (s *Store) Create(ctx context.Context, orgID, name, provider, baseURL, plaintextKey string) (OrgCredential, error) {
	if s.db == nil {
		return OrgCredential{}, fmt.Errorf("database not available")
	}
	if orgID == "" {
		return OrgCredential{}, fmt.Errorf("org id is required")
	}
	if name == "" {
		return OrgCredential{}, fmt.Errorf("credential name is required")
	}
	if provider == "" {
		return OrgCredential{}, fmt.Errorf("provider is required")
	}
	ct, last4, err := s.encryptOrgCredentialKey(ctx, plaintextKey)
	if err != nil {
		return OrgCredential{}, err
	}

	var c OrgCredential
	err = s.withCredentialTx(ctx, orgID, func(tx auditTx) error {
		err := tx.QueryRow(ctx,
			`INSERT INTO `+orgCredentialTable+
				` (org_id, name, provider, base_url, api_key_ct, key_last4)
			 VALUES ($1::uuid, $2, $3, $4, $5, $6)
			 RETURNING `+orgCredentialColumns,
			orgID, name, provider, baseURL, ct, last4,
		).Scan(scanOrgCredentialDests(&c)...)
		if err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("credential name %q already exists in this org: %w", name, err)
			}
			return fmt.Errorf("create org credential: %w", err)
		}
		return nil
	})
	if err != nil {
		return OrgCredential{}, err
	}
	return c, nil
}

// Update applies the mutable fields of updated (name, provider, base_url,
// enabled) to the credential with the given id. org_id, created_at and
// key_version are never taken from updated: credentials do not move between
// orgs, and key_version only ever moves through rotations. newPlaintextKey ""
// keeps the stored key untouched; a non-empty value replaces it and bumps
// key_version by one (rotation). The whole update is a single atomic
// UPDATE ... RETURNING, so a concurrent rotation cannot be lost.
func (s *Store) Update(ctx context.Context, orgID, id string, updated OrgCredential, newPlaintextKey string) (OrgCredential, error) {
	if s.db == nil {
		return OrgCredential{}, fmt.Errorf("database not available")
	}
	if orgID == "" {
		return OrgCredential{}, fmt.Errorf("org id is required")
	}
	if id == "" {
		return OrgCredential{}, fmt.Errorf("credential id is required")
	}
	if updated.Name == "" {
		return OrgCredential{}, fmt.Errorf("credential name is required")
	}
	if updated.Provider == "" {
		return OrgCredential{}, fmt.Errorf("provider is required")
	}

	var ctPtr *string
	var last4Ptr *string
	if newPlaintextKey != "" {
		ct, last4, err := s.encryptOrgCredentialKey(ctx, newPlaintextKey)
		if err != nil {
			return OrgCredential{}, err
		}
		ctPtr, last4Ptr = &ct, &last4
	}

	var c OrgCredential
	// $7 IS NULL => key kept, version unchanged; otherwise ct+last4 swap in
	// and key_version increments in the same statement (rotation marker).
	// The WHERE clause pins BOTH id and org: the org-isolation GUC plus the
	// explicit predicate make a cross-org id a clean ErrNotFound.
	err := s.withCredentialTx(ctx, orgID, func(tx auditTx) error {
		// Versioned mode only: when the caller keeps the existing key, the
		// write is still the drain point of the rotation runbook — read the
		// stored envelope in this same tx so it can be lazily re-sealed
		// under the current keyset version after the UPDATE below.
		// Legacy mode never issues this SELECT (byte-identical statement
		// shapes for single-key deployments).
		var stored string
		if s.credKMS != nil && ctPtr == nil {
			err := tx.QueryRow(ctx,
				`SELECT api_key_ct FROM `+orgCredentialTable+` WHERE id = $1::uuid AND org_id = $2::uuid`,
				id, orgID,
			).Scan(&stored)
			if err != nil {
				if IsNotFound(err) {
					return ErrNotFound
				}
				return fmt.Errorf("read org credential for envelope migration: %w", err)
			}
		}
		err := tx.QueryRow(ctx,
			`UPDATE `+orgCredentialTable+` SET
			     name = $3, provider = $4, base_url = $5, enabled = $6,
			     api_key_ct = COALESCE($7::text, api_key_ct),
			     key_last4 = COALESCE($8::text, key_last4),
			     key_version = key_version + CASE WHEN $7::text IS NULL THEN 0 ELSE 1 END
			 WHERE id = $2::uuid AND org_id = $1::uuid
			 RETURNING `+orgCredentialColumns,
			orgID, id, updated.Name, updated.Provider, updated.BaseURL, updated.Enabled, ctPtr, last4Ptr,
		).Scan(scanOrgCredentialDests(&c)...)
		if err != nil {
			if IsNotFound(err) {
				return ErrNotFound
			}
			if isUniqueViolation(err) {
				return fmt.Errorf("credential name %q already exists in this org: %w", updated.Name, err)
			}
			return fmt.Errorf("update org credential: %w", err)
		}
		// Lazy envelope migration (versioned mode, key kept): re-seal the
		// value we read and swap it in ONLY while api_key_ct still equals
		// what we read — a concurrent key rotation that changed the column
		// between our SELECT and this statement makes the guarded UPDATE a
		// no-op, so a metadata write can never clobber a rotation with the
		// old key's envelope. Zero affected rows after a concurrent change
		// is success (the winner already migrated or rotated the row).
		if s.credKMS != nil && ctPtr == nil {
			if migrated, ok := s.migrateOrgCredentialEnvelope(ctx, stored); ok {
				tag, err := tx.Exec(ctx,
					`UPDATE `+orgCredentialTable+` SET api_key_ct = $3
					 WHERE id = $1::uuid AND org_id = $2::uuid AND api_key_ct = $4`,
					id, orgID, migrated, stored,
				)
				if err != nil {
					return fmt.Errorf("migrate org credential envelope: %w", err)
				}
				if s.log != nil && tag.RowsAffected() > 0 {
					s.log.Info("org credential envelope re-sealed under the current keyset version", "credential_id", id)
				}
			}
		}
		return nil
	})
	if err != nil {
		if IsNotFound(err) {
			return OrgCredential{}, ErrNotFound
		}
		return OrgCredential{}, err
	}
	return c, nil
}

// Delete removes the credential by id. Deleting a missing credential is
// ErrNotFound (mirrors DeleteAPIKey).
func (s *Store) Delete(ctx context.Context, orgID, id string) error {
	if orgID == "" {
		return fmt.Errorf("org id is required")
	}
	if id == "" {
		return fmt.Errorf("credential id is required")
	}
	var deleted int64
	err := s.withCredentialTx(ctx, orgID, func(tx auditTx) error {
		tag, err := tx.Exec(ctx,
			`DELETE FROM `+orgCredentialTable+` WHERE id = $1::uuid AND org_id = $2::uuid`, id, orgID)
		if err != nil {
			return fmt.Errorf("delete org credential: %w", err)
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

// ResolveKey returns the decrypted key of the org's ENABLED credential
// matching (provider, baseURL), newest first when several match. ok=false
// (nil error) when nothing matches — including credentials that exist but
// are disabled. This is the only plaintext egress, in-process only: the
// value must never be logged or serialized by callers.
func (s *Store) ResolveKey(ctx context.Context, orgID, provider, baseURL string) (string, bool, error) {
	if s.db == nil {
		return "", false, fmt.Errorf("database not available")
	}
	if orgID == "" || provider == "" {
		return "", false, nil
	}
	var ct string
	err := s.withCredentialTx(ctx, orgID, func(tx auditTx) error {
		// W-VER: match the exact base_url OR its /v1-degenerate form — org
		// model rows conventionally carry the OpenAI-compat /v1 suffix
		// (vLLM, Ollama) while credentials are registered at the host root.
		stripped := StripV1Suffix(baseURL)
		err := tx.QueryRow(ctx,
			`SELECT api_key_ct FROM `+orgCredentialTable+
				` WHERE org_id = $1::uuid AND provider = $2 AND base_url IN ($3, $4) AND enabled = true
				 ORDER BY updated_at DESC, created_at DESC, id DESC
				 LIMIT 1`,
			orgID, provider, baseURL, stripped,
		).Scan(&ct)
		if err != nil {
			if IsNotFound(err) {
				return nil // ok=false below
			}
			return fmt.Errorf("resolve org credential: %w", err)
		}
		return nil
	})
	if err != nil {
		return "", false, err
	}
	if ct == "" {
		return "", false, nil
	}
	plain, err := s.decryptOrgCredentialKey(ctx, ct)
	if err != nil {
		return "", false, err
	}
	return plain, true, nil
}

// encryptOrgCredentialKey returns the at-rest value plus the display mask for
// a plaintext credential key.
//
// With a versioned keyset adopted (AdoptCredentialKMS) the value is sealed as
// a versioned envelope under the keyset's CURRENT version — a KMS failure is
// a hard error, never a downgrade to the legacy cipher or plaintext.
// Fail-closed as before: without any cipher (and outside the dev/test
// plaintext escape hatch) it refuses, so a missing encryption config can
// never silently downgrade to plaintext at rest.
func (s *Store) encryptOrgCredentialKey(ctx context.Context, plaintext string) (string, string, error) {
	if plaintext == "" {
		return "", "", fmt.Errorf("api key is required: org credentials exist to carry a key")
	}
	last4 := orgCredentialKeyLast4(plaintext)
	if s.credKMS != nil {
		env, err := s.credKMS.Encrypt(ctx, []byte(plaintext))
		if err != nil {
			return "", "", fmt.Errorf("failed to encrypt org credential API key: %w", err)
		}
		return encodeVersionedCredentialEnvelope(env), last4, nil
	}
	if s.enc == nil {
		if encryption.PlaintextWritesAllowed() {
			if s.log != nil {
				s.log.Warn("org provider API key stored as PLAINTEXT: no encryption_key configured (dev/test fallback; production refuses this)")
			}
			return plaintext, last4, nil
		}
		return "", "", fmt.Errorf("refusing to store org provider API key as plaintext: encryption_key is not configured; set encryption_key (YABANIN_ENCRYPTION_KEY) before writing org credentials")
	}
	ct, err := s.enc.Encrypt(plaintext)
	if err != nil {
		return "", "", fmt.Errorf("failed to encrypt org credential API key: %w", err)
	}
	return ct, last4, nil
}

// decryptOrgCredentialKey inverts encryptOrgCredentialKey on the read path.
// The dispatch is the dual-trust read of the migration: a versioned envelope
// opens under the adopted keyset (whatever version its header names), a
// legacy enc: value opens under the single-key encryptor — both stay
// readable while the keyset and the legacy key coexist. Each mismatch is a
// hard error (fail closed): serving nothing silently would misroute traffic
// with an empty credential.
//
// The versioned framing is a claim: a value that carries the ykm1: prefix
// but whose hex payload does not parse (corruption, torn row, truncated
// write) is NOT a plaintext dev row — it fails closed exactly like the
// legacy path (an enc: value with invalid base64 fails in Decrypt, never
// falls through to the passthrough). Serving the corrupted string as the
// credential would hand routing garbage for a key under a misleading
// plaintext-row warning. Structural detail (lengths) only in errors: the
// stored value itself is never echoed back.
func (s *Store) decryptOrgCredentialKey(ctx context.Context, stored string) (string, error) {
	if strings.HasPrefix(stored, versionedCredPrefix) {
		raw, ok := decodeVersionedCredentialEnvelope(stored)
		if !ok {
			return "", fmt.Errorf("org credential key claims a versioned envelope but its hex payload (%d chars after the framing) does not parse; refusing to serve a corrupted value",
				len(stored)-len(versionedCredPrefix))
		}
		if s.credKMS == nil {
			return "", fmt.Errorf("org credential key uses a versioned envelope but no keyset is configured; refusing to serve")
		}
		plain, err := s.credKMS.Decrypt(ctx, raw)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt org credential API key: %w", err)
		}
		return string(plain), nil
	}
	if encryption.IsEncrypted(stored) {
		if s.enc == nil {
			return "", fmt.Errorf("org credential key is encrypted but no encryption_key is configured; refusing to serve")
		}
		plain, err := s.enc.Decrypt(stored)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt org credential API key: %w", err)
		}
		return plain, nil
	}
	// Legacy/dev plaintext row (only reachable via the dev write fallback).
	if s.log != nil {
		s.log.Warn("org credential api_key_ct is stored as PLAINTEXT (dev fallback row); configure encryption_key and re-save the credential")
	}
	return stored, nil
}

// migrateOrgCredentialEnvelope lazily re-seals an already-stored credential
// value under the keyset's CURRENT version — the drain step of the rotation
// runbook, applied at the write path (every credential Update) so no
// dedicated data migration and no traffic pause are ever required. It
// returns the replacement at-rest value and true when the row should be
// rewritten, ("", false) when the stored value is already current or cannot
// be migrated. Every skip keeps the original stored value byte-identical:
// there is no code path here that degrades an encrypted row to plaintext.
func (s *Store) migrateOrgCredentialEnvelope(ctx context.Context, stored string) (string, bool) {
	if s.credKMS == nil {
		return "", false
	}
	// Already-current versioned envelopes are a cheap no-op (header probe,
	// no AEAD open) so a backlog sweep over migrated rows stays cheap.
	if raw, ok := decodeVersionedCredentialEnvelope(stored); ok {
		if v, isVersioned := s.credKMS.(*kms.VersionedKMS); isVersioned {
			if ver, err := v.EnvelopeVersion(raw); err == nil && ver == v.Current() {
				return "", false
			}
		}
	}
	plain, err := s.decryptOrgCredentialKey(ctx, stored)
	if err != nil {
		// Loud skip: the row keeps its current (still unreadable-or-old)
		// envelope exactly as before; the error is the operator's signal
		// that this row needs attention before its old version is retired.
		if s.log != nil {
			s.log.Warn("org credential envelope migration skipped: stored key did not decrypt under any configured cipher", "error", err)
		}
		return "", false
	}
	sealed, _, err := s.encryptOrgCredentialKey(ctx, plain)
	if err != nil {
		if s.log != nil {
			s.log.Warn("org credential envelope migration skipped: re-encrypt under the current keyset version failed", "error", err)
		}
		return "", false
	}
	return sealed, true
}

// orgCredentialKeyLast4 masks a key down to its last 4 characters. Keys too
// short to hide at least half their length mask to "" instead of leaking
// most of themselves through the "mask".
func orgCredentialKeyLast4(key string) string {
	if len(key) <= 8 {
		return ""
	}
	return key[len(key)-4:]
}

// scanOrgCredential scans one row (api_key_ct deliberately absent).
func scanOrgCredential(row scanner, c *OrgCredential) error {
	return row.Scan(scanOrgCredentialDests(c)...)
}

// scanOrgCredentialDests is the destination tuple matching
// orgCredentialColumns, shared by single-row and multi-row scans.
func scanOrgCredentialDests(c *OrgCredential) []any {
	return []any{
		&c.ID, &c.OrgID, &c.Name, &c.Provider, &c.BaseURL,
		&c.KeyLast4, &c.Enabled, &c.KeyVersion, &c.CreatedAt, &c.UpdatedAt,
	}
}

// StripV1Suffix removes a trailing "/v1" or "/v1/" from an OpenAI-compat
// base URL (and a trailing slash). Empty input stays empty. Exported for the
// gateway's org-key candidate matching (same normalization, both sides).
func StripV1Suffix(u string) string {
	return strings.TrimSuffix(strings.TrimRight(u, "/"), "/v1")
}

//
// D-2 round-robin selection in the gateway; D-3 version-scoped quarantine on
// upstream 401/429 until the end of the current UTC day; D-5 pool state in
// the DB under the same org RLS as the credentials; D-6 additive-only — none
// of the frozen OrgCredentialStore methods above change behavior.

// OrgCredentialPoolEntry is one rotation-eligible credential of the pool for
// an (org, provider, base_url) endpoint: credential metadata (no plaintext —
// the display mask only) plus the persisted pool-state snapshot.
type OrgCredentialPoolEntry struct {
	OrgCredential
	// QuarantinedUntil is the persisted quarantine deadline for the
	// credential's CURRENT key_version (Go zero when not quarantined).
	QuarantinedUntil time.Time
}

// version-scoped quarantine bookkeeping, never key material.
const orgCredentialPoolTable = `org_credential_pool_state` //nolint:gosec // SQL table name, not a credential value

// orgCredentialEligible is the shared quarantine-snapshot arm of the pool
// reads: a LEFT JOIN onto the version-scoped quarantine row. Version
// scoping IS the rotation semantics (D-3): after Update with a new key
// (key_version++) the stored quarantine row no longer matches, so the
// credential reads as unquarantined and returns to rotation without
// touching the frozen Update path. The join exposes quarantined_until; the
const orgCredentialEligible = `
	LEFT JOIN ` + orgCredentialPoolTable + ` q
	       ON q.credential_id = c.id AND q.key_version = c.key_version`

// ListActiveOrgCredentials returns the org's enabled credentials for
// (provider, baseURL) together with their version-scoped quarantine
// snapshot: rows matching the exact or /v1-stripped base URL (same W-VER
// normalization as ResolveKey), each carrying QuarantinedUntil (Go zero
// when the credential is not quarantined on its current key_version).
// Boundary semantics: eligibility (quarantine expired) is evaluated
// by the gateway pool against its own clock, so a deadline exposes exactly
// when the credential returns and the all-quarantined state stays
// distinguishable from "the org holds no credential here" (fail-closed vs
// routing miss). Deterministic created_at ASC order so the gateway's
// round-robin (D-2) is stable across refreshes. nil (nil error) when org or
// provider is empty — a routing miss, not an error. The frozen ResolveKey
// semantics (newest-first LIMIT 1) are untouched.
func (s *Store) ListActiveOrgCredentials(ctx context.Context, orgID, provider, baseURL string) ([]OrgCredentialPoolEntry, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	if orgID == "" || provider == "" {
		return nil, nil
	}
	var out []OrgCredentialPoolEntry
	stripped := StripV1Suffix(baseURL)
	err := s.withCredentialTx(ctx, orgID, func(tx auditTx) error {
		rows, err := tx.Query(ctx,
			`SELECT c.id::text, c.org_id::text, c.name, c.provider, c.base_url, c.key_last4,
			        c.enabled, c.key_version, c.created_at, c.updated_at, q.quarantined_until
			   FROM `+orgCredentialTable+` c`+orgCredentialEligible+`
			  WHERE c.org_id = $1::uuid AND c.provider = $2 AND c.base_url IN ($3, $4) AND c.enabled = true
			  ORDER BY c.created_at ASC, c.id ASC`,
			orgID, provider, baseURL, stripped,
		)
		if err != nil {
			return fmt.Errorf("list active org credentials: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var e OrgCredentialPoolEntry
			var quarantined *time.Time
			dests := append(scanOrgCredentialDests(&e.OrgCredential), &quarantined)
			if err := rows.Scan(dests...); err != nil {
				return fmt.Errorf("scan org credential pool entry: %w", err)
			}
			if quarantined != nil {
				e.QuarantinedUntil = *quarantined
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ResolveKeyEntry returns the decrypted key of ONE pinned pool credential
// (the gateway pool's round-robin selection). Eligibility matches
// ListActiveOrgCredentials exactly (enabled, exact or /v1-stripped base URL,
// version-scoped quarantine expired) plus the credential-id pin, so a key
// disabled or quarantined between selection and resolution yields ok=false
// (nil error) and the caller moves to the next candidate. This is the only
// plaintext egress besides the frozen ResolveKey: in-process only, never
// logged or serialized by callers, one attempt per fetch.
func (s *Store) ResolveKeyEntry(ctx context.Context, orgID, provider, baseURL, credentialID string) (string, bool, error) {
	if s.db == nil {
		return "", false, fmt.Errorf("database not available")
	}
	if orgID == "" || provider == "" || credentialID == "" {
		return "", false, nil
	}
	var ct string
	stripped := StripV1Suffix(baseURL)
	err := s.withCredentialTx(ctx, orgID, func(tx auditTx) error {
		err := tx.QueryRow(ctx,
			`SELECT c.api_key_ct
			   FROM `+orgCredentialTable+` c`+orgCredentialEligible+`
			  WHERE c.id = $5::uuid AND c.org_id = $1::uuid AND c.provider = $2
			    AND c.base_url IN ($3, $4) AND c.enabled = true
			    AND (q.quarantined_until IS NULL OR q.quarantined_until <= now())`,
			orgID, provider, baseURL, stripped, credentialID,
		).Scan(&ct)
		if err != nil {
			if IsNotFound(err) {
				return nil // ok=false below
			}
			return fmt.Errorf("resolve pinned org credential: %w", err)
		}
		return nil
	})
	if err != nil {
		return "", false, err
	}
	if ct == "" {
		return "", false, nil
	}
	plain, err := s.decryptOrgCredentialKey(ctx, ct)
	if err != nil {
		return "", false, err
	}
	return plain, true, nil
}

// QuarantineOrgCredential removes one credential from rotation until the
// UTC day). The row stores the credential's CURRENT key_version, so a later
// rotation lifts the quarantine implicitly. ErrNotFound when the (org,
// credential) pair does not exist — under the org_isolation RLS policy a
// foreign org's credential is simply invisible (same contract as
// Update/Delete). In-flight requests are unaffected: they already hold their
// per-attempt plaintext (per-request pinning).
func (s *Store) QuarantineOrgCredential(ctx context.Context, orgID, credentialID string, until time.Time) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	if orgID == "" {
		return fmt.Errorf("org id is required")
	}
	if credentialID == "" {
		return fmt.Errorf("credential id is required")
	}
	if until.IsZero() {
		return fmt.Errorf("quarantine deadline is required")
	}
	var applied int64
	err := s.withCredentialTx(ctx, orgID, func(tx auditTx) error {
		tag, err := tx.Exec(ctx,
			`INSERT INTO `+orgCredentialPoolTable+` (credential_id, org_id, key_version, quarantined_until)
			 SELECT c.id, c.org_id, c.key_version, $3
			   FROM `+orgCredentialTable+` c
			  WHERE c.id = $2::uuid AND c.org_id = $1::uuid
			 ON CONFLICT (credential_id) DO UPDATE
			   SET key_version = EXCLUDED.key_version,
			       quarantined_until = EXCLUDED.quarantined_until`,
			orgID, credentialID, until,
		)
		if err != nil {
			if isUniqueViolation(err) {
				return ErrNotFound
			}
			return fmt.Errorf("quarantine org credential: %w", err)
		}
		applied = tag.RowsAffected()
		return nil
	})
	if err != nil {
		return err
	}
	if applied == 0 {
		return ErrNotFound
	}
	return nil
}
