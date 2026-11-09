package lineage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// LedgerStore writes lineage attestations to the request_lineage table.
type LedgerStore struct {
	pool *pgxpool.Pool
}

// NewLedgerStore returns a LedgerStore.
func NewLedgerStore(pool *pgxpool.Pool) *LedgerStore {
	return &LedgerStore{pool: pool}
}

// canonicalRecord builds the fixed-order, pipe-delimited string over the row's
// INSERT columns (H1). record_hash = SHA-256(prevHash + "|" + canonicalRecord),
// so each row commits to the previous row's hash — a per-org tamper-evident
// chain. Column order is fixed and must match rowCanonicalHash in verify.go.
func canonicalRecord(att Attestation, hash, sigB64, keyID string) string {
	return strings.Join([]string{
		att.RequestID, att.OrgID, att.ModelUsed, att.InferenceRegion,
		att.ModelOrigin, att.LogStorageRegion, att.ProviderEntity,
		att.RegionEvidence, hash, sigB64, keyID,
	}, "|")
}

// lastRecordHash returns the record_hash of the most recent chained row for the
// org (the chain head). Empty string when the org has no chained rows yet
// (legacy rows have record_hash=”).
func (ls *LedgerStore) lastRecordHash(ctx context.Context, orgID string) (string, error) {
	var prev string
	err := ls.pool.QueryRow(ctx, `
		SELECT record_hash FROM request_lineage
		WHERE org_id = $1 AND record_hash <> ''
		ORDER BY ts DESC
		LIMIT 1
	`, orgID).Scan(&prev)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", nil
		}
		return "", fmt.Errorf("lookup last lineage hash for org %s: %w", orgID, err)
	}
	return prev, nil
}

// Append inserts a lineage record with its hash-chain links. The row is
// append-only (blocked by DB trigger). The writer is single-goroutine
// (async_ledger), so the read-prev-then-insert is race-free per org.
func (ls *LedgerStore) Append(ctx context.Context, att Attestation, sigB64, keyID string) error {
	raw, err := json.Marshal(att)
	if err != nil {
		return fmt.Errorf("marshal attestation for ledger: %w", err)
	}

	hash, err := att.Hash()
	if err != nil {
		return err
	}

	prev, err := ls.lastRecordHash(ctx, att.OrgID)
	if err != nil {
		return err
	}
	recHash := rowHash(prev, canonicalRecord(att, hash, sigB64, keyID))

	_, err = ls.pool.Exec(ctx, `
		INSERT INTO request_lineage (
			request_id, org_id, model_used, inference_region,
			model_origin_country, log_storage_region, provider_entity_jurisdiction,
			region_evidence,
			attestation_hash, attestation_signature, attestation_key_id, raw_attestation,
			record_hash, prev_hash
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
	`, att.RequestID, att.OrgID, att.ModelUsed, att.InferenceRegion,
		att.ModelOrigin, att.LogStorageRegion, att.ProviderEntity,
		att.RegionEvidence,
		hash, sigB64, keyID, raw, recHash, nullIfEmpty(prev))
	if err != nil {
		return fmt.Errorf("append lineage: %w", err)
	}
	return nil
}

// rowHash computes the per-row chain hash: SHA-256(prevHash + "|" + payload) as
// lowercase hex. Empty prevHash (chain head) hashes the payload alone prefixed
// with the separator, keeping the formula uniform.
func rowHash(prevHash, payload string) string {
	h := sha256.Sum256([]byte(prevHash + "|" + payload))
	return hex.EncodeToString(h[:])
}

// nullIfEmpty renders an empty string as SQL NULL (for prev_hash on the chain
// head) and any non-empty string as the value.
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// AppendBatch was removed with L02: the outbox relay (outbox.go) is now the
// single writer of chained request_lineage rows. A batch writer racing the
// relay could interleave per-org chain links (two writers reading the same
// head), so all writes go through the idempotent relay.

// GetByRequestID returns the lineage record for a request.
func (ls *LedgerStore) GetByRequestID(ctx context.Context, requestID string) (Attestation, error) {
	var att Attestation
	var raw json.RawMessage
	err := ls.pool.QueryRow(ctx, `
		SELECT raw_attestation FROM request_lineage WHERE request_id = $1
	`, requestID).Scan(&raw)
	if err != nil {
		return Attestation{}, fmt.Errorf("get lineage: %w", err)
	}
	if err := json.Unmarshal(raw, &att); err != nil {
		return Attestation{}, fmt.Errorf("unmarshal lineage: %w", err)
	}
	return att, nil
}

// ListByOrgFiltered returns recent lineage records for an org, with
// server-side filters: model_used and a
// [from, to] window. Zero times skip the bound. Filters run on the stored
// columns (not the JSON payload) so the LIMIT applies AFTER filtering.
func (ls *LedgerStore) ListByOrgFiltered(ctx context.Context, orgID string, model string, from, to time.Time, limit int) ([]Attestation, error) {
	where := "org_id = $1"
	args := []interface{}{orgID}
	if model != "" {
		args = append(args, model)
		where += fmt.Sprintf(" AND model_used = $%d", len(args))
	}
	if !from.IsZero() {
		args = append(args, from)
		where += fmt.Sprintf(" AND ts >= $%d", len(args))
	}
	if !to.IsZero() {
		args = append(args, to)
		where += fmt.Sprintf(" AND ts <= $%d", len(args))
	}
	args = append(args, limit)
	q := "SELECT raw_attestation FROM request_lineage WHERE " + where +
		fmt.Sprintf(" ORDER BY ts DESC LIMIT $%d", len(args))
	rows, err := ls.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list lineage filtered: %w", err)
	}
	defer rows.Close()
	var out []Attestation
	for rows.Next() {
		var raw json.RawMessage
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var a Attestation
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListByOrg returns the collection of byorg records visible to the caller.
func (ls *LedgerStore) ListByOrg(ctx context.Context, orgID string, limit int) ([]Attestation, error) {
	rows, err := ls.pool.Query(ctx, `
		SELECT raw_attestation FROM request_lineage
		WHERE org_id = $1 ORDER BY ts DESC LIMIT $2
	`, orgID, limit)
	if err != nil {
		return nil, fmt.Errorf("list lineage: %w", err)
	}
	defer rows.Close()

	var out []Attestation
	for rows.Next() {
		var raw json.RawMessage
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var a Attestation
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetSignatureByRequestID returns the stored signature and key_id for a request.
func (ls *LedgerStore) GetSignatureByRequestID(ctx context.Context, requestID string) (signatureB64, keyID string, err error) {
	err = ls.pool.QueryRow(ctx, `
		SELECT attestation_signature, attestation_key_id FROM request_lineage WHERE request_id = $1
	`, requestID).Scan(&signatureB64, &keyID)
	if err != nil {
		return "", "", fmt.Errorf("get lineage signature: %w", err)
	}
	if signatureB64 == "" {
		return "", "", fmt.Errorf("no signature found for request %s", requestID)
	}
	return signatureB64, keyID, nil
}
