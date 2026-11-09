package lineage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// ExportRow is one lineage row for export (H2). It carries the canonical
// columns plus the hash-chain links so the exported JSONL is self-verifying.
type ExportRow struct {
	RequestID        string `json:"request_id"`
	OrgID            string `json:"org_id"`
	TS               string `json:"ts"` // RFC3339Nano
	ModelUsed        string `json:"model_used"`
	InferenceRegion  string `json:"inference_region"`
	ModelOrigin      string `json:"model_origin_country"`
	LogStorageRegion string `json:"log_storage_region"`
	ProviderEntity   string `json:"provider_entity_jurisdiction"`
	RegionEvidence   string `json:"region_evidence"`
	AttestationHash  string `json:"attestation_hash"`
	RecordHash       string `json:"record_hash"` // "" for legacy rows
	PrevHash         string `json:"prev_hash"`   // "" for the head / legacy
	Raw              any    `json:"raw_attestation"`
}

// QueryForExport returns lineage rows in ts order for an optional org. An empty
// orgID exports all orgs. It is used by `tr lineage export` (H2).
func (ls *LedgerStore) QueryForExport(ctx context.Context, orgID string, limit int) ([]ExportRow, error) {
	q := `
		SELECT request_id, org_id, ts, model_used, inference_region,
		       model_origin_country, log_storage_region, provider_entity_jurisdiction,
		       region_evidence, attestation_hash, record_hash,
		       COALESCE(prev_hash, ''), raw_attestation
		FROM request_lineage
	`
	args := []any{}
	if orgID != "" {
		q += " WHERE org_id = $1"
		args = append(args, orgID)
	}
	if limit > 0 {
		q += fmt.Sprintf(" ORDER BY ts ASC LIMIT $%d", len(args)+1)
		args = append(args, limit)
	} else {
		q += " ORDER BY ts ASC"
	}
	rs, err := ls.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query lineage for export: %w", err)
	}
	defer rs.Close()

	var out []ExportRow
	for rs.Next() {
		var (
			row      ExportRow
			ts       time.Time
			raw      []byte
			prevHash string
		)
		if err := rs.Scan(&row.RequestID, &row.OrgID, &ts, &row.ModelUsed,
			&row.InferenceRegion, &row.ModelOrigin, &row.LogStorageRegion,
			&row.ProviderEntity, &row.RegionEvidence, &row.AttestationHash,
			&row.RecordHash, &prevHash, &raw); err != nil {
			return nil, fmt.Errorf("scan export row: %w", err)
		}
		row.TS = ts.UTC().Format(time.RFC3339Nano)
		row.PrevHash = prevHash
		var decoded any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			row.Raw = string(raw) // keep raw bytes if not JSON
		} else {
			row.Raw = decoded
		}
		out = append(out, row)
	}
	if err := rs.Err(); err != nil {
		return nil, fmt.Errorf("iterate export rows: %w", err)
	}
	return out, nil
}

// ChainStatus is the result of verifying an org's hash chain.
type ChainStatus struct {
	OrgID    string `json:"org_id"`
	Rows     int    `json:"rows"`      // total rows scanned
	Chained  int    `json:"chained"`   // rows with record_hash != ''
	Legacy   int    `json:"legacy"`    // rows with record_hash == '' (skipped)
	Intact   bool   `json:"intact"`    // true when no break was found
	BrokenAt string `json:"broken_at"` // request_id where the break was found ("" if intact)
}

// VerifyChain walks the org's lineage rows in ts order and re-verifies the
// per-org hash chain. Legacy rows (record_hash = ”) are skipped (not part of
// the chain). It returns the status; a non-nil error is only for DB failures.
//
// The chain is verified per-org: for each chained row, record_hash must equal
// SHA-256(prevHash + "|" + canonicalRecord) and prev_hash must equal the
// previous chained row's record_hash (or be NULL/empty for the head).
func (ls *LedgerStore) VerifyChain(ctx context.Context, orgID string) (ChainStatus, error) {
	rows, err := ls.pool.Query(ctx, `
		SELECT request_id, model_used, inference_region,
		       model_origin_country, log_storage_region, provider_entity_jurisdiction,
		       region_evidence, attestation_hash, attestation_signature, attestation_key_id,
		       record_hash, prev_hash
		FROM request_lineage
		WHERE org_id = $1
		ORDER BY ts ASC
	`, orgID)
	if err != nil {
		return ChainStatus{}, fmt.Errorf("query lineage chain: %w", err)
	}
	defer rows.Close()

	status := ChainStatus{OrgID: orgID, Intact: true}
	var prevRecordHash string
	for rows.Next() {
		var (
			requestID, modelUsed, infRegion, modelOrigin, logRegion, providerEntity string
			regionEvidence, attHash, sigB64, keyID, recordHash                      string
			prevHash                                                                *string // NULL for the chain head
		)
		if err := rows.Scan(&requestID, &modelUsed, &infRegion, &modelOrigin,
			&logRegion, &providerEntity, &regionEvidence, &attHash, &sigB64, &keyID,
			&recordHash, &prevHash); err != nil {
			return status, fmt.Errorf("scan lineage row: %w", err)
		}
		status.Rows++
		if recordHash == "" {
			status.Legacy++
			continue // legacy row — not part of the chain
		}
		status.Chained++

		att := Attestation{
			RequestID:        requestID,
			OrgID:            orgID,
			ModelUsed:        modelUsed,
			InferenceRegion:  infRegion,
			ModelOrigin:      modelOrigin,
			LogStorageRegion: logRegion,
			ProviderEntity:   providerEntity,
			RegionEvidence:   regionEvidence,
		}
		payload := canonicalRecord(att, attHash, sigB64, keyID)
		expected := rowHash(prevRecordHash, payload)

		if recordHash != expected {
			status.Intact = false
			status.BrokenAt = requestID
			break
		}
		// prev_hash must be NULL (head) or the previous row's record_hash.
		storedPrev := ""
		if prevHash != nil {
			storedPrev = *prevHash
		}
		if storedPrev != prevRecordHash {
			status.Intact = false
			status.BrokenAt = requestID
			break
		}
		prevRecordHash = recordHash
	}
	if err := rows.Err(); err != nil {
		return status, fmt.Errorf("iterate lineage rows: %w", err)
	}
	return status, nil
}
