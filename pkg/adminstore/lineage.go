package adminstore

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/reireirei/yabanin/pkg/lineage"
)

// GetLineageByRequestID fetches a lineage record by request ID.
func (s *Store) GetLineageByRequestID(ctx context.Context, requestID string) (lineage.Attestation, error) {
	if s.db == nil {
		return lineage.Attestation{}, fmt.Errorf("database not available")
	}
	var raw json.RawMessage
	err := s.db.QueryRow(ctx, `
		SELECT raw_attestation FROM request_lineage WHERE request_id = $1
	`, requestID).Scan(&raw)
	if IsNotFound(err) {
		return lineage.Attestation{}, fmt.Errorf("lineage not found: %s", requestID)
	}
	if err != nil {
		return lineage.Attestation{}, fmt.Errorf("get lineage by request: %w", err)
	}
	var att lineage.Attestation
	if err := json.Unmarshal(raw, &att); err != nil {
		return lineage.Attestation{}, fmt.Errorf("unmarshal lineage: %w", err)
	}
	return att, nil
}

// ListLineageByOrgFiltered is ListLineageByOrg with server-side model and
// [from, to] filters (zero times skip the bound); LIMIT applies after them.
func (s *Store) ListLineageByOrgFiltered(ctx context.Context, orgID, model string, from, to time.Time, limit int) ([]lineage.Attestation, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
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
	rows, err := s.db.Query(ctx,
		"SELECT raw_attestation FROM request_lineage WHERE "+where+
			fmt.Sprintf(" ORDER BY ts DESC LIMIT $%d", len(args)), args...)
	if err != nil {
		return nil, fmt.Errorf("list lineage filtered: %w", err)
	}
	defer rows.Close()
	var out []lineage.Attestation
	for rows.Next() {
		var raw json.RawMessage
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var a lineage.Attestation
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListLineageByOrg returns recent lineage records for an org.
func (s *Store) ListLineageByOrg(ctx context.Context, orgID string, limit int) ([]lineage.Attestation, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	rows, err := s.db.Query(ctx, `
		SELECT raw_attestation FROM request_lineage
		WHERE org_id = $1 ORDER BY ts DESC LIMIT $2
	`, orgID, limit)
	if err != nil {
		return nil, fmt.Errorf("list lineage: %w", err)
	}
	defer rows.Close()

	var out []lineage.Attestation
	for rows.Next() {
		var raw json.RawMessage
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var a lineage.Attestation
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
