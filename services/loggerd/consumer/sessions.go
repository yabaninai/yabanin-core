package consumer

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// sessionRegistryUUID maps (org, raw client id) to the registry row id
// offered for NEW sessions rows: a deterministic v5 UUID derived from BOTH
// the org and the raw id under the frozen nsRequestLogs namespace, so ids
// never collide across orgs. The mapping governs only new rows — uuidField
// stays frozen for the request_logs agent/user/team columns.
//
// Legacy row preservation: an existing (org, raw) pair always conflicts on
// the (org_id, client_session) arbiter (0032) and keeps its original row id
// — including pre-0032 rows (verbatim UUIDs or global v5(raw) ids) — so
// stored request_logs references never move.
//
// To predict the registry id of a new row:
//
//	python3 -c "import uuid; print(uuid.uuid5(uuid.UUID('6f9d2c1e-8b47-4a9b-9d3a-5e2f7c4b1a00'), '<org>\x00<ses_...>'))"
func sessionRegistryUUID(orgID, raw string) string {
	return uuid.NewSHA1(nsRequestLogsUUID, []byte(orgID+"\x00"+raw)).String()
}

// resolveSessionID registers the client session in the sessions registry and
// returns the uuid to store in request_logs.session_id so the
// request_logs_session_id_fkey holds. Rows carry the RAW client id (e.g. an
// OpenCode "ses_..." X-Session-Id value) under the org-scoped (org_id,
// client_session) conflict target (0032): sessions RLS is region-only, so
// the scope is what keeps a delivery from returning another org's registry
// row.
//
// optionalSessionID carries the nullable request log session ID explicitly.
type optionalSessionID struct {
	id      string
	present bool
}

func (id optionalSessionID) sqlValue() any {
	if !id.present {
		return nil
	}
	return id.id
}

func validSessionOrgID(orgID string) bool {
	_, err := uuid.Parse(orgID)
	return err == nil
}

// Statement-free input guards (absent session, absent/invalid org) return an
// absent ID — no statement has run, so nil cannot poison the delivery
// transaction. A failed upsert propagates instead: PostgreSQL aborts the
// enclosing transaction on a failed statement, so swallowing the error would
// only move the failure to the next insert (25P02) under a success log line.
// Failing the delivery cleanly sends it to redelivery.
func (c *StreamConsumer) resolveSessionID(ctx context.Context, tx InboxTx, orgID, raw string) (optionalSessionID, error) {
	if raw == "" || orgID == "" {
		return optionalSessionID{}, nil
	}
	if !validSessionOrgID(orgID) {
		return optionalSessionID{}, nil // sessions.org_id has an FK to organizations; don't even try
	}
	sessionUUID := sessionRegistryUUID(orgID, raw)
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO sessions (id, org_id, client_session)
		VALUES ($1, $2, $3)
		ON CONFLICT (org_id, client_session) DO UPDATE SET updated_at = now()
		RETURNING id`, sessionUUID, orgID, raw).Scan(&id)
	if err != nil {
		return optionalSessionID{}, fmt.Errorf("session registry upsert: %w", err)
	}
	return optionalSessionID{id: id, present: true}, nil
}
