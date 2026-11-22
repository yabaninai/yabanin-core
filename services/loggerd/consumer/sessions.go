package consumer

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// sessionRegistryUUID maps (org, raw client id) onto the registry row id
// offered to the sessions upsert: a deterministic v5 UUID derived from BOTH
// the org and the raw id under the frozen nsRequestLogs namespace. The
// mapping is org-scoped for EVERY raw shape — a client-supplied valid UUID
// is not kept verbatim, because verbatim ids collide across orgs on the
// sessions primary key and a primary-key violation is a statement error
// that aborts the whole delivery transaction (a poison loop: the same
// shared id would fail every redelivery of the second org). The v5 mapping
// never collides across orgs (a deliberate preimage is infeasible), so the
// primary key stays a pure safety net.
//
// uuidField stays frozen for the request_logs agent/user/team columns; this
// mapping only governs NEW registry rows. An existing (org, raw) pair
// always conflicts on the (org_id, client_session) arbiter (0032) and keeps
// its original row id — including rows written by the pre-0032 mapping
// (verbatim UUIDs or global v5(raw) ids) — so stored request_logs
// references never move.
//
// To map an org and a client id to the registry id a NEW row will get,
// compute the same v5 UUID with the frozen namespace:
//
//	python3 -c "import uuid; print(uuid.uuid5(uuid.UUID('6f9d2c1e-8b47-4a9b-9d3a-5e2f7c4b1a00'), '<org>\x00<ses_...>'))"
func sessionRegistryUUID(orgID, raw string) string {
	return uuid.NewSHA1(nsRequestLogsUUID, []byte(orgID + "\x00" + raw)).String()
}

// resolveSessionID registers the client session in the sessions registry and
// returns the uuid to store in request_logs.session_id so the
// request_logs_session_id_fkey holds.
//
// The schema contract is: request_logs.session_id REFERENCES sessions(id),
// and sessions carries the RAW client id (e.g. an OpenCode "ses_..."
// X-Session-Id value) under the (org_id, client_session) conflict target
// (0032). Nothing in the product wrote to that registry before, so every
// non-NULL session_id failed the FK with SQLSTATE 23503 — the layer beneath
// the LG-U1 uuid-cast fix.
//
// The conflict target is org-scoped because the sessions RLS posture is
// region isolation only (app.region), never org isolation: without it, two
// orgs in the same permitted region delivering the same raw session id
// resolved onto ONE row — the second org's deliveries updated the foreign
// org's row and stored the foreign session id in their request_logs rows.
// Under the scoped target each org owns its own row; a delivery can never
// update or return another org's registry row.
//
// Statement-free input guards (absent session, absent/invalid org) return
// nil: sessions.org_id has an FK to organizations, and no statement has
// run, so returning nil cannot poison the delivery transaction. A FAILED
// upsert statement propagates instead: in PostgreSQL a failed statement
// aborts the enclosing transaction, so logging-and-continuing would make
// the very next insert die with 25P02 and still roll the delivery back —
// while the log line claimed success. Failing the delivery cleanly sends
// the event to redelivery, where the deterministic upsert either succeeds
// (transient failure) or fails with the same wrapped cause.
func (c *StreamConsumer) resolveSessionID(ctx context.Context, tx InboxTx, orgID, raw string) (any, error) {
	if raw == "" || orgID == "" {
		return nil, nil
	}
	if _, err := uuid.Parse(orgID); err != nil {
		return nil, nil // sessions.org_id has an FK to organizations; don't even try
	}
	sessionUUID := sessionRegistryUUID(orgID, raw)
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO sessions (id, org_id, client_session)
		VALUES ($1, $2, $3)
		ON CONFLICT (org_id, client_session) DO UPDATE SET updated_at = now()
		RETURNING id`, sessionUUID, orgID, raw).Scan(&id)
	if err != nil {
		return nil, fmt.Errorf("session registry upsert: %w", err)
	}
	return id, nil
}
