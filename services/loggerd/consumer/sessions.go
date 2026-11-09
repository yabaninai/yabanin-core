package consumer

import (
	"context"

	"github.com/google/uuid"
)

// resolveSessionID registers the client session in the sessions registry and
// returns the uuid to store in request_logs.session_id so the
// request_logs_session_id_fkey holds.
//
// The schema contract is: request_logs.session_id REFERENCES sessions(id),
// and sessions.client_session (unique) carries the RAW client id (e.g. an
// OpenCode "ses_..." X-Session-Id value). Nothing in the product wrote to
// that registry before, so every non-NULL session_id failed the FK with
// SQLSTATE 23503 — the layer beneath the LG-U1 uuid-cast fix.
//
// The registry row id reuses the uuidField mapping of the raw client id — a
// client-supplied valid UUID keeps its exact value, anything else maps to the
// deterministic v5 UUID under the frozen nsRequestLogs namespace — so the
// mapping is stable across restarts, never collides with gen_random_uuid()
// values in practice, and the LG-U1 golden vectors still hold.
//
// Fail-open: an absent/invalid org or a failed upsert logs and returns nil —
// the row must be persisted even when session attribution is impossible.
// The upsert runs inside the delivery transaction (AF-04) and is idempotent:
// ON CONFLICT (client_session) makes replays safe within the same commit.
func (c *StreamConsumer) resolveSessionID(ctx context.Context, tx InboxTx, orgID, raw string) any {
	if raw == "" || orgID == "" {
		return nil
	}
	if _, err := uuid.Parse(orgID); err != nil {
		return nil // sessions.org_id has an FK to organizations; don't even try
	}
	sessionUUID, ok := uuidField(raw).(string)
	if !ok {
		return nil
	}
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO sessions (id, org_id, client_session)
		VALUES ($1, $2, $3)
		ON CONFLICT (client_session) DO UPDATE SET updated_at = now()
		RETURNING id`, sessionUUID, orgID, raw).Scan(&id)
	if err != nil {
		c.logger.Warn("session registry upsert failed; logging without session",
			"client_session_digest", sessionUUID, "error", err.Error())
		return nil
	}
	return id
}
