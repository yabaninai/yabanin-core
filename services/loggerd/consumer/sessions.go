package consumer

import (
	"context"

	"github.com/google/uuid"
)

// sessionRegistryUUID maps a raw client id onto the registry row id offered
// to the sessions upsert: a client-supplied valid UUID keeps its exact
// value, anything else maps to a deterministic v5 UUID derived from BOTH
// the org and the raw id. The org-scoped derivation is what makes the
// (org_id, client_session) conflict target (0032) safe for new rows: two
// orgs delivering the same non-UUID session id mint two distinct registry
// rows instead of colliding on the sessions primary key. uuidField stays
// frozen for the request_logs columns; this mapping only governs NEW
// registry rows — an existing (org, raw) pair always conflicts on the
// arbiter and keeps its original row id, so stored references never move.
//
// To map an org and a client id to the registry id a NEW row will get,
// compute the same v5 UUID with the frozen namespace:
//
//	python3 -c "import uuid; print(uuid.uuid5(uuid.UUID('6f9d2c1e-8b47-4a9b-9d3a-5e2f7c4b1a00'), '<org>\x00<ses_...>'))"
func sessionRegistryUUID(orgID, raw string) string {
	if u, err := uuid.Parse(raw); err == nil {
		return u.String()
	}
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
// Fail-open: an absent/invalid org, a client-supplied valid UUID that
// collides with another org's row (the exact-value contract makes that the
// one cross-org collision the primary key still rejects), or a failed
// upsert logs and returns nil — the row must be persisted even when session
// attribution is impossible. The upsert runs inside the delivery
// transaction (AF-04) and is idempotent: ON CONFLICT (org_id,
// client_session) makes replays safe within the same commit.
func (c *StreamConsumer) resolveSessionID(ctx context.Context, tx InboxTx, orgID, raw string) any {
	if raw == "" || orgID == "" {
		return nil
	}
	if _, err := uuid.Parse(orgID); err != nil {
		return nil // sessions.org_id has an FK to organizations; don't even try
	}
	sessionUUID := sessionRegistryUUID(orgID, raw)
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO sessions (id, org_id, client_session)
		VALUES ($1, $2, $3)
		ON CONFLICT (org_id, client_session) DO UPDATE SET updated_at = now()
		RETURNING id`, sessionUUID, orgID, raw).Scan(&id)
	if err != nil {
		c.logger.Warn("session registry upsert failed; logging without session",
			"client_session_digest", sessionUUID, "error", err.Error())
		return nil
	}
	return id
}
