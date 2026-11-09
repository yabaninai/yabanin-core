-- expand-contract: expand — fleet installation registry: the persistent home
-- of pkg/fleet (E03-P01 W03-C03, lane imp-e03p01b, batch B). Number 0024 is
-- the packet's allocated slot (dispatch §8 allocation table; held until now
-- by the mirror reservedGaps pin, deleted with this landing).
--
-- fleet_installations stores one row per enrolled installation: the
-- (org_id, deployment_id) identity pair of identity-model.md §2–§3, the
-- lifecycle state (the four-value vocabulary of pkg/fleet State — the
-- CHECK mirrors identity.go's model; revoked is terminal and the
-- revocation columns carry its stamps), and the negotiated caps document
-- (one JSON value: the NegotiatedCaps of caps.go — format_version +
-- capabilities + unsupported — written by the caps store after a
-- successful NegotiateCaps; caps-matrix.md §5).
--
-- Timestamps are ALWAYS caller-injected (the package determinism law:
-- no now() here — enrolled_at/caps_updated_at arrive as statement
-- parameters from the store). last_heartbeat_at is NULL until the first
-- verified heartbeat (the W04-C01 machinery owns it).
--
-- ISOLATION POSTURE — the house RLS pattern (0002:11/:13/:15 posture):
-- ENABLE + FORCE + one org_isolation policy. The org key is TEXT (fleet
-- OrgID is a validated string coordinate of identity-model.md §3, not a
-- uuid — no FK to organizations, mirroring the 0026 secevents TEXT-org
-- decision), so the GUC comparison uses the NULLIF form WITHOUT a cast:
-- an empty or unbound app.current_org reads NULL and matches nothing —
-- fail-closed (0026 shape). FORCE ROW LEVEL SECURITY keeps even the
-- owning role bound. The store (pkg/fleet caps_store.go) pins the GUC
-- inside the same transaction as its statements and keeps the explicit
-- org_id predicate as defense-in-depth (the E06 inbox store law);
-- superuser/RLS-exempt sessions skip the inert pin (same law as the
-- secevents writer).
CREATE TABLE fleet_installations (
	org_id            TEXT        NOT NULL,
	deployment_id     TEXT        NOT NULL,
	state             TEXT        NOT NULL,
	caps              JSONB       NOT NULL,
	enrolled_at       TIMESTAMPTZ NOT NULL,
	caps_updated_at   TIMESTAMPTZ NOT NULL,
	last_heartbeat_at TIMESTAMPTZ,
	revoked_at        TIMESTAMPTZ,
	revocation_reason TEXT        NOT NULL DEFAULT '',
	PRIMARY KEY (org_id, deployment_id),
	CONSTRAINT chk_fleet_installations_state CHECK (state = ANY (ARRAY['enrolled'::text, 'active'::text, 'stale'::text, 'revoked'::text])),
	CONSTRAINT chk_fleet_installations_revoked_stamp CHECK (state <> 'revoked'::text OR revoked_at IS NOT NULL),
	CONSTRAINT chk_fleet_installations_not_revoked_stamp CHECK (state = 'revoked'::text OR revoked_at IS NULL)
);

ALTER TABLE fleet_installations ENABLE ROW LEVEL SECURITY;
ALTER TABLE fleet_installations FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON fleet_installations
  USING (org_id = NULLIF(current_setting('app.current_org', true), ''))
  WITH CHECK (org_id = NULLIF(current_setting('app.current_org', true), ''));

-- Org-scan read path for the registry read API (W04-C03 list endpoint):
-- the PK already serves (org_id, deployment_id) point lookups.
CREATE INDEX idx_fleet_installations_org_state ON fleet_installations (org_id, state, deployment_id);
