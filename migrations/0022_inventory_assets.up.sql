-- expand-contract: expand — observable asset registry: the persistent home of pkg/inventory assets.
-- 0022_inventory_assets — E02-P01 W01-C02, lane imp-e02p01a (batch A).
--
-- inventory_assets is the store behind pkg/inventory.Store (E02-P01): the
-- org-scoped registry of agent/service/mcp_server/tool/model/provider
-- identities. The W01-C01 provenance invariant — every asset carries
-- source/confidence/last_seen, and absence of observations is NOT absence of
-- the asset — is a row shape here: imported rows persist without any
-- observation, and only an explicit upstream signal flips tombstone (the
-- import adapters own that decision); nothing deletes rows for missing
-- observations.
--
-- payload is the verbatim source document (jsonb) at import time and stays
-- the source of truth; kind/confidence are projection columns with closed
-- vocabularies (the checks mirror pkg/inventory AssetKind/Confidence).
-- first_seen/last_seen are monotonic per row: the store keeps
-- LEAST(first_seen)/GREATEST(last_seen) on upsert, so a re-import never
-- moves the discovery stamp backwards.
--
-- ISOLATION POSTURE — NO RLS, org key in every access (0012/sso and 0021
-- rationale shape): the registry has no production consumer yet (pkg/inventory
-- is the additive SPI; the admin read path lands with its own cards). The org
-- dimension is the leading PRIMARY KEY column and every store access keys by
-- (org_id, asset_key, kind); the tenant read-path decision (RLS or explicit
-- predicate) belongs to the wiring cards together with the E01-P04 isolation
-- contract — this migration adds an empty table and no readers.
CREATE TABLE inventory_assets (
	org_id        TEXT        NOT NULL,
	asset_key     TEXT        NOT NULL,
	kind          TEXT        NOT NULL,
	payload       JSONB       NOT NULL,
	source        TEXT        NOT NULL,
	confidence    TEXT        NOT NULL,
	first_seen    TIMESTAMPTZ NOT NULL,
	last_seen     TIMESTAMPTZ NOT NULL,
	tombstone     BOOLEAN     NOT NULL DEFAULT false,
	tombstoned_at TIMESTAMPTZ,
	PRIMARY KEY (org_id, asset_key, kind),
	CONSTRAINT chk_inventory_assets_kind CHECK (kind = ANY (ARRAY['agent'::text, 'service'::text, 'mcp_server'::text, 'tool'::text, 'model'::text, 'provider'::text])),
	CONSTRAINT chk_inventory_assets_confidence CHECK (confidence = ANY (ARRAY['high'::text, 'low'::text])),
	CONSTRAINT chk_inventory_assets_tombstone CHECK (NOT tombstone OR tombstoned_at IS NOT NULL)
);

-- Live listing access path for the admin read API: org-scoped, kind-filtered,
-- newest-activity first, tombstones excluded.
CREATE INDEX idx_inventory_assets_live ON public.inventory_assets (org_id, kind, last_seen DESC) WHERE NOT tombstone;
