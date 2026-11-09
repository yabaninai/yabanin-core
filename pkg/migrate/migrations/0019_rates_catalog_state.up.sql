-- expand-contract: expand — deployment-global active rates-catalog record (pack bytes + provenance) backing durable promotion.
-- 0019_rates_catalog_state — AUDIT-P1-04: durable active rates-catalog state.
--
-- rates_catalog_state is the DEPLOYMENT-GLOBAL activation record for the
-- reference-currency rates catalog (the source the gateway prices from via
-- models_pricing / DBPricer). Exactly one row (id = 1, pinned by CHECK). It is
-- written ONLY through pkg/adminstore PromoteRefCatalogDurable inside the
-- promotion transaction (pg_advisory_xact_lock serialization): the state row
-- and the models_pricing materialization commit or roll back together — there
-- is never a recorded active catalog that the projection does not reflect.
--
-- Before this table the active catalog lived only in the binary (the embedded
-- reference pack) and promotions were process-local (SetDefaultFilePricer in
-- the admin process): a gateway restart — or any other process — silently
-- kept pricing from the bundled pack. The row makes promotion durable and
-- cross-process: gateways read promoted prices via models_pricing (DBPricer,
-- per-entry cache TTL ⇒ bounded propagation delay, no restart), the admin GET
-- returns the active-of-record bytes, and chain verification anchors on this
-- row when present (the bundled pack remains the genesis anchor — the row
-- stays absent until the first promotion; a rollback re-promotes the previous
-- pack, which is exactly the row's pack_json).
--
-- pack_json is the full sealed pack (bytea, ~2.3 MiB for the current
-- reference pack). It is the exact bytes GET /api/rates/catalog returns and
-- the exact bytes the next promotion's chain verification reads.
--
-- ISOLATION POSTURE — NO RLS (0011/sso and 0013/guard_pack_state rationale):
-- the row has no org dimension. It is one deployment's active catalog,
-- mutated only by the root-only rates routes (requireRootForRates + audit
-- journal) and read by the deployment's own admin/gateway processes; an
-- app.current_org RLS policy would hide the row from exactly the readers
-- that need it. Access control lives at the caller.

CREATE TABLE rates_catalog_state (
    id integer PRIMARY KEY CHECK (id = 1),
    catalog_version text NOT NULL,
    catalog_digest text NOT NULL,
    pack_sha256 text NOT NULL,
    pack_json bytea NOT NULL,
    activated_by text NOT NULL DEFAULT '',
    activated_at timestamptz NOT NULL DEFAULT now()
);
