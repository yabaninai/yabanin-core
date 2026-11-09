-- Reverse of 0019_rates_catalog_state.up.sql: the durable active-catalog record
-- is removed; the schema reverts to the pre-AUDIT-P1-04 posture (bundled pack
-- anchor only). No catalog data is restored here — promotions made while the
-- row existed are no longer recorded, and a re-promotion after re-upgrade
-- rewrites both the row and the projection.
DROP TABLE IF EXISTS rates_catalog_state;
