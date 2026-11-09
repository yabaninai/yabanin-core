-- Reverse of 0022_inventory_assets.up.sql: the observable asset registry is
-- removed. No asset rows are restored here — the registry reverts to the
-- pre-0022 posture (no persistent inventory; imports have no durable home);
-- a re-upgrade starts the table empty and imports re-populate it from the
-- upstream sources.
DROP INDEX IF EXISTS idx_inventory_assets_live;
DROP TABLE IF EXISTS inventory_assets;
