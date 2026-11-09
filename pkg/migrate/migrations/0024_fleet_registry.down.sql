-- Reverse of 0024_fleet_registry.up.sql: the fleet installation registry
-- is removed. Only this migration's own objects are touched (the card's
-- rollback contract): the state index, the org_isolation policy, the
-- RLS posture and the table itself ride together. No installation rows
-- are restored here — a re-upgrade starts the registry empty and
-- enrollments re-populate it from verified enrollments.
DROP POLICY org_isolation ON fleet_installations;
DROP INDEX IF EXISTS idx_fleet_installations_org_state;
DROP TABLE IF EXISTS fleet_installations;
