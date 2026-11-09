-- bootstrap-app-role.sql — idempotent app-role bootstrap for the quickstart
-- stack on a FRESH database.
--
-- The consolidated baseline migration (migrations/0001_init.up.sql) is a
-- pg_dump: it cannot carry cluster-level roles, and the historical migration
-- that created yabanin_app was dropped during consolidation. The app DSN in
-- docker-compose.yml logs in as yabanin_app (IMP-88 non-owner posture), so
-- this one-shot recreates the role exactly as pkg/testdb.applyMigrations does
-- (NOLOGIN least-privilege + application-surface grants), then enables LOGIN
-- with the quickstart's fixed dev credential — the same split the deployment
-- layer uses (LOGIN and the password stay a deploy-layer concern).
--
-- Every statement is idempotent: the stack can be re-upped against an
-- already-bootstrapped database without manual SQL.

DO $$ BEGIN
	IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'yabanin_app') THEN
		CREATE ROLE yabanin_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
	END IF;
END $$;

ALTER ROLE yabanin_app LOGIN PASSWORD 'yabanin_app';

GRANT USAGE ON SCHEMA public TO yabanin_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO yabanin_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO yabanin_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO yabanin_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO yabanin_app;
