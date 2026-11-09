-- Reverse of 0016_mcp_credential_mode.up.sql: the columns carry no external
-- state (mode re-derives from the legacy chain; config_version restarts at 1),
-- so a plain drop is lossless for the pre-0016 feature surface.
ALTER TABLE public.mcp_servers
    DROP CONSTRAINT IF EXISTS mcp_servers_credential_mode_check;
ALTER TABLE public.mcp_servers
    DROP COLUMN IF EXISTS config_version,
    DROP COLUMN IF EXISTS credential_mode;
