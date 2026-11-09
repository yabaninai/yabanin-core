-- Reverse of 0020_mcp_grant_actions.up.sql: per-grant action narrowing is
-- lost and every grant returns to authorizing both actions (pre-0020
-- behavior, which the column default had already preserved for untouched
-- rows).
ALTER TABLE public.mcp_server_grants
    DROP CONSTRAINT IF EXISTS mcp_server_grants_actions_valid_check;
ALTER TABLE public.mcp_server_grants
    DROP COLUMN IF EXISTS allowed_actions;
