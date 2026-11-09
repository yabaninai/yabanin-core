-- expand-contract: expand — per-grant MCP action vocabulary (adds mcp_server_grants.allowed_actions).
-- N05-P06-T02 (owner decision 2026-11-05: per-grant action column EARLY,
-- FIX-21 item — card N05-P02-T04 built the enforcement seam grantAllowsAction
-- that this column backs).
--
-- The column is the ACTION dimension of the four-dimension grant check
-- (subject / server / tool / action): the actions this grant authorizes on
-- the server. Vocabulary (mcpagg grant actions since N05-P02-T04):
-- "invoke" (tools/call) and "list" (tools/list).
--
-- DEFAULT '["invoke","list"]' preserves today's behavior for every existing
-- row: grantcheck authorized both actions before the column existed. This is
-- the expand phase; flipping the default to per-grant opt-in belongs to the
-- contract successor. An EXPLICIT empty array is a real restriction: the
-- grant stays subject-valid (audit, admin reads) but authorizes no action —
-- the check fails closed. Unknown action strings are refused by the CHECK.
ALTER TABLE public.mcp_server_grants
    ADD COLUMN allowed_actions jsonb DEFAULT '["invoke","list"]'::jsonb NOT NULL,
    ADD CONSTRAINT mcp_server_grants_actions_valid_check CHECK (
        jsonb_typeof(allowed_actions) = 'array'::text
        AND allowed_actions <@ '["invoke","list"]'::jsonb
        AND jsonb_array_length(allowed_actions) <= 2
    );
