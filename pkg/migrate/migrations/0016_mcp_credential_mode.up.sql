-- expand-contract: expand — MCP connection credential-mode configuration (adds mcp_servers.credential_mode and mcp_servers.config_version).
-- N05-P02-T02 (I54): credential mode on the MCP connection configuration.
--
-- Two credential modes are configurable per registered server, plus the
-- legacy chain as the compatibility default:
--
--   'auto'      per-user active -> server-level enabled -> none (pre-0016
--               behavior, byte-for-byte; existing rows keep it)
--   'service'   only the org/project service credential (server-level);
--               per-user credentials are never consulted
--   'delegated' only the per-user credential after its authorization; an
--               unavailable user credential NEVER silently escalates to the
--               more privileged service credential (I54 negative)
--
-- config_version versions the connection configuration: every successful
-- admin update bumps it monotonically, so operators and auditors can tell
-- which revision of the connection a credential decision belonged to.
ALTER TABLE public.mcp_servers
    ADD COLUMN credential_mode text DEFAULT 'auto'::text NOT NULL,
    ADD COLUMN config_version bigint DEFAULT 1::bigint NOT NULL;

ALTER TABLE public.mcp_servers
    ADD CONSTRAINT mcp_servers_credential_mode_check
        CHECK ((credential_mode = ANY (ARRAY['auto'::text, 'service'::text, 'delegated'::text])));
