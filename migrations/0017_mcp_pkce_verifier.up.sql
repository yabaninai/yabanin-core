-- expand-contract: expand — MCP delegated-access PKCE (adds mcp_user_credentials.code_verifier_ct).
-- N05-P02-T03: PKCE (RFC 7636) for the MCP delegated-access OAuth flow.
--
-- The gateway is the confidential client: it generates the code_verifier at
-- flow start and performs the token exchange server-side, so the verifier is
-- stored encrypted (same envelope as secret_ct) on the pending credential
-- row and consumed once at the exchange (cleared after use). NULL for rows
-- created before this migration or after consumption: the exchange then runs
-- without code_verifier (pre-PKCE behavior) — pre-0017 rows keep working.
ALTER TABLE public.mcp_user_credentials
    ADD COLUMN code_verifier_ct text;
