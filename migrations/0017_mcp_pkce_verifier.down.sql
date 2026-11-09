-- Reverse of 0017_mcp_pkce_verifier.up.sql: pending flows created before the
-- downgrade lose their verifier; their token exchange runs without
-- code_verifier (pre-PKCE behavior), which servers without a PKCE challenge
-- still accept.
ALTER TABLE public.mcp_user_credentials
    DROP COLUMN IF EXISTS code_verifier_ct;
