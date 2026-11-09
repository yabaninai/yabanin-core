-- Reverse of 0004_org_credential_pool_state.up.sql: drop the org credential
-- pool state table (quarantine bookkeeping only — no credential material
-- lives here; the credentials themselves stay in org_provider_credentials).

DROP TABLE IF EXISTS public.org_credential_pool_state CASCADE;
