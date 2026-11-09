-- R107-02 (ratified D-5: pool state in DB): org credential pool state.
-- One row per quarantined credential, keyed by credential_id and scoped to
-- the credential's CURRENT key_version: a rotation (Update + newPlaintextKey,
-- key_version++) or a delete+recreate no longer matches the stored row, so a
-- quarantined credential returns to rotation implicitly and the frozen
-- W-BYOK-DB OrgCredentialStore contract stays untouched (ratified D-6:
-- additive only). The table carries bookkeeping exclusively — never key
-- material. Org isolation mirrors org_provider_credentials (migration 0001):
-- FORCE RLS + org_isolation on the app.current_org GUC, fail closed for
-- unbound sessions; the store pins the GUC transaction-locally
-- (withCredentialTx).

CREATE TABLE public.org_credential_pool_state (
    credential_id uuid NOT NULL,
    org_id uuid NOT NULL,
    key_version integer NOT NULL,
    quarantined_until timestamp with time zone NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT org_credential_pool_state_pkey PRIMARY KEY (credential_id),
    CONSTRAINT org_credential_pool_state_key_version_check CHECK ((key_version >= 1)),
    CONSTRAINT org_credential_pool_state_credential_id_fkey FOREIGN KEY (credential_id) REFERENCES public.org_provider_credentials(id) ON DELETE CASCADE,
    CONSTRAINT org_credential_pool_state_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE
);

CREATE INDEX idx_org_credential_pool_state_org ON public.org_credential_pool_state USING btree (org_id);

ALTER TABLE public.org_credential_pool_state ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.org_credential_pool_state FORCE ROW LEVEL SECURITY;

CREATE POLICY org_isolation ON public.org_credential_pool_state USING ((org_id = (NULLIF(current_setting('app.current_org'::text, true), ''::text))::uuid)) WITH CHECK ((org_id = (NULLIF(current_setting('app.current_org'::text, true), ''::text))::uuid));

CREATE TRIGGER set_org_credential_pool_state_updated_at BEFORE UPDATE ON public.org_credential_pool_state FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();
