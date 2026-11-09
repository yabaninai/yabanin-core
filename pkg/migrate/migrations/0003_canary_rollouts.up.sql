-- R106-02 (D5 ratified 2026-10-16): versioned canary model rollouts — the
-- R019 pattern (policy_pipelines/policy_versions) applied to model traffic
-- splits. One rollout row per (org, name); immutable version rows carry the
-- (base_model, canary_model, percent) triple; current_version + label move
-- only through atomic activation (SetActiveCanaryRolloutVersion, one
-- transaction); enabled=false is the manual rollback (D3) and never touches
-- version history. percent is a WHOLE number 1..99 (D2): 0 and 100 are
-- rejected by CHECK — "canary получает весь трафик" is the packet's named
-- negative scenario, and a 0% rollout is a deactivated rollout, not a row.
-- Org isolation mirrors the policy_* posture (migration 0001 / 0002): RLS
-- ENABLE+FORCE with the app.current_org GUC; a cross-org resource id reads
-- as not found, never as a leak (fail closed).

CREATE TABLE public.canary_rollouts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id uuid NOT NULL,
    name text NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    current_version integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT canary_rollouts_pkey PRIMARY KEY (id),
    CONSTRAINT canary_rollouts_current_version_check CHECK ((current_version >= 1)),
    CONSTRAINT canary_rollouts_name_check CHECK ((name <> ''::text))
);

ALTER TABLE public.canary_rollouts ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.canary_rollouts FORCE ROW LEVEL SECURITY;

CREATE POLICY org_isolation ON public.canary_rollouts USING ((org_id = (NULLIF(current_setting('app.current_org'::text, true), ''::text))::uuid)) WITH CHECK ((org_id = (NULLIF(current_setting('app.current_org'::text, true), ''::text))::uuid));

CREATE TABLE public.canary_rollout_versions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    rollout_id uuid NOT NULL,
    org_id uuid NOT NULL,
    version integer NOT NULL,
    base_model text NOT NULL,
    canary_model text NOT NULL,
    percent integer NOT NULL,
    label text DEFAULT 'draft'::text NOT NULL,
    created_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT canary_rollout_versions_pkey PRIMARY KEY (id),
    CONSTRAINT canary_rollout_versions_label_check CHECK ((label = ANY (ARRAY['draft'::text, 'active'::text]))),
    CONSTRAINT canary_rollout_versions_percent_check CHECK ((percent >= 1 AND percent <= 99)),
    CONSTRAINT canary_rollout_versions_base_ne_canary_check CHECK ((base_model <> canary_model))
);

ALTER TABLE public.canary_rollout_versions ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.canary_rollout_versions FORCE ROW LEVEL SECURITY;

CREATE POLICY org_isolation ON public.canary_rollout_versions USING ((org_id = (NULLIF(current_setting('app.current_org'::text, true), ''::text))::uuid)) WITH CHECK ((org_id = (NULLIF(current_setting('app.current_org'::text, true), ''::text))::uuid));

CREATE UNIQUE INDEX ux_canary_rollouts_org_name ON public.canary_rollouts USING btree (org_id, name);

CREATE UNIQUE INDEX ux_canary_rollout_versions_rollout_version ON public.canary_rollout_versions USING btree (rollout_id, version);

CREATE TRIGGER set_canary_rollouts_updated_at BEFORE UPDATE ON public.canary_rollouts FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

ALTER TABLE ONLY public.canary_rollouts
    ADD CONSTRAINT canary_rollouts_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.canary_rollout_versions
    ADD CONSTRAINT canary_rollout_versions_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.canary_rollout_versions
    ADD CONSTRAINT canary_rollout_versions_rollout_id_fkey FOREIGN KEY (rollout_id) REFERENCES public.canary_rollouts(id) ON DELETE CASCADE;
