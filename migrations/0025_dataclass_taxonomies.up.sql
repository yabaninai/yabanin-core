-- expand-contract: expand — org-scoped classification taxonomies: the persistent home of pkg/dataclass taxonomies.
-- 0025_dataclass_taxonomies (E04-P01 W02-C02): one org-scoped contextual
-- classification taxonomy row per organization. Numbering per dispatch
-- E04-P01 §8 (orchestrator decision D-R1a): 0022 = E02-P01 inventory,
-- 0023/0024 = imp-ebetaplan3a pins (0023 released-unused permanent gap,
-- 0024 fleet_registry gated on E03-P01), 0025 = this migration.
-- Posture: house-RLS org_isolation per the 0001_init pattern (uuid org_id,
-- NULLIF(current_setting('app.current_org')) binding) — deliberately the
-- 0001 posture, not the 0021/0022 no-RLS expand posture: this table is an
-- org-isolated admin-owned document (E01-P04 mapping, dispatch §9).
-- Expand-only: a new table, no existing object is touched; readers land
-- with later cards of the packet.

CREATE TABLE public.dataclass_taxonomies (
    org_id     uuid        NOT NULL,
    version    bigint      NOT NULL DEFAULT 1,
    labels     jsonb       NOT NULL DEFAULT '[]'::jsonb,
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by text        NOT NULL DEFAULT '',
    PRIMARY KEY (org_id)
);

ALTER TABLE public.dataclass_taxonomies ENABLE ROW LEVEL SECURITY;

CREATE POLICY org_isolation ON public.dataclass_taxonomies USING ((org_id = (NULLIF(current_setting('app.current_org'::text, true), ''::text))::uuid)) WITH CHECK ((org_id = (NULLIF(current_setting('app.current_org'::text, true), ''::text))::uuid));
