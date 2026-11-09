-- expand-contract: expand — security inbox incidents table (E06-P01 W01-C02):
-- the unified inbox's own state, org-scoped by the house RLS pattern
-- (0001_init.up.sql:5712 form: uuid org_id compared against the
-- app.current_org GUC through NULLIF(...)::uuid — empty/unbound GUC casts
-- to NULL and matches nothing, fail-closed like 0026's TEXT variant). FORCE
-- ROW LEVEL SECURITY follows the 0026/W04-readpath-decision §5.1 precedent:
-- the only owner is the migration role, never the application. The store
-- (pkg/inbox store.go) pins the GUC in the same transaction as its
-- statements; superuser/RLS-exempt sessions skip the inert pin (same law as
-- the secevents writer). status/severity/confidence dictionaries are pinned
-- by CHECK constraints here — this is the packet's only inbox migration, and
-- the vocabularies are fixed by the card table (severity low|medium|high per
-- pkg/pipeline/builtins/params.go:12, status machine per W04-C01). The
-- (org_id, last_seen DESC, id) index serves the keyset pagination order
-- (W05-C02 lands later, but migrations end at 0027 in this packet).
CREATE TABLE public.security_inbox (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id uuid NOT NULL,
    group_key text NOT NULL,
    summary text DEFAULT ''::text NOT NULL,
    severity text NOT NULL,
    confidence double precision NOT NULL,
    status text DEFAULT 'new'::text NOT NULL,
    assignee uuid,
    first_seen timestamp with time zone NOT NULL,
    last_seen timestamp with time zone NOT NULL,
    event_count bigint DEFAULT 1 NOT NULL,
    first_event_id text NOT NULL,
    last_event_id text NOT NULL,
    evidence jsonb DEFAULT '[]'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT security_inbox_pkey PRIMARY KEY (id),
    CONSTRAINT security_inbox_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE,
    CONSTRAINT security_inbox_org_group_key_key UNIQUE (org_id, group_key),
    CONSTRAINT security_inbox_severity_dict CHECK (severity = ANY (ARRAY['low'::text, 'medium'::text, 'high'::text])),
    CONSTRAINT security_inbox_confidence_range CHECK ((confidence >= (0)::double precision) AND (confidence <= (1)::double precision)),
    CONSTRAINT security_inbox_status_dict CHECK (status = ANY (ARRAY['new'::text, 'acknowledged'::text, 'in_progress'::text, 'resolved'::text, 'dismissed'::text]))
);
ALTER TABLE public.security_inbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_inbox FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON public.security_inbox
  USING (org_id = (NULLIF(current_setting('app.current_org', true), ''))::uuid)
  WITH CHECK (org_id = (NULLIF(current_setting('app.current_org', true), ''))::uuid);
CREATE INDEX security_inbox_org_last_seen_id_idx ON public.security_inbox USING btree (org_id, last_seen DESC, id);
