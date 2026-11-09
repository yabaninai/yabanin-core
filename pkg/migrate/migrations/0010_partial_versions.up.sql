CREATE TABLE public.partial_versions (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    org_id uuid NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    partial_id uuid NOT NULL REFERENCES public.partials(id) ON DELETE CASCADE,
    version integer NOT NULL CHECK (version >= 1),
    body text NOT NULL CHECK (body <> ''),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (partial_id, version)
);

INSERT INTO public.partial_versions (org_id, partial_id, version, body)
SELECT org_id, id, version, body FROM public.partials;

ALTER TABLE public.partial_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.partial_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON public.partial_versions
    USING (org_id = NULLIF(current_setting('app.current_org', true), '')::uuid)
    WITH CHECK (org_id = NULLIF(current_setting('app.current_org', true), '')::uuid);
