-- Reverse of 0002_tool_policies_org_isolation.up.sql: drop the org_isolation
-- policy and the RLS posture on tool_policies (app-level `WHERE org_id`
-- scoping remains the isolation layer).

DROP POLICY IF EXISTS org_isolation ON public.tool_policies;

ALTER TABLE public.tool_policies NO FORCE ROW LEVEL SECURITY;

ALTER TABLE public.tool_policies DISABLE ROW LEVEL SECURITY;
