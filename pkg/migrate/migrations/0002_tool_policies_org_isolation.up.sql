-- R035-02 (G4, D5 default): tool_policies org_isolation RLS — tenant-boundary
-- parity with the R034 credential tables (mcp_server_credentials,
-- mcp_user_credentials) and policy_decisions. A session not bound to an org
-- (app.current_org unset or empty) sees no rows and cannot write across the
-- tenant boundary (fail closed); application sessions bind the GUC
-- transaction-locally (pkg/toolpolicy Store.withOrgTx, the adminstore
-- withOrgTx parity). FORCE binds the (non-superuser) table owner too.
-- tool_policies is NOT a seed-path table, so the R059 clean-install seed
-- bootstrap is unaffected.

ALTER TABLE public.tool_policies ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.tool_policies FORCE ROW LEVEL SECURITY;

CREATE POLICY org_isolation ON public.tool_policies USING ((org_id = (NULLIF(current_setting('app.current_org'::text, true), ''::text))::uuid)) WITH CHECK ((org_id = (NULLIF(current_setting('app.current_org'::text, true), ''::text))::uuid));
