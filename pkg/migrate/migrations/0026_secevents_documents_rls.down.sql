-- Reverse of 0026_secevents_documents_rls.up.sql: the org_isolation policy and
-- the RLS posture are removed (structural reverse, no data transformation —
-- W04-readpath-decision.md §5.1 down side, verbatim). The pre-0026 posture
-- returns: no production reader exists under RLS, org isolation relies on the
-- org key in every query; no event documents are touched.
DROP POLICY org_isolation ON public.secevents_documents;
ALTER TABLE public.secevents_documents NO FORCE ROW LEVEL SECURITY;
ALTER TABLE public.secevents_documents DISABLE ROW LEVEL SECURITY;
