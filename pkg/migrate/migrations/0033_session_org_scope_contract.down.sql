-- Contract for 0033_session_org_scope_contract: restores the bare
-- client_session conflict target. Run this only together with retired
-- 0033 writers (the org-scoped constraint from 0032 must be present for
-- same-org replays to stay unambiguous).

ALTER TABLE public.sessions
    ADD CONSTRAINT sessions_client_session_key UNIQUE (client_session);
