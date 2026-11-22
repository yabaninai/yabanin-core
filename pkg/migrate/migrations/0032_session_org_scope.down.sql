-- Contract for 0032_session_org_scope: drops the org-scoped registry
-- conflict target. Cross-org rows written under it violate the restored
-- bare constraint; run this only together with retired 0032 writers.

ALTER TABLE public.sessions
    DROP CONSTRAINT sessions_org_client_session_key;
