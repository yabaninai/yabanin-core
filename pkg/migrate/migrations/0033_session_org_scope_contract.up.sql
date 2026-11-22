-- expand-contract: contract — replaces expand 0032_session_org_scope;
-- removes the superseded bare client_session conflict target whose
-- org-scoped replacement domain shipped in 0032. UNIQUE (org_id,
-- client_session) is implied by UNIQUE (client_session) for every possible
-- row, so the legacy constraint is redundant from the moment the expand
-- arm exists: dropping it retires the last cross-org resolution path.
-- Same-org replays keep resolving through the scoped arbiter and keep
-- their original row ids.
--
-- Scope: this preview assumes a clean install; the drop is also safe in
-- place on an existing installation once 0032 writers are the only ones.

ALTER TABLE public.sessions
    DROP CONSTRAINT sessions_client_session_key;
