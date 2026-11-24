-- expand-contract: expand — tenant-safe session attribution, expand arm:
-- adds the org-scoped registry conflict target alongside the legacy one.
--
-- Before this change, two orgs in the same permitted region delivering the
-- same X-Session-Id value resolved onto ONE registry row: the second org's
-- deliveries updated the first org's row (updated_at churn with no
-- attribution of their own) and stored the foreign org's session id in
-- their request_logs rows. The sessions RLS posture is region isolation
-- only (app.region), so it never separated tenants here; the separation is
-- now enforced by the conflict target itself.
--
-- Expand arm: UNIQUE (org_id, client_session) is implied by the existing
-- UNIQUE (client_session), so both constraints coexist for every possible
-- row, no backfill or rewrite is needed, and existing row ids are
-- unchanged. The matching contract arm (0033) drops the legacy constraint
-- once 0032 writers and probes are the only ones left.

ALTER TABLE public.sessions
    ADD CONSTRAINT sessions_org_client_session_key UNIQUE (org_id, client_session);
