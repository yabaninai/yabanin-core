-- N04-P05 T03: scoped principal delegation chain (human → agent/CI subject).
--
-- Creating an agent key authenticates a principal but grants nothing: access
-- exists only while a live delegation row — not revoked, unexpired, covering
-- the exact permission — backs the subject, AND the grantor still holds the
-- delegated permission at evaluation time (membership/root re-checked per
-- evaluation, so demotion or removal of the delegator cascades immediately).
--
-- Provenance (who delegated what to whom) is the row itself: grantor_type +
-- grantor_id → subject_type + subject_id + permission subset, revocable.

CREATE TABLE principal_delegations (
    id uuid PRIMARY KEY,
    org_id uuid NOT NULL REFERENCES organizations(id),
    grantor_type text NOT NULL CHECK (grantor_type IN ('admin', 'root')),
    grantor_id uuid NOT NULL REFERENCES admin_users(id),
    subject_type text NOT NULL CHECK (subject_type IN ('agent', 'ci')),
    subject_id uuid NOT NULL REFERENCES agent_keys(id),
    permissions text[] NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    CHECK (expires_at > created_at)
);

CREATE INDEX principal_delegations_subject_idx
    ON principal_delegations (org_id, subject_id, expires_at)
    WHERE revoked_at IS NULL;
