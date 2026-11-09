CREATE TABLE request_payload_grants (
    id uuid PRIMARY KEY,
    token_hash bytea NOT NULL UNIQUE,
    grantor_root uuid NOT NULL REFERENCES admin_users(id),
    grantee uuid NOT NULL REFERENCES admin_users(id),
    org_id uuid NOT NULL REFERENCES organizations(id),
    request_id text,
    scope text NOT NULL CHECK (scope IN ('payload.read', 'payload.read_originals')),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (expires_at > created_at)
);

CREATE INDEX request_payload_grants_active_idx
    ON request_payload_grants (grantee, org_id, expires_at)
    WHERE revoked_at IS NULL AND consumed_at IS NULL;
