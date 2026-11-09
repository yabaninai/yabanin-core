CREATE TABLE revoked_admin_sessions (
    session_id TEXT PRIMARY KEY,
    revoked_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
