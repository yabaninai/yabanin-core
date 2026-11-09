-- 0012_sso_group_role_rules — N04-P01: SSO group → local-role mapping.
--
-- sso_group_role_rules is the ORG-LEVEL DECLARED rule set: per organization,
-- one row per (IdP group, effect). effect 'grant' maps the group onto exactly
-- one local admin role; effect 'deny' blocks mapping grants for holders of
-- that group. Resolution (deny-wins) lives in pkg/adminstore.ResolveSSORole;
-- the rules are applied at every SSO login by services/admin/handlers.
--
-- sso_role_grants is the mapping PROVENANCE: the (org, user) pairs whose
-- current membership role was granted by the group mapping. Only these rows
-- are revocable by a later sync (rule removed / groups changed / deny rule
-- matched) — memberships an admin granted directly never carry a provenance
-- row and are never touched by the mapping.
--
-- ISOLATION POSTURE — NO RLS, org predicate in every query (same rationale as
-- the scim_tokens/scim_identities tables folded into migration 0001): the
-- SSO login path resolves the caller BEFORE any org context exists, so an
-- app.current_org-gated RLS policy (which hides every row while the GUC is
-- unset) would make the mapping silently inert at login. The explicit
-- `org_id = $n` predicate in EVERY store query is the isolation layer; the
-- handler and store tests assert cross-org isolation.

CREATE TABLE sso_group_role_rules (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id uuid NOT NULL,
    group_name text NOT NULL CHECK (group_name <> '' AND char_length(group_name) <= 256),
    effect text NOT NULL CHECK (effect IN ('grant', 'deny')),
    role text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    -- effect consistency: a grant names exactly one local role, a deny never does.
    CONSTRAINT sso_group_role_rules_role_check CHECK (
        (effect = 'grant' AND role IS NOT NULL) OR (effect = 'deny' AND role IS NULL)
    ),
    -- one rule per (org, group, effect): a group grants at most one role and
    -- may additionally carry a deny entry (which wins at resolution time).
    CONSTRAINT sso_group_role_rules_org_group_effect_key UNIQUE (org_id, group_name, effect),
    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
);

CREATE INDEX idx_sso_group_role_rules_org ON sso_group_role_rules (org_id);

CREATE TABLE sso_role_grants (
    org_id uuid NOT NULL,
    user_id uuid NOT NULL,
    role text NOT NULL,
    granted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id),
    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES admin_users(id) ON DELETE CASCADE
);
