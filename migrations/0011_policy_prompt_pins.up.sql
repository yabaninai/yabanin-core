CREATE TABLE policy_prompt_pins (
    org_id uuid NOT NULL,
    policy_id uuid NOT NULL,
    policy_version integer NOT NULL,
    ref text NOT NULL,
    prompt_version text NOT NULL,
    body text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, policy_id, policy_version, ref),
    FOREIGN KEY (policy_id) REFERENCES policy_pipelines(id) ON DELETE CASCADE,
    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
);
ALTER TABLE policy_prompt_pins ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_prompt_pins FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON policy_prompt_pins
    USING (org_id = NULLIF(current_setting('app.current_org', true), '')::uuid)
    WITH CHECK (org_id = NULLIF(current_setting('app.current_org', true), '')::uuid);
