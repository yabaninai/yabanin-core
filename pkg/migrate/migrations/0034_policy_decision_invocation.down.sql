-- Contract for 0034_policy_decision_invocation: drops the decision
-- identity column. Mirror decisions written while the column existed lose
-- their durable identity; run this only together with retired 0034
-- writers and probes.

ALTER TABLE public.policy_decisions
    DROP COLUMN invocation_id;
