-- 0013_guard_pack_state — N02-P02/P04/P08: durable guard detector-pack policy state.
--
-- guard_pack_state is the DEPLOYMENT-GLOBAL activation record for guard
-- detector packs: exactly one row (id = 1, pinned by CHECK). It is written
-- ONLY through the compare-and-swap in pkg/policystore (GuardPolicyCAS:
-- INSERT .. ON CONFLICT (id) DO UPDATE .. WHERE active_version = expected),
-- so two replicas racing on one activation produce exactly one winner and
-- the loser reads the winner's version from this row — the durable side of
-- the guardhooks.PolicyVersionCAS port (the gateway-local no-op CAS remains
-- the startup-wiring default; this row is the coordination point the admin
-- API and multi-replica activations go through).
--
-- ISOLATION POSTURE — NO RLS (0011/sso rationale): the row has no org
-- dimension. It is one deployment's active guard policy, mutated only by the
-- root-only admin API (services/admin/handlers guard-pack routes) and read
-- by the deployment's own gateway replicas; an app.current_org RLS policy
-- would make the row silently invisible to exactly the replicas that need
-- it. Access control lives at the caller (root gate + audit journal).
--
-- previous_version mirrors the lifecycle's rollback target: every CAS win
-- moves the old active_version into previous_version, so an operator (or a
-- future replica resync) can always see the last known-good version.

CREATE TABLE guard_pack_state (
    id integer PRIMARY KEY CHECK (id = 1),
    active_version text NOT NULL,
    previous_version text NOT NULL DEFAULT '',
    updated_by text NOT NULL DEFAULT '',
    updated_at timestamptz NOT NULL DEFAULT now()
);
