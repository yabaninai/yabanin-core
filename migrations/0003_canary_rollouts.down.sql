-- R106-02 down: drop the versioned canary rollout tables (children first —
-- the explicit order keeps the down path honest even though the FKs CASCADE).

DROP TABLE IF EXISTS public.canary_rollout_versions CASCADE;

DROP TABLE IF EXISTS public.canary_rollouts CASCADE;
