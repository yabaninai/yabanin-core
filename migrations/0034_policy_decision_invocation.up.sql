-- expand-contract: expand — durable policy-decision identity, expand arm:
-- policy_decisions rows record the invocation they were produced for.
--
-- The duplicate-enrichment probe (org_id, request_id) alone cannot tell a
-- mirror decision from its primary's: a primary and its shadow mirror may
-- share both org_id and request_id (0028 invocation identity), so whichever
-- delivery materialized first suppressed the other's decision row. The new
-- column becomes part of the probe (writer lands with this migration), so
-- a mirror decision persists even when the primary's decision is already
-- present, and vice versa.
--
-- Legacy treatment: NOT NULL DEFAULT ''. Rows written before this column
-- exist stay unbound; a bound probe never matches them, so a legacy request
-- replayed after the upgrade records one freshly bound decision row. The
-- bounded duplicate row is the migration cost; request_logs and settlement
-- identity are untouched. The column is additive: explicit reader SELECT
-- lists are unaffected.
--
-- Scope: this preview assumes a clean install; the column is also safe in
-- place on an existing installation.

ALTER TABLE public.policy_decisions
    ADD COLUMN invocation_id text NOT NULL DEFAULT '';
