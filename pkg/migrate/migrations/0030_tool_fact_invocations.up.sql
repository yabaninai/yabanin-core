-- expand-contract: expand — per-invocation identity on the retained tool
-- facts: invocation_id columns on tool_calls (distinct retained names) and
-- tool_call_invocations (per-occurrence rows), with the invocation-domain
-- unique arbiters that make a redelivery or recovery replay of one
-- invocation idempotent for these children.
--
-- Design:
--   * New invocation-bearing retained tool names and occurrences carry the
--     minted invocation_id of the response they were extracted from
--     (0028 identity). The legacy domain keeps NULL invocation_id rows and
--     their exact previous semantics: no legacy-side unique is introduced,
--     so legacy redelivery behavior — dedupe by the delivery inbox, the
--     request-scoped enrichment probe — is unchanged.
--   * Two legitimate invocations from one org that share a client-supplied
--     X-Request-ID (0028) keep independent tool facts: the arbiters key on
--     (org_id, request_id, invocation_id, tool_name) and
--     (org_id, request_id, invocation_id, seq), so the second invocation
--     inserts its own rows while a redelivery of either is a no-op.
--   * Linkage is never guessed: the writer binds invocation_id only from
--     the delivery's own invocation identity (absent key → NULL → legacy
--     domain); nothing backfills, correlates across request_id, or infers
--     an invocation from a sibling row.
--   * Retention stays protected: rows are only written when the org
--     original-retention resolution retained the upstream response sample
--     (the extraction source), and the arguments column keeps its capture
--     cap. This migration only adds shape; it writes no rows and changes
--     no reader output — existing queries see one added nullable column.
--
-- Index reuse (no new plain indexes): the enrichment probes stay served by
-- existing shapes — the legacy request-scoped probe by 0001's
-- idx_tool_calls_request (request_id), the invocation-scoped probe by the
-- new arbiter's (org_id, request_id, invocation_id) prefix. Reader-side
-- access paths beyond these are deliberately NOT added here; the reader
-- surface ships separately with its own measured needs.
--
-- Interim posture: readers that SELECT these tables under star or explicit
-- column lists are unaffected; no shipped query filters or projects
-- invocation_id on these tables yet (the reader surface ships separately).

ALTER TABLE public.tool_calls ADD COLUMN invocation_id uuid;
ALTER TABLE public.tool_call_invocations ADD COLUMN invocation_id uuid;

CREATE UNIQUE INDEX uniq_tool_calls_invocation
    ON public.tool_calls (org_id, request_id, invocation_id, tool_name)
    WHERE invocation_id IS NOT NULL;

CREATE UNIQUE INDEX uniq_tool_call_invocations_occurrence
    ON public.tool_call_invocations (org_id, request_id, invocation_id, seq)
    WHERE invocation_id IS NOT NULL;
