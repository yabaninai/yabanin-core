-- 0030_tool_fact_invocations (down): remove the additive tool-fact identity
-- shape. Invocation-bearing rows lose their identity column (and with it the
-- invocation-domain arbiters); legacy NULL-domain rows and their semantics
-- were never touched by the up, and 0001's own indexes on these tables
-- (idx_tool_calls_request, idx_tool_calls_org_tool, idx_tool_calls_created,
-- idx_tool_call_invocations_request, idx_tool_call_invocations_org) survive
-- untouched — this down only drops what 0030 created.

DROP INDEX IF EXISTS public.uniq_tool_call_invocations_occurrence;
DROP INDEX IF EXISTS public.uniq_tool_calls_invocation;

ALTER TABLE public.tool_call_invocations DROP COLUMN IF EXISTS invocation_id;
ALTER TABLE public.tool_calls DROP COLUMN IF EXISTS invocation_id;
