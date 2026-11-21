-- 0028_request_invocations (down): remove the additive identity shape.
-- Applied after 0029's down has restored the superseded keys, this drops
-- only what the expand created (0029 checks the contract order).

DROP INDEX IF EXISTS public.uniq_credit_transactions_invocation;
DROP INDEX IF EXISTS public.uniq_credit_transactions_usage_legacy;
ALTER TABLE public.credit_transactions DROP COLUMN IF EXISTS invocation_id;

DROP INDEX IF EXISTS public.uniq_settlement_jobs_request_legacy;
DROP INDEX IF EXISTS public.uniq_settlement_jobs_invocation;
ALTER TABLE public.settlement_jobs DROP COLUMN IF EXISTS invocation_id;

DROP INDEX IF EXISTS public.uniq_request_logs_invocation;
ALTER TABLE public.request_logs DROP COLUMN IF EXISTS invocation_id;

DROP TABLE IF EXISTS public.request_terminal_facts;
DROP TABLE IF EXISTS public.request_admissions;
