-- expand-contract: contract — replaces expand 0028_request_invocations;
-- removes the superseded settlement_jobs_charge_key constraint and the
-- original global credit-usage index whose replacement domains shipped in
-- 0028 (uniq_settlement_jobs_request_legacy over the NULL-invocation domain
-- keeps the exact legacy (org_id, request_id, charge_kind) semantics;
-- uniq_credit_transactions_usage_legacy keeps the global-on-request_id
-- semantics for legacy rows while invocation rows dedupe on
-- uniq_credit_transactions_invocation). Structure-only removals: no rows
-- are touched, and the interim overlap period failed loudly instead of
-- silently suppressing a charge.
--
-- Compatibility note for rolling deploys: old code using the bare
-- `ON CONFLICT (org_id, request_id, charge_kind)` arbiter must be retired
-- from service before this contract runs (the partial replacement needs the
-- `WHERE invocation_id IS NULL` inference clause); the credit-side bare
-- `ON CONFLICT (request_id) WHERE request_id IS NOT NULL AND type='usage'`
-- arbiter needs `AND invocation_id IS NULL` added likewise. Deploy the
-- expand with the new writers, then contract during the same release's
-- migration run once the old writer fleet is drained.

ALTER TABLE public.settlement_jobs DROP CONSTRAINT settlement_jobs_charge_key;

DROP INDEX public.uniq_credit_transactions_usage_request_id;
