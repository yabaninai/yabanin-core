-- 0029_request_invocations_contract (down): restore the pre-0028 keys the
-- contract removed. Run BEFORE 0028's down (which then drops the
-- replacement indexes and identity columns).

ALTER TABLE public.settlement_jobs ADD CONSTRAINT settlement_jobs_charge_key
    UNIQUE (org_id, request_id, charge_kind);

CREATE UNIQUE INDEX uniq_credit_transactions_usage_request_id
    ON public.credit_transactions (request_id)
    WHERE ((request_id IS NOT NULL) AND (type = 'usage'::text));
