-- expand-contract: expand — one-request payload grants bind to one physical
-- request_logs row. The request_id column stays (it is the redemption
-- correlation the caller presents); request_row_key pins the immutable row
-- resolved at issuance, so a correlation two legitimate invocations may
-- share (0028) can never retarget or widen a grant, and a row replaced
-- after issuance leaves the grant addressing a gone row (deny, no burn)
-- rather than the replacement.
--
-- Legacy treatment is deliberately conservative: NO backfill. A grant whose
-- row key is NULL predates binding and its original row is not provable
-- (the sole present carrier may itself postdate the grant), so it stays
-- NULL and is permanently unusable at redemption — deny fail-closed, token
-- not burned; the root re-issues against the now-bound path. Ordinary
-- read/export of legacy history is unchanged: only bearer-grant redemption
-- of pre-binding grants denies.
--
-- Scope: this preview assumes a clean install. The guarantee is a
-- new-reader guarantee from 0031 onward: grants issued by 0031+ writers are
-- bound to exactly one physical row at issuance, and 0031+ readers (peek +
-- keyed consume) never redeem a grant without a bound row key. No
-- rolling-upgrade protection is claimed: a predecessor binary's consume
-- UPDATE carries no request_row_key predicate and would redeem an unbound
-- grant.

ALTER TABLE public.request_payload_grants
    ADD COLUMN request_row_key bigint;
