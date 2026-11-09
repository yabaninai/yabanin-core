-- N04-P05 T07 (RV-n04p5c): harden the delegation TTL bound in the schema
-- itself. The store already refuses TTL > 30 days (MaxPrincipalDelegationTTL,
-- checked in CreatePrincipalDelegation); this CHECK makes the bound durable
-- against any future writer that bypasses the store (manual psql, ETL, a
-- regressions in another service sharing the database).
--
-- Existing rows are unaffected: every row so far was written through the
-- bounded Go path, so all of them already satisfy expires_at <= created_at +
-- interval '30 days'. The CHECK pairs with 0014's (expires_at > created_at)
-- to pin the whole lifetime envelope: 0 < expires_at - created_at <= 30 days.

ALTER TABLE principal_delegations
    ADD CONSTRAINT principal_delegations_ttl_bound_check
    CHECK (expires_at <= created_at + interval '30 days');
