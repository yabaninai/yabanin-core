-- Reverse of 0015: drop the schema-level TTL bound (the Go-side
-- MaxPrincipalDelegationTTL check stays regardless).
ALTER TABLE principal_delegations
    DROP CONSTRAINT IF EXISTS principal_delegations_ttl_bound_check;
