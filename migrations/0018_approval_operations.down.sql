-- Reverse of 0018_approval_operations.up.sql: drops the durable approval
-- operation store (N05-P04-T02 foundations). Pending approvals created
-- before the downgrade are lost with the table — it is the only record of
-- them; existing allow/deny policy and invocation paths are unaffected
-- (nothing in the pre-0018 schema or code reads this table).
DROP INDEX IF EXISTS approval_operations_pending_expiry_idx;
DROP INDEX IF EXISTS approval_operations_operation_id_idx;
DROP TABLE IF EXISTS approval_operations;
