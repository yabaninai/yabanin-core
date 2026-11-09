-- expand-contract: expand — approval_operations: durable tool-approval operation store (N05-P04-T02).
-- N05-P04-T02: durable approval operations (packet «Durable подтверждения
-- через UI и API»), composing the frozen pkg/agentloop ApprovalSPI contract.
--
-- Persists the operation ID plus the five-state approval vocabulary of
-- agentloop.ApprovalState (pending/approved/rejected/expired/cancelled,
-- spi.go:523-544) and the exact invocation binding (subject + authenticated
-- initiator kind, server, tool, canonical-JSON args digest, policy ref) as
-- immutable columns; expires_at is the absolute deadline persisted with the
-- request so TTL enforcement survives restart and HA failover (I59; zero-TTL
-- default 15 min lives in the store, not the schema). Nothing existing
-- changes: tool_policies stays allow/deny (widening the action vocabulary is
-- a later packet card), jit_access is untouched. Approver permission/eligibility
-- (N05-P04-T03) and the UI/API decision surfaces (N05-P04-T06) build on this
-- table; access control stays at the service layer, as for jit_access.
--
-- The decision triple (outcome, approver, decided_at) exists exactly on
-- decided rows (outcome = state); pending/expired/cancelled carry no
-- fabricated human decision (enforced by approval_operations_decision_shape).

CREATE TABLE approval_operations (
    id uuid PRIMARY KEY,
    operation_id text NOT NULL,
    org_id uuid NOT NULL REFERENCES organizations(id),
    project_id text NOT NULL DEFAULT '',
    step_index integer NOT NULL DEFAULT 0,
    turn_id text NOT NULL DEFAULT '',
    initiator text NOT NULL,
    initiator_kind text NOT NULL CHECK (initiator_kind IN ('human', 'agent', 'service', 'ci')),
    server_name text NOT NULL,
    tool_name text NOT NULL,
    args_digest text NOT NULL,
    policy_ref text NOT NULL DEFAULT '',
    ttl_secs double precision NOT NULL CHECK (ttl_secs >= 0),
    requires_different_human boolean NOT NULL DEFAULT false,
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'approved', 'rejected', 'expired', 'cancelled')),
    outcome text,
    approver text,
    decided_at timestamptz,
    recheck_required boolean NOT NULL DEFAULT false,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    -- A decision exists exactly as its full triple on decided rows;
    -- pending/expired/cancelled carry no fabricated human decision.
    CONSTRAINT approval_operations_decision_shape CHECK (
        (state IN ('approved', 'rejected')
             AND outcome = state AND approver IS NOT NULL AND decided_at IS NOT NULL)
        OR (state IN ('pending', 'expired', 'cancelled')
             AND outcome IS NULL AND approver IS NULL AND decided_at IS NULL)
    )
);

CREATE INDEX approval_operations_operation_id_idx
    ON approval_operations (operation_id);

CREATE INDEX approval_operations_pending_expiry_idx
    ON approval_operations (expires_at)
    WHERE state = 'pending';
