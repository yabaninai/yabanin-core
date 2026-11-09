package adminstore

import (
	"context"
	"errors"
	"fmt"
)

// Delegation budget invariant (AUDIT-P1-03): a delegated child key's daily
// cap may never exceed the parent's remaining headroom
//
//	headroom = parent_limit − parent_spend_today − Σ(active, non-expired child caps)
//
// and the parent MUST have a budget row (a child cannot be capped wider than
// a parent that has no cap at all). This file enforces that invariant
// ATOMICALLY at delegation time — the child key row and its agent_budgets
// enforcement row are written in ONE transaction that first takes
//
//	pg_advisory_xact_lock(hashtext(org))
//
// — the same advisory key family as the gateway money writers
// (pkg/budget/reservations.go) — and then locks the parent's agent_budgets
// row FOR UPDATE (lock-then-read). Two concurrent delegations on the same
// parent therefore serialize, and the second one recomputes the child-cap
// sum after the first committed: exactly-one-wins under READ COMMITTED.
//
// The runtime backstops are independent: the AgentEnforcer (pkg/budget)
// denies a child whose ancestor subtree spend has exhausted the parent cap,
// and the reservation escrow bounds grants by the parent subtree headroom.
// Delegation-time enforcement keeps the PROMISE honest (the sum of caps can
// never exceed what the parent can still fund); spend-time enforcement keeps
// the REALITY bounded even for rows created before this gate.

var (
	// ErrDelegationHeadroomExceeded reports a requested child cap that does
	// not fit under the parent's remaining headroom. The wrapped message
	// carries the requested cap, the parent limit and the committed amounts.
	ErrDelegationHeadroomExceeded = errors.New("delegated daily limit exceeds the parent's remaining headroom")
	// ErrParentBudgetMissing reports a parent agent without an agent_budgets
	// row: no child cap can be justified (fail-closed).
	ErrParentBudgetMissing = errors.New("parent agent has no daily budget configured")
	// ErrParentNotDelegable reports a parent key row that vanished / was
	// revoked / moved org / is itself a child between the handler's
	// pre-checks and the transaction (defense in depth; the handler normally
	// rejects first).
	ErrParentNotDelegable = errors.New("parent agent key is not delegable")
)

// delegationBudgetStoreExtra is the capability surface for the checked
// delegation-budget methods (type-asserted like CASStore — handlers.Keep
// DelegationBudgetStore).
type delegationBudgetStoreExtra interface {
	CreateAgentKeyDelegatedChecked(ctx context.Context, p AgentKeyCreateParams) (*AgentKey, error)
	UpsertAgentBudgetChecked(ctx context.Context, agentID string, dailyLimitCents int64) (*AgentBudget, error)
	UpsertAgentBudgetPreconditionedChecked(ctx context.Context, agentID string, dailyLimitCents int64, expect *AgentBudgetExpectation) (*AgentBudget, error)
}

// compile-time: the real store implements the capability.
var _ delegationBudgetStoreExtra = (*Store)(nil)

// CreateAgentKeyDelegatedChecked is the delegation-create path with the
// parent-headroom invariant enforced inside the same transaction that
// inserts the child key AND its agent_budgets row. Params without a cap
// (ParentID nil or DailyLimitCents nil/<=0) fall through to the legacy
// insert — a cap-less child has nothing to enforce and is denied at spend
// time anyway (no budget row ⇒ fail-closed).
func (s *Store) CreateAgentKeyDelegatedChecked(ctx context.Context, p AgentKeyCreateParams) (*AgentKey, error) {
	if p.ParentID == nil || p.DailyLimitCents == nil || *p.DailyLimitCents <= 0 {
		return s.CreateAgentKeyDelegated(ctx, p)
	}
	childCap := *p.DailyLimitCents

	tx, err := s.beginDelegationBudgetTx(ctx, p.OrgID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Defense in depth: re-validate the parent inside the tx (the handler
	// checked existence/active/root/org before calling; a concurrent revoke
	// or move must not slip a cap past a dead parent).
	parentID, err := validateDelegationParentTx(ctx, tx, *p.ParentID, p.OrgID)
	if err != nil {
		return nil, err
	}

	// Lock-then-read the parent budget row: this is the serialization point
	// for concurrent delegations on the same parent.
	limit, headroom, err := parentHeadroomCentsTx(ctx, tx, parentID, "")
	if err != nil {
		return nil, err
	}
	if childCap > headroom {
		return nil, fmt.Errorf("%w: cap %d > parent limit %d minus committed amounts (%d left)",
			ErrDelegationHeadroomExceeded, childCap, limit, headroom)
	}

	// Insert the child key row (same columns/semantics as the legacy insert).
	k, err := scanAgentKey(tx.QueryRow(ctx,
		`INSERT INTO agent_keys (key_hash, org_id, name, active, parent_id, expires_at, daily_limit_cents)
		 VALUES ($1, $2, $3, true, $4, $5, $6)
		 RETURNING `+agentKeyCols,
		p.KeyHash, p.OrgID, p.Name, p.ParentID, p.ExpiresAt, p.DailyLimitCents))
	if err != nil {
		return nil, fmt.Errorf("create agent key: %w", err)
	}

	// ... and its enforcement row, atomically.
	if _, err := tx.Exec(ctx,
		`INSERT INTO agent_budgets (agent_id, daily_limit_cents)
		 VALUES ($1::uuid, $2)
		 ON CONFLICT (agent_id) DO UPDATE SET daily_limit_cents = $2, updated_at = now()`,
		k.ID, childCap); err != nil {
		return nil, fmt.Errorf("apply delegated budget: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit delegated key: %w", err)
	}
	return k, nil
}

// UpsertAgentBudgetChecked is the update path with the invariant enforced
// for delegated children: the new cap replaces the old one in the sibling
// sum, so shrinking one child frees headroom for another. Root keys (no
// parent_id) follow the legacy unconstrained upsert — shrinking a parent
// only tightens the family, which is fail-closed.
func (s *Store) UpsertAgentBudgetChecked(ctx context.Context, agentID string, dailyLimitCents int64) (*AgentBudget, error) {
	return s.upsertAgentBudgetChecked(ctx, agentID, dailyLimitCents, nil, false)
}

// UpsertAgentBudgetPreconditionedChecked is the AF-09 audited-rollback CAS
// under the same invariant: the compare-and-set runs INSIDE the
// headroom-checked transaction, so a stale rollback either lands exactly on
// the expected previous state or conflicts — never widens a child past the
// parent's headroom.
func (s *Store) UpsertAgentBudgetPreconditionedChecked(ctx context.Context, agentID string, dailyLimitCents int64, expect *AgentBudgetExpectation) (*AgentBudget, error) {
	if expect == nil {
		return s.UpsertAgentBudgetChecked(ctx, agentID, dailyLimitCents)
	}
	return s.upsertAgentBudgetChecked(ctx, agentID, dailyLimitCents, expect, true)
}

// upsertAgentBudgetChecked is the shared skeleton for both update variants.
// When cas is set, expect must be non-nil and the final write is the CAS
// upsert (no-returning-row ⇒ ErrPreconditionFailed with the current row).
func (s *Store) upsertAgentBudgetChecked(ctx context.Context, agentID string, dailyLimitCents int64, expect *AgentBudgetExpectation, cas bool) (*AgentBudget, error) {
	if dailyLimitCents <= 0 {
		return nil, fmt.Errorf("daily_limit_cents must be positive")
	}
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}

	// Resolve the key (org for the advisory lock, parent for the invariant).
	var orgID string
	var parentID *string
	err := s.db.QueryRow(ctx,
		`SELECT org_id::text, parent_id::text FROM agent_keys WHERE id = $1::uuid`,
		agentID).Scan(&orgID, &parentID)
	if err != nil {
		if IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("resolve agent key: %w", err)
	}

	tx, err := s.beginDelegationBudgetTx(ctx, orgID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if parentID == nil {
		// Root key: no delegation invariant applies. Same upsert as the
		// legacy path, executed inside the (already open) tx for lock
		// symmetry with the sibling branches.
		return finishAgentBudgetTx(ctx, tx, cas, expect, agentID, dailyLimitCents)
	}

	if _, err := validateDelegationParentTx(ctx, tx, *parentID, orgID); err != nil {
		return nil, err
	}

	// The child's own CURRENT cap is excluded from the sibling sum — the new
	// cap replaces it. A missing own row counts as zero.
	var ownCurrent int64
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(daily_limit_cents, 0) FROM agent_budgets WHERE agent_id = $1::uuid`,
		agentID).Scan(&ownCurrent); err != nil && !IsNotFound(err) {
		return nil, fmt.Errorf("read current budget: %w", err)
	}

	limit, headroom, err := parentHeadroomCentsTx(ctx, tx, *parentID, agentID)
	if err != nil {
		return nil, err
	}
	// Subtraction (not summation): parentSpend+childCaps can exceed the
	// limit, the difference then goes negative and any positive cap is
	// rejected — int64 subtraction of non-negative operands cannot wrap.
	if dailyLimitCents > headroom {
		return nil, fmt.Errorf("%w: cap %d > parent limit %d minus committed amounts (%d left)",
			ErrDelegationHeadroomExceeded, dailyLimitCents, limit, headroom)
	}

	return finishAgentBudgetTx(ctx, tx, cas, expect, agentID, dailyLimitCents)
}

// finishAgentBudgetTx performs the final agent_budgets write (plain or CAS)
// inside the open transaction and commits.
func finishAgentBudgetTx(ctx context.Context, tx auditTx, cas bool, expect *AgentBudgetExpectation, agentID string, dailyLimitCents int64) (*AgentBudget, error) {
	var row scanner
	if cas && expect != nil {
		if expect.Absent {
			row = tx.QueryRow(ctx,
				`INSERT INTO agent_budgets (agent_id, daily_limit_cents)
				 VALUES ($1::uuid, $2)
				 ON CONFLICT (agent_id) DO NOTHING
				 RETURNING agent_id::text, daily_limit_cents, updated_at`,
				agentID, dailyLimitCents)
		} else {
			row = tx.QueryRow(ctx,
				`INSERT INTO agent_budgets (agent_id, daily_limit_cents)
				 VALUES ($1::uuid, $2)
				 ON CONFLICT (agent_id) DO UPDATE SET daily_limit_cents = $2, updated_at = now()
				 WHERE agent_budgets.daily_limit_cents = $3
				 RETURNING agent_id::text, daily_limit_cents, updated_at`,
				agentID, dailyLimitCents, expect.DailyLimitCents)
		}
	} else {
		row = tx.QueryRow(ctx,
			`INSERT INTO agent_budgets (agent_id, daily_limit_cents)
			 VALUES ($1::uuid, $2)
			 ON CONFLICT (agent_id) DO UPDATE SET daily_limit_cents = $2, updated_at = now()
			 RETURNING agent_id::text, daily_limit_cents, updated_at`,
			agentID, dailyLimitCents)
	}

	b, err := scanAgentBudget(row)
	if err != nil {
		if cas && IsNotFound(err) {
			// CAS miss: read the current row inside the same tx for the 409.
			current, cerr := scanAgentBudget(tx.QueryRow(ctx,
				`SELECT agent_id::text, daily_limit_cents, updated_at FROM agent_budgets WHERE agent_id = $1::uuid`,
				agentID))
			if cerr != nil && !IsNotFound(cerr) {
				return nil, fmt.Errorf("read current budget: %w", cerr)
			}
			return current, ErrPreconditionFailed
		}
		return nil, fmt.Errorf("upsert agent budget: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit agent budget: %w", err)
	}
	return b, nil
}

// beginDelegationBudgetTx opens the advisory-locked transaction shared by
// the delegation create/update paths. The lock key (hashtext of the org) is
// the SAME expression the gateway money writers use (see
// pkg/budget/reservations.go), so delegation mutations and reservation
// grants for one org never interleave.
func (s *Store) beginDelegationBudgetTx(ctx context.Context, orgID string) (auditTx, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}
	tx, err := s.db.BeginAuditTx(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin delegation tx: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, orgID); err != nil {
		_ = tx.Rollback(ctx)
		return nil, fmt.Errorf("lock delegation tx: %w", err)
	}
	return tx, nil
}

// validateDelegationParentTx re-checks, inside the transaction, that the
// parent key exists, is active, is a root and belongs to orgID. Returns the
// verified parent ID.
func validateDelegationParentTx(ctx context.Context, tx auditTx, parentID, orgID string) (string, error) {
	var rowOrg string
	var rowActive bool
	var rowParent *string
	err := tx.QueryRow(ctx,
		`SELECT org_id::text, active, parent_id::text FROM agent_keys WHERE id = $1::uuid`,
		parentID).Scan(&rowOrg, &rowActive, &rowParent)
	if err != nil {
		if IsNotFound(err) {
			return "", fmt.Errorf("%w: parent %s not found", ErrParentNotDelegable, parentID)
		}
		return "", fmt.Errorf("resolve parent key: %w", err)
	}
	if !rowActive || rowParent != nil || rowOrg != orgID {
		return "", fmt.Errorf("%w: parent %s (active=%v, child=%v, org=%s)",
			ErrParentNotDelegable, parentID, rowActive, rowParent != nil, rowOrg)
	}
	return parentID, nil
}

// parentHeadroomCentsTx locks the parent's agent_budgets row FOR UPDATE and
// computes the remaining delegation headroom in cents:
//
//	limit − parent's own spend today (cost_cents) − Σ active non-expired child caps
//
// excludeChildID ("") excludes nothing; the update path passes the child's
// own ID so its current cap is not counted against itself. The parent
// budget row must exist — ErrParentBudgetMissing otherwise (fail-closed).
// The day boundary is the database clock (now() at UTC), matching the
// accumulator the real-time enforcer compares against the same limit.
func parentHeadroomCentsTx(ctx context.Context, tx auditTx, parentID, excludeChildID string) (limit, headroom int64, err error) {
	err = tx.QueryRow(ctx,
		`SELECT daily_limit_cents FROM agent_budgets WHERE agent_id = $1::uuid FOR UPDATE`,
		parentID).Scan(&limit)
	if err != nil {
		if IsNotFound(err) {
			return 0, 0, fmt.Errorf("%w: parent %s", ErrParentBudgetMissing, parentID)
		}
		return 0, 0, fmt.Errorf("lock parent budget: %w", err)
	}

	var parentSpend int64
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(SUM(cost_cents), 0) FROM agent_spend_daily
		 WHERE agent_id = $1::uuid AND day = (now() AT TIME ZONE 'utc')::date`,
		parentID).Scan(&parentSpend); err != nil {
		return 0, 0, fmt.Errorf("read parent spend: %w", err)
	}

	var childCaps int64
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(SUM(b.daily_limit_cents), 0)
		 FROM agent_keys k
		 JOIN agent_budgets b ON b.agent_id = k.id
		 WHERE k.parent_id = $1::uuid
		   AND k.active
		   AND (k.expires_at IS NULL OR k.expires_at > now())
		   AND ($2::text = '' OR k.id::text <> $2)`,
		parentID, excludeChildID).Scan(&childCaps); err != nil {
		return 0, 0, fmt.Errorf("sum committed child caps: %w", err)
	}

	return limit, limit - parentSpend - childCaps, nil
}
