# Agent Loop SPI

`pkg/agentloop` defines versioned Go interfaces and a state machine for integrating
an agent loop with model calls, guarded tools, approvals, budgets and accounting.
`SPIVersion` is `v1`. These interfaces do not provide a running loop engine, HTTP
service, approval queue or durable storage implementation.

See also [Loop Execution SPI](LOOP-EXEC-SPI.md) for the built-in guarded executor.

## Interfaces

| Interface | Responsibility |
| --- | --- |
| `ExecutorSPI` | Execute a step with an operation and step request |
| `ToolRegistrySPI` | Resolve a named tool and its permission checker |
| `AllowedChecker` | Check whether the requested tool use is allowed |
| `ModelClientSPI` | Stream a model turn and report deltas |
| `ApprovalSPI` | Request an approval and retrieve its decision |
| `BudgetGuardSPI` | Admit a step against configured limits |
| `ProgressSink` | Publish status and result notifications |
| `SettlementSPI` | Record usage for accounting |

The types in `pkg/agentloop/spi.go` carry operation and step identities, tool
specifications, model-turn requests and results, approval records, budget limits,
cost estimates, usage entries and final results. Use the Go definitions for exact
field names and method signatures.

Implementations must propagate context cancellation, refuse unknown tools, and
complete admission checks before making an external call. An uncertain external
side effect must remain uncertain; retrying it can duplicate an action.

## Approval binding

An approval is tied to the proposed arguments digest and policy version. The
default TTL is 15 minutes; a negative TTL is invalid. A late decision returns
`ErrApprovalExpired`. Storage implementations must resolve competing decisions
atomically and recheck authorization when resuming work. An approval is not a
reusable permission grant.

## Budgets and settlement

Zero budget bounds mean unconfigured and must deny admission. Unknown prices are
not zero prices: report `AmountKnown=false` when an amount cannot be established.

Usage identity is the tuple `OperationID`, `StepIndex`, `TurnID`. A duplicate must
be a no-op or return `ErrDuplicateSettlement`; a genuinely new turn needs a new
turn identifier. In v1 an unknown-price entry is final rather than a promise of
later automatic repricing.

`ProgressSink` notifications are best-effort. Use durable operation and usage
storage when recovery or an audit trail is required; progress delivery does not
supply either.

## State transitions

`pkg/agentloop/state.go` defines the allowed transitions:

| Current state | Allowed next states |
| --- | --- |
| `created` | `running` |
| `running` | `awaiting_approval`, `cancelled`, `expired`, `failed`, `completed` |
| `awaiting_approval` | `running`, `cancelled`, `expired` |
| `cancelled`, `expired`, `failed`, `completed` | None |

There is no separate `approved` state. Resumption returns to `running` and repeats
checks. Transitioning a state to itself is invalid. In particular, an operation
cannot transition directly from `awaiting_approval` to `completed` or `failed`.

An implementation that persists operations must make state changes atomic and
retain enough information to distinguish an unstarted call from an uncertain
external effect after a crash. The state helper alone does not implement this
storage or recovery behavior.

## Versioning

Version 1 is additive. Breaking interface changes require a separate version;
consumers should not assume that a compatible interface implies a complete loop
engine or durable operational guarantees.
