// Package historyops implements the ENT-HIST history-operation engine: a
// managed background-job executor for org-scoped history cleanup operations
// (preview, archive_copy, archive_and_remove_hot, purge, redact_content) over
// the selectable request-history families (request_logs, tool_calls,
// tool_call_invocations, cache_entries, sessions).
//
// Design sources (artifacts/internal-delivery-program/ENT-HIST/):
//
//   - 02-PREVIEW-OPERATION-DESIGN: selection tuple (§1), digest scheme (§4),
//     refusal catalogue (§7), output/counts contract (§3).
//   - 03-RIGHTS-MODEL: role/permission mapping, delegated-subject refusals,
//     audit-journal vocabulary.
//   - 04-ACCEPTANCE-CRITERIA: digest gate, managed-job semantics, refusal
//     discipline.
//
// Job semantics (managed background jobs): lease/checkpoint/cancel/resume. At-least-once batch execution plus an
// idempotent-per-batch Runner contract yields exactly-once effect across
// worker restarts; no second cleanup is ever created for a repeated
// idempotency key. Cancel always stops BEFORE the next batch; already-applied
// rows stay applied and the terminal state carries confirmed counts only.
// Each checkpoint renews the lease (checkpoint = progress = renewal), so
// LeaseTTL bounds ONE batch rather than the whole job; a future SQL-backed
// store must keep that renewal atomic with the checkpoint write under the
// same lease guard (status=processing, worker match, lease_until > now()).
//
// Rights (03-RIGHTS-MODEL): interactive enqueue requires a human org-admin;
// content-destructive operations additionally require explicit payload-class
// permissions. Delegated subjects (agent, CI key, API key) are refused
// fail-closed. Auto-retention enqueues carry a service actor with a policy
// version stamp and are journalled with it.
//
// Deferred by design:
//   - durable job persistence: the JobStore seam accepts a SQL-backed store;
//     that store needs migration 0017 (historyops_jobs) and is therefore NOT
//     delivered here (STOP-AND-REPORT item). MemoryJobStore is the reference
//     in-process implementation used by tests and callers without a store.
//   - purge confirmation verification: purge enqueue is refused wholesale
//     (purge_confirmation_missing) until the ENT-HIST-07 confirmation-token
//     store exists — refusing is fail-closed.
//   - HTTP handler surface: openapi is frozen; the handler mount is a
//     documented follow-up with its openapi delta.
//   - encryption/key-availability, readback/restore, hot/cold membership
//     accounting (other lanes).
//
// DO-NOT-TOUCH respected: the engine never writes request_lineage or
// policy_decisions (never selectable), and journaling goes through the
// existing admin audit seam so the audit chain stays append-only and intact.
package historyops
