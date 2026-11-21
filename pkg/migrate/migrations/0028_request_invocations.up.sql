-- expand-contract: expand — per-invocation durable accounting identity:
-- request_admissions (confirmed start), request_terminal_facts (synchronous
-- terminal write), invocation_id columns on request_logs, settlement_jobs and
-- credit_transactions, and the invocation/legacy-domain unique indexes that
-- ship BEFORE the superseded keys are removed (0029 contracts them away).
--
-- Design:
--   * Every dispatch-bearing invocation gets a server-minted invocation_id
--     (uuid) distinct from the client-supplied X-Request-ID, which remains a
--     correlation field only. Two legitimate invocations from one org that
--     share a client-supplied id must bill independently; a minted uuid can
--     never collide across orgs.
--   * request_admissions is the confirmed durable start: the gateway writes
--     one 'admitted' row synchronously BEFORE the first paid provider call.
--     A failed or lost-ack write refuses the request (503
--     history_unavailable) with zero provider calls. 'voided' marks a start
--     proven never to have dispatched; the consumer reconciler moves rows to
--     'reconciled' when terminal evidence lands, or 'unresolved' after a
--     grace window when none does — never back to dispatch.
--   * request_terminal_facts is the synchronous terminal write at finalize:
--     usage, attribution and exact cost committed to Postgres before the
--     completion event is published. `event` holds an accounting-only
--     projection (identities, tokens, quote states, costs, reservations,
--     termination, status, timestamp) — content-free by construction; raw
--     request/response captures never ride this column, so content-profile
--     redaction cannot be bypassed through it. Crash recovery materializes
--     the request_logs row and settlement intents exactly once from this
--     durable state without re-invoking any provider.
--   * Settlement and credit dedupe split by identity presence. Legacy rows
--     (NULL invocation_id) keep the previous semantics EXACTLY: settlement
--     stays (org_id, request_id, charge_kind) under a partial unique over
--     the legacy domain; the credit usage key stays GLOBAL on request_id
--     (cross-org identity conflicts park as requires_attention — pinned
--     behavior) under a same-named-domain partial index. Invocation rows
--     dedupe on the minted identity instead.
--
-- Interim posture (this expand applied, 0029 not yet): the superseded
-- settlement constraint and the global credit usage index are still live, so
-- an invocation-bearing usage row that shares a request_id with another usage
-- row still collides on the old global key and fails loudly (retry, then
-- requires_attention). No silent suppression is possible in either phase.
--
-- Row security: these are service-owned accounting tables in the
-- settlement_jobs / credit_transactions / event_inbox class — written by the
-- gateway request path and the loggerd reconciler under service roles, with
-- no org-authenticated endpoint reader in scope. They therefore carry
-- org_id without RLS, exactly like those siblings. The gateway request path
-- holds no app.current_org GUC to pin and the reconciler sweeps across
-- orgs, so an org_isolation policy here would only deny service writes
-- (the fail-closed outcome for accounting, not a tenant boundary).

CREATE TABLE public.request_admissions (
    invocation_id uuid PRIMARY KEY,
    org_id text NOT NULL,
    kind text NOT NULL,
    client_request_id text,         -- correlation only, never an identity
    session_id text,
    api_key_id bigint,
    session_key_id bigint,
    model_requested text,
    state text NOT NULL DEFAULT 'admitted',
    admitted_at timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz,
    resolve_reason text,
    CONSTRAINT request_admissions_state_check
        CHECK (state IN ('admitted', 'voided', 'reconciled', 'unresolved')),
    CONSTRAINT request_admissions_kind_check
        CHECK (kind IN ('chat', 'stream', 'judge', 'shadow'))
);

-- The composite key backs the terminal-facts foreign key: facts bind to the
-- same admitted invocation AND org (a uuid minted under one org can never
-- be completed under another).
CREATE UNIQUE INDEX uniq_request_admissions_invocation_org
    ON public.request_admissions (invocation_id, org_id);

-- Reconciler scan surface: only still-open admissions, oldest first.
CREATE INDEX idx_request_admissions_open
    ON public.request_admissions (admitted_at)
    WHERE state = 'admitted';

-- Recovery keyset sweep: the consumer scans PENDING admissions — still
-- 'admitted' or already reclassified 'unresolved' — by invocation uuid to
-- pair terminal facts with their confirmed starts. The partial btree keeps
-- that sweep proportional to the pending set after many completed requests
-- instead of walking the full primary-key index. Time-based unresolved
-- classification (grace-window expiry) rides idx_request_admissions_open
-- above; this index serves only the pending-facts keyset pagination.
CREATE INDEX idx_request_admissions_pending
    ON public.request_admissions (invocation_id)
    WHERE state IN ('admitted', 'unresolved');

CREATE TABLE public.request_terminal_facts (
    invocation_id uuid NOT NULL,
    org_id text NOT NULL,
    kind text NOT NULL,
    client_request_id text,
    event jsonb NOT NULL,
    committed_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT request_terminal_facts_pkey PRIMARY KEY (invocation_id),
    CONSTRAINT request_terminal_facts_invocation_fkey
        FOREIGN KEY (invocation_id, org_id)
        REFERENCES public.request_admissions (invocation_id, org_id),
    CONSTRAINT request_terminal_facts_kind_check
        CHECK (kind IN ('chat', 'stream', 'judge', 'shadow'))
);

-- Per-invocation identity on the log row: a redelivery of the same
-- invocation (fresh Redis entry id, consumer restart, DLQ replay) is a
-- no-op against the partial unique; unrelated invocations sharing a
-- client X-Request-ID keep independent rows.
ALTER TABLE public.request_logs ADD COLUMN invocation_id uuid;
CREATE UNIQUE INDEX uniq_request_logs_invocation
    ON public.request_logs (invocation_id)
    WHERE invocation_id IS NOT NULL;

-- Settlement: invocation rows dedupe on the minted identity; legacy rows
-- keep the original (org_id, request_id, charge_kind) semantics under a
-- partial unique over the NULL-invocation domain (the superseded constraint
-- itself is removed by 0029, the citing contract).
ALTER TABLE public.settlement_jobs ADD COLUMN invocation_id uuid;
CREATE UNIQUE INDEX uniq_settlement_jobs_invocation
    ON public.settlement_jobs (org_id, invocation_id, charge_kind)
    WHERE invocation_id IS NOT NULL;
CREATE UNIQUE INDEX uniq_settlement_jobs_request_legacy
    ON public.settlement_jobs (org_id, request_id, charge_kind)
    WHERE invocation_id IS NULL;

-- Credit ledger: the replacement usage key for the legacy domain stays
-- GLOBAL on request_id for NULL-invocation rows — the cross-org
-- identity-conflict parking behavior is pinned by tests and unchanged.
-- Invocation-bearing rows dedupe on the invocation identity and are
-- excluded from the legacy domain. The original global index keeps its
-- name and domain until 0029 contracts it away.
ALTER TABLE public.credit_transactions ADD COLUMN invocation_id uuid;
CREATE UNIQUE INDEX uniq_credit_transactions_usage_legacy
    ON public.credit_transactions (request_id)
    WHERE ((request_id IS NOT NULL) AND (invocation_id IS NULL) AND (type = 'usage'::text));
CREATE UNIQUE INDEX uniq_credit_transactions_invocation
    ON public.credit_transactions (invocation_id)
    WHERE ((invocation_id IS NOT NULL) AND (type = 'usage'::text));
