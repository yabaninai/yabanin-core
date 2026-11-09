-- expand-contract: expand — durable security-event store: the exactly-once home for pkg/secevents documents.
-- 0021_secevents_documents — E01-P03 closure, lane imp-e01p03v C4 (owner
-- decision D13 «E01 implementation», ENTERPRISE-DECISIONS-2026-11-05).
--
-- secevents_documents is the durable store behind pkg/secevents.DurableSink
-- (AUD-EVENT-01, 15c7f0df): the exactly-once decision is one statement —
-- INSERT ... ON CONFLICT (org_id, event_id) DO NOTHING — so persist-then-error
-- retries, redeliveries after a restart and concurrent ingester instances all
-- converge to exactly one durable JSON document per (org, event_id); first
-- write wins, a recorded document is never mutated by redeliveries
-- (E01-P03 acceptance invariant: redelivery never doubles events).
--
-- document is the canonical wire encoding (Event.Encode) at record time and
-- stays the source of truth; schema_version/event_type are projection columns
-- for operational queries only. occurred_at is the PRODUCER timestamp stored
-- verbatim — delivery skew is never rebased or clamped here (recorded_at is
-- server-side delivery bookkeeping; the skew contract lives in the Ingester).
--
-- The DDL mirrors durableSchemaSQL (pkg/secevents/durable.go) minus the
-- IF NOT EXISTS: THIS migration is the production home of the table;
-- EnsureSchema remains the idempotent bootstrap for SPI and test stands
-- (a no-op once this migration has run).
--
-- ISOLATION POSTURE — NO RLS, org key in every access (0012/sso rationale
-- shape): the store has no production consumer yet (pkg/secevents is the
-- additive enterprise SPI; the production event path is eventpublisher →
-- loggerd/consumer event_inbox). The org dimension is the leading PRIMARY
-- KEY column and every store access keys by (org_id, event_id); when the
-- E01 wiring cards connect a real consumer, THAT card owns the tenant
-- read-path decision (RLS or explicit predicate) together with the E01-P04
-- isolation contract — this migration adds an empty table and no readers.
CREATE TABLE secevents_documents (
	org_id         TEXT        NOT NULL,
	event_id       TEXT        NOT NULL,
	schema_version INT         NOT NULL,
	event_type     TEXT        NOT NULL,
	occurred_at    TIMESTAMPTZ NOT NULL,
	document       JSONB       NOT NULL,
	recorded_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (org_id, event_id)
);
