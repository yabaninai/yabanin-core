-- expand-contract: expand — additive per-request dimensional cost-component
-- storage (CM-00-02): one org-scoped row per validated pkg/dimensions
-- Component, keyed by the stable (org_id, tenant_id, event_id, component_id)
-- identity so a replayed delivery cannot double-count (the unique key fails
-- loudly; silent dedup semantics belong to CM-00-03).
--
-- Decimal carrier (MULTIDIMENSIONAL-ACCOUNTING.md): quantities and bounds are
-- stored as canonical decimal TEXT (dimensions.Decimal.String ⇄ ParseDecimal
-- roundtrip). NULL means absent/unknown and can never read as zero; an
-- explicit zero is stored as '0'. No float or numeric coercion exists on the
-- path, and the fractional/significant-digit working limits live in the
-- validated contract, not in SQL rounding.
--
-- Instant carrier: the contract's time.Time instants keep nanosecond
-- precision and carry no range restriction. Timestamptz keeps only
-- microseconds; a single int64-nanosecond column wraps for contract-valid
-- instants (any year past ~2262); and even a bigint epoch-seconds column
-- is NOT chronologically monotonic: time.Time can represent seconds below
-- the int64 seconds floor (internal int64 seconds reach further down), and
-- time.Time.Unix silently wraps mod 2^64 there — one second before
-- time.Unix(math.MinInt64, 0) reads back as math.MaxInt64, so that older
-- instant would sort as the newest row. Each instant therefore splits into
-- its TRUE mathematical second — stored as arbitrary-precision numeric,
-- corrected by -2^64 when Unix wrapped — plus a nanosecond fraction
-- (integer, 0..999999999, time.Time.Nanosecond, which never wraps). The
-- numeric keys order exactly chronologically; reading back wraps the
-- second into the int64 congruence class and time.Unix(sec, frac)
-- reconstructs the exact original instant, wrap included. The composite
-- (event_time_unix DESC, event_time_nanos DESC) page ordering is the exact
-- instant order on this axis.
--
-- Legacy treatment: pure additive — a new table only. request_logs, its
-- monetary columns and every existing read keep their exact previous shape;
-- explicit reader SELECT lists elsewhere are unaffected.
--
-- Scope posture: house-RLS org_isolation (uuid org_id, NULLIF
-- (current_setting('app.current_org')) binding) with FORCE so a session
-- without the org GUC is fail-closed, matching the policy_decisions posture.
-- The store keeps the explicit WHERE org_id predicate as the
-- statement-level guarantee on every operation.
--
-- Scope: this preview assumes a clean install; the table is also safe in
-- place on an existing installation.

CREATE TABLE public.dimensional_components (
    org_id                uuid        NOT NULL,
    tenant_id             text        NOT NULL,
    event_id              text        NOT NULL,
    component_id          text        NOT NULL,
    request_id            text        NOT NULL,
    task_id               text        NOT NULL DEFAULT '',
    meter                 text        NOT NULL,
    unit                  text        NOT NULL,
    quantity_text         text,
    bounds_lower_text     text,
    bounds_upper_text     text,
    source_kind           text        NOT NULL,
    source_ref            text        NOT NULL,
    method                text        NOT NULL,
    formula               text        NOT NULL DEFAULT '',
    factor_version        text        NOT NULL DEFAULT '',
    event_time_unix       numeric     NOT NULL,
    event_time_nanos      integer     NOT NULL,
    effective_time_unix   numeric     NOT NULL,
    effective_time_nanos  integer     NOT NULL,
    boundary              text        NOT NULL,
    allocation_basis      text        NOT NULL DEFAULT '',
    precision_kind        text        NOT NULL,
    lifecycle             text        NOT NULL,
    corrects_component_id text        NOT NULL DEFAULT '',
    coverage_meters       text[]      NOT NULL DEFAULT '{}',
    created_at            timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, tenant_id, event_id, component_id),
    CONSTRAINT dimensional_components_org_id_fkey FOREIGN KEY (org_id)
        REFERENCES public.organizations (id) ON DELETE CASCADE,
    CONSTRAINT dimensional_components_precision_check
        CHECK (precision_kind = ANY (ARRAY['exact'::text, 'estimated'::text, 'unknown'::text])),
    CONSTRAINT dimensional_components_boundary_check
        CHECK (boundary = ANY (ARRAY['measurement'::text, 'allocation'::text])),
    CONSTRAINT dimensional_components_lifecycle_check
        CHECK (lifecycle = ANY (ARRAY['provisional'::text, 'final'::text, 'corrected'::text]))
);

CREATE INDEX idx_dimensional_components_org_request
    ON public.dimensional_components USING btree (org_id, request_id);

ALTER TABLE public.dimensional_components ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.dimensional_components FORCE ROW LEVEL SECURITY;

CREATE POLICY org_isolation ON public.dimensional_components
    USING ((org_id = (NULLIF(current_setting('app.current_org'::text, true), ''::text))::uuid))
    WITH CHECK ((org_id = (NULLIF(current_setting('app.current_org'::text, true), ''::text))::uuid));
