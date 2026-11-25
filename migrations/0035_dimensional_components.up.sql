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
-- Instant carrier: event_time and effective_time are int64 nanoseconds since
-- the Unix epoch (time.Time.UnixNano ⇄ time.Unix(0, n)). Go's time.Time keeps
-- nanosecond precision while timestamptz keeps only microseconds, so a
-- timestamptz column would silently truncate the contract's sub-microsecond
-- instants; the bigint axis preserves the instant exactly and keeps the
-- (event_time DESC) page ordering monotonic. The store refuses instants
-- outside the int64 nanosecond range before any statement runs.
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
    event_time            bigint      NOT NULL,
    effective_time        bigint      NOT NULL,
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
