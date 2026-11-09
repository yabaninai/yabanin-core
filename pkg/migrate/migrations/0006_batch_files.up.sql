-- R048-02 (ratified 2026-10-18): Batch + Files capability.
-- D1: Postgres queue — batch_jobs follows the settlement_jobs claim/lease
--     pattern (FOR UPDATE SKIP LOCKED claim, lease_until recovery, bounded
--     attempts); per-line durability lives in batch_lines so a crashed
--     executor resumes without re-billing executed lines (deterministic
--     request_id per line dedupes settlement).
-- D2: file payloads are stored in Postgres bytea (batch_files.content) —
--     size-bounded by the application cap (100 MiB, D3).
-- D3: limits — file cap 100 MiB / batch ≤ 1000 requests / 30-day retention
--     (expires_at columns + the executor retention sweep).
-- Org isolation: every query filters org_id; a foreign id resolves to
-- "not found" (404 semantics), never 403.

CREATE TABLE public.batch_files (
    id text NOT NULL,
    org_id text NOT NULL,
    filename text DEFAULT ''::text NOT NULL,
    purpose text NOT NULL,
    bytes bigint NOT NULL,
    content bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT batch_files_pkey PRIMARY KEY (id),
    CONSTRAINT batch_files_purpose_check CHECK ((purpose = ANY (ARRAY['batch'::text, 'batch.output'::text, 'batch.error'::text]))),
    CONSTRAINT batch_files_bytes_check CHECK ((bytes >= 0))
);

CREATE INDEX batch_files_org_idx ON public.batch_files USING btree (org_id, created_at);
CREATE INDEX batch_files_retention_idx ON public.batch_files USING btree (expires_at);

CREATE TABLE public.batch_jobs (
    id text NOT NULL,
    org_id text NOT NULL,
    api_key_id text DEFAULT ''::text NOT NULL,
    input_file_id text NOT NULL,
    endpoint text NOT NULL,
    model text DEFAULT ''::text NOT NULL,
    metadata jsonb,
    status text DEFAULT 'validating'::text NOT NULL,
    total_count integer DEFAULT 0 NOT NULL,
    completed_count integer DEFAULT 0 NOT NULL,
    failed_count integer DEFAULT 0 NOT NULL,
    output_file_id text,
    error_file_id text,
    cancel_requested_at timestamp with time zone,
    attempts integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    lease_until timestamp with time zone,
    last_error text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT batch_jobs_pkey PRIMARY KEY (id),
    CONSTRAINT batch_jobs_status_check CHECK ((status = ANY (ARRAY['validating'::text, 'in_progress'::text, 'finalizing'::text, 'completed'::text, 'failed'::text, 'cancelling'::text, 'cancelled'::text, 'expired'::text]))),
    CONSTRAINT batch_jobs_counts_check CHECK (((completed_count >= 0) AND (failed_count >= 0) AND (total_count >= (completed_count + failed_count))))
);

CREATE INDEX batch_jobs_org_idx ON public.batch_jobs USING btree (org_id, created_at);
CREATE INDEX batch_jobs_claim_idx ON public.batch_jobs USING btree (status, next_attempt_at);
CREATE INDEX batch_jobs_retention_idx ON public.batch_jobs USING btree (expires_at);

CREATE TABLE public.batch_lines (
    batch_id text NOT NULL,
    line_no integer NOT NULL,
    custom_id text DEFAULT ''::text NOT NULL,
    request_id text NOT NULL,
    request_body jsonb NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    response_code integer,
    response_body jsonb,
    error text,
    CONSTRAINT batch_lines_pkey PRIMARY KEY (batch_id, line_no),
    CONSTRAINT batch_lines_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'done'::text, 'failed'::text]))),
    CONSTRAINT batch_lines_batch_id_fkey FOREIGN KEY (batch_id) REFERENCES public.batch_jobs(id) ON DELETE CASCADE
);
