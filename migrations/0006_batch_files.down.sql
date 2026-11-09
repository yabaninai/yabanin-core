-- R048-02 down: drop the Batch/Files capability tables (lines cascade with
-- their batch).

DROP TABLE public.batch_lines;
DROP TABLE public.batch_jobs;
DROP TABLE public.batch_files;
