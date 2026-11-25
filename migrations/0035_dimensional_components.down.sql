-- Contract for 0035_dimensional_components: drops the additive dimensional
-- cost-component storage. Rows written while the table existed lose their
-- stored dimensional history (request_logs and every monetary column are
-- untouched by design — 0035 never referenced them); run this only together
-- with retired 0035 writers and readers.

DROP TABLE public.dimensional_components;
