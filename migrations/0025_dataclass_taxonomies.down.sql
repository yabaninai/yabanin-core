-- 0025_dataclass_taxonomies down (E04-P01 W02-C02): rollback removes ONLY
-- the taxonomy table (dispatch AC: "down-миграция удаляет ТОЛЬКО таблицу
-- таксономий"). No other object exists in this migration's down scope.

DROP TABLE IF EXISTS public.dataclass_taxonomies;
