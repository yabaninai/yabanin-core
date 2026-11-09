-- expand-contract: expand — secevents_documents row-level security: the W04-C01
-- Option-D tenant boundary (E06-P01 W01-C01, Trigger ②): ENABLE+FORCE RLS and the
-- house org_isolation policy on the app.current_org GUC. The org key is TEXT
-- (0021 PK), so the house NULLIF shape carries no ::uuid cast. DDL is verbatim
-- from the decision record (W04-readpath-decision.md §5.1); numbering: the
-- decision planned 0022 for the first-reader wiring card, the number moved to
-- 0026 by the fleet convergence rule (0022 observed assets / 0023 reserved
-- unused / 0024 fleet registry / 0025 dataclass taxonomies claimed first —
-- reservedGaps in pkg/migrate/mirror_numbering_test.go). Policies are
-- migration-only (house rule, never in EnsureSchema), so the 0021 mirror pin is
-- unaffected. The writer pins the GUC in the same transaction as its INSERT
-- (pkg/secevents durablePinSQL; bypass/RLS-exempt sessions skip the inert pin so
-- superuser stands keep pristine GUC-less connections); the reader (pkg/inbox)
-- derives org from
-- the authenticated context (W04 §5.3) and keeps the WHERE org_id predicate as
-- defense-in-depth.
ALTER TABLE public.secevents_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.secevents_documents FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON public.secevents_documents
  USING (org_id = NULLIF(current_setting('app.current_org', true), ''))
  WITH CHECK (org_id = NULLIF(current_setting('app.current_org', true), ''));
