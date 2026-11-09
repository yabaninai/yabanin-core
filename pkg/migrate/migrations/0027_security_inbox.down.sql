-- Reverse of 0027_security_inbox.up.sql: DROP TABLE only (the card's
-- rollback contract: only this migration's own objects). The policy, the
-- FORCE/ENABLE RLS posture, the constraint, the unique group key and the
-- keyset index all ride with the table. No other table is touched; the
-- referenced organizations rows and the secevents_documents events are
-- left exactly as they were — the inbox is derived state, the events are
-- the source of truth and stay durable.
DROP POLICY org_isolation ON public.security_inbox;
DROP TABLE public.security_inbox;
