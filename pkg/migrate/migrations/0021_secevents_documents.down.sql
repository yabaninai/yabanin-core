-- Reverse of 0021_secevents_documents.up.sql: the durable security-event
-- store is removed. No event documents are restored here — security-event
-- durability reverts to the pre-0021 posture (in-memory per-instance dedup
-- only, AUD-EVENT-01 baseline); a re-upgrade starts the store empty and
-- redeliveries after re-upgrade record fresh documents.
DROP TABLE IF EXISTS secevents_documents;
