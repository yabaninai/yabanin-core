-- Contract for 0031_request_payload_grant_row: drops the row binding column.
-- Redeemable grants lose their pinned row and would resolve through the
-- legacy single-carrier path; run this only together with retired 0031
-- readers (the column is additive and unreferenced by earlier versions).

ALTER TABLE public.request_payload_grants
    DROP COLUMN request_row_key;
