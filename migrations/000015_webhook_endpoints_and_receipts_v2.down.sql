DROP INDEX IF EXISTS webhook_receipts_v2_principal_contract_idx;
DROP INDEX IF EXISTS webhook_receipts_v2_principal_received_idx;
DROP INDEX IF EXISTS webhook_receipts_v2_principal_provider_event_uq;
DROP TABLE IF EXISTS webhook_receipts_v2;

DROP INDEX IF EXISTS webhook_endpoints_principal_provider_idx;
DROP INDEX IF EXISTS webhook_endpoints_token_uq;
DROP INDEX IF EXISTS webhook_endpoints_provider_token_uq;
DROP TABLE IF EXISTS webhook_endpoints;
