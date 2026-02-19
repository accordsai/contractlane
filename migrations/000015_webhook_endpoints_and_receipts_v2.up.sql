CREATE TABLE webhook_endpoints (
  endpoint_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  principal_id UUID NOT NULL,
  provider TEXT NOT NULL,
  endpoint_token TEXT NOT NULL,
  secret TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ NULL
);

CREATE UNIQUE INDEX webhook_endpoints_provider_token_uq ON webhook_endpoints(provider, endpoint_token);
CREATE UNIQUE INDEX webhook_endpoints_token_uq ON webhook_endpoints(endpoint_token);
CREATE INDEX webhook_endpoints_principal_provider_idx ON webhook_endpoints(principal_id, provider);

CREATE TABLE webhook_receipts_v2 (
  receipt_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  principal_id UUID NOT NULL,
  provider TEXT NOT NULL,
  event_type TEXT NOT NULL,
  provider_event_id TEXT NULL,
  received_at TIMESTAMPTZ NOT NULL,
  request_method TEXT NOT NULL,
  request_path TEXT NOT NULL,
  raw_body BYTEA NOT NULL,
  raw_body_sha256 TEXT NOT NULL,
  headers_canonical_json JSONB NOT NULL,
  headers_sha256 TEXT NOT NULL,
  request_sha256 TEXT NOT NULL,
  signature_valid BOOLEAN NOT NULL,
  signature_scheme TEXT NOT NULL,
  signature_details JSONB NOT NULL,
  linked_contract_id UUID NULL,
  linked_action TEXT NULL,
  processing_status TEXT NOT NULL,
  processed_at TIMESTAMPTZ NULL
);

CREATE UNIQUE INDEX webhook_receipts_v2_principal_provider_event_uq
  ON webhook_receipts_v2(principal_id, provider, provider_event_id)
  WHERE provider_event_id IS NOT NULL;

CREATE INDEX webhook_receipts_v2_principal_received_idx
  ON webhook_receipts_v2(principal_id, received_at);

CREATE INDEX webhook_receipts_v2_principal_contract_idx
  ON webhook_receipts_v2(principal_id, linked_contract_id);
