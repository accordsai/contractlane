CREATE TABLE webhook_receipts (
  provider TEXT NOT NULL,
  event_id TEXT NOT NULL,
  envelope_id TEXT NULL,
  event_type TEXT NULL,
  payload_hash TEXT NOT NULL,
  signature_valid BOOLEAN NOT NULL,
  replay_count BIGINT NOT NULL DEFAULT 0,
  raw_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  processed_at TIMESTAMPTZ NULL,
  processing_result TEXT NOT NULL DEFAULT 'RECEIVED',
  last_replayed_at TIMESTAMPTZ NULL,
  PRIMARY KEY (provider, event_id)
);

CREATE INDEX webhook_receipts_envelope_idx ON webhook_receipts(provider, envelope_id, received_at DESC);
