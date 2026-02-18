CREATE TABLE contract_hash_artifacts (
  contract_id TEXT PRIMARY KEY REFERENCES contracts(contract_id) ON DELETE CASCADE,
  packet_input JSONB NOT NULL,
  diff_input JSONB NOT NULL,
  risk_input JSONB NOT NULL,
  packet_hash TEXT NOT NULL,
  diff_hash TEXT NOT NULL,
  risk_hash TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
