ALTER TABLE contracts
  ADD COLUMN IF NOT EXISTS subject_actor_id TEXT NULL REFERENCES actors(actor_id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS template_version TEXT NULL;

CREATE INDEX IF NOT EXISTS contracts_gate_status_idx
  ON contracts(principal_id, subject_actor_id, state, template_id, template_version);
