ALTER TABLE contracts
  ADD COLUMN IF NOT EXISTS gate_key TEXT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS contracts_gate_subject_version_uq
  ON contracts(principal_id, gate_key, subject_actor_id, template_id, template_version)
  WHERE gate_key IS NOT NULL AND subject_actor_id IS NOT NULL AND template_version IS NOT NULL;
