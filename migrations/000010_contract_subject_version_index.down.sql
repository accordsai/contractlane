DROP INDEX IF EXISTS contracts_gate_status_idx;

ALTER TABLE contracts
  DROP COLUMN IF EXISTS template_version,
  DROP COLUMN IF EXISTS subject_actor_id;
