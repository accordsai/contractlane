DROP INDEX IF EXISTS contracts_gate_subject_version_uq;

ALTER TABLE contracts
  DROP COLUMN IF EXISTS gate_key;
