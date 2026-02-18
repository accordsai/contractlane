CREATE TABLE contract_changesets (
  changeset_id TEXT PRIMARY KEY,
  contract_id TEXT NOT NULL REFERENCES contracts(contract_id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK (status IN ('PENDING','APPROVED','REJECTED','APPLIED')),
  payload JSONB NOT NULL,
  required_roles TEXT[] NOT NULL DEFAULT '{LEGAL}',
  proposed_by_actor_id TEXT NOT NULL REFERENCES actors(actor_id) ON DELETE RESTRICT,
  decided_by_actor_id TEXT NULL REFERENCES actors(actor_id) ON DELETE SET NULL,
  decided_at TIMESTAMPTZ NULL,
  applied_by_actor_id TEXT NULL REFERENCES actors(actor_id) ON DELETE SET NULL,
  applied_at TIMESTAMPTZ NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
