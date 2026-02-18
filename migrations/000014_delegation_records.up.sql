CREATE TABLE delegation_records (
  delegation_id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
  delegator_actor_id TEXT NOT NULL REFERENCES actors(actor_id) ON DELETE CASCADE,
  delegate_actor_id TEXT NOT NULL REFERENCES actors(actor_id) ON DELETE CASCADE,
  scope JSONB NOT NULL,
  issued_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NULL,
  revoked_at TIMESTAMPTZ NULL,
  signature JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX delegation_records_principal_idx ON delegation_records(principal_id);
CREATE INDEX delegation_records_principal_delegate_idx ON delegation_records(principal_id, delegate_actor_id);
CREATE INDEX delegation_records_delegate_idx ON delegation_records(delegate_actor_id);
