CREATE TABLE magic_link_tokens (
  token_id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
  actor_id TEXT NOT NULL REFERENCES actors(actor_id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX magic_link_tokens_lookup_idx
  ON magic_link_tokens(principal_id, email, expires_at DESC);

CREATE TABLE human_auth_sessions (
  session_id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
  actor_id TEXT NOT NULL REFERENCES actors(actor_id) ON DELETE CASCADE,
  auth_method TEXT NOT NULL CHECK (auth_method IN ('MAGIC_LINK')),
  token_hash TEXT NOT NULL UNIQUE,
  issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ NULL
);

CREATE INDEX human_auth_sessions_actor_idx
  ON human_auth_sessions(actor_id, expires_at DESC);
