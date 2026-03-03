CREATE TABLE IF NOT EXISTS webauthn_challenges (
  challenge_id TEXT PRIMARY KEY,
  challenge_type TEXT NOT NULL CHECK (challenge_type IN ('ASSERTION','REGISTRATION')),
  principal_id TEXT NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
  actor_id TEXT NOT NULL REFERENCES actors(actor_id) ON DELETE CASCADE,
  approval_request_id TEXT NULL,
  payload_hash TEXT NULL,
  context TEXT NOT NULL,
  challenge_bytes BYTEA NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS webauthn_challenges_actor_idx
  ON webauthn_challenges(actor_id, challenge_type, used_at, expires_at);

CREATE INDEX IF NOT EXISTS webauthn_challenges_principal_idx
  ON webauthn_challenges(principal_id, challenge_type, created_at DESC);
