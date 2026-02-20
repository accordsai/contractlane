CREATE TABLE onboarding_signup_sessions (
  session_id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  org_name TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('PENDING','VERIFIED','EXPIRED')),
  verification_code_hash TEXT NOT NULL,
  verification_attempts INT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  verified_at TIMESTAMPTZ NULL,
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX onboarding_signup_sessions_email_created_idx
  ON onboarding_signup_sessions(email, created_at DESC);

CREATE INDEX onboarding_signup_sessions_status_expires_idx
  ON onboarding_signup_sessions(status, expires_at);
