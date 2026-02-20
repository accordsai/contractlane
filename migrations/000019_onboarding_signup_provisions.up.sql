ALTER TABLE onboarding_signup_sessions
  DROP CONSTRAINT IF EXISTS onboarding_signup_sessions_status_check;

ALTER TABLE onboarding_signup_sessions
  ADD CONSTRAINT onboarding_signup_sessions_status_check
  CHECK (status IN ('PENDING','VERIFIED','COMPLETED','EXPIRED'));

ALTER TABLE onboarding_signup_sessions
  ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ NULL;

CREATE TABLE onboarding_signup_provisions (
  session_id TEXT PRIMARY KEY REFERENCES onboarding_signup_sessions(session_id) ON DELETE CASCADE,
  org_id TEXT NOT NULL REFERENCES onboarding_orgs(org_id) ON DELETE RESTRICT,
  project_id TEXT NOT NULL REFERENCES onboarding_projects(project_id) ON DELETE RESTRICT,
  principal_id TEXT NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
  actor_id TEXT NOT NULL REFERENCES actors(actor_id) ON DELETE RESTRICT,
  credential_id TEXT NOT NULL REFERENCES onboarding_credentials(credential_id) ON DELETE RESTRICT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX onboarding_signup_provisions_org_idx
  ON onboarding_signup_provisions(org_id, created_at DESC);
