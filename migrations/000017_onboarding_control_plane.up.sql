CREATE TABLE onboarding_orgs (
  org_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE onboarding_users (
  user_id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE onboarding_memberships (
  org_id TEXT NOT NULL REFERENCES onboarding_orgs(org_id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES onboarding_users(user_id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('OWNER','ADMIN','MEMBER')),
  status TEXT NOT NULL CHECK (status IN ('ACTIVE','SUSPENDED')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, user_id)
);

CREATE TABLE onboarding_projects (
  project_id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES onboarding_orgs(org_id) ON DELETE CASCADE,
  principal_id TEXT NOT NULL UNIQUE REFERENCES principals(principal_id) ON DELETE RESTRICT,
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE onboarding_credentials (
  credential_id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES onboarding_projects(project_id) ON DELETE CASCADE,
  principal_id TEXT NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
  actor_id TEXT NOT NULL REFERENCES actors(actor_id) ON DELETE RESTRICT,
  token_hash TEXT NOT NULL UNIQUE,
  scopes TEXT[] NOT NULL DEFAULT '{}',
  status TEXT NOT NULL CHECK (status IN ('ACTIVE','REVOKED')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ NULL
);

CREATE TABLE onboarding_idempotency_records (
  scope_id TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  response_status INT NOT NULL,
  response_body JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (scope_id, actor_id, idempotency_key, endpoint)
);

CREATE TABLE onboarding_audit_events (
  event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id TEXT NULL REFERENCES onboarding_orgs(org_id) ON DELETE SET NULL,
  project_id TEXT NULL REFERENCES onboarding_projects(project_id) ON DELETE SET NULL,
  actor_id TEXT NULL REFERENCES actors(actor_id) ON DELETE SET NULL,
  event_type TEXT NOT NULL,
  payload JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX onboarding_projects_org_idx ON onboarding_projects(org_id);
CREATE INDEX onboarding_credentials_project_idx ON onboarding_credentials(project_id, created_at DESC);
CREATE INDEX onboarding_audit_events_org_created_idx ON onboarding_audit_events(org_id, created_at DESC);
