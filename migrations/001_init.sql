-- Contract Lane V1 - Minimal Postgres Schema
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE principals (
  principal_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  jurisdiction TEXT NOT NULL,
  timezone TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE actors (
  actor_id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
  actor_type TEXT NOT NULL CHECK (actor_type IN ('HUMAN','AGENT')),
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','REVOKED')),
  email TEXT NULL,
  name TEXT NULL,
  roles TEXT[] NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK ((actor_type='HUMAN' AND email IS NOT NULL) OR (actor_type='AGENT' AND name IS NOT NULL))
);

CREATE INDEX actors_principal_idx ON actors(principal_id);
CREATE INDEX actors_roles_gin_idx ON actors USING GIN (roles);

CREATE TABLE agent_credentials (
  actor_id TEXT PRIMARY KEY REFERENCES actors(actor_id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL,
  scopes TEXT[] NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ NULL
);

CREATE TABLE invites (
  invite_id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  requested_roles TEXT[] NOT NULL DEFAULT '{}',
  status TEXT NOT NULL CHECK (status IN ('PENDING','COMPLETED','EXPIRED','REVOKED')),
  expires_at TIMESTAMPTZ NOT NULL,
  actor_id TEXT NULL REFERENCES actors(actor_id) ON DELETE SET NULL,
  token_hash TEXT NOT NULL,
  callback_url TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at TIMESTAMPTZ NULL
);

CREATE UNIQUE INDEX invites_token_hash_uq ON invites(token_hash);

CREATE TABLE webauthn_credentials (
  credential_id TEXT PRIMARY KEY,
  actor_id TEXT NOT NULL REFERENCES actors(actor_id) ON DELETE CASCADE,
  public_key_cbor BYTEA NOT NULL,
  sign_count BIGINT NOT NULL DEFAULT 0,
  rp_id TEXT NOT NULL,
  transports TEXT[] NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at TIMESTAMPTZ NULL,
  revoked_at TIMESTAMPTZ NULL
);

CREATE TABLE policy_profiles (
  actor_id TEXT PRIMARY KEY REFERENCES actors(actor_id) ON DELETE CASCADE,
  principal_id TEXT NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
  automation_level TEXT NOT NULL CHECK (automation_level IN ('A0_FULL_MANUAL','A1_GUARDED','A2_FAST_LANE','A3_AGENT_FIRST')),
  action_gates JSONB NOT NULL DEFAULT '{}'::jsonb,
  variable_rules JSONB NOT NULL DEFAULT '[]'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE templates (
  template_id TEXT PRIMARY KEY,
  contract_type TEXT NOT NULL,
  jurisdiction TEXT NOT NULL,
  display_name TEXT NOT NULL,
  risk_tier TEXT NOT NULL CHECK (risk_tier IN ('LOW','MEDIUM','HIGH')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE template_governance (
  template_id TEXT PRIMARY KEY REFERENCES templates(template_id) ON DELETE CASCADE,
  template_gates JSONB NOT NULL DEFAULT '{}'::jsonb,
  protected_slots TEXT[] NOT NULL DEFAULT '{}',
  prohibited_slots TEXT[] NOT NULL DEFAULT '{}',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE template_variables (
  template_id TEXT NOT NULL REFERENCES templates(template_id) ON DELETE CASCADE,
  var_key TEXT NOT NULL,
  var_type TEXT NOT NULL CHECK (var_type IN ('STRING','DATE','MONEY','INT','DURATION','ADDRESS')),
  required BOOLEAN NOT NULL DEFAULT false,
  sensitivity TEXT NOT NULL DEFAULT 'NONE' CHECK (sensitivity IN ('NONE','PII')),
  set_policy TEXT NOT NULL CHECK (set_policy IN ('AGENT_ALLOWED','HUMAN_REQUIRED','AGENT_FILL_HUMAN_REVIEW','DEFER_TO_IDENTITY')),
  constraints JSONB NOT NULL DEFAULT '{}'::jsonb,
  PRIMARY KEY (template_id, var_key)
);

CREATE TABLE principal_templates (
  principal_id TEXT NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
  template_id TEXT NOT NULL REFERENCES templates(template_id) ON DELETE CASCADE,
  enabled BOOLEAN NOT NULL DEFAULT true,
  enabled_by_actor_id TEXT NULL REFERENCES actors(actor_id) ON DELETE SET NULL,
  override_gates JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (principal_id, template_id)
);

CREATE TABLE contracts (
  contract_id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
  template_id TEXT NOT NULL REFERENCES templates(template_id),
  state TEXT NOT NULL CHECK (state IN (
    'DRAFT_CREATED','POLICY_VALIDATED','RENDERED','AWAITING_APPROVAL','APPROVED',
    'SENT_TO_COUNTERPARTY','REDLINE_RECEIVED','NEGOTIATION_IN_PROGRESS',
    'READY_TO_SIGN','SIGNATURE_SENT','SIGNED_BY_US','SIGNED_BY_THEM','EFFECTIVE','ARCHIVED','REJECTED'
  )),
  risk_level TEXT NOT NULL DEFAULT 'LOW' CHECK (risk_level IN ('LOW','MEDIUM','HIGH')),
  counterparty_name TEXT NULL,
  counterparty_email TEXT NULL,
  created_by_actor_id TEXT NULL REFERENCES actors(actor_id) ON DELETE SET NULL,
  packet_hash TEXT NULL,
  diff_hash TEXT NULL,
  risk_hash TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE contract_variables (
  contract_id TEXT NOT NULL REFERENCES contracts(contract_id) ON DELETE CASCADE,
  var_key TEXT NOT NULL,
  value TEXT NOT NULL,
  source TEXT NOT NULL CHECK (source IN ('HUMAN','AGENT','SYSTEM')),
  review_status TEXT NOT NULL DEFAULT 'NOT_NEEDED' CHECK (review_status IN ('NOT_NEEDED','PENDING','APPROVED','REJECTED')),
  updated_by_actor_id TEXT NULL REFERENCES actors(actor_id) ON DELETE SET NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  reviewed_by_actor_id TEXT NULL REFERENCES actors(actor_id) ON DELETE SET NULL,
  reviewed_at TIMESTAMPTZ NULL,
  PRIMARY KEY (contract_id, var_key)
);

CREATE TABLE approval_requests (
  approval_request_id TEXT PRIMARY KEY,
  contract_id TEXT NOT NULL REFERENCES contracts(contract_id) ON DELETE CASCADE,
  action TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('PENDING','APPROVED','REJECTED','CANCELLED')),
  required_roles TEXT[] NOT NULL DEFAULT '{}',
  missing_required_vars TEXT[] NOT NULL DEFAULT '{}',
  needs_human_entry TEXT[] NOT NULL DEFAULT '{}',
  needs_human_review TEXT[] NOT NULL DEFAULT '{}',
  review_token_hash TEXT NOT NULL,
  created_by_actor_id TEXT NULL REFERENCES actors(actor_id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  decided_at TIMESTAMPTZ NULL
);

CREATE TABLE approval_decisions (
  approval_request_id TEXT NOT NULL REFERENCES approval_requests(approval_request_id) ON DELETE CASCADE,
  actor_id TEXT NOT NULL REFERENCES actors(actor_id) ON DELETE CASCADE,
  decision TEXT NOT NULL CHECK (decision IN ('APPROVE','REJECT')),
  decided_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  signed_payload JSONB NOT NULL,
  signed_payload_hash TEXT NOT NULL,
  signature_type TEXT NOT NULL CHECK (signature_type IN ('WEBAUTHN_ASSERTION','SECP256K1','HMAC')),
  signature_object JSONB NOT NULL,
  PRIMARY KEY (approval_request_id, actor_id)
);

CREATE TABLE signature_envelopes (
  contract_id TEXT PRIMARY KEY REFERENCES contracts(contract_id) ON DELETE CASCADE,
  provider TEXT NOT NULL CHECK (provider IN ('DOCUSIGN','ADOBESIGN','INTERNAL')),
  envelope_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('CREATED','SENT','SIGNED_BY_US','SIGNED_BY_THEM','VOIDED','DECLINED','ERROR')),
  last_event_at TIMESTAMPTZ NULL,
  raw_last_event JSONB NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE contract_events (
  event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  contract_id TEXT NOT NULL REFERENCES contracts(contract_id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  actor_id TEXT NULL,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  payload_hash TEXT NULL
);

