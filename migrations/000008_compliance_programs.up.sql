CREATE TABLE compliance_programs (
  principal_id TEXT NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
  program_key TEXT NOT NULL,
  mode TEXT NOT NULL CHECK (mode IN ('STRICT_RECONSENT')),
  required_template_id TEXT NULL REFERENCES templates(template_id),
  required_template_version TEXT NULL,
  published_at TIMESTAMPTZ NULL,
  created_by_actor_id TEXT NOT NULL REFERENCES actors(actor_id) ON DELETE RESTRICT,
  updated_by_actor_id TEXT NULL REFERENCES actors(actor_id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (principal_id, program_key)
);

CREATE TABLE compliance_program_events (
  event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  principal_id TEXT NOT NULL,
  program_key TEXT NOT NULL,
  event_type TEXT NOT NULL,
  actor_id TEXT NULL,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  FOREIGN KEY (principal_id, program_key) REFERENCES compliance_programs(principal_id, program_key) ON DELETE CASCADE
);
