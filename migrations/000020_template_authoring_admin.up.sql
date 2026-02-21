ALTER TABLE templates
  ADD COLUMN IF NOT EXISTS template_version TEXT NOT NULL DEFAULT 'v1',
  ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'PUBLISHED',
  ADD COLUMN IF NOT EXISTS visibility TEXT NOT NULL DEFAULT 'GLOBAL',
  ADD COLUMN IF NOT EXISTS owner_principal_id TEXT NULL REFERENCES principals(principal_id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS published_at TIMESTAMPTZ NULL,
  ADD COLUMN IF NOT EXISTS published_by TEXT NULL REFERENCES actors(actor_id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ NULL,
  ADD COLUMN IF NOT EXISTS archived_by TEXT NULL REFERENCES actors(actor_id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

ALTER TABLE templates
  DROP CONSTRAINT IF EXISTS templates_status_check;
ALTER TABLE templates
  ADD CONSTRAINT templates_status_check CHECK (status IN ('DRAFT','PUBLISHED','ARCHIVED'));

ALTER TABLE templates
  DROP CONSTRAINT IF EXISTS templates_visibility_check;
ALTER TABLE templates
  ADD CONSTRAINT templates_visibility_check CHECK (visibility IN ('GLOBAL','PRIVATE'));

UPDATE templates
SET template_version = COALESCE(NULLIF(split_part(template_id, '_', array_length(string_to_array(template_id, '_'), 1)), ''), 'v1')
WHERE template_version = 'v1';

UPDATE templates
SET published_at = created_at
WHERE status = 'PUBLISHED' AND published_at IS NULL;

CREATE INDEX IF NOT EXISTS templates_status_visibility_idx ON templates(status, visibility, contract_type, jurisdiction);
CREATE INDEX IF NOT EXISTS templates_owner_status_idx ON templates(owner_principal_id, status);

CREATE TABLE IF NOT EXISTS template_admin_idempotency (
  admin_subject TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  response_status INT NOT NULL,
  response_body JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (admin_subject, idempotency_key, endpoint)
);

CREATE TABLE IF NOT EXISTS template_admin_audit_events (
  event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  template_id TEXT NOT NULL REFERENCES templates(template_id) ON DELETE CASCADE,
  action TEXT NOT NULL,
  admin_subject TEXT NOT NULL,
  actor_id TEXT NULL REFERENCES actors(actor_id) ON DELETE SET NULL,
  principal_id TEXT NULL REFERENCES principals(principal_id) ON DELETE SET NULL,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS template_admin_audit_template_created_idx
  ON template_admin_audit_events(template_id, created_at DESC);
