DROP TABLE IF EXISTS template_admin_audit_events;
DROP TABLE IF EXISTS template_admin_idempotency;

DROP INDEX IF EXISTS templates_owner_status_idx;
DROP INDEX IF EXISTS templates_status_visibility_idx;

ALTER TABLE templates DROP CONSTRAINT IF EXISTS templates_visibility_check;
ALTER TABLE templates DROP CONSTRAINT IF EXISTS templates_status_check;

ALTER TABLE templates
  DROP COLUMN IF EXISTS updated_at,
  DROP COLUMN IF EXISTS archived_by,
  DROP COLUMN IF EXISTS archived_at,
  DROP COLUMN IF EXISTS published_by,
  DROP COLUMN IF EXISTS published_at,
  DROP COLUMN IF EXISTS metadata,
  DROP COLUMN IF EXISTS owner_principal_id,
  DROP COLUMN IF EXISTS visibility,
  DROP COLUMN IF EXISTS status,
  DROP COLUMN IF EXISTS template_version;
